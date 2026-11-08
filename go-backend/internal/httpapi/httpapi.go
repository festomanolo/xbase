// Package httpapi wires the Go backend's HTTP routes and middleware.
package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
	"github.com/festomanolo/xbase/go-backend/internal/config"
	"github.com/festomanolo/xbase/go-backend/internal/db"
	"github.com/festomanolo/xbase/go-backend/internal/ratelimit"
)

type Server struct {
	cfg     *config.Config
	pool    *pgxpool.Pool
	limiter *ratelimit.Limiter
	metrics *metrics
	hub     *hub
	// httpc talks to Supabase Storage and the embeddings provider. No overall
	// Timeout: uploads/downloads stream; per-call deadlines come from contexts.
	httpc *http.Client
}

func New(cfg *config.Config, pool *pgxpool.Pool, limiter *ratelimit.Limiter) *Server {
	return &Server{
		cfg: cfg, pool: pool, limiter: limiter,
		metrics: &metrics{},
		hub:     newHub(cfg.AppID),
		httpc:   &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 8, IdleConnTimeout: 60 * time.Second}},
	}
}

type ctxKey int

const claimsKey ctxKey = 0

// Handler returns the full middleware-wrapped router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /health/db", s.healthDB)
	mux.Handle("GET /api/v1/me", s.requireUser(s.me))
	mux.Handle("GET /api/v1/workspaces", s.requireUser(s.listWorkspaces))
	mux.Handle("POST /api/v1/workspaces", s.requireUser(s.createWorkspace))
	mux.Handle("GET /api/v1/workspaces/{id}", s.requireUser(s.getWorkspace))
	mux.HandleFunc("GET /api/v1/server/whoami", s.whoami)
	mux.HandleFunc("GET /metrics", s.metricsHandler)
	s.storageRoutes(mux)
	s.vectorRoutes(mux)
	s.billingRoutes(mux)
	s.realtimeRoutes(mux)
	return s.metrics.track(s.cors(s.rateLimit(s.logRequests(mux))))
}

// --- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

// dbError maps Postgres errors to HTTP statuses (mirrors the Rust ApiError).
func dbError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Resource not found")
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			writeError(w, http.StatusConflict, "conflict", "Resource already exists")
			return
		case "42501":
			writeError(w, http.StatusForbidden, "forbidden", "Not allowed by row-level security")
			return
		case "23503", "23514", "22P02", "P0001":
			writeError(w, http.StatusBadRequest, "bad_request", pgErr.Message)
			return
		}
	}
	slog.Error("database error", "error", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error")
}

func claimsFrom(r *http.Request) *auth.Claims {
	c, _ := r.Context().Value(claimsKey).(*auth.Claims)
	return c
}

// --- middleware -----------------------------------------------------------

func (s *Server) requireUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, apiErr := s.resolveUser(r)
		if apiErr != nil {
			writeAPIError(w, apiErr)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), claimsKey, p.claims)))
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if ip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); ip != "" {
			return ip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first, _, _ := strings.Cut(xff, ","); strings.TrimSpace(first) != "" {
				return strings.TrimSpace(first)
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) rateKey(r *http.Request) string {
	if p := auth.APIKeyPrefix(r.Header.Get(auth.APIKeyHeader)); p != "" {
		return "key:" + p
	}
	if t := auth.BearerToken(r); t != "" {
		if c, err := auth.Verify(t, s.cfg.JWTSecret); err == nil {
			return "user:" + c.Subject
		}
	}
	return "ip:" + s.clientIP(r)
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/health") || r.URL.Path == "/metrics" || strings.HasPrefix(r.URL.Path, "/webhooks/") {
			next.ServeHTTP(w, r)
			return
		}
		ok, remaining, retry := s.allow(r.Context(), s.rateKey(r))
		w.Header().Set("X-Ratelimit-Limit", strconv.Itoa(s.limiter.Burst()))
		w.Header().Set("X-Ratelimit-Remaining", strconv.Itoa(remaining))
		if !ok {
			s.metrics.rateLimited.Add(1)
			secs := max(int(retry.Seconds()), 1)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow consumes a rate-limit token from the configured backend. With the
// shared (postgres) backend any DB failure or >250ms stall falls back to the
// local bucket, so a database blip never turns into an API outage.
func (s *Server) allow(ctx context.Context, key string) (bool, int, time.Duration) {
	if s.cfg.RateLimitBackend == "postgres" {
		cctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		ok, remaining, retry, err := s.limiter.AllowShared(cctx, s.pool, s.cfg.AppID, key)
		cancel()
		if err == nil {
			return ok, remaining, retry
		}
		s.metrics.rateLimitFallbacks.Add(1)
		slog.Warn("shared rate limiter failed; using local bucket", "error", err)
	}
	return s.limiter.Allow(key)
}

// SweepRateLimits drops idle buckets (memory and, when enabled, shared).
func (s *Server) SweepRateLimits(ctx context.Context) {
	s.limiter.Sweep()
	if s.cfg.RateLimitBackend == "postgres" {
		if err := s.limiter.SweepShared(ctx, s.pool, s.cfg.AppID); err != nil {
			slog.Debug("shared rate-limit sweep failed", "error", err)
		}
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController (and therefore WebSocket upgrades and
// per-request deadlines) reach the real ResponseWriter through the middleware.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(s.ResponseWriter).Hijack()
	if err == nil {
		s.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

func (s *statusRecorder) Flush() { _ = http.NewResponseController(s.ResponseWriter).Flush() }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration", time.Since(start))
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowed := len(s.cfg.CORSAllowedOrigins) == 0 || slices.Contains(s.cfg.CORSAllowedOrigins, "*") ||
				slices.Contains(s.cfg.CORSAllowedOrigins, origin)
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Api-Key")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- handlers -------------------------------------------------------------

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok", "service": "xbase-go-backend", "app_id": s.cfg.AppID,
		"pooler_mode": "supavisor_transaction_6543",
	})
}

func (s *Server) healthDB(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var one int
	if err := s.pool.QueryRow(ctx, "select 1").Scan(&one); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "disconnected", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "connected", "probe": one})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": c.Subject, "email": c.Email, "role": c.Role,
		"app_metadata": c.Raw["app_metadata"], "user_metadata": c.Raw["user_metadata"],
	})
}

type Workspace struct {
	ID                 string     `json:"id"`
	AppSlug            string     `json:"app_slug"`
	Name               string     `json:"name"`
	OwnerID            string     `json:"owner_id"`
	Plan               string     `json:"plan"`
	SubscriptionStatus *string    `json:"subscription_status"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

const workspaceColumns = `id::text, app_slug, name, owner_id::text, plan, subscription_status,
	current_period_end, created_at, updated_at`

func scanWorkspace(row pgx.Row) (Workspace, error) {
	var ws Workspace
	err := row.Scan(&ws.ID, &ws.AppSlug, &ws.Name, &ws.OwnerID, &ws.Plan,
		&ws.SubscriptionStatus, &ws.CurrentPeriodEnd, &ws.CreatedAt, &ws.UpdatedAt)
	return ws, err
}

func (s *Server) listWorkspaces(w http.ResponseWriter, r *http.Request) {
	out := []Workspace{}
	err := db.WithRLS(r.Context(), s.pool, claimsFrom(r), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			"select "+workspaceColumns+" from xbase.workspaces where app_slug = $1 order by created_at desc", s.cfg.AppID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ws, err := scanWorkspace(rows)
			if err != nil {
				return err
			}
			out = append(out, ws)
		}
		return rows.Err()
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createWorkspace(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len([]rune(name)) > 120 {
		writeError(w, http.StatusBadRequest, "bad_request", "name must be 1-120 characters")
		return
	}
	claims := claimsFrom(r)
	var ws Workspace
	err := db.WithRLS(r.Context(), s.pool, claims, func(tx pgx.Tx) error {
		var err error
		ws, err = scanWorkspace(tx.QueryRow(r.Context(),
			"insert into xbase.workspaces (app_slug, name, owner_id) values ($1, $2, $3::uuid) returning "+workspaceColumns,
			s.cfg.AppID, name, claims.Subject))
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, ws)
}

func (s *Server) getWorkspace(w http.ResponseWriter, r *http.Request) {
	var ws Workspace
	err := db.WithRLS(r.Context(), s.pool, claimsFrom(r), func(tx pgx.Tx) error {
		var err error
		ws, err = scanWorkspace(tx.QueryRow(r.Context(),
			"select "+workspaceColumns+" from xbase.workspaces where id = $1::uuid and app_slug = $2",
			r.PathValue("id"), s.cfg.AppID))
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

// whoami authenticates an x-api-key created by the Rust backend.
func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.Header.Get(auth.APIKeyHeader))
	if raw == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Missing or malformed x-api-key")
		return
	}
	k, apiErr := s.authenticateKey(r.Context(), raw)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key_id": k.KeyID, "workspace_id": k.WorkspaceID, "scopes": k.Scopes})
}
