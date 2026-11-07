// Package httpapi wires the Go backend's HTTP routes and middleware.
package httpapi

import (
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
}

func New(cfg *config.Config, pool *pgxpool.Pool, limiter *ratelimit.Limiter) *Server {
	return &Server{cfg: cfg, pool: pool, limiter: limiter}
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
	return s.cors(s.rateLimit(s.logRequests(mux)))
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
		token := auth.BearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Missing Authorization: Bearer <token>")
			return
		}
		claims, err := auth.Verify(token, s.cfg.JWTSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
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
		if strings.HasPrefix(r.URL.Path, "/health") {
			next.ServeHTTP(w, r)
			return
		}
		ok, remaining, retry := s.limiter.Allow(s.rateKey(r))
		w.Header().Set("X-Ratelimit-Limit", strconv.Itoa(s.limiter.Burst()))
		w.Header().Set("X-Ratelimit-Remaining", strconv.Itoa(remaining))
		if !ok {
			secs := max(int(retry.Seconds()), 1)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
