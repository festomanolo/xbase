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
