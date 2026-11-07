// Package db builds a Supavisor-safe pgx pool and the RLS impersonation helper.
package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
)

// NewPool connects through Supavisor (port 6543, transaction mode).
//
// QueryExecModeExec sends every query as an unnamed statement, so no prepared
// statement ever outlives the transaction — the pgx equivalent of the Rust
// backend's statement_cache_capacity(0).
func NewPool(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	cfg.MaxConns = maxConns
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = time.Minute
	return pgxpool.NewWithConfig(ctx, cfg)
}

var allowedRoles = map[string]bool{"authenticated": true, "anon": true, "service_role": true}

// ErrRoleNotAllowed is returned for JWT roles that may not touch the database.
var ErrRoleNotAllowed = errors.New("jwt role is not allowed to access the database")

// Beginner is satisfied by *pgxpool.Pool.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// WithRLS runs fn in a transaction impersonating the JWT, so Postgres RLS
// policies (auth.uid(), auth.jwt()) apply exactly as they do for PostgREST.
// Settings are transaction-local and therefore safe behind Supavisor.
func WithRLS(ctx context.Context, pool Beginner, claims *auth.Claims, fn func(pgx.Tx) error) error {
	if !allowedRoles[claims.Role] {
		return ErrRoleNotAllowed
	}
	raw, err := json.Marshal(claims.Raw)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx,
		`select set_config('request.jwt.claims', $1, true),
		        set_config('request.jwt.claim.sub', $2, true),
		        set_config('request.jwt.claim.role', $3, true),
		        set_config('role', $3, true)`,
		string(raw), claims.Subject, claims.Role); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
