package ratelimit

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SharedDB is the slice of *pgxpool.Pool the shared limiter needs.
type SharedDB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// AllowShared consumes a token from the bucket stored in Postgres
// (xbase.rate_limit_check, migration 0004), shared by every replica. Keys are
// namespaced by appID so SaaS apps sharing a database never share buckets.
//
// Callers should bound ctx (a few hundred ms) and fall back to Allow on error:
// a database blip then degrades to per-replica limiting instead of an outage.
func (l *Limiter) AllowShared(ctx context.Context, db SharedDB, appID, key string) (ok bool, remaining int, retryAfter time.Duration, err error) {
	var allowed bool
	var rem, retry float64
	err = db.QueryRow(ctx,
		`select allowed, remaining, retry_after from xbase.rate_limit_check($1, $2::float8, $3::float8)`,
		appID+":"+key, l.rate, l.burst).Scan(&allowed, &rem, &retry)
	if err != nil {
		return false, 0, 0, err
	}
	if retry < 0 {
		retry = 0
	}
	if retry > 3600 {
		retry = 3600
	}
	return allowed, max(int(rem), 0), time.Duration(retry * float64(time.Second)), nil
}

// SweepShared deletes this app's buckets that are idle long enough to be full again.
func (l *Limiter) SweepShared(ctx context.Context, db SharedDB, appID string) error {
	idle := l.burst/l.rate + 60
	// APP_ID is [a-z0-9-], so the LIKE pattern needs no escaping.
	_, err := db.Exec(ctx,
		`delete from xbase.rate_limits where key like $1 and updated_at < now() - make_interval(secs => $2::float8)`,
		appID+":%", idle)
	return err
}
