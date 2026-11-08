package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
	"github.com/festomanolo/xbase/go-backend/internal/db"
)

// apiError carries an HTTP status plus the {error,message} JSON the Rust
// backend returns, so clients see identical errors from either backend.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func errBadRequest(format string, a ...any) *apiError {
	return &apiError{http.StatusBadRequest, "bad_request", fmt.Sprintf(format, a...)}
}
func errUnauthorized(msg string) *apiError {
	return &apiError{http.StatusUnauthorized, "unauthorized", msg}
}
func errForbidden(msg string) *apiError { return &apiError{http.StatusForbidden, "forbidden", msg} }
func errUnavailable(msg string) *apiError {
	return &apiError{http.StatusServiceUnavailable, "service_unavailable", msg}
}

func writeAPIError(w http.ResponseWriter, e *apiError) { writeError(w, e.status, e.code, e.msg) }

// keyPrincipal is an authenticated x-api-key, bound to exactly one workspace.
type keyPrincipal struct {
	KeyID       string   `json:"key_id"`
	WorkspaceID string   `json:"workspace_id"`
	Scopes      []string `json:"scopes"`
}

func (k *keyPrincipal) requireScope(scope string) *apiError {
	if slices.Contains(k.Scopes, "*") || slices.Contains(k.Scopes, scope) {
		return nil
	}
	return errForbidden("API key lacks scope '" + scope + "'")
}

// authenticateKey looks the key up by its SHA-256 hash, scoped to this APP_ID.
func (s *Server) authenticateKey(ctx context.Context, raw string) (*keyPrincipal, *apiError) {
	raw = strings.TrimSpace(raw)
	if auth.APIKeyPrefix(raw) == "" {
		return nil, errUnauthorized("Malformed API key")
	}
	var k keyPrincipal
	var stale bool
	err := s.pool.QueryRow(ctx, `
		select id::text, workspace_id::text, scopes,
		       (last_used_at is null or last_used_at < now() - interval '1 minute')
		  from xbase.api_keys
		 where key_hash = $1 and app_slug = $2 and revoked_at is null
		   and (expires_at is null or expires_at > now())`,
		auth.HashAPIKey(raw), s.cfg.AppID).Scan(&k.KeyID, &k.WorkspaceID, &k.Scopes, &stale)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errUnauthorized("Invalid, expired or revoked API key")
	}
	if err != nil {
		return nil, &apiError{http.StatusInternalServerError, "internal_error", "Internal server error"}
	}
	if stale { // throttled, fire-and-forget usage tracking
		id := k.KeyID
		go func() {
			_, _ = s.pool.Exec(context.Background(), "update xbase.api_keys set last_used_at = now() where id = $1::uuid", id)
		}()
	}
	return &k, nil
}

// principal is either an end user (JWT) or an API key.
type principal struct {
	claims *auth.Claims
	token  string
	key    *keyPrincipal
}

// resolvePrincipal accepts x-api-key first, then a Bearer JWT.
func (s *Server) resolvePrincipal(r *http.Request) (*principal, *apiError) {
	if raw := r.Header.Get(auth.APIKeyHeader); raw != "" {
		k, err := s.authenticateKey(r.Context(), raw)
		if err != nil {
			return nil, err
		}
		return &principal{key: k}, nil
	}
	return s.resolveUser(r)
}

// resolveUser accepts only a Bearer JWT from a user or service_role.
func (s *Server) resolveUser(r *http.Request) (*principal, *apiError) {
	token := auth.BearerToken(r)
	if token == "" {
		return nil, errUnauthorized("Missing Authorization: Bearer <token>")
	}
	claims, err := auth.Verify(token, s.cfg.JWTSecret)
	if err != nil {
		return nil, errUnauthorized(err.Error())
	}
	return &principal{claims: claims, token: token}, nil
}

// requireWorkspace checks a principal may act on a workspace with `scope`.
// Users are additionally constrained by RLS; keys are bound to one workspace.
func (p *principal) requireWorkspace(workspaceID, scope string) *apiError {
	if p.key == nil {
		return nil
	}
	if !strings.EqualFold(p.key.WorkspaceID, workspaceID) {
		return errForbidden("API key is not valid for this workspace")
	}
	return p.key.requireScope(scope)
}

// inTx runs fn in a transaction: RLS-impersonated for users, plain (service
// connection) for API keys whose workspace binding was already verified.
func (s *Server) inTx(ctx context.Context, p *principal, fn func(pgx.Tx) error) error {
	if p.claims != nil {
		return db.WithRLS(ctx, s.pool, p.claims, fn)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// requireAdmin: a service_role JWT or a user listed in ADMIN_USER_IDS.
func (s *Server) requireAdmin(next http.HandlerFunc) http.Handler {
	return s.requireUser(func(w http.ResponseWriter, r *http.Request) {
		c := claimsFrom(r)
		if !c.IsServiceRole() && !slices.Contains(s.cfg.AdminUserIDs, c.Subject) {
			writeError(w, http.StatusForbidden, "forbidden", "Administrator privileges required")
			return
		}
		next(w, r)
	})
}
