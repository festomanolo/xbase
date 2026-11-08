package httpapi

// API-key management — same routes and key format as backend/src/api_keys.rs.
// Keys look like xb_<12 hex prefix>_<base64url secret>; only the SHA-256 hash is
// stored and the plaintext is returned exactly once. Owners/admins manage keys
// (enforced by the api_keys RLS policies).

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
)

// knownScopes mirrors KNOWN_SCOPES in the Rust backend.
var knownScopes = []string{"*", "workspace:read", "embeddings:read", "embeddings:write", "storage:read", "storage:write", "rest:read", "rest:write"}

func (s *Server) apiKeyRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/workspaces/{id}/api-keys", s.requireUser(s.listKeys))
	mux.Handle("POST /api/v1/workspaces/{id}/api-keys", s.requireUser(s.createKey))
	mux.Handle("DELETE /api/v1/workspaces/{id}/api-keys/{key_id}", s.requireUser(s.revokeKey))
	mux.HandleFunc("GET /api/v1/server/whoami", s.whoami)
}

type APIKeyRecord struct {
	ID          string     `json:"id"`
	WorkspaceID string     `json:"workspace_id"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"`
	Scopes      []string   `json:"scopes"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

const keyColumns = "id::text, workspace_id::text, name, prefix, scopes, created_by::text, created_at, last_used_at, expires_at, revoked_at"

func scanKey(row pgx.Row) (APIKeyRecord, error) {
	var k APIKeyRecord
	err := row.Scan(&k.ID, &k.WorkspaceID, &k.Name, &k.Prefix, &k.Scopes, &k.CreatedBy, &k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt)
	return k, err
}

// generateKey returns (plaintext, prefix).
func generateKey() (string, string) {
	p := make([]byte, 6)
	sec := make([]byte, 32)
	_, _ = rand.Read(p)
	_, _ = rand.Read(sec)
	prefix := hex.EncodeToString(p)
	return "xb_" + prefix + "_" + base64.RawURLEncoding.EncodeToString(sec), prefix
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id")
	if !ok {
		return
	}
	var out []APIKeyRecord
	err := s.rls(r, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			"select "+keyColumns+" from xbase.api_keys where workspace_id = $1::uuid and app_slug = $2 order by created_at desc", ids[0], s.cfg.AppID)
		if err != nil {
			return err
		}
		out, err = collect(rows, scanKey)
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func validateScopes(scopes []string) ([]string, *apiError) {
	if len(scopes) == 0 {
		return []string{"workspace:read"}, nil
	}
	for _, sc := range scopes {
		if !slices.Contains(knownScopes, sc) {
			return nil, errBadRequest("Unknown scope '%s'. Allowed: %s", sc, strings.Join(knownScopes, ", "))
		}
	}
	return scopes, nil
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		writeAPIError(w, errBadRequest("name must be 1-100 characters"))
		return
	}
	scopes, e := validateScopes(body.Scopes)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	plaintext, prefix := generateKey()
	var rec APIKeyRecord
	err := s.rls(r, func(tx pgx.Tx) error {
		var err error
		rec, err = scanKey(tx.QueryRow(r.Context(), `
			insert into xbase.api_keys (app_slug, workspace_id, name, prefix, key_hash, scopes, created_by, expires_at)
			values ($1, $2::uuid, $3, $4, $5, $6, $7::uuid, $8) returning `+keyColumns,
			s.cfg.AppID, ids[0], name, prefix, auth.HashAPIKey(plaintext), scopes, claimsFrom(r).Subject, body.ExpiresAt))
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"api_key": plaintext,
		"warning": "Store this key now; it cannot be retrieved again.",
		"key":     rec,
	})
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id", "key_id")
	if !ok {
		return
	}
	s.execAffected(w, r, "API key not found",
		"update xbase.api_keys set revoked_at = now() where id = $1::uuid and workspace_id = $2::uuid and revoked_at is null",
		ids[1], ids[0])
}

// whoami lets an integration verify its key and discover its workspace.
func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.Header.Get(auth.APIKeyHeader))
	if raw == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "This endpoint expects an x-api-key header")
		return
	}
	k, apiErr := s.authenticateKey(r.Context(), raw)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	ws, err := scanWorkspace(s.pool.QueryRow(r.Context(),
		"select "+workspaceColumns+" from xbase.workspaces where id = $1::uuid and app_slug = $2", k.WorkspaceID, s.cfg.AppID))
	if err != nil {
		dbError(w, err)
		return
	}
	key := map[string]any{"key_id": k.KeyID, "workspace_id": k.WorkspaceID, "app_slug": s.cfg.AppID, "scopes": k.Scopes}
	// key_id / workspace_id / scopes stay at the top level for older Go clients.
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "workspace": ws,
		"key_id": k.KeyID, "workspace_id": k.WorkspaceID, "scopes": k.Scopes})
}
