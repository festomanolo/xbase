package httpapi

// Workspace, membership and invitation CRUD — same routes and semantics as
// backend/src/workspaces.rs. Every user-facing query runs in an RLS-impersonated
// transaction, so authorization lives in the Postgres policies of migration 0002.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
	"github.com/festomanolo/xbase/go-backend/internal/db"
)

func (s *Server) workspaceRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/workspaces", s.requireUser(s.listWorkspaces))
	mux.Handle("POST /api/v1/workspaces", s.requireUser(s.createWorkspace))
	mux.HandleFunc("GET /api/v1/workspaces/{id}", s.getWorkspace) // user or API key (workspace:read)
	mux.Handle("PATCH /api/v1/workspaces/{id}", s.requireUser(s.updateWorkspace))
	mux.Handle("DELETE /api/v1/workspaces/{id}", s.requireUser(s.deleteWorkspace))
	mux.Handle("GET /api/v1/workspaces/{id}/members", s.requireUser(s.listMembers))
	mux.Handle("PATCH /api/v1/workspaces/{id}/members/{user_id}", s.requireUser(s.updateMember))
	mux.Handle("DELETE /api/v1/workspaces/{id}/members/{user_id}", s.requireUser(s.removeMember))
	mux.Handle("GET /api/v1/workspaces/{id}/invitations", s.requireUser(s.listInvitations))
	mux.Handle("POST /api/v1/workspaces/{id}/invitations", s.requireUser(s.createInvitation))
	mux.Handle("DELETE /api/v1/workspaces/{id}/invitations/{invitation_id}", s.requireUser(s.revokeInvitation))
	mux.Handle("POST /api/v1/invitations/accept", s.requireUser(s.acceptInvitation))
	mux.Handle("GET /api/v1/tenants/{app_slug}", s.requireUser(s.listWorkspacesForApp))
}

type Workspace struct {
	ID                 string     `json:"id"`
	AppSlug            string     `json:"app_slug"`
	Name               string     `json:"name"`
	OwnerID            string     `json:"owner_id"`
	Plan               string     `json:"plan"`
	SubscriptionStatus *string    `json:"subscription_status"`
	BillingProvider    *string    `json:"billing_provider"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

const workspaceColumns = `id::text, app_slug, name, owner_id::text, plan, subscription_status,
	billing_provider, current_period_end, created_at, updated_at`

func scanWorkspace(row pgx.Row) (Workspace, error) {
	var ws Workspace
	err := row.Scan(&ws.ID, &ws.AppSlug, &ws.Name, &ws.OwnerID, &ws.Plan,
		&ws.SubscriptionStatus, &ws.BillingProvider, &ws.CurrentPeriodEnd, &ws.CreatedAt, &ws.UpdatedAt)
	return ws, err
}

type Member struct {
	WorkspaceID string    `json:"workspace_id"`
	UserID      string    `json:"user_id"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

const memberColumns = "workspace_id::text, user_id::text, role, created_at"

func scanMember(row pgx.Row) (Member, error) {
	var m Member
	err := row.Scan(&m.WorkspaceID, &m.UserID, &m.Role, &m.CreatedAt)
	return m, err
}

type Invitation struct {
	ID          string     `json:"id"`
	WorkspaceID string     `json:"workspace_id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	InvitedBy   string     `json:"invited_by"`
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

const invitationColumns = "id::text, workspace_id::text, email, role, invited_by::text, expires_at, accepted_at, revoked_at, created_at"

func scanInvitation(row pgx.Row) (Invitation, error) {
	var i Invitation
	err := row.Scan(&i.ID, &i.WorkspaceID, &i.Email, &i.Role, &i.InvitedBy, &i.ExpiresAt, &i.AcceptedAt, &i.RevokedAt, &i.CreatedAt)
	return i, err
}

// collect scans every row with fn.
func collect[T any](rows pgx.Rows, fn func(pgx.Row) (T, error)) ([]T, error) {
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := fn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func validateName(raw string) (string, *apiError) {
	name := strings.TrimSpace(raw)
	if name == "" || len([]rune(name)) > 120 {
		return "", errBadRequest("name must be 1-120 characters")
	}
	return name, nil
}

func validateRole(role string) *apiError {
	switch role {
	case "admin", "member", "viewer":
		return nil
	}
	return errBadRequest("role must be one of: admin, member, viewer")
}

// pathUUIDs returns the named path values, or writes a 400 if one is not a UUID.
func pathUUIDs(w http.ResponseWriter, r *http.Request, names ...string) ([]string, bool) {
	out := make([]string, len(names))
	for i, n := range names {
		v := r.PathValue(n)
		if !isUUID(v) {
			writeAPIError(w, errBadRequest("%s must be a UUID", n))
			return nil, false
		}
		out[i] = v
	}
	return out, true
}

// rls runs fn as the request's user.
func (s *Server) rls(r *http.Request, fn func(pgx.Tx) error) error {
	return db.WithRLS(r.Context(), s.pool, claimsFrom(r), fn)
}

// --- workspaces ------------------------------------------------------------------

func (s *Server) listWorkspaces(w http.ResponseWriter, r *http.Request) {
	var out []Workspace
	err := s.rls(r, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			"select "+workspaceColumns+" from xbase.workspaces where app_slug = $1 order by created_at desc", s.cfg.AppID)
		if err != nil {
			return err
		}
		out, err = collect(rows, scanWorkspace)
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// listWorkspacesForApp is the backwards-compatible listing by explicit slug (RLS-enforced).
func (s *Server) listWorkspacesForApp(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("app_slug")
	var out []Workspace
	err := s.rls(r, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			"select "+workspaceColumns+" from xbase.workspaces where app_slug = $1 order by created_at desc", slug)
		if err != nil {
			return err
		}
		out, err = collect(rows, scanWorkspace)
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app_slug": slug, "owner_id": claimsFrom(r).Subject, "workspaces": out})
}

func (s *Server) createWorkspace(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	name, e := validateName(body.Name)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	var ws Workspace
	err := s.rls(r, func(tx pgx.Tx) error {
		var err error
		ws, err = scanWorkspace(tx.QueryRow(r.Context(),
			"insert into xbase.workspaces (app_slug, name, owner_id) values ($1, $2, $3::uuid) returning "+workspaceColumns,
			s.cfg.AppID, name, claimsFrom(r).Subject))
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, ws)
}

func (s *Server) getWorkspace(w http.ResponseWriter, r *http.Request) {
	p, e := s.resolvePrincipal(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	ids, ok := pathUUIDs(w, r, "id")
	if !ok {
		return
	}
	if e := p.requireWorkspace(ids[0], "workspace:read"); e != nil {
		writeAPIError(w, e)
		return
	}
	var ws Workspace
	err := s.inTx(r.Context(), p, func(tx pgx.Tx) error {
		var err error
		ws, err = scanWorkspace(tx.QueryRow(r.Context(),
			"select "+workspaceColumns+" from xbase.workspaces where id = $1::uuid and app_slug = $2", ids[0], s.cfg.AppID))
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

func (s *Server) updateWorkspace(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	name, e := validateName(body.Name)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	var ws Workspace
	err := s.rls(r, func(tx pgx.Tx) error {
		var err error
		ws, err = scanWorkspace(tx.QueryRow(r.Context(),
			"update xbase.workspaces set name = $1 where id = $2::uuid and app_slug = $3 returning "+workspaceColumns,
			name, ids[0], s.cfg.AppID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Workspace not found or not editable")
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

// execAffected runs one statement under RLS and writes 204, or 404 with notFound.
func (s *Server) execAffected(w http.ResponseWriter, r *http.Request, notFound, sql string, args ...any) {
	var n int64
	err := s.rls(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), sql, args...)
		n = tag.RowsAffected()
		return err
	})
	switch {
	case err != nil:
		dbError(w, err)
	case n == 0:
		writeError(w, http.StatusNotFound, "not_found", notFound)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) deleteWorkspace(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id")
	if !ok {
		return
	}
	s.execAffected(w, r, "Workspace not found or you are not the owner",
		"delete from xbase.workspaces where id = $1::uuid and app_slug = $2", ids[0], s.cfg.AppID)
}

// --- members ----------------------------------------------------------------------

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id")
	if !ok {
		return
	}
	var out []Member
	err := s.rls(r, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			"select "+memberColumns+" from xbase.workspace_members where workspace_id = $1::uuid order by created_at", ids[0])
		if err != nil {
			return err
		}
		out, err = collect(rows, scanMember)
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateMember(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id", "user_id")
	if !ok {
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if e := validateRole(body.Role); e != nil {
		writeAPIError(w, e)
		return
	}
	var m Member
	err := s.rls(r, func(tx pgx.Tx) error {
		var err error
		m, err = scanMember(tx.QueryRow(r.Context(),
			"update xbase.workspace_members set role = $1 where workspace_id = $2::uuid and user_id = $3::uuid returning "+memberColumns,
			body.Role, ids[0], ids[1]))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Member not found or not editable")
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id", "user_id")
	if !ok {
		return
	}
	s.execAffected(w, r, "Member not found or not removable",
		"delete from xbase.workspace_members where workspace_id = $1::uuid and user_id = $2::uuid", ids[0], ids[1])
}

// --- invitations ------------------------------------------------------------------

// generateInviteToken returns 32 random bytes, base64url without padding (like Rust).
func generateInviteToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) listInvitations(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id")
	if !ok {
		return
	}
	var out []Invitation
	err := s.rls(r, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			"select "+invitationColumns+" from xbase.workspace_invitations where workspace_id = $1::uuid order by created_at desc", ids[0])
		if err != nil {
			return err
		}
		out, err = collect(rows, scanInvitation)
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Role == "" {
		body.Role = "member"
	}
	if e := validateRole(body.Role); e != nil {
		writeAPIError(w, e)
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if !strings.Contains(email, "@") || len(email) > 320 {
		writeAPIError(w, errBadRequest("A valid email is required"))
		return
	}
	token := generateInviteToken()
	var inv Invitation
	err := s.rls(r, func(tx pgx.Tx) error {
		var err error
		inv, err = scanInvitation(tx.QueryRow(r.Context(),
			`insert into xbase.workspace_invitations (workspace_id, email, role, token_hash, invited_by)
			 values ($1::uuid, $2, $3, $4, $5::uuid) returning `+invitationColumns,
			ids[0], email, body.Role, auth.HashAPIKey(token), claimsFrom(r).Subject))
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	// Deliver `token` to the invitee yourself (email link); only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"invitation": inv, "token": token})
}

func (s *Server) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	ids, ok := pathUUIDs(w, r, "id", "invitation_id")
	if !ok {
		return
	}
	s.execAffected(w, r, "Invitation not found",
		`update xbase.workspace_invitations set revoked_at = now()
		  where id = $1::uuid and workspace_id = $2::uuid and accepted_at is null and revoked_at is null`, ids[1], ids[0])
}

func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Token) == "" {
		writeAPIError(w, errBadRequest("token is required"))
		return
	}
	var ws Workspace
	err := s.rls(r, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(r.Context(), "select xbase.accept_invitation($1)::text", auth.HashAPIKey(strings.TrimSpace(body.Token))).Scan(&id); err != nil {
			return err
		}
		var err error
		ws, err = scanWorkspace(tx.QueryRow(r.Context(), "select "+workspaceColumns+" from xbase.workspaces where id = $1::uuid", id))
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ws)
}
