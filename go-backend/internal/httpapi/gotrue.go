package httpapi

// Supabase Auth (GoTrue) proxy — same routes and semantics as backend/src/gotrue.rs:
// sign-up, password / OTP / magic-link sign-in, verify, recovery, OAuth + PKCE,
// refresh rotation, user update, logout, and admin user CRUD. GoTrue stays the
// source of truth; this gives each SaaS one API surface with shared rate limiting
// and per-app sign-up metadata.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/festomanolo/xbase/go-backend/internal/auth"
)

func (s *Server) gotrueRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/signup", s.authSignup)
	mux.HandleFunc("POST /api/v1/auth/token", s.authPassword)
	mux.HandleFunc("POST /api/v1/auth/refresh", s.authRefresh)
	mux.HandleFunc("POST /api/v1/auth/otp", s.authOTP)
	mux.HandleFunc("POST /api/v1/auth/magiclink", s.authPassthrough("/magiclink", true))
	mux.HandleFunc("POST /api/v1/auth/verify", s.authPassthrough("/verify", false))
	mux.HandleFunc("POST /api/v1/auth/recover", s.authPassthrough("/recover", true))
	mux.HandleFunc("GET /api/v1/auth/authorize", s.authAuthorize)
	mux.HandleFunc("POST /api/v1/auth/exchange", s.authExchange)
	mux.Handle("GET /api/v1/auth/user", s.requireUser(s.authGetUser))
	mux.Handle("PUT /api/v1/auth/user", s.requireUser(s.authUpdateUser))
	mux.Handle("POST /api/v1/auth/logout", s.requireUser(s.authLogout))
	mux.Handle("GET /api/v1/admin/users", s.requireAdmin(s.adminListUsers))
	mux.Handle("POST /api/v1/admin/users", s.requireAdmin(s.adminUserBody(http.MethodPost, false)))
	mux.Handle("GET /api/v1/admin/users/{id}", s.requireAdmin(s.adminUserNoBody(http.MethodGet)))
	mux.Handle("PUT /api/v1/admin/users/{id}", s.requireAdmin(s.adminUserBody(http.MethodPut, true)))
	mux.Handle("DELETE /api/v1/admin/users/{id}", s.requireAdmin(s.adminUserNoBody(http.MethodDelete)))
}

type credKind int

const (
	credAnon credKind = iota
	credUser
	credService
)

// gotrueForward sends a request to GoTrue and relays its status and JSON body verbatim.
func (s *Server) gotrueForward(w http.ResponseWriter, ctx context.Context, method, path string, q url.Values, body any, cred credKind, userToken string) {
	target := s.cfg.GoTrueURL + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target, rdr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error")
		return
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	anon := s.cfg.SupabaseAnonKey
	switch cred {
	case credAnon:
		if anon != "" {
			req.Header.Set("apikey", anon)
			req.Header.Set("Authorization", "Bearer "+anon)
		}
	case credUser:
		req.Header.Set("Authorization", "Bearer "+userToken)
		if anon != "" {
			req.Header.Set("apikey", anon)
		}
	case credService:
		key := s.cfg.SupabaseServiceKey
		if key == "" {
			writeAPIError(w, errUnavailable("SUPABASE_SERVICE_ROLE_KEY is not configured"))
			return
		}
		req.Header.Set("apikey", key)
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		writeAPIError(w, errUnavailable("Upstream service unavailable"))
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if resp.StatusCode == http.StatusNoContent || (ok && (len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null")) {
		w.WriteHeader(resp.StatusCode)
		return
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		parsed = map[string]any{"message": string(raw)}
	}
	writeJSON(w, resp.StatusCode, parsed)
}

// readObject decodes a JSON object body (GoTrue endpoints all take objects).
func readObject(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	var v any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return nil, false
	}
	obj, ok := v.(map[string]any)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "JSON object body required")
		return nil, false
	}
	return obj, true
}

// tagSignup records the app a user signed up through, without overwriting a caller value.
func tagSignup(body map[string]any, appID string) map[string]any {
	data, ok := body["data"].(map[string]any)
	if !ok {
		if _, present := body["data"]; present && body["data"] != nil {
			return body // non-object data: leave it to GoTrue to reject
		}
		data = map[string]any{}
		body["data"] = data
	}
	if _, set := data["signup_app"]; !set {
		data["signup_app"] = appID
	}
	return body
}

func redirectQuery(r *http.Request) url.Values {
	q := url.Values{}
	if v := r.URL.Query().Get("redirect_to"); v != "" {
		q.Set("redirect_to", v)
	}
	return q
}

func (s *Server) authSignup(w http.ResponseWriter, r *http.Request) {
	body, ok := readObject(w, r)
	if !ok {
		return
	}
	s.gotrueForward(w, r.Context(), http.MethodPost, "/signup", redirectQuery(r), tagSignup(body, s.cfg.AppID), credAnon, "")
}

func (s *Server) authPassword(w http.ResponseWriter, r *http.Request) {
	body, ok := readObject(w, r)
	if !ok {
		return
	}
	s.gotrueForward(w, r.Context(), http.MethodPost, "/token", url.Values{"grant_type": {"password"}}, body, credAnon, "")
}

func (s *Server) authRefresh(w http.ResponseWriter, r *http.Request) {
	body, ok := readObject(w, r)
	if !ok {
		return
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "refresh_token is required")
		return
	}
	s.gotrueForward(w, r.Context(), http.MethodPost, "/token", url.Values{"grant_type": {"refresh_token"}},
		map[string]any{"refresh_token": rt}, credAnon, "")
}

func (s *Server) authOTP(w http.ResponseWriter, r *http.Request) {
	body, ok := readObject(w, r)
	if !ok {
		return
	}
	s.gotrueForward(w, r.Context(), http.MethodPost, "/otp", redirectQuery(r), tagSignup(body, s.cfg.AppID), credAnon, "")
}

func (s *Server) authPassthrough(path string, withRedirect bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readObject(w, r)
		if !ok {
			return
		}
		var q url.Values
		if withRedirect {
			q = redirectQuery(r)
		}
		s.gotrueForward(w, r.Context(), http.MethodPost, path, q, body, credAnon, "")
	}
}

func validProvider(p string) bool {
	if p == "" {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// authAuthorize redirects the browser to GoTrue's public OAuth endpoint (PKCE when
// code_challenge is given). GoTrue handles the provider callback itself.
func (s *Server) authAuthorize(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query()
	provider := in.Get("provider")
	if !validProvider(provider) {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid provider")
		return
	}
	q := url.Values{"provider": {provider}}
	for _, k := range []string{"redirect_to", "scopes"} {
		if v := in.Get(k); v != "" {
			q.Set(k, v)
		}
	}
	if cc := in.Get("code_challenge"); cc != "" {
		q.Set("code_challenge", cc)
		m := in.Get("code_challenge_method")
		if m == "" {
			m = "s256"
		}
		q.Set("code_challenge_method", m)
	}
	http.Redirect(w, r, s.cfg.SupabasePublicURL+"/auth/v1/authorize?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) authExchange(w http.ResponseWriter, r *http.Request) {
	body, ok := readObject(w, r)
	if !ok {
		return
	}
	s.gotrueForward(w, r.Context(), http.MethodPost, "/token", url.Values{"grant_type": {"pkce"}}, body, credAnon, "")
}

func (s *Server) authGetUser(w http.ResponseWriter, r *http.Request) {
	s.gotrueForward(w, r.Context(), http.MethodGet, "/user", nil, nil, credUser, auth.BearerToken(r))
}

func (s *Server) authUpdateUser(w http.ResponseWriter, r *http.Request) {
	body, ok := readObject(w, r)
	if !ok {
		return
	}
	s.gotrueForward(w, r.Context(), http.MethodPut, "/user", nil, body, credUser, auth.BearerToken(r))
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	if sc := r.URL.Query().Get("scope"); sc != "" {
		q.Set("scope", sc)
	}
	s.gotrueForward(w, r.Context(), http.MethodPost, "/logout", q, nil, credUser, auth.BearerToken(r))
}

// --- admin ---------------------------------------------------------------------

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	if per < 1 {
		per = 50
	}
	per = min(per, 1000)
	q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(per)}}
	s.gotrueForward(w, r.Context(), http.MethodGet, "/admin/users", q, nil, credService, "")
}

func (s *Server) adminPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeError(w, http.StatusBadRequest, "bad_request", "user id must be a UUID")
		return "", false
	}
	return "/admin/users/" + id, true
}

func (s *Server) adminUserBody(method string, withID bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := "/admin/users"
		if withID {
			p, ok := s.adminPath(w, r)
			if !ok {
				return
			}
			path = p
		}
		body, ok := readObject(w, r)
		if !ok {
			return
		}
		s.gotrueForward(w, r.Context(), method, path, nil, body, credService, "")
	}
}

func (s *Server) adminUserNoBody(method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path, ok := s.adminPath(w, r)
		if !ok {
			return
		}
		s.gotrueForward(w, r.Context(), method, path, nil, nil, credService, "")
	}
}
