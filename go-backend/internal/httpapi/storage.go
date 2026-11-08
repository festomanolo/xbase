package httpapi

// Storage proxy — same endpoints and rules as backend/src/storage.rs.
//
//   * Bucket management uses the service role key and needs an admin caller.
//   * Object calls from users forward the user's JWT, so Storage's RLS policies
//     on storage.objects (migration 0005) decide access.
//   * Object calls from API keys (scopes storage:read / storage:write) run with
//     the service role, so THIS proxy confines the key to `<workspace_id>/…`.
//   * Buckets are namespaced `<APP_ID>-<name>`.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) storageRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/storage/buckets", s.requireAdmin(s.listBuckets))
	mux.Handle("POST /api/v1/storage/buckets", s.requireAdmin(s.createBucket))
	mux.Handle("DELETE /api/v1/storage/buckets/{bucket}", s.requireAdmin(s.deleteBucket))
	mux.HandleFunc("POST /api/v1/storage/objects/{bucket}/list", s.listObjects)
	mux.HandleFunc("POST /api/v1/storage/objects/{bucket}/sign-upload", s.signUpload)
	mux.HandleFunc("POST /api/v1/storage/objects/{bucket}/sign-download", s.signDownload)
	mux.HandleFunc("DELETE /api/v1/storage/objects/{bucket}", s.deleteObjects)
	mux.HandleFunc("GET /api/v1/storage/objects/{bucket}/{path...}", s.downloadObject)
	mux.HandleFunc("PUT /api/v1/storage/objects/{bucket}/{path...}", s.uploadObject)
	mux.HandleFunc("POST /api/v1/storage/objects/{bucket}/{path...}", s.uploadObject)
	mux.HandleFunc("POST /api/v1/storage/uploads/resumable", s.resumableInfo)
}

// --- pure helpers (unit-tested) ---------------------------------------------

// scopedBucket applies the per-app bucket namespace.
func scopedBucket(appID, bucket string) (string, *apiError) {
	valid := bucket != "" && len(bucket) <= 63
	for _, c := range bucket {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			valid = false
		}
	}
	if !valid {
		return "", errBadRequest("Bucket names may contain lowercase letters, digits, '-' and '_' (max 63)")
	}
	prefix := appID + "-"
	if strings.HasPrefix(bucket, prefix) {
		return bucket, nil
	}
	return prefix + bucket, nil
}

// validateObjectPath rejects traversal and empty segments.
func validateObjectPath(p string) (string, *apiError) {
	p = strings.TrimLeft(p, "/")
	if p == "" || len(p) > 1024 {
		return "", errBadRequest("Invalid object path")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", errBadRequest("Invalid object path")
		}
	}
	return p, nil
}

// storageCaller is who is calling an object endpoint.
type storageCaller struct {
	token string        // user JWT (forwarded to Storage)
	key   *keyPrincipal // or an API key (service role + path confinement)
}

func (c *storageCaller) objectPath(p string, write bool) (string, *apiError) {
	p, err := validateObjectPath(p)
	if err != nil {
		return "", err
	}
	if c.key != nil {
		scope := "storage:read"
		if write {
			scope = "storage:write"
		}
		if e := c.key.requireScope(scope); e != nil {
			return "", e
		}
		if e := c.confine(p); e != nil {
			return "", e
		}
	}
	return p, nil
}

// listPrefix pins a key's listings to its workspace folder; users pass through.
func (c *storageCaller) listPrefix(prefix string) (string, *apiError) {
	if c.key == nil {
		return prefix, nil
	}
	if e := c.key.requireScope("storage:read"); e != nil {
		return "", e
	}
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return c.key.WorkspaceID, nil
	}
	prefix, err := validateObjectPath(prefix)
	if err != nil {
		return "", err
	}
	if e := c.confine(prefix); e != nil {
		return "", e
	}
	return prefix, nil
}

func (c *storageCaller) confine(p string) *apiError {
	first, _, _ := strings.Cut(p, "/")
	if !strings.EqualFold(first, c.key.WorkspaceID) {
		return errForbidden("API keys may only access objects under '<workspace_id>/'")
	}
	return nil
}

// --- upstream plumbing --------------------------------------------------------

// storageEndpoint builds {STORAGE_URL}/{fixed...}/{bucket}[/{path...}] with proper escaping.
func (s *Server) storageEndpoint(fixed []string, bucket, objPath string) (string, error) {
	elems := append(append([]string{}, fixed...), bucket)
	if objPath != "" {
		elems = append(elems, strings.Split(objPath, "/")...)
	}
	return url.JoinPath(s.cfg.StorageURL, elems...)
}

func (s *Server) storageCallerFrom(r *http.Request) (*storageCaller, *apiError) {
	p, e := s.resolvePrincipal(r)
	if e != nil {
		return nil, e
	}
	if p.key != nil {
		return &storageCaller{key: p.key}, nil
	}
	return &storageCaller{token: p.token}, nil
}

// authorize sets the upstream credentials for the caller.
func (s *Server) storageAuthorize(req *http.Request, c *storageCaller) *apiError {
	if c == nil || c.key != nil || c.token == "" {
		if s.cfg.SupabaseServiceKey == "" {
			return errUnavailable("SUPABASE_SERVICE_ROLE_KEY is not configured")
		}
		req.Header.Set("apikey", s.cfg.SupabaseServiceKey)
		req.Header.Set("Authorization", "Bearer "+s.cfg.SupabaseServiceKey)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if s.cfg.SupabaseAnonKey != "" {
		req.Header.Set("apikey", s.cfg.SupabaseAnonKey)
	}
	return nil
}

// storageDo performs an upstream call and returns the HTTP response; the
// caller owns resp.Body.
func (s *Server) storageDo(ctx context.Context, method, target string, c *storageCaller, body io.Reader, headers map[string]string) (*http.Response, *apiError) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, &apiError{http.StatusInternalServerError, "internal_error", "Internal server error"}
	}
	if e := s.storageAuthorize(req, c); e != nil {
		return nil, e
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		return nil, errUnavailable("Upstream service unavailable")
	}
	return resp, nil
}

// storageJSON calls Storage and decodes a JSON reply. Non-2xx replies are
// returned as *upstreamError so they can be forwarded verbatim.
type upstreamError struct {
	status int
	body   any
}

func (e *upstreamError) Error() string { return fmt.Sprintf("upstream returned %d", e.status) }

func (s *Server) storageJSON(ctx context.Context, method, target string, c *storageCaller, payload any, headers map[string]string) (any, error) {
	var body io.Reader
	hdr := map[string]string{}
	for k, v := range headers {
		hdr[k] = v
	}
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = strings.NewReader(string(b))
		hdr["Content-Type"] = "application/json"
	}
	resp, apiErr := s.storageDo(ctx, method, target, c, body, hdr)
	if apiErr != nil {
		return nil, apiErr
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var out any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			out = map[string]string{"message": string(raw)}
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &upstreamError{resp.StatusCode, out}
	}
	return out, nil
}

func writeUpstreamErr(w http.ResponseWriter, err error) {
	var ue *upstreamError
	var ae *apiError
	switch {
	case errors.As(err, &ue):
		writeJSON(w, ue.status, ue.body)
	case errors.As(err, &ae):
		writeAPIError(w, ae)
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error")
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body")
		return false
	}
	return true
}

// --- buckets (admin) ----------------------------------------------------------

func (s *Server) listBuckets(w http.ResponseWriter, r *http.Request) {
	out, err := s.storageJSON(r.Context(), http.MethodGet, s.cfg.StorageURL+"/bucket", nil, nil, nil)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	own := []any{}
	prefix := s.cfg.AppID + "-"
	if all, ok := out.([]any); ok {
		for _, b := range all {
			if m, ok := b.(map[string]any); ok {
				if id, _ := m["id"].(string); strings.HasPrefix(id, prefix) {
					own = append(own, b)
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, own)
}

func (s *Server) createBucket(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name             string   `json:"name"`
		Public           bool     `json:"public"`
		FileSizeLimit    *uint64  `json:"file_size_limit"`
		AllowedMimeTypes []string `json:"allowed_mime_types"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	id, e := scopedBucket(s.cfg.AppID, body.Name)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	_, err := s.storageJSON(r.Context(), http.MethodPost, s.cfg.StorageURL+"/bucket", nil, map[string]any{
		"id": id, "name": id, "public": body.Public,
		"file_size_limit": body.FileSizeLimit, "allowed_mime_types": body.AllowedMimeTypes,
	}, nil)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "public": body.Public})
}

func (s *Server) deleteBucket(w http.ResponseWriter, r *http.Request) {
	id, e := scopedBucket(s.cfg.AppID, r.PathValue("bucket"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	if force, _ := strconv.ParseBool(r.URL.Query().Get("force")); force {
		u, _ := s.storageEndpoint([]string{"bucket"}, id, "empty")
		if _, err := s.storageJSON(r.Context(), http.MethodPost, u, nil, nil, nil); err != nil {
			writeUpstreamErr(w, err)
			return
		}
	}
	u, _ := s.storageEndpoint([]string{"bucket"}, id, "")
	if _, err := s.storageJSON(r.Context(), http.MethodDelete, u, nil, nil, nil); err != nil {
		writeUpstreamErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- objects ------------------------------------------------------------------

func (s *Server) listObjects(w http.ResponseWriter, r *http.Request) {
	c, e := s.storageCallerFrom(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	id, e := scopedBucket(s.cfg.AppID, r.PathValue("bucket"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	body := struct {
		Prefix string  `json:"prefix"`
		Limit  int     `json:"limit"`
		Offset int     `json:"offset"`
		Search *string `json:"search"`
	}{Limit: 100}
	if !decodeBody(w, r, &body) {
		return
	}
	prefix, e := c.listPrefix(body.Prefix)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	u, _ := s.storageEndpoint([]string{"object", "list"}, id, "")
	out, err := s.storageJSON(r.Context(), http.MethodPost, u, c, map[string]any{
		"prefix": prefix, "limit": min(max(body.Limit, 1), 1000), "offset": max(body.Offset, 0),
		"search": body.Search, "sortBy": map[string]string{"column": "name", "order": "asc"},
	}, nil)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) signUpload(w http.ResponseWriter, r *http.Request) {
	c, e := s.storageCallerFrom(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	id, e := scopedBucket(s.cfg.AppID, r.PathValue("bucket"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	var body struct {
		Path   string `json:"path"`
		Upsert bool   `json:"upsert"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	p, e := c.objectPath(body.Path, true)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	u, _ := s.storageEndpoint([]string{"object", "upload", "sign"}, id, p)
	hdr := map[string]string{}
	if body.Upsert {
		hdr["x-upsert"] = "true"
	}
	out, err := s.storageJSON(r.Context(), http.MethodPost, u, c, nil, hdr)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	resp, _ := out.(map[string]any)
	rel, _ := resp["url"].(string)
	writeJSON(w, http.StatusOK, map[string]any{
		"signed_url": s.cfg.SupabasePublicURL + "/storage/v1" + rel,
		"token":      resp["token"], "path": p, "bucket": id,
	})
}

func (s *Server) signDownload(w http.ResponseWriter, r *http.Request) {
	c, e := s.storageCallerFrom(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	id, e := scopedBucket(s.cfg.AppID, r.PathValue("bucket"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	var body struct {
		Path      string         `json:"path"`
		ExpiresIn int            `json:"expires_in"`
		Transform map[string]any `json:"transform"`
		Download  any            `json:"download"`
	}
	body.ExpiresIn = 3600
	if !decodeBody(w, r, &body) {
		return
	}
	p, e := c.objectPath(body.Path, false)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	payload := map[string]any{"expiresIn": min(max(body.ExpiresIn, 1), 7*24*3600)}
	if body.Transform != nil {
		payload["transform"] = body.Transform
	}
	u, _ := s.storageEndpoint([]string{"object", "sign"}, id, p)
	out, err := s.storageJSON(r.Context(), http.MethodPost, u, c, payload, nil)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	resp, _ := out.(map[string]any)
	rel, _ := resp["signedURL"].(string)
	signed := s.cfg.SupabasePublicURL + "/storage/v1" + rel
	switch d := body.Download.(type) {
	case bool:
		if d {
			signed += "&download="
		}
	case string:
		signed += "&download=" + url.QueryEscape(d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"signed_url": signed, "expires_in": body.ExpiresIn})
}

func (s *Server) downloadObject(w http.ResponseWriter, r *http.Request) {
	c, e := s.storageCallerFrom(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	id, e := scopedBucket(s.cfg.AppID, r.PathValue("bucket"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	p, e := c.objectPath(r.PathValue("path"), false)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	extendDeadlines(w)
	u, _ := s.storageEndpoint([]string{"object", "authenticated"}, id, p)
	resp, e := s.storageDo(r.Context(), http.MethodGet, u, c, nil, nil)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var body any
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
		writeJSON(w, resp.StatusCode, body)
		return
	}
	for _, h := range []string{"Content-Type", "Content-Length", "Etag", "Cache-Control", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

// uploadObject streams the request body to Storage without buffering it.
// PUT = upsert (replace), POST = create only.
func (s *Server) uploadObject(w http.ResponseWriter, r *http.Request) {
	c, e := s.storageCallerFrom(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	id, e := scopedBucket(s.cfg.AppID, r.PathValue("bucket"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	p, e := c.objectPath(r.PathValue("path"), true)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	extendDeadlines(w)
	u, _ := s.storageEndpoint([]string{"object"}, id, p)
	hdr := map[string]string{}
	for _, h := range []string{"Content-Type", "Cache-Control"} {
		if v := r.Header.Get(h); v != "" {
			hdr[h] = v
		}
	}
	if r.Method == http.MethodPut {
		hdr["x-upsert"] = "true"
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u, r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error")
		return
	}
	req.ContentLength = r.ContentLength
	if e := s.storageAuthorize(req, c); e != nil {
		writeAPIError(w, e)
		return
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		writeAPIError(w, errUnavailable("Upstream service unavailable"))
		return
	}
	defer resp.Body.Close()
	var out any
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		writeJSON(w, resp.StatusCode, out)
		return
	}
	writeJSON(w, resp.StatusCode, map[string]any{"bucket": id, "path": p, "result": out})
}

func (s *Server) deleteObjects(w http.ResponseWriter, r *http.Request) {
	c, e := s.storageCallerFrom(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	id, e := scopedBucket(s.cfg.AppID, r.PathValue("bucket"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	var body struct {
		Paths []string `json:"paths"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.Paths) == 0 || len(body.Paths) > 1000 {
		writeAPIError(w, errBadRequest("paths must contain 1-1000 entries"))
		return
	}
	paths := make([]string, 0, len(body.Paths))
	for _, raw := range body.Paths {
		p, e := c.objectPath(raw, true)
		if e != nil {
			writeAPIError(w, e)
			return
		}
		paths = append(paths, p)
	}
	u, _ := s.storageEndpoint([]string{"object"}, id, "")
	out, err := s.storageJSON(r.Context(), http.MethodDelete, u, c, map[string]any{"prefixes": paths}, nil)
	if err != nil {
		writeUpstreamErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// resumableInfo returns TUS connection details. Users only: the response embeds
// the caller's own token, and an API key has no token to hand back.
func (s *Server) resumableInfo(w http.ResponseWriter, r *http.Request) {
	p, e := s.resolveUser(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	var body struct {
		Bucket string `json:"bucket"`
		Path   string `json:"path"`
		Upsert bool   `json:"upsert"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	id, e := scopedBucket(s.cfg.AppID, body.Bucket)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	path, e := validateObjectPath(body.Path)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	headers := map[string]string{"authorization": "Bearer " + p.token, "x-upsert": strconv.FormatBool(body.Upsert)}
	if s.cfg.SupabaseAnonKey != "" {
		headers["apikey"] = s.cfg.SupabaseAnonKey
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint":   s.cfg.SupabasePublicURL + "/storage/v1/upload/resumable",
		"protocol":   "tus-1.0.0",
		"chunk_size": 6 * 1024 * 1024,
		"headers":    headers,
		"metadata":   map[string]string{"bucketName": id, "objectName": path},
	})
}

// extendDeadlines lifts the server's short Read/Write timeouts for one request
// so large objects can stream (the defaults are sized for JSON APIs).
func extendDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	d := time.Now().Add(30 * time.Minute)
	_ = rc.SetReadDeadline(d)
	_ = rc.SetWriteDeadline(d)
}
