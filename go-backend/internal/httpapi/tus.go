package httpapi

// TUS resumable-upload proxy — same routes and token format as the Rust backend
// (backend/src/storage.rs). It exists so API keys can upload large files: the
// creation request is confined like any other key write, and the upload URL handed
// back carries an HMAC (keyed with SUPABASE_JWT_SECRET) binding it to the bucket and
// the caller, so any replica can verify it and nobody else can reuse it.
//
//	POST   /api/v1/storage/tus/{bucket}          Upload-Length + Upload-Metadata (objectName, contentType?, cacheControl?)
//	HEAD   /api/v1/storage/tus/{bucket}/{token}  current offset
//	PATCH  /api/v1/storage/tus/{bucket}/{token}  next chunk (streamed)
//	DELETE /api/v1/storage/tus/{bucket}/{token}  terminate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const tusVersion = "1.0.0"

var tusResponseHeaders = []string{"Upload-Offset", "Upload-Length", "Upload-Expires", "Tus-Resumable", "Tus-Version", "Tus-Extension", "Cache-Control"}

func (c *storageCaller) tusPrincipal() string {
	if c.key != nil {
		return "key:" + c.key.KeyID + ":" + c.key.WorkspaceID
	}
	return "user:" + c.sub
}

func tusMAC(secret, app, bucket, uploadID, principal string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("tus|" + app + "|" + bucket + "|" + uploadID + "|" + principal))
	return hex.EncodeToString(m.Sum(nil))
}

func tusToken(secret, app, bucket, uploadID, principal string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(uploadID)) + "." + tusMAC(secret, app, bucket, uploadID, principal)
}

func tusVerify(secret, app, bucket, token, principal string) (string, *apiError) {
	bad := errForbidden("Invalid upload URL for this caller")
	idB64, mac, ok := strings.Cut(token, ".")
	if !ok {
		return "", bad
	}
	raw, err := base64.RawURLEncoding.DecodeString(idB64)
	id := string(raw)
	if err != nil || id == "" || strings.Contains(id, "/") {
		return "", bad
	}
	if !hmac.Equal([]byte(mac), []byte(tusMAC(secret, app, bucket, id, principal))) {
		return "", bad
	}
	return id, nil
}

type kv struct{ k, v string }

// parseTusMetadata parses `key base64,key2 base64`.
func parseTusMetadata(raw string) ([]kv, *apiError) {
	var out []kv
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, " ")
		val := ""
		if v = strings.TrimSpace(v); v != "" {
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, errBadRequest("Upload-Metadata is not base64")
			}
			val = string(b)
		}
		out = append(out, kv{k, val})
	}
	return out, nil
}

func encodeTusMetadata(pairs []kv) string {
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + " " + base64.StdEncoding.EncodeToString([]byte(p.v))
	}
	return strings.Join(parts, ",")
}

func tusRelay(w http.ResponseWriter, resp *http.Response, location string) {
	h := w.Header()
	for _, k := range tusResponseHeaders {
		if v := resp.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	h.Set("Tus-Resumable", tusVersion)
	h.Set("Access-Control-Expose-Headers", "Location, Upload-Offset, Upload-Length, Tus-Resumable, Upload-Expires")
	if location != "" {
		h.Set("Location", location)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) tusCreate(w http.ResponseWriter, r *http.Request) {
	c, e := s.storageCallerFrom(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	bucket := r.PathValue("bucket")
	id, e := scopedBucket(s.cfg.AppID, bucket)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	length, err := strconv.ParseUint(strings.TrimSpace(r.Header.Get("Upload-Length")), 10, 64)
	if err != nil {
		writeAPIError(w, errBadRequest("Upload-Length header is required (deferred length is not supported)"))
		return
	}
	meta, e := parseTusMetadata(r.Header.Get("Upload-Metadata"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	object := ""
	var extra []kv
	for _, m := range meta {
		switch m.k {
		case "objectName":
			object = m.v
		case "contentType", "cacheControl":
			extra = append(extra, m)
		}
	}
	if object == "" {
		writeAPIError(w, errBadRequest("Upload-Metadata must include objectName"))
		return
	}
	object, e = c.objectPath(object, true)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	upsert := strconv.FormatBool(r.Header.Get("X-Upsert") == "true")
	resp, e := s.storageDo(r.Context(), http.MethodPost, s.cfg.StorageURL+"/upload/resumable", c, http.NoBody, map[string]string{
		"Tus-Resumable":   tusVersion,
		"Upload-Length":   strconv.FormatUint(length, 10),
		"Upload-Metadata": encodeTusMetadata(append([]kv{{"bucketName", id}, {"objectName", object}}, extra...)),
		"X-Upsert":        upsert,
	})
	if e != nil {
		writeAPIError(w, e)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		tusRelay(w, resp, "")
		return
	}
	loc := strings.TrimRight(resp.Header.Get("Location"), "/")
	upstream := loc[strings.LastIndex(loc, "/")+1:]
	if upstream == "" {
		writeError(w, http.StatusBadGateway, "bad_gateway", "Storage returned no upload Location")
		return
	}
	token := tusToken(s.cfg.JWTSecret, s.cfg.AppID, id, upstream, c.tusPrincipal())
	tusRelay(w, resp, "/api/v1/storage/tus/"+bucket+"/"+token)
}

func (s *Server) tusForward(w http.ResponseWriter, r *http.Request) {
	c, e := s.storageCallerFrom(r)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	if c.key != nil {
		if e := c.key.requireScope("storage:write"); e != nil {
			writeAPIError(w, e)
			return
		}
	}
	id, e := scopedBucket(s.cfg.AppID, r.PathValue("bucket"))
	if e != nil {
		writeAPIError(w, e)
		return
	}
	upstream, e := tusVerify(s.cfg.JWTSecret, s.cfg.AppID, id, r.PathValue("token"), c.tusPrincipal())
	if e != nil {
		writeAPIError(w, e)
		return
	}
	target, err := s.storageEndpoint([]string{"upload", "resumable"}, upstream, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error")
		return
	}
	hdr := map[string]string{"Tus-Resumable": tusVersion}
	for _, k := range []string{"Upload-Offset", "Content-Type", "Upload-Checksum"} {
		if v := r.Header.Get(k); v != "" {
			hdr[k] = v
		}
	}
	var resp *http.Response
	if r.Method == http.MethodPatch {
		extendDeadlines(w)
		resp, e = s.storagePatch(r, target, c, hdr)
	} else {
		resp, e = s.storageDo(r.Context(), r.Method, target, c, http.NoBody, hdr)
	}
	if e != nil {
		writeAPIError(w, e)
		return
	}
	defer resp.Body.Close()
	tusRelay(w, resp, "")
}

// storagePatch streams a PATCH body upstream, preserving Content-Length (TUS servers require it).
func (s *Server) storagePatch(r *http.Request, target string, c *storageCaller, hdr map[string]string) (*http.Response, *apiError) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPatch, target, r.Body)
	if err != nil {
		return nil, &apiError{http.StatusInternalServerError, "internal_error", "Internal server error"}
	}
	req.ContentLength = r.ContentLength
	if e := s.storageAuthorize(req, c); e != nil {
		return nil, e
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		return nil, errUnavailable("Upstream service unavailable")
	}
	return resp, nil
}
