package httpapi

// Vector / AI search with pgvector — same endpoints and semantics as
// backend/src/vector.rs. Works with user JWTs (RLS-enforced) and API keys
// (embeddings:read / embeddings:write, bound to one workspace).
// POST .../embeddings/reindex runs on the durable job queue (jobs.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	maxEmbedBatch   = 100
	maxContentChars = 32_000
)

func (s *Server) vectorRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/workspaces/{id}/embeddings", s.upsertEmbeddings)
	mux.HandleFunc("POST /api/v1/workspaces/{id}/embeddings/search", s.searchEmbeddings)
	mux.HandleFunc("POST /api/v1/workspaces/{id}/embeddings/reindex", s.reindexEmbeddings)
	mux.HandleFunc("DELETE /api/v1/workspaces/{id}/embeddings/{embedding_id}", s.deleteEmbedding)
}

// vectorLiteral renders a pgvector text literal, e.g. "[0.1,0.2]".
func vectorLiteral(v []float32) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, x := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(x), 'g', -1, 32))
	}
	b.WriteByte(']')
	return b.String()
}

func (s *Server) checkDims(v []float32) *apiError {
	if len(v) != s.cfg.EmbeddingDims {
		return errBadRequest("embedding must have %d dimensions, got %d", s.cfg.EmbeddingDims, len(v))
	}
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return errBadRequest("embedding contains non-finite values")
		}
	}
	return nil
}

// embedTexts calls an OpenAI-compatible /embeddings endpoint.
func (s *Server) embedTexts(ctx context.Context, inputs []string) ([][]float32, *apiError) {
	if s.cfg.EmbeddingAPIURL == "" {
		return nil, errBadRequest("No embedding provided and EMBEDDING_API_URL is not configured")
	}
	payload, _ := json.Marshal(map[string]any{"model": s.cfg.EmbeddingModel, "input": inputs})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.EmbeddingAPIURL+"/embeddings", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.EmbeddingAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.EmbeddingAPIKey)
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		return nil, errUnavailable("Upstream service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		slog.Warn("embedding provider error", "status", resp.StatusCode, "body", string(raw))
		return nil, errUnavailable(fmt.Sprintf("Embedding provider returned %d", resp.StatusCode))
	}
	var parsed struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&parsed); err != nil || len(parsed.Data) != len(inputs) {
		return nil, errUnavailable("Embedding provider returned an unexpected response")
	}
	sort.Slice(parsed.Data, func(i, j int) bool { return parsed.Data[i].Index < parsed.Data[j].Index })
	out := make([][]float32, len(parsed.Data))
	for i, d := range parsed.Data {
		out[i] = d.Embedding
	}
	return out, nil
}

func (s *Server) ensureWorkspace(ctx context.Context, tx pgx.Tx, id string) error {
	var ok bool
	if err := tx.QueryRow(ctx,
		"select exists(select 1 from xbase.workspaces where id = $1::uuid and app_slug = $2)", id, s.cfg.AppID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Server) vectorPrincipal(w http.ResponseWriter, r *http.Request, scope string) (*principal, string, bool) {
	p, e := s.resolvePrincipal(r)
	if e != nil {
		writeAPIError(w, e)
		return nil, "", false
	}
	id := r.PathValue("id")
	if !isUUID(id) {
		writeAPIError(w, errBadRequest("workspace id must be a UUID"))
		return nil, "", false
	}
	if e := p.requireWorkspace(id, scope); e != nil {
		writeAPIError(w, e)
		return nil, "", false
	}
	return p, id, true
}

func (s *Server) upsertEmbeddings(w http.ResponseWriter, r *http.Request) {
	p, wsID, ok := s.vectorPrincipal(w, r, "embeddings:write")
	if !ok {
		return
	}
	var body struct {
		Items []struct {
			ExternalID *string        `json:"external_id"`
			Content    string         `json:"content"`
			Metadata   map[string]any `json:"metadata"`
			Embedding  []float32      `json:"embedding"`
		} `json:"items"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.Items) == 0 || len(body.Items) > maxEmbedBatch {
		writeAPIError(w, errBadRequest("items must contain 1-%d entries", maxEmbedBatch))
		return
	}
	var missing []int
	var texts []string
	for i, it := range body.Items {
		if n := len([]rune(it.Content)); n == 0 || n > maxContentChars {
			writeAPIError(w, errBadRequest("content must be 1-%d characters", maxContentChars))
			return
		}
		if it.Embedding == nil {
			missing = append(missing, i)
			texts = append(texts, it.Content)
		}
	}
	if len(texts) > 0 { // one batched provider call
		vecs, e := s.embedTexts(r.Context(), texts)
		if e != nil {
			writeAPIError(w, e)
			return
		}
		for n, i := range missing {
			body.Items[i].Embedding = vecs[n]
		}
	}
	for _, it := range body.Items {
		if e := s.checkDims(it.Embedding); e != nil {
			writeAPIError(w, e)
			return
		}
	}

	type row struct {
		ID         string  `json:"id"`
		ExternalID *string `json:"external_id"`
	}
	rows := make([]row, 0, len(body.Items))
	err := s.inTx(r.Context(), p, func(tx pgx.Tx) error {
		if err := s.ensureWorkspace(r.Context(), tx, wsID); err != nil {
			return err
		}
		for _, it := range body.Items {
			meta := it.Metadata
			if meta == nil {
				meta = map[string]any{}
			}
			metaJSON, _ := json.Marshal(meta)
			var out row
			if err := tx.QueryRow(r.Context(), `
				insert into xbase.embeddings (app_slug, workspace_id, external_id, content, metadata, embedding)
				values ($1, $2::uuid, $3, $4, $5::jsonb, $6::extensions.vector)
				on conflict (workspace_id, external_id) do update
				   set content = excluded.content, metadata = excluded.metadata,
				       embedding = excluded.embedding, updated_at = now()
				returning id::text, external_id`,
				s.cfg.AppID, wsID, it.ExternalID, it.Content, string(metaJSON), vectorLiteral(it.Embedding)).Scan(&out.ID, &out.ExternalID); err != nil {
				return err
			}
			rows = append(rows, out)
		}
		return nil
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"upserted": rows})
}

func (s *Server) searchEmbeddings(w http.ResponseWriter, r *http.Request) {
	p, wsID, ok := s.vectorPrincipal(w, r, "embeddings:read")
	if !ok {
		return
	}
	body := struct {
		Embedding     []float32      `json:"embedding"`
		Query         string         `json:"query"`
		Limit         int            `json:"limit"`
		Filter        map[string]any `json:"filter"`
		MinSimilarity float64        `json:"min_similarity"`
	}{Limit: 10}
	if !decodeBody(w, r, &body) {
		return
	}
	emb := body.Embedding
	switch {
	case emb != nil:
	case strings.TrimSpace(body.Query) != "":
		vecs, e := s.embedTexts(r.Context(), []string{body.Query})
		if e != nil {
			writeAPIError(w, e)
			return
		}
		emb = vecs[0]
	default:
		writeAPIError(w, errBadRequest("Provide `embedding` or `query`"))
		return
	}
	if e := s.checkDims(emb); e != nil {
		writeAPIError(w, e)
		return
	}
	var filterJSON *string
	if body.Filter != nil {
		b, _ := json.Marshal(body.Filter)
		str := string(b)
		filterJSON = &str
	}

	type hit struct {
		ID         string         `json:"id"`
		ExternalID *string        `json:"external_id"`
		Content    string         `json:"content"`
		Metadata   map[string]any `json:"metadata"`
		Similarity float64        `json:"similarity"`
	}
	hits := []hit{}
	err := s.inTx(r.Context(), p, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			select id::text, external_id, content, metadata,
			       (1 - (embedding <=> $2::extensions.vector))::float8
			  from xbase.embeddings
			 where workspace_id = $1::uuid and app_slug = $5
			   and ($3::jsonb is null or metadata @> $3::jsonb)
			 order by embedding <=> $2::extensions.vector
			 limit $4`,
			wsID, vectorLiteral(emb), filterJSON, min(max(body.Limit, 1), 100), s.cfg.AppID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h hit
			if err := rows.Scan(&h.ID, &h.ExternalID, &h.Content, &h.Metadata, &h.Similarity); err != nil {
				return err
			}
			if h.Similarity >= body.MinSimilarity {
				hits = append(hits, h)
			}
		}
		return rows.Err()
	})
	if err != nil {
		dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": hits})
}

func (s *Server) deleteEmbedding(w http.ResponseWriter, r *http.Request) {
	p, wsID, ok := s.vectorPrincipal(w, r, "embeddings:write")
	if !ok {
		return
	}
	embID := r.PathValue("embedding_id")
	if !isUUID(embID) {
		writeAPIError(w, errBadRequest("embedding id must be a UUID"))
		return
	}
	var n int64
	err := s.inTx(r.Context(), p, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(),
			"delete from xbase.embeddings where id = $1::uuid and workspace_id = $2::uuid and app_slug = $3",
			embID, wsID, s.cfg.AppID)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		dbError(w, err)
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Embedding not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'):
			return false
		}
	}
	return true
}
