package httpapi

// Durable background jobs on xbase.jobs — the same table, claim query, backoff and
// reaper as backend/src/jobs.rs, so Rust and Go replicas of different apps share one
// queue table safely (every query carries app_id) and replicas of one app share work
// (FOR UPDATE SKIP LOCKED).
//
// Kinds handled here: embeddings.reindex. (Billing webhooks are applied inline in the
// webhook transaction, so billing.webhook jobs are never enqueued by this backend.)

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

type job struct {
	ID          int64
	Kind        string
	Payload     json.RawMessage
	Attempts    int32
	MaxAttempts int32
}

// jobQueue wakes idle workers when this replica enqueues work.
type jobQueue struct {
	wake      chan struct{}
	succeeded atomic.Uint64
	failed    atomic.Uint64
}

func newJobQueue() *jobQueue { return &jobQueue{wake: make(chan struct{}, 1)} }

func (q *jobQueue) notify() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// enqueueJob inserts a job; db may be the pool or a transaction.
func (s *Server) enqueueJob(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, kind string, payload any) (int64, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	var id int64
	err = db.QueryRow(ctx, "insert into xbase.jobs (app_id, kind, payload) values ($1, $2, $3::jsonb) returning id",
		s.cfg.AppID, kind, string(raw)).Scan(&id)
	return id, err
}

// backoffSecs: 2^attempts seconds, capped at one hour (matches Rust backoff_secs).
func backoffSecs(attempts int32) int64 {
	a := min(max(attempts, 0), 12)
	return min(int64(1)<<a, 3600)
}

func (s *Server) claimJob(ctx context.Context) (*job, error) {
	var j job
	var payload []byte
	err := s.pool.QueryRow(ctx, `
		update xbase.jobs
		   set status = 'running', locked_at = now(), attempts = attempts + 1, updated_at = now()
		 where id = (
		     select id from xbase.jobs
		      where app_id = $1 and status = 'queued' and run_at <= now()
		      order by run_at, id
		      for update skip locked
		      limit 1)
		returning id, kind, payload::text, attempts, max_attempts`, s.cfg.AppID).
		Scan(&j.ID, &j.Kind, &payload, &j.Attempts, &j.MaxAttempts)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	j.Payload = payload
	return &j, nil
}

func (s *Server) finishJob(ctx context.Context, j *job, runErr error) error {
	if runErr == nil {
		s.jobs.succeeded.Add(1)
		_, err := s.pool.Exec(ctx,
			"update xbase.jobs set status = 'done', finished_at = now(), updated_at = now(), last_error = null where id = $1", j.ID)
		return err
	}
	s.jobs.failed.Add(1)
	exhausted := j.Attempts >= j.MaxAttempts
	slog.Warn("job failed", "job_id", j.ID, "kind", j.Kind, "attempts", j.Attempts, "exhausted", exhausted, "error", runErr)
	_, err := s.pool.Exec(ctx, `
		update xbase.jobs
		   set status = case when $2 then 'failed' else 'queued' end,
		       run_at = now() + make_interval(secs => $3),
		       locked_at = null, last_error = $4, updated_at = now(),
		       finished_at = case when $2 then now() end
		 where id = $1`, j.ID, exhausted, float64(backoffSecs(j.Attempts)), runErr.Error())
	return err
}

func (s *Server) dispatchJob(ctx context.Context, j *job) error {
	switch j.Kind {
	case "embeddings.reindex":
		return s.processReindex(ctx, j.Payload)
	}
	return fmt.Errorf("no handler for job kind '%s'", j.Kind)
}

func (s *Server) jobWorker(ctx context.Context, n int) {
	slog.Info("job worker started", "worker", n)
	for ctx.Err() == nil {
		j, err := s.claimJob(ctx)
		if err != nil {
			slog.Warn("job claim failed", "worker", n, "error", err)
		}
		if j != nil {
			jctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			runErr := s.dispatchJob(jctx, j)
			cancel()
			// record the result even if we are shutting down
			fctx, fcancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.finishJob(fctx, j, runErr); err != nil {
				slog.Error("failed to record job result", "job_id", j.ID, "error", err)
			}
			fcancel()
			continue // drain before sleeping
		}
		select {
		case <-ctx.Done():
		case <-s.jobs.wake:
		case <-time.After(2 * time.Second):
		}
	}
	slog.Info("job worker stopped", "worker", n)
}

// jobReaper re-queues jobs whose worker died (locked > 10 min) and prunes done jobs after 7 days.
func (s *Server) jobReaper(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		tag, err := s.pool.Exec(ctx, `update xbase.jobs set status = 'queued', locked_at = null, updated_at = now()
			where app_id = $1 and status = 'running' and locked_at < now() - interval '10 minutes'`, s.cfg.AppID)
		if err != nil {
			slog.Warn("job reaper failed", "error", err)
		} else if tag.RowsAffected() > 0 {
			slog.Warn("re-queued stuck jobs", "count", tag.RowsAffected())
		}
		_, _ = s.pool.Exec(ctx, `delete from xbase.jobs where app_id = $1 and status = 'done'
			and finished_at < now() - interval '7 days'`, s.cfg.AppID)
	}
}

// startJobs launches JOBS_CONCURRENCY workers plus the reaper.
func (s *Server) startJobs(ctx context.Context) {
	for i := 0; i < s.cfg.JobsConcurrency; i++ {
		go s.jobWorker(ctx, i)
	}
	go s.jobReaper(ctx)
}

// --- embeddings.reindex ------------------------------------------------------------

func (s *Server) reindexEmbeddings(w http.ResponseWriter, r *http.Request) {
	p, wsID, ok := s.vectorPrincipal(w, r, "embeddings:write")
	if !ok {
		return
	}
	if s.cfg.EmbeddingAPIURL == "" {
		writeAPIError(w, errBadRequest("EMBEDDING_API_URL is not configured"))
		return
	}
	if !s.cfg.JobsEnabled {
		writeAPIError(w, errUnavailable("JOBS_ENABLED=false: no worker would run the reindex"))
		return
	}
	if err := s.inTx(r.Context(), p, func(tx pgx.Tx) error { return s.ensureWorkspace(r.Context(), tx, wsID) }); err != nil {
		dbError(w, err)
		return
	}
	id, err := s.enqueueJob(r.Context(), s.pool, "embeddings.reindex", map[string]string{"workspace_id": wsID})
	if err != nil {
		dbError(w, err)
		return
	}
	s.jobs.notify()
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": id})
}

func (s *Server) processReindex(ctx context.Context, payload json.RawMessage) error {
	var p struct {
		WorkspaceID string `json:"workspace_id"`
	}
	if err := json.Unmarshal(payload, &p); err != nil || !isUUID(p.WorkspaceID) {
		return fmt.Errorf("reindex job missing workspace_id")
	}
	last := "00000000-0000-0000-0000-000000000000"
	for {
		rows, err := s.pool.Query(ctx, `select id::text, content from xbase.embeddings
			where workspace_id = $1::uuid and app_slug = $2 and id > $3::uuid order by id limit 64`, p.WorkspaceID, s.cfg.AppID, last)
		if err != nil {
			return err
		}
		var ids, texts []string
		for rows.Next() {
			var id, content string
			if err := rows.Scan(&id, &content); err != nil {
				rows.Close()
				return err
			}
			ids, texts = append(ids, id), append(texts, content)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		last = ids[len(ids)-1]
		vecs, apiErr := s.embedTexts(ctx, texts)
		if apiErr != nil {
			return apiErr
		}
		for i, v := range vecs {
			if e := s.checkDims(v); e != nil {
				return e
			}
			if _, err := s.pool.Exec(ctx, "update xbase.embeddings set embedding = $1::extensions.vector, updated_at = now() where id = $2::uuid",
				vectorLiteral(v), ids[i]); err != nil {
				return err
			}
		}
	}
}
