//! Durable background job queue on Postgres (`xbase.jobs`).
//!
//! Workers claim jobs with `FOR UPDATE SKIP LOCKED`, so any number of replicas
//! can run safely. Jobs are scoped by `app_id`, so ten SaaS backends sharing a
//! database never steal each other's work. Failures retry with exponential
//! backoff until `max_attempts`, then move to `failed`.
//!
//! Add a new job kind by matching on it in [`dispatch`].

use std::time::Duration;

use serde_json::Value;
use sqlx::{FromRow, PgExecutor};

use crate::{error::ApiError, state::AppState};

#[derive(Debug, FromRow)]
pub struct Job {
    pub id: i64,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
    pub max_attempts: i32,
}

pub async fn enqueue<'e>(
    exec: impl PgExecutor<'e>,
    app_id: &str,
    kind: &str,
    payload: &Value,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "insert into xbase.jobs (app_id, kind, payload) values ($1, $2, $3) returning id",
    )
    .bind(app_id)
    .bind(kind)
    .bind(payload)
    .fetch_one(exec)
    .await
}

async fn claim(state: &AppState) -> Result<Option<Job>, sqlx::Error> {
    sqlx::query_as::<_, Job>(
        r#"
        update xbase.jobs
           set status = 'running', locked_at = now(), attempts = attempts + 1, updated_at = now()
         where id = (
             select id from xbase.jobs
              where app_id = $1 and status = 'queued' and run_at <= now()
              order by run_at, id
              for update skip locked
              limit 1)
        returning id, kind, payload, attempts, max_attempts
        "#,
    )
    .bind(&state.config.app_id)
    .fetch_optional(&state.pool)
    .await
}

/// Exponential backoff: 2^attempts seconds, capped at one hour.
pub fn backoff_secs(attempts: i32) -> i64 {
    2i64.saturating_pow(attempts.clamp(0, 12) as u32).min(3600)
}

async fn finish(state: &AppState, job: &Job, result: Result<(), ApiError>) -> Result<(), sqlx::Error> {
    match result {
        Ok(()) => {
            state.metrics.jobs_succeeded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            sqlx::query(
                "update xbase.jobs set status = 'done', finished_at = now(), updated_at = now(), last_error = null where id = $1",
            )
            .bind(job.id)
            .execute(&state.pool)
            .await?;
        }
        Err(err) => {
            state.metrics.jobs_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let exhausted = job.attempts >= job.max_attempts;
            tracing::warn!(job_id = job.id, kind = %job.kind, attempts = job.attempts, exhausted, error = %err, "job failed");
            sqlx::query(
                r#"
                update xbase.jobs
                   set status = case when $2 then 'failed' else 'queued' end,
                       run_at = now() + make_interval(secs => $3),
                       locked_at = null, last_error = $4, updated_at = now(),
                       finished_at = case when $2 then now() end
                 where id = $1
                "#,
            )
            .bind(job.id)
            .bind(exhausted)
            .bind(backoff_secs(job.attempts) as f64)
            .bind(err.to_string())
            .execute(&state.pool)
            .await?;
        }
    }
    Ok(())
}

async fn dispatch(state: &AppState, job: &Job) -> Result<(), ApiError> {
    match job.kind.as_str() {
        "billing.webhook" => crate::billing::process_webhook_job(state, &job.payload).await,
        "embeddings.reindex" => crate::vector::process_reindex_job(state, &job.payload).await,
        other => Err(ApiError::internal(format!("no handler for job kind '{other}'"))),
    }
}

async fn worker_loop(state: AppState, worker: usize, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tracing::info!(worker, "job worker started");
    loop {
        if *shutdown.borrow() {
            break;
        }
        match claim(&state).await {
            Ok(Some(job)) => {
                let result = dispatch(&state, &job).await;
                if let Err(e) = finish(&state, &job, result).await {
                    tracing::error!(job_id = job.id, error = %e, "failed to record job result");
                }
                continue; // drain the queue before sleeping
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(worker, error = %e, "job claim failed"),
        }
        tokio::select! {
            _ = state.jobs_notify.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = shutdown.changed() => {}
        }
    }
    tracing::info!(worker, "job worker stopped");
}

/// Re-queues jobs whose worker died mid-flight (locked for > 10 minutes).
async fn reaper_loop(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = shutdown.changed() => break,
        }
        let res = sqlx::query(
            "update xbase.jobs set status = 'queued', locked_at = null, updated_at = now() \
             where app_id = $1 and status = 'running' and locked_at < now() - interval '10 minutes'",
        )
        .bind(&state.config.app_id)
        .execute(&state.pool)
        .await;
        match res {
            Ok(r) if r.rows_affected() > 0 => tracing::warn!(count = r.rows_affected(), "re-queued stuck jobs"),
            Err(e) => tracing::warn!(error = %e, "job reaper failed"),
            _ => {}
        }
        // Keep the table small: completed jobs are retained for 7 days.
        let _ = sqlx::query(
            "delete from xbase.jobs where app_id = $1 and status = 'done' and finished_at < now() - interval '7 days'",
        )
        .bind(&state.config.app_id)
        .execute(&state.pool)
        .await;
    }
}

pub fn spawn_workers(state: &AppState, shutdown: tokio::sync::watch::Receiver<bool>) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles: Vec<_> = (0..state.config.jobs_concurrency)
        .map(|i| tokio::spawn(worker_loop(state.clone(), i, shutdown.clone())))
        .collect();
    handles.push(tokio::spawn(reaper_loop(state.clone(), shutdown)));
    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(5), 32);
        assert_eq!(backoff_secs(50), 3600);
    }
}
