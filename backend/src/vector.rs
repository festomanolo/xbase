//! Vector / AI search with pgvector, scoped per workspace.
//!
//! Embeddings can be supplied by the caller or computed server-side through any
//! OpenAI-compatible endpoint (`EMBEDDING_API_URL`: OpenAI, Ollama, vLLM,
//! LocalAI, ...). Works with user JWTs (RLS-enforced) and API keys
//! (`embeddings:read` / `embeddings:write` scopes).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, post},
    Json, Router,
};
use pgvector::Vector;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    auth::Principal,
    error::{ApiError, ApiResult},
    jobs,
    rls::begin_rls,
    state::AppState,
};

const MAX_BATCH: usize = 100;
const MAX_CONTENT_CHARS: usize = 32_000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/workspaces/:id/embeddings", post(upsert_embeddings))
        .route("/api/v1/workspaces/:id/embeddings/search", post(search))
        .route("/api/v1/workspaces/:id/embeddings/reindex", post(reindex))
        .route("/api/v1/workspaces/:id/embeddings/:embedding_id", delete(delete_embedding))
}

/// Opens a transaction for the principal: RLS-impersonated for users, plain
/// (service) for API keys whose workspace binding was already verified.
async fn begin_for(state: &AppState, principal: &Principal) -> ApiResult<Transaction<'static, Postgres>> {
    match principal {
        Principal::User(claims) => begin_rls(&state.pool, claims).await,
        Principal::ApiKey(_) => Ok(state.pool.begin().await?),
    }
}

async fn ensure_workspace(tx: &mut Transaction<'static, Postgres>, state: &AppState, id: Uuid) -> ApiResult<()> {
    let ok: bool = sqlx::query_scalar("select exists(select 1 from xbase.workspaces where id = $1 and app_slug = $2)")
        .bind(id)
        .bind(&state.config.app_id)
        .fetch_one(&mut **tx)
        .await?;
    if ok { Ok(()) } else { Err(ApiError::not_found("Workspace not found")) }
}

/// Calls an OpenAI-compatible `/embeddings` endpoint.
pub async fn embed_texts(state: &AppState, inputs: &[String]) -> ApiResult<Vec<Vec<f32>>> {
    let base = state.config.embedding_api_url.as_deref().ok_or_else(|| {
        ApiError::bad_request("No embedding provided and EMBEDDING_API_URL is not configured")
    })?;
    let mut req = state
        .http
        .post(format!("{base}/embeddings"))
        .json(&json!({ "model": state.config.embedding_model, "input": inputs }));
    if let Some(key) = &state.config.embedding_api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        tracing::warn!(status, body = %text, "embedding provider error");
        return Err(ApiError::ServiceUnavailable(format!("Embedding provider returned {status}")));
    }
    #[derive(Deserialize)]
    struct Item {
        index: usize,
        embedding: Vec<f32>,
    }
    #[derive(Deserialize)]
    struct Resp {
        data: Vec<Item>,
    }
    let mut parsed: Resp = resp.json().await?;
    parsed.data.sort_by_key(|i| i.index);
    if parsed.data.len() != inputs.len() {
        return Err(ApiError::ServiceUnavailable("Embedding provider returned wrong count".into()));
    }
    Ok(parsed.data.into_iter().map(|i| i.embedding).collect())
}

fn check_dims(state: &AppState, v: &[f32]) -> ApiResult<()> {
    if v.len() != state.config.embedding_dims {
        return Err(ApiError::bad_request(format!(
            "embedding must have {} dimensions, got {}",
            state.config.embedding_dims,
            v.len()
        )));
    }
    if v.iter().any(|x| !x.is_finite()) {
        return Err(ApiError::bad_request("embedding contains non-finite values"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct UpsertItem {
    external_id: Option<String>,
    content: String,
    #[serde(default)]
    metadata: Value,
    embedding: Option<Vec<f32>>,
}

#[derive(Deserialize)]
struct UpsertBody {
    items: Vec<UpsertItem>,
}

#[derive(Serialize, FromRow)]
struct UpsertedRow {
    id: Uuid,
    external_id: Option<String>,
}

async fn upsert_embeddings(
    State(state): State<AppState>,
    principal: Principal,
    Path(workspace_id): Path<Uuid>,
    Json(body): Json<UpsertBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    principal.require_workspace_scope(workspace_id, "embeddings:write")?;
    if body.items.is_empty() || body.items.len() > MAX_BATCH {
        return Err(ApiError::bad_request(format!("items must contain 1-{MAX_BATCH} entries")));
    }
    if body.items.iter().any(|i| i.content.is_empty() || i.content.chars().count() > MAX_CONTENT_CHARS) {
        return Err(ApiError::bad_request(format!("content must be 1-{MAX_CONTENT_CHARS} characters")));
    }

    // Compute missing embeddings in one batched provider call.
    let missing: Vec<usize> = body.items.iter().enumerate().filter(|(_, i)| i.embedding.is_none()).map(|(n, _)| n).collect();
    let mut computed = if missing.is_empty() {
        Vec::new()
    } else {
        let texts: Vec<String> = missing.iter().map(|&n| body.items[n].content.clone()).collect();
        embed_texts(&state, &texts).await?
    }
    .into_iter();

    let mut tx = begin_for(&state, &principal).await?;
    ensure_workspace(&mut tx, &state, workspace_id).await?;
    let mut rows = Vec::with_capacity(body.items.len());
    for item in body.items {
        let embedding = match item.embedding {
            Some(e) => e,
            None => computed.next().ok_or_else(|| ApiError::internal("embedding count mismatch"))?,
        };
        check_dims(&state, &embedding)?;
        let metadata = if item.metadata.is_null() { json!({}) } else { item.metadata };
        if !metadata.is_object() {
            return Err(ApiError::bad_request("metadata must be a JSON object"));
        }
        let row = sqlx::query_as::<_, UpsertedRow>(
            r#"
            insert into xbase.embeddings (app_slug, workspace_id, external_id, content, metadata, embedding)
            values ($1, $2, $3, $4, $5, $6)
            on conflict (workspace_id, external_id) do update
               set content = excluded.content, metadata = excluded.metadata,
                   embedding = excluded.embedding, updated_at = now()
            returning id, external_id
            "#,
        )
        .bind(&state.config.app_id)
        .bind(workspace_id)
        .bind(&item.external_id)
        .bind(&item.content)
        .bind(&metadata)
        .bind(Vector::from(embedding))
        .fetch_one(&mut *tx)
        .await?;
        rows.push(row);
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "upserted": rows }))))
}

#[derive(Deserialize)]
struct SearchBody {
    /// Raw query vector, or `query` text to embed server-side.
    embedding: Option<Vec<f32>>,
    query: Option<String>,
    #[serde(default = "default_k")]
    limit: i64,
    /// JSONB containment filter on metadata, e.g. `{"lang":"en"}`.
    filter: Option<Value>,
    #[serde(default)]
    min_similarity: f64,
}

fn default_k() -> i64 {
    10
}

#[derive(Serialize, FromRow)]
struct Hit {
    id: Uuid,
    external_id: Option<String>,
    content: String,
    metadata: Value,
    similarity: f64,
}

async fn search(
    State(state): State<AppState>,
    principal: Principal,
    Path(workspace_id): Path<Uuid>,
    Json(body): Json<SearchBody>,
) -> ApiResult<Json<Value>> {
    principal.require_workspace_scope(workspace_id, "embeddings:read")?;
    let embedding = match (body.embedding, body.query) {
        (Some(e), _) => e,
        (None, Some(q)) if !q.trim().is_empty() => embed_texts(&state, &[q]).await?.remove(0),
        _ => return Err(ApiError::bad_request("Provide `embedding` or `query`")),
    };
    check_dims(&state, &embedding)?;
    if let Some(f) = &body.filter {
        if !f.is_object() {
            return Err(ApiError::bad_request("filter must be a JSON object"));
        }
    }

    let mut tx = begin_for(&state, &principal).await?;
    let hits = sqlx::query_as::<_, Hit>(
        r#"
        select id, external_id, content, metadata,
               (1 - (embedding <=> $2))::float8 as similarity
          from xbase.embeddings
         where workspace_id = $1 and app_slug = $5
           and ($3::jsonb is null or metadata @> $3)
         order by embedding <=> $2
         limit $4
        "#,
    )
    .bind(workspace_id)
    .bind(Vector::from(embedding))
    .bind(&body.filter)
    .bind(body.limit.clamp(1, 100))
    .bind(&state.config.app_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let hits: Vec<Hit> = hits.into_iter().filter(|h| h.similarity >= body.min_similarity).collect();
    Ok(Json(json!({ "results": hits })))
}

async fn delete_embedding(
    State(state): State<AppState>,
    principal: Principal,
    Path((workspace_id, embedding_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    principal.require_workspace_scope(workspace_id, "embeddings:write")?;
    let mut tx = begin_for(&state, &principal).await?;
    let res = sqlx::query("delete from xbase.embeddings where id = $1 and workspace_id = $2 and app_slug = $3")
        .bind(embedding_id)
        .bind(workspace_id)
        .bind(&state.config.app_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Embedding not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Re-embeds every document in a workspace (e.g. after switching models) as a background job.
async fn reindex(
    State(state): State<AppState>,
    principal: Principal,
    Path(workspace_id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    principal.require_workspace_scope(workspace_id, "embeddings:write")?;
    if state.config.embedding_api_url.is_none() {
        return Err(ApiError::bad_request("EMBEDDING_API_URL is not configured"));
    }
    let mut tx = begin_for(&state, &principal).await?;
    ensure_workspace(&mut tx, &state, workspace_id).await?;
    tx.commit().await?;
    let job_id = jobs::enqueue(&state.pool, &state.config.app_id, "embeddings.reindex", &json!({ "workspace_id": workspace_id })).await?;
    state.jobs_notify.notify_one();
    Ok((StatusCode::ACCEPTED, Json(json!({ "job_id": job_id }))))
}

pub async fn process_reindex_job(state: &AppState, payload: &Value) -> Result<(), ApiError> {
    let workspace_id = payload["workspace_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::internal("reindex job missing workspace_id"))?;
    let mut last_id = Uuid::nil();
    loop {
        let batch: Vec<(Uuid, String)> = sqlx::query_as(
            "select id, content from xbase.embeddings where workspace_id = $1 and app_slug = $2 and id > $3 order by id limit 64",
        )
        .bind(workspace_id)
        .bind(&state.config.app_id)
        .bind(last_id)
        .fetch_all(&state.pool)
        .await?;
        let Some((tail, _)) = batch.last() else { break };
        last_id = *tail;
        let texts: Vec<String> = batch.iter().map(|(_, c)| c.clone()).collect();
        let vectors = embed_texts(state, &texts).await?;
        for ((id, _), v) in batch.iter().zip(vectors) {
            check_dims(state, &v)?;
            sqlx::query("update xbase.embeddings set embedding = $1, updated_at = now() where id = $2")
                .bind(Vector::from(v))
                .bind(id)
                .execute(&state.pool)
                .await?;
        }
    }
    Ok(())
}
