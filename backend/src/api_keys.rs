//! Hashed API keys for server-to-server integrations (`x-api-key` header).
//!
//! Keys look like `xb_<prefix>_<secret>`. Only the SHA-256 hash is stored; the
//! plaintext is returned exactly once at creation time. SHA-256 (rather than a
//! slow KDF) is appropriate because keys carry 256 bits of randomness.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::SupabaseClaims,
    error::{ApiError, ApiResult},
    rls::begin_rls,
    state::AppState,
};

pub const API_KEY_HEADER: &str = "x-api-key";

/// Scopes a key may carry. `*` grants everything within its workspace.
pub const KNOWN_SCOPES: [&str; 6] = [
    "*",
    "workspace:read",
    "embeddings:read",
    "embeddings:write",
    "storage:read",
    "storage:write",
];

#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyPrincipal {
    pub key_id: Uuid,
    pub workspace_id: Uuid,
    pub app_slug: String,
    pub scopes: Vec<String>,
}

impl ApiKeyPrincipal {
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        if self.scopes.iter().any(|s| s == "*" || s == scope) {
            Ok(())
        } else {
            Err(ApiError::forbidden(format!("API key lacks scope '{scope}'")))
        }
    }
}

pub fn hash_key(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Returns `(plaintext_key, prefix)`.
pub fn generate_key() -> (String, String) {
    let mut prefix = [0u8; 6];
    let mut secret = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut prefix);
    rng.fill_bytes(&mut secret);
    let prefix = hex::encode(prefix);
    (format!("xb_{prefix}_{}", URL_SAFE_NO_PAD.encode(secret)), prefix)
}

/// Extracts the public prefix from a key, used as a rate-limit bucket key.
pub fn key_prefix(raw: &str) -> Option<&str> {
    let rest = raw.strip_prefix("xb_")?;
    let (prefix, secret) = rest.split_once('_')?;
    (prefix.len() == 12 && !secret.is_empty()).then_some(prefix)
}

pub async fn authenticate(state: &AppState, raw: &str) -> ApiResult<ApiKeyPrincipal> {
    let raw = raw.trim();
    if key_prefix(raw).is_none() {
        return Err(ApiError::Unauthorized("Malformed API key".into()));
    }

    #[derive(FromRow)]
    struct Row {
        id: Uuid,
        workspace_id: Uuid,
        app_slug: String,
        scopes: Vec<String>,
        stale: bool,
    }

    let row = sqlx::query_as::<_, Row>(
        r#"
        select id, workspace_id, app_slug, scopes,
               (last_used_at is null or last_used_at < now() - interval '1 minute') as stale
        from xbase.api_keys
        where key_hash = $1 and app_slug = $2
          and revoked_at is null
          and (expires_at is null or expires_at > now())
        "#,
    )
    .bind(hash_key(raw))
    .bind(&state.config.app_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Invalid, expired or revoked API key".into()))?;

    if row.stale {
        // Throttled, fire-and-forget usage tracking keeps the hot path fast.
        let pool = state.pool.clone();
        let id = row.id;
        tokio::spawn(async move {
            let _ = sqlx::query("update xbase.api_keys set last_used_at = now() where id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        });
    }

    Ok(ApiKeyPrincipal {
        key_id: row.id,
        workspace_id: row.workspace_id,
        app_slug: row.app_slug,
        scopes: row.scopes,
    })
}

// ---------------------------------------------------------------------------
// Management endpoints (workspace owners/admins, enforced by RLS)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, FromRow)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

const KEY_COLUMNS: &str =
    "id, workspace_id, name, prefix, scopes, created_by, created_at, last_used_at, expires_at, revoked_at";

#[derive(Debug, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workspaces/:workspace_id/api-keys",
            get(list_keys).post(create_key),
        )
        .route(
            "/api/v1/workspaces/:workspace_id/api-keys/:key_id",
            delete(revoke_key),
        )
        .route("/api/v1/server/whoami", get(whoami))
}

async fn list_keys(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(workspace_id): Path<Uuid>,
) -> ApiResult<Json<Vec<ApiKeyRecord>>> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let keys = sqlx::query_as::<_, ApiKeyRecord>(&format!(
        "select {KEY_COLUMNS} from xbase.api_keys where workspace_id = $1 order by created_at desc"
    ))
    .bind(workspace_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(keys))
}

async fn create_key(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(workspace_id): Path<Uuid>,
    Json(body): Json<CreateApiKey>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let name = body.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad_request("name must be 1-100 characters"));
    }
    let scopes = if body.scopes.is_empty() {
        vec!["workspace:read".to_string()]
    } else {
        body.scopes
    };
    if let Some(bad) = scopes.iter().find(|s| !KNOWN_SCOPES.contains(&s.as_str())) {
        return Err(ApiError::bad_request(format!(
            "Unknown scope '{bad}'. Allowed: {}",
            KNOWN_SCOPES.join(", ")
        )));
    }

    let (plaintext, prefix) = generate_key();
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let record = sqlx::query_as::<_, ApiKeyRecord>(&format!(
        r#"
        insert into xbase.api_keys (app_slug, workspace_id, name, prefix, key_hash, scopes, created_by, expires_at)
        values ($1, $2, $3, $4, $5, $6, $7, $8)
        returning {KEY_COLUMNS}
        "#
    ))
    .bind(&state.config.app_id)
    .bind(workspace_id)
    .bind(name)
    .bind(&prefix)
    .bind(hash_key(&plaintext))
    .bind(&scopes)
    .bind(claims.sub)
    .bind(body.expires_at)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "api_key": plaintext,
            "warning": "Store this key now; it cannot be retrieved again.",
            "key": record,
        })),
    ))
}

async fn revoke_key(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path((workspace_id, key_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let result = sqlx::query(
        "update xbase.api_keys set revoked_at = now() \
         where id = $1 and workspace_id = $2 and revoked_at is null",
    )
    .bind(key_id)
    .bind(workspace_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("API key not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Lets integrations verify their key and discover their workspace.
async fn whoami(
    State(state): State<AppState>,
    principal: crate::auth::Principal,
) -> ApiResult<Json<serde_json::Value>> {
    let crate::auth::Principal::ApiKey(key) = principal else {
        return Err(ApiError::bad_request("This endpoint expects an x-api-key header"));
    };
    let workspace = sqlx::query_as::<_, crate::workspaces::Workspace>(&format!(
        "select {} from xbase.workspaces where id = $1 and app_slug = $2",
        crate::workspaces::WORKSPACE_COLUMNS
    ))
    .bind(key.workspace_id)
    .bind(&state.config.app_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(serde_json::json!({ "key": key, "workspace": workspace })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_roundtrip_prefix_and_hash() {
        let (key, prefix) = generate_key();
        assert!(key.starts_with("xb_"));
        assert_eq!(key_prefix(&key), Some(prefix.as_str()));
        assert_eq!(hash_key(&key).len(), 64);
        assert_ne!(generate_key().0, key);
    }

    #[test]
    fn rejects_malformed_keys() {
        assert!(key_prefix("sk_live_123").is_none());
        assert!(key_prefix("xb_short_secret").is_none());
        assert!(key_prefix("xb_abcdefabcdef_").is_none());
    }

    #[test]
    fn scope_checks() {
        let key = ApiKeyPrincipal {
            key_id: Uuid::nil(),
            workspace_id: Uuid::nil(),
            app_slug: "a".into(),
            scopes: vec!["embeddings:read".into()],
        };
        assert!(key.require_scope("embeddings:read").is_ok());
        assert!(key.require_scope("embeddings:write").is_err());
    }
}
