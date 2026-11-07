//! Workspace, membership and invitation CRUD. Every user-facing query runs inside
//! an RLS-impersonated transaction, so authorization lives in Postgres policies
//! (see migrations/0002_*.sql) rather than being re-implemented here.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    api_keys::hash_key,
    auth::{Principal, SupabaseClaims},
    error::{ApiError, ApiResult},
    rls::begin_rls,
    state::AppState,
};

#[derive(Debug, Serialize, FromRow)]
pub struct Workspace {
    pub id: Uuid,
    pub app_slug: String,
    pub name: String,
    pub owner_id: Uuid,
    pub plan: String,
    pub subscription_status: Option<String>,
    pub billing_provider: Option<String>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub const WORKSPACE_COLUMNS: &str = "id, app_slug, name, owner_id, plan, subscription_status, \
     billing_provider, current_period_end, created_at, updated_at";

#[derive(Debug, Serialize, FromRow)]
pub struct Member {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct Invitation {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub role: String,
    pub invited_by: Uuid,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const INVITATION_COLUMNS: &str =
    "id, workspace_id, email, role, invited_by, expires_at, accepted_at, revoked_at, created_at";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/workspaces", get(list_workspaces).post(create_workspace))
        .route(
            "/api/v1/workspaces/:id",
            get(get_workspace)
                .patch(update_workspace)
                .delete(delete_workspace),
        )
        .route("/api/v1/workspaces/:id/members", get(list_members))
        .route(
            "/api/v1/workspaces/:id/members/:user_id",
            patch(update_member).delete(remove_member),
        )
        .route(
            "/api/v1/workspaces/:id/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/api/v1/workspaces/:id/invitations/:invitation_id",
            delete(revoke_invitation),
        )
        .route("/api/v1/invitations/accept", post(accept_invitation))
        .route("/api/v1/tenants/:app_slug", get(list_workspaces_for_app))
}

fn validate_name(name: &str) -> ApiResult<&str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        return Err(ApiError::bad_request("name must be 1-120 characters"));
    }
    Ok(name)
}

fn validate_role(role: &str) -> ApiResult<()> {
    match role {
        "admin" | "member" | "viewer" => Ok(()),
        _ => Err(ApiError::bad_request("role must be one of: admin, member, viewer")),
    }
}

// --- Workspaces ------------------------------------------------------------

async fn list_workspaces(
    State(state): State<AppState>,
    claims: SupabaseClaims,
) -> ApiResult<Json<Vec<Workspace>>> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let rows = sqlx::query_as::<_, Workspace>(&format!(
        "select {WORKSPACE_COLUMNS} from xbase.workspaces where app_slug = $1 order by created_at desc"
    ))
    .bind(&state.config.app_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

/// Backwards-compatible listing by explicit app slug (now RLS-enforced).
async fn list_workspaces_for_app(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(app_slug): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let rows = sqlx::query_as::<_, Workspace>(&format!(
        "select {WORKSPACE_COLUMNS} from xbase.workspaces where app_slug = $1 order by created_at desc"
    ))
    .bind(&app_slug)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({
        "app_slug": app_slug,
        "owner_id": claims.sub,
        "workspaces": rows
    })))
}

#[derive(Deserialize)]
struct WorkspaceBody {
    name: String,
}

async fn create_workspace(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Json(body): Json<WorkspaceBody>,
) -> ApiResult<(StatusCode, Json<Workspace>)> {
    let name = validate_name(&body.name)?;
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let ws = sqlx::query_as::<_, Workspace>(&format!(
        "insert into xbase.workspaces (app_slug, name, owner_id) values ($1, $2, $3) \
         returning {WORKSPACE_COLUMNS}"
    ))
    .bind(&state.config.app_id)
    .bind(name)
    .bind(claims.sub)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(ws)))
}

async fn get_workspace(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Workspace>> {
    principal.require_workspace_scope(id, "workspace:read")?;
    let sql = format!(
        "select {WORKSPACE_COLUMNS} from xbase.workspaces where id = $1 and app_slug = $2"
    );
    let ws = match &principal {
        Principal::User(claims) => {
            let mut tx = begin_rls(&state.pool, claims).await?;
            let ws = sqlx::query_as::<_, Workspace>(&sql)
                .bind(id)
                .bind(&state.config.app_id)
                .fetch_one(&mut *tx)
                .await?;
            tx.commit().await?;
            ws
        }
        Principal::ApiKey(_) => {
            sqlx::query_as::<_, Workspace>(&sql)
                .bind(id)
                .bind(&state.config.app_id)
                .fetch_one(&state.pool)
                .await?
        }
    };
    Ok(Json(ws))
}

async fn update_workspace(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(id): Path<Uuid>,
    Json(body): Json<WorkspaceBody>,
) -> ApiResult<Json<Workspace>> {
    let name = validate_name(&body.name)?;
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let ws = sqlx::query_as::<_, Workspace>(&format!(
        "update xbase.workspaces set name = $1 where id = $2 and app_slug = $3 \
         returning {WORKSPACE_COLUMNS}"
    ))
    .bind(name)
    .bind(id)
    .bind(&state.config.app_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("Workspace not found or not editable"))?;
    tx.commit().await?;
    Ok(Json(ws))
}

async fn delete_workspace(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let res = sqlx::query("delete from xbase.workspaces where id = $1 and app_slug = $2")
        .bind(id)
        .bind(&state.config.app_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Workspace not found or you are not the owner"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- Members ---------------------------------------------------------------

async fn list_members(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Member>>> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let rows = sqlx::query_as::<_, Member>(
        "select workspace_id, user_id, role, created_at from xbase.workspace_members \
         where workspace_id = $1 order by created_at",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct RoleBody {
    role: String,
}

async fn update_member(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RoleBody>,
) -> ApiResult<Json<Member>> {
    validate_role(&body.role)?;
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let member = sqlx::query_as::<_, Member>(
        "update xbase.workspace_members set role = $1 where workspace_id = $2 and user_id = $3 \
         returning workspace_id, user_id, role, created_at",
    )
    .bind(&body.role)
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("Member not found or not editable"))?;
    tx.commit().await?;
    Ok(Json(member))
}

async fn remove_member(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let res = sqlx::query("delete from xbase.workspace_members where workspace_id = $1 and user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Member not found or not removable"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- Invitations -----------------------------------------------------------

#[derive(Deserialize)]
struct InviteBody {
    email: String,
    #[serde(default = "default_role")]
    role: String,
}

fn default_role() -> String {
    "member".to_string()
}

pub fn generate_invite_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn list_invitations(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Invitation>>> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let rows = sqlx::query_as::<_, Invitation>(&format!(
        "select {INVITATION_COLUMNS} from xbase.workspace_invitations \
         where workspace_id = $1 order by created_at desc"
    ))
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rows))
}

async fn create_invitation(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(id): Path<Uuid>,
    Json(body): Json<InviteBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    validate_role(&body.role)?;
    let email = body.email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 320 {
        return Err(ApiError::bad_request("A valid email is required"));
    }

    let token = generate_invite_token();
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let inv = sqlx::query_as::<_, Invitation>(&format!(
        "insert into xbase.workspace_invitations (workspace_id, email, role, token_hash, invited_by) \
         values ($1, $2, $3, $4, $5) returning {INVITATION_COLUMNS}"
    ))
    .bind(id)
    .bind(&email)
    .bind(&body.role)
    .bind(hash_key(&token))
    .bind(claims.sub)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    // Deliver `token` to the invitee (email via GoTrue SMTP / your mailer, or a
    // link like https://app.example.com/invite?token=...). It is never stored.
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "invitation": inv, "token": token })),
    ))
}

async fn revoke_invitation(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path((id, invitation_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let res = sqlx::query(
        "update xbase.workspace_invitations set revoked_at = now() \
         where id = $1 and workspace_id = $2 and accepted_at is null and revoked_at is null",
    )
    .bind(invitation_id)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("Invitation not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AcceptBody {
    token: String,
}

async fn accept_invitation(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Json(body): Json<AcceptBody>,
) -> ApiResult<Json<Workspace>> {
    let mut tx = begin_rls(&state.pool, &claims).await?;
    let workspace_id: Uuid = sqlx::query_scalar("select xbase.accept_invitation($1)")
        .bind(hash_key(body.token.trim()))
        .fetch_one(&mut *tx)
        .await?;
    let ws = sqlx::query_as::<_, Workspace>(&format!(
        "select {WORKSPACE_COLUMNS} from xbase.workspaces where id = $1"
    ))
    .bind(workspace_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(ws))
}
