use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, PgPool};
use std::sync::Arc;
use uuid::Uuid;

use crate::{auth::SupabaseClaims, config::AppConfig};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct WorkspaceRecord {
    pub id: Uuid,
    pub app_slug: String,
    pub name: String,
    pub owner_id: Uuid,
    pub plan: String,
    pub created_at: DateTime<Utc>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/health/db", get(db_health_check))
        .route("/api/v1/me", get(current_user))
        .route("/api/v1/tenants/:app_slug", get(list_workspaces_for_app))
        .with_state(state)
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "xbase-backend",
        "app_id": state.config.app_id,
        "pooler_mode": "supavisor_transaction_6543"
    }))
}

async fn db_health_check(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(val) => (
            StatusCode::OK,
            Json(json!({
                "status": "connected",
                "probe": val
            })),
        ),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "disconnected",
                "error": err.to_string()
            })),
        ),
    }
}

async fn current_user(claims: SupabaseClaims) -> impl IntoResponse {
    Json(json!({
        "user_id": claims.sub,
        "email": claims.email,
        "role": claims.role
    }))
}

async fn list_workspaces_for_app(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(app_slug): Path<String>,
) -> impl IntoResponse {
    let query = r#"
        SELECT id, app_slug, name, owner_id, plan, created_at
        FROM xbase.workspaces
        WHERE app_slug = $1 AND owner_id = $2
        ORDER BY created_at DESC
    "#;

    match sqlx::query_as::<_, WorkspaceRecord>(query)
        .bind(&app_slug)
        .bind(claims.sub)
        .fetch_all(&state.pool)
        .await
    {
        Ok(workspaces) => (
            StatusCode::OK,
            Json(json!({
                "app_slug": app_slug,
                "owner_id": claims.sub,
                "workspaces": workspaces
            })),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "database_query_failed",
                "message": err.to_string()
            })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::create_pool;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn test_state() -> AppState {
        let config = AppConfig {
            app_id: "saas-test-1".to_string(),
            host: "127.0.0.1".to_string(),
            port: 3000,
            database_url: "postgres://postgres.tenant:pass@localhost:6543/postgres".to_string(),
            db_max_connections: 2,
            supabase_jwt_secret: "test-secret-at-least-32-characters-long!".to_string(),
            supabase_url: "http://localhost:8000".to_string(),
        };
        let pool = create_pool(&config).await.unwrap();
        AppState {
            pool,
            config: Arc::new(config),
        }
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = build_router(test_state().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["app_id"], "saas-test-1");
    }

    #[tokio::test]
    async fn protected_route_rejects_missing_token() {
        let app = build_router(test_state().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
