use axum::{
    extract::State,
    http::{header, HeaderValue, Method, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::json;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{api_keys, auth::SupabaseClaims, billing, gotrue, metrics, rate_limit, realtime, storage, vector, workspaces};

pub use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    let cors = cors_layer(&state.config.cors_allowed_origins);
    Router::new()
        .route("/health", get(health_check))
        .route("/health/db", get(db_health_check))
        .route("/metrics", get(metrics::render))
        .route("/api/v1/me", get(current_user))
        .merge(gotrue::router())
        .merge(workspaces::router())
        .merge(api_keys::router())
        .merge(storage::router())
        .merge(vector::router())
        .merge(billing::router())
        .merge(realtime::router())
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit::middleware))
        .layer(middleware::from_fn_with_state(state.clone(), metrics::track))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

fn cors_layer(origins: &[String]) -> CorsLayer {
    if origins.is_empty() || origins.iter().any(|o| o == "*") {
        return CorsLayer::permissive();
    }
    let origins: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, "x-api-key".parse().unwrap(), "x-upsert".parse().unwrap()])
        .allow_credentials(true)
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
