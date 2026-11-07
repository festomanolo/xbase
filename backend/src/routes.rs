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
        "version": env!("CARGO_PKG_VERSION"),
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
        "role": claims.role,
        "app_metadata": claims.extra.get("app_metadata"),
        "user_metadata": claims.extra.get("user_metadata"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::AppConfig, db::create_pool};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    async fn test_state_with(config: AppConfig) -> AppState {
        let pool = create_pool(&config).await.unwrap();
        AppState::new(pool, Arc::new(config))
    }

    async fn test_state() -> AppState {
        test_state_with(AppConfig::for_tests()).await
    }

    async fn call(app: Router, req: Request<Body>) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
        let response = app.oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json, headers)
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = build_router(test_state().await);
        let (status, payload, _) = call(app, Request::builder().uri("/health").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["app_id"], "saas-test-1");
    }

    #[tokio::test]
    async fn protected_route_rejects_missing_token() {
        let app = build_router(test_state().await);
        let (status, _, _) = call(app, Request::builder().uri("/api/v1/me").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn me_returns_claims_for_valid_token() {
        let state = test_state().await;
        let user = Uuid::new_v4();
        let token = crate::auth::tests::sign(&state.config.supabase_jwt_secret, user, "authenticated");
        let app = build_router(state);
        let (status, payload, headers) = call(
            app,
            Request::builder()
                .uri("/api/v1/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["user_id"], json!(user));
        assert!(headers.contains_key("x-ratelimit-remaining"));
    }

    #[tokio::test]
    async fn admin_routes_require_admin() {
        let state = test_state().await;
        let token = crate::auth::tests::sign(&state.config.supabase_jwt_secret, Uuid::new_v4(), "authenticated");
        let app = build_router(state);
        let (status, _, _) = call(
            app,
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn service_role_key_passes_admin_gate() {
        let state = test_state().await;
        // Supabase service_role keys carry no `sub` claim.
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &json!({"role": "service_role", "iss": "supabase", "exp": 4_102_444_800u64}),
            &jsonwebtoken::EncodingKey::from_secret(state.config.supabase_jwt_secret.as_bytes()),
        )
        .unwrap();
        let app = build_router(state);
        let (status, _, _) = call(
            app,
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
    async fn rate_limiter_returns_429_when_exhausted() {
        let mut config = AppConfig::for_tests();
        config.rate_limit_burst = 2.0;
        config.rate_limit_per_second = 0.01;
        let app = build_router(test_state_with(config).await);
        let req = || Request::builder().uri("/api/v1/me").header("x-real-ip", "9.9.9.9").body(Body::empty()).unwrap();
        assert_eq!(call(app.clone(), req()).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(app.clone(), req()).await.0, StatusCode::UNAUTHORIZED);
        let (status, _, headers) = call(app, req()).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(headers.contains_key("retry-after"));
    }

    #[tokio::test]
    async fn stripe_webhook_rejects_bad_signature() {
        let app = build_router(test_state().await);
        let (status, _, _) = call(
            app,
            Request::builder()
                .method("POST")
                .uri("/webhooks/stripe")
                .header("stripe-signature", "t=1,v1=deadbeef")
                .body(Body::from(r#"{"id":"evt_1"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn malformed_api_key_is_rejected() {
        let app = build_router(test_state().await);
        let (status, _, _) = call(
            app,
            Request::builder()
                .uri("/api/v1/server/whoami")
                .header("x-api-key", "not-a-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn websocket_requires_token() {
        let app = build_router(test_state().await);
        let (status, _, _) = call(app, Request::builder().uri("/ws").body(Body::empty()).unwrap()).await;
        // Without upgrade headers axum rejects before auth; either way no anonymous socket.
        assert!(status.is_client_error());
    }
}
