//! Supabase Auth (GoTrue) operations exposed through the Rust backend:
//! sign-up, password / magic-link / OTP sign-in, OAuth + PKCE, token refresh
//! rotation, password recovery, user updates, logout and admin user CRUD.
//!
//! GoTrue remains the source of truth (it is written in Go and already very
//! fast); this module is a thin, typed proxy so each SaaS gets one API surface,
//! shared rate limiting, and per-app sign-up metadata.

use axum::{
    extract::{Path, Query, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::{AdminClaims, UserToken},
    error::{ApiError, ApiResult},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/signup", post(signup))
        .route("/api/v1/auth/token", post(password_sign_in))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/otp", post(otp))
        .route("/api/v1/auth/magiclink", post(magiclink))
        .route("/api/v1/auth/verify", post(verify))
        .route("/api/v1/auth/recover", post(recover))
        .route("/api/v1/auth/authorize", get(authorize))
        .route("/api/v1/auth/exchange", post(exchange_pkce))
        .route("/api/v1/auth/user", get(get_user).put(update_user))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/admin/users", get(admin_list_users).post(admin_create_user))
        .route(
            "/api/v1/admin/users/:id",
            get(admin_get_user)
                .put(admin_update_user)
                .delete(admin_delete_user),
        )
}

enum Credential<'a> {
    /// Public anon key (required by Kong for unauthenticated calls).
    Anon,
    /// The end user's own access token.
    User(&'a str),
    /// Service role key for /admin endpoints.
    Service,
}

/// Forwards a request to GoTrue and relays its status + JSON body verbatim.
async fn forward(
    state: &AppState,
    method: Method,
    path: &str,
    query: &[(&str, String)],
    body: Option<Value>,
    cred: Credential<'_>,
) -> ApiResult<Response> {
    let url = format!("{}{}", state.config.gotrue_url, path);
    let mut req = state.http.request(method, &url).query(query);

    let anon = state.config.supabase_anon_key.as_deref();
    req = match cred {
        Credential::Anon => match anon {
            Some(key) => req.header("apikey", key).bearer_auth(key),
            None => req,
        },
        Credential::User(token) => {
            let req = req.bearer_auth(token);
            match anon {
                Some(key) => req.header("apikey", key),
                None => req,
            }
        }
        Credential::Service => {
            let key = state.config.supabase_service_role_key.as_deref().ok_or_else(|| {
                ApiError::ServiceUnavailable("SUPABASE_SERVICE_ROLE_KEY is not configured".into())
            })?;
            req.header("apikey", key).bearer_auth(key)
        }
    };
    if let Some(body) = body {
        req = req.json(&body);
    }

    let resp = req.send().await?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = resp.bytes().await?;
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({ "message": String::from_utf8_lossy(&bytes) }))
    };

    if status == StatusCode::NO_CONTENT || (status.is_success() && body.is_null()) {
        return Ok(status.into_response());
    }
    Ok((status, Json(body)).into_response())
}

fn require_object(body: Value) -> ApiResult<Value> {
    if body.is_object() {
        Ok(body)
    } else {
        Err(ApiError::bad_request("JSON object body required"))
    }
}

/// Tags new users with the app they signed up through (`user_metadata.signup_app`).
fn tag_signup(mut body: Value, app_id: &str) -> Value {
    if let Some(obj) = body.as_object_mut() {
        let data = obj.entry("data").or_insert_with(|| json!({}));
        if let Some(data) = data.as_object_mut() {
            data.entry("signup_app").or_insert_with(|| json!(app_id));
        }
    }
    body
}

#[derive(Deserialize)]
struct RedirectQuery {
    redirect_to: Option<String>,
}

fn redirect_query(q: &RedirectQuery) -> Vec<(&'static str, String)> {
    q.redirect_to
        .clone()
        .map(|r| vec![("redirect_to", r)])
        .unwrap_or_default()
}

/// `POST /api/v1/auth/signup` — `{ email | phone, password, data? }`
async fn signup(
    State(state): State<AppState>,
    Query(q): Query<RedirectQuery>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let body = tag_signup(require_object(body)?, &state.config.app_id);
    forward(&state, Method::POST, "/signup", &redirect_query(&q), Some(body), Credential::Anon).await
}

/// `POST /api/v1/auth/token` — `{ email | phone, password }`
async fn password_sign_in(State(state): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let q = [("grant_type", "password".to_string())];
    forward(&state, Method::POST, "/token", &q, Some(require_object(body)?), Credential::Anon).await
}

#[derive(Deserialize)]
struct RefreshBody {
    refresh_token: String,
}

/// `POST /api/v1/auth/refresh` — rotates the refresh token (GoTrue enforces reuse detection).
async fn refresh(State(state): State<AppState>, Json(body): Json<RefreshBody>) -> ApiResult<Response> {
    let q = [("grant_type", "refresh_token".to_string())];
    forward(
        &state,
        Method::POST,
        "/token",
        &q,
        Some(json!({ "refresh_token": body.refresh_token })),
        Credential::Anon,
    )
    .await
}

/// `POST /api/v1/auth/otp` — `{ email | phone, create_user?, data? }` sends an OTP / magic link.
async fn otp(
    State(state): State<AppState>,
    Query(q): Query<RedirectQuery>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let body = tag_signup(require_object(body)?, &state.config.app_id);
    forward(&state, Method::POST, "/otp", &redirect_query(&q), Some(body), Credential::Anon).await
}

/// `POST /api/v1/auth/magiclink` — `{ email }`
async fn magiclink(
    State(state): State<AppState>,
    Query(q): Query<RedirectQuery>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    forward(&state, Method::POST, "/magiclink", &redirect_query(&q), Some(require_object(body)?), Credential::Anon).await
}

/// `POST /api/v1/auth/verify` — `{ type: signup|magiclink|recovery|invite|email|sms, token | token_hash, email | phone }`
async fn verify(State(state): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    forward(&state, Method::POST, "/verify", &[], Some(require_object(body)?), Credential::Anon).await
}

/// `POST /api/v1/auth/recover` — `{ email }` sends a password reset email.
async fn recover(
    State(state): State<AppState>,
    Query(q): Query<RedirectQuery>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    forward(&state, Method::POST, "/recover", &redirect_query(&q), Some(require_object(body)?), Credential::Anon).await
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    provider: String,
    redirect_to: Option<String>,
    scopes: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// `GET /api/v1/auth/authorize?provider=github&redirect_to=...` — redirects the
/// browser to GoTrue's public OAuth endpoint. GoTrue handles the provider
/// callback at `/auth/v1/callback`; pass `code_challenge` for the PKCE flow.
async fn authorize(State(state): State<AppState>, Query(q): Query<AuthorizeQuery>) -> ApiResult<Redirect> {
    if q.provider.is_empty() || !q.provider.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ApiError::bad_request("Invalid provider"));
    }
    let base = format!("{}/auth/v1/authorize", state.config.supabase_public_url);
    let mut url = reqwest::Url::parse(&base).map_err(|e| ApiError::internal(e.to_string()))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("provider", &q.provider);
        if let Some(v) = &q.redirect_to {
            pairs.append_pair("redirect_to", v);
        }
        if let Some(v) = &q.scopes {
            pairs.append_pair("scopes", v);
        }
        if let Some(v) = &q.code_challenge {
            pairs.append_pair("code_challenge", v);
            pairs.append_pair(
                "code_challenge_method",
                q.code_challenge_method.as_deref().unwrap_or("s256"),
            );
        }
    }
    Ok(Redirect::to(url.as_str()))
}

/// `POST /api/v1/auth/exchange` — `{ auth_code, code_verifier }` (PKCE code exchange).
async fn exchange_pkce(State(state): State<AppState>, Json(body): Json<Value>) -> ApiResult<Response> {
    let q = [("grant_type", "pkce".to_string())];
    forward(&state, Method::POST, "/token", &q, Some(require_object(body)?), Credential::Anon).await
}

async fn get_user(State(state): State<AppState>, user: UserToken) -> ApiResult<Response> {
    forward(&state, Method::GET, "/user", &[], None, Credential::User(&user.token)).await
}

/// `PUT /api/v1/auth/user` — `{ email?, password?, phone?, data?, nonce? }`
async fn update_user(State(state): State<AppState>, user: UserToken, Json(body): Json<Value>) -> ApiResult<Response> {
    forward(&state, Method::PUT, "/user", &[], Some(require_object(body)?), Credential::User(&user.token)).await
}

#[derive(Deserialize)]
struct LogoutQuery {
    /// `global` (default), `local` or `others`.
    scope: Option<String>,
}

async fn logout(State(state): State<AppState>, user: UserToken, Query(q): Query<LogoutQuery>) -> ApiResult<Response> {
    let q = q.scope.map(|s| vec![("scope", s)]).unwrap_or_default();
    forward(&state, Method::POST, "/logout", &q, None, Credential::User(&user.token)).await
}

// --- Admin -----------------------------------------------------------------

#[derive(Deserialize)]
struct PageQuery {
    page: Option<u32>,
    per_page: Option<u32>,
}

async fn admin_list_users(
    State(state): State<AppState>,
    _admin: AdminClaims,
    Query(p): Query<PageQuery>,
) -> ApiResult<Response> {
    let q = [
        ("page", p.page.unwrap_or(1).to_string()),
        ("per_page", p.per_page.unwrap_or(50).min(1000).to_string()),
    ];
    forward(&state, Method::GET, "/admin/users", &q, None, Credential::Service).await
}

/// `{ email, password?, email_confirm?, phone?, user_metadata?, app_metadata?, ban_duration? }`
async fn admin_create_user(
    State(state): State<AppState>,
    _admin: AdminClaims,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    forward(&state, Method::POST, "/admin/users", &[], Some(require_object(body)?), Credential::Service).await
}

async fn admin_get_user(State(state): State<AppState>, _admin: AdminClaims, Path(id): Path<Uuid>) -> ApiResult<Response> {
    forward(&state, Method::GET, &format!("/admin/users/{id}"), &[], None, Credential::Service).await
}

async fn admin_update_user(
    State(state): State<AppState>,
    _admin: AdminClaims,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    forward(&state, Method::PUT, &format!("/admin/users/{id}"), &[], Some(require_object(body)?), Credential::Service).await
}

async fn admin_delete_user(
    State(state): State<AppState>,
    _admin: AdminClaims,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    forward(&state, Method::DELETE, &format!("/admin/users/{id}"), &[], None, Credential::Service).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signup_is_tagged_with_app_without_overwriting() {
        let tagged = tag_signup(json!({"email": "a@b.c", "password": "x"}), "app-1");
        assert_eq!(tagged["data"]["signup_app"], "app-1");

        let kept = tag_signup(json!({"email": "a@b.c", "data": {"signup_app": "mine"}}), "app-1");
        assert_eq!(kept["data"]["signup_app"], "mine");
    }
}
