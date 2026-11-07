use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, HeaderMap},
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    api_keys::{self, ApiKeyPrincipal},
    error::ApiError,
    state::AppState,
};

/// Standard Supabase GoTrue JWT claims. Unknown claims (app_metadata,
/// user_metadata, aal, session_id, ...) are preserved in `extra` so the full
/// claim set can be forwarded to Postgres for RLS (`auth.jwt()`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupabaseClaims {
    pub sub: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub role: String,
    pub exp: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<usize>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SupabaseClaims {
    pub fn is_service_role(&self) -> bool {
        self.role == "service_role"
    }

    pub fn is_expired(&self) -> bool {
        (self.exp as i64) < chrono::Utc::now().timestamp()
    }
}

pub fn verify_supabase_jwt(
    token: &str,
    jwt_secret: &str,
) -> Result<SupabaseClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    validation.leeway = 5;

    let token_data = decode::<SupabaseClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )?;

    Ok(token_data.claims)
}

pub struct AuthError(pub &'static str);

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "message": self.0
            })),
        )
            .into_response()
    }
}

#[async_trait]
impl FromRequestParts<AppState> for SupabaseClaims {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(AuthError("Missing Authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthError("Authorization header must be Bearer <token>"))?;

        verify_supabase_jwt(token, &state.config.supabase_jwt_secret)
            .map_err(|_| AuthError("Invalid or expired Supabase JWT"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[test]
    fn roundtrip_supabase_jwt_verification() {
        let secret = "super-secret-jwt-key-with-at-least-32-bytes!";
        let user_id = Uuid::new_v4();
        let claims = SupabaseClaims {
            sub: user_id,
            email: Some("founder@xbase.dev".to_string()),
            role: "authenticated".to_string(),
            exp: 4_102_444_800, // 2100-01-01
            iat: Some(1_700_000_000),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("token encoding succeeds");

        let verified = verify_supabase_jwt(&token, secret).expect("token verification succeeds");
        assert_eq!(verified.sub, user_id);
        assert_eq!(verified.role, "authenticated");
        assert_eq!(verified.email.as_deref(), Some("founder@xbase.dev"));
    }
}
