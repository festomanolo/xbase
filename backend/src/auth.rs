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
    /// Absent on Supabase's `anon` / `service_role` API keys (decoded as nil).
    #[serde(default, skip_serializing_if = "Uuid::is_nil")]
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

pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

#[async_trait]
impl FromRequestParts<AppState> for SupabaseClaims {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        if parts.headers.get(AUTHORIZATION).is_none() {
            return Err(ApiError::Unauthorized("Missing Authorization header".into()));
        }
        let token = bearer_token(&parts.headers).ok_or_else(|| {
            ApiError::Unauthorized("Authorization header must be Bearer <token>".into())
        })?;

        verify_supabase_jwt(token, &state.config.supabase_jwt_secret)
            .map_err(|_| ApiError::Unauthorized("Invalid or expired Supabase JWT".into()))
    }
}

/// Raw bearer token of an authenticated user, for forwarding to GoTrue/Storage
/// so Supabase services apply their own policies to the same identity.
pub struct UserToken {
    pub claims: SupabaseClaims,
    pub token: String,
}

#[async_trait]
impl FromRequestParts<AppState> for UserToken {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let claims = SupabaseClaims::from_request_parts(parts, state).await?;
        let token = bearer_token(&parts.headers).unwrap_or_default().to_string();
        Ok(Self { claims, token })
    }
}

/// Platform administrator: a service_role JWT or a user listed in ADMIN_USER_IDS.
pub struct AdminClaims(pub SupabaseClaims);

#[async_trait]
impl FromRequestParts<AppState> for AdminClaims {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let claims = SupabaseClaims::from_request_parts(parts, state).await?;
        if claims.is_service_role() || state.config.admin_user_ids.contains(&claims.sub) {
            Ok(Self(claims))
        } else {
            Err(ApiError::forbidden("Administrator privileges required"))
        }
    }
}

/// Either an end user (Supabase JWT) or a server-to-server integration (`x-api-key`).
#[derive(Debug, Clone)]
pub enum Principal {
    User(SupabaseClaims),
    ApiKey(ApiKeyPrincipal),
}

impl Principal {
    /// Ensures the principal may act on `workspace_id` with `scope`.
    /// Users are additionally checked by RLS; API keys are bound to one workspace.
    pub fn require_workspace_scope(&self, workspace_id: Uuid, scope: &str) -> Result<(), ApiError> {
        match self {
            Principal::User(_) => Ok(()),
            Principal::ApiKey(key) => {
                if key.workspace_id != workspace_id {
                    return Err(ApiError::forbidden("API key is not valid for this workspace"));
                }
                key.require_scope(scope)
            }
        }
    }
}

#[async_trait]
impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        if let Some(raw) = parts.headers.get(api_keys::API_KEY_HEADER) {
            let raw = raw
                .to_str()
                .map_err(|_| ApiError::Unauthorized("Malformed x-api-key header".into()))?;
            let key = api_keys::authenticate(state, raw).await?;
            return Ok(Principal::ApiKey(key));
        }
        Ok(Principal::User(SupabaseClaims::from_request_parts(parts, state).await?))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    pub fn sign(secret: &str, sub: Uuid, role: &str) -> String {
        let claims = SupabaseClaims {
            sub,
            email: Some("founder@xbase.dev".to_string()),
            role: role.to_string(),
            exp: 4_102_444_800, // 2100-01-01
            iat: Some(1_700_000_000),
            extra: Map::new(),
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("token encoding succeeds")
    }

    #[test]
    fn roundtrip_supabase_jwt_verification() {
        let secret = "super-secret-jwt-key-with-at-least-32-bytes!";
        let user_id = Uuid::new_v4();
        let token = sign(secret, user_id, "authenticated");

        let verified = verify_supabase_jwt(&token, secret).expect("token verification succeeds");
        assert_eq!(verified.sub, user_id);
        assert_eq!(verified.role, "authenticated");
        assert_eq!(verified.email.as_deref(), Some("founder@xbase.dev"));
    }

    #[test]
    fn preserves_extra_claims_for_rls() {
        let secret = "super-secret-jwt-key-with-at-least-32-bytes!";
        let claims = serde_json::json!({
            "sub": Uuid::new_v4(), "role": "authenticated", "exp": 4_102_444_800u64,
            "app_metadata": {"provider": "github"}, "aal": "aal1"
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let verified = verify_supabase_jwt(&token, secret).unwrap();
        let back = serde_json::to_value(&verified).unwrap();
        assert_eq!(back["app_metadata"]["provider"], "github");
        assert_eq!(back["aal"], "aal1");
    }

    #[test]
    fn rejects_wrong_secret() {
        let token = sign("super-secret-jwt-key-with-at-least-32-bytes!", Uuid::new_v4(), "authenticated");
        assert!(verify_supabase_jwt(&token, "another-secret-that-is-at-least-32-bytes").is_err());
    }
}
