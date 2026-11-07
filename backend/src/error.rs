use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

/// Unified error type for every handler. Database and upstream errors are mapped
/// to sensible HTTP statuses without leaking internal details to clients.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    ServiceUnavailable(String),
    /// Response forwarded verbatim from an upstream Supabase service.
    #[error("upstream returned {status}")]
    Upstream { status: StatusCode, body: Value },
    #[error("{0}")]
    Internal(String),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::Upstream { status, body } => return (status, Json(body)).into_response(),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, "conflict", m),
            ApiError::ServiceUnavailable(m) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", m)
            }
            ApiError::Internal(m) => {
                tracing::error!(error = %m, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal server error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => ApiError::not_found("Resource not found"),
            sqlx::Error::PoolTimedOut => {
                ApiError::ServiceUnavailable("Database pool exhausted, retry shortly".into())
            }
            sqlx::Error::Database(db) => match db.code().as_deref() {
                Some("23505") => ApiError::Conflict("Resource already exists".into()),
                Some("23503") => ApiError::bad_request("Referenced resource does not exist"),
                Some("23514" | "22P02" | "22023") => ApiError::bad_request(db.message().to_string()),
                // insufficient_privilege / RLS violation
                Some("42501") => ApiError::forbidden("Not allowed by row-level security"),
                Some("P0001") => ApiError::bad_request(db.message().to_string()),
                _ => ApiError::internal(err.to_string()),
            },
            _ => ApiError::internal(err.to_string()),
        }
    }
}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        tracing::warn!(error = %err, "upstream request failed");
        ApiError::ServiceUnavailable("Upstream service unavailable".into())
    }
}
