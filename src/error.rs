//! One error type for every handler.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Why a request could not be served.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// No usable credential was presented.
    #[error("unauthorized")]
    Unauthorized,
    /// The credential was valid but lacks the scope for this route.
    #[error("forbidden")]
    Forbidden,
    /// The named resource does not exist for this account.
    #[error("not found")]
    NotFound,
    /// The request body or parameters were unusable.
    #[error("{0}")]
    BadRequest(String),
    /// The resource already exists.
    #[error("{0}")]
    Conflict(String),
    /// The caller has spent its request budget. Carries the seconds to wait.
    #[error("too many requests")]
    TooManyRequests(u64),
    /// Anything the caller cannot fix.
    #[error("internal error")]
    Internal,
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        // Database detail never reaches the caller: it leaks schema and, in
        // constraint messages, customer identifiers.
        tracing::error!(%error, "database error");
        Self::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(json!({ "error": self.to_string() }));
        let mut response = (status, body).into_response();
        if matches!(self, Self::Unauthorized) {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                "Bearer".parse().unwrap(),
            );
        }
        // Without this a refused client has nothing to base a backoff on, and
        // the usual answer to a bare 429 is to retry immediately.
        if let Self::TooManyRequests(seconds) = self
            && let Ok(value) = axum::http::HeaderValue::from_str(&seconds.to_string())
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        response
    }
}

/// Handler result alias.
pub type ApiResult<T> = Result<T, ApiError>;
