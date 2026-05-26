use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use valo_core::Error as CoreError;

/// Wraps a valo-core error and renders it as an HTTP response. Internal errors
/// (DB/Redis/crypto/mail) collapse to a generic 500 so no internal detail leaks.
pub struct ApiError(pub CoreError);

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message): (StatusCode, &str) = match self.0 {
            CoreError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid email or password"),
            CoreError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid or expired token"),
            CoreError::InvalidMfaCode => (StatusCode::UNAUTHORIZED, "invalid MFA code"),
            CoreError::EmailNotVerified => (StatusCode::FORBIDDEN, "email is not verified"),
            CoreError::AccountInactive => (StatusCode::FORBIDDEN, "account is not active"),
            CoreError::EmailTaken => (StatusCode::CONFLICT, "email is already registered"),
            CoreError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "too many attempts"),
            CoreError::OAuthState => (StatusCode::BAD_REQUEST, "invalid or expired oauth state"),
            CoreError::ProviderNotFound => (StatusCode::NOT_FOUND, "unknown oauth provider"),
            CoreError::MfaNotConfigured => (StatusCode::NOT_IMPLEMENTED, "MFA is not configured"),
            // Internal: never leak detail.
            CoreError::WeakSecret
            | CoreError::Hashing
            | CoreError::Encryption
            | CoreError::Db(_)
            | CoreError::Redis(_)
            | CoreError::Jwt(_)
            | CoreError::Mail(_)
            | CoreError::OAuth(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_invalid_credentials_to_401() {
        let resp = ApiError(CoreError::InvalidCredentials).into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn maps_rate_limited_to_429() {
        let resp = ApiError(CoreError::RateLimited).into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn internal_errors_collapse_to_500() {
        let resp = ApiError(CoreError::Hashing).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
