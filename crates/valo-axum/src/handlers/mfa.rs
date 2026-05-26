use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use valo_core::Valo;

use crate::config::AxumConfig;
use crate::error::ApiError;
use crate::extract::AuthUser;
use crate::response::issue_session;

/// POST /mfa/enroll — begin enrollment for the authenticated user.
pub async fn enroll(State(valo): State<Valo>, user: AuthUser) -> Result<Response, ApiError> {
    let e = valo.mfa_begin_enrollment(user.user_id).await?;
    Ok(Json(json!({ "otpauth_url": e.otpauth_url, "secret_base32": e.secret_base32 })).into_response())
}

#[derive(Deserialize)]
pub struct CodeBody {
    pub code: String,
}

/// POST /mfa/confirm — confirm enrollment; returns the one-time recovery codes.
pub async fn confirm(
    State(valo): State<Valo>,
    user: AuthUser,
    Json(body): Json<CodeBody>,
) -> Result<Response, ApiError> {
    let codes = valo.mfa_confirm_enrollment(user.user_id, &body.code).await?;
    Ok(Json(json!({ "recovery_codes": codes })).into_response())
}

#[derive(Deserialize)]
pub struct CompleteBody {
    pub mfa_token: String,
    pub code: String,
}

/// POST /mfa/complete — finish an MFA signin with a TOTP or recovery code.
pub async fn complete(
    State(valo): State<Valo>,
    State(config): State<AxumConfig>,
    Json(body): Json<CompleteBody>,
) -> Result<Response, ApiError> {
    let session = valo.complete_mfa(&body.mfa_token, &body.code).await?;
    Ok(issue_session(&config, session))
}

/// POST /mfa/disable — disable MFA for the authenticated user (requires a code).
pub async fn disable(
    State(valo): State<Valo>,
    user: AuthUser,
    Json(body): Json<CodeBody>,
) -> Result<StatusCode, ApiError> {
    valo.mfa_disable(user.user_id, &body.code).await?;
    Ok(StatusCode::NO_CONTENT)
}
