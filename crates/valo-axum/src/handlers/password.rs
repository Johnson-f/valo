use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use valo_core::{SigninOutcome, Valo};

use crate::config::AxumConfig;
use crate::error::ApiError;
use crate::extract::{AuthUser, ClientIp};
use crate::response::{issue_session, refresh_token_from};

#[derive(Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

pub async fn signup(
    State(valo): State<Valo>,
    ClientIp(ip): ClientIp,
    Json(body): Json<Credentials>,
) -> Result<StatusCode, ApiError> {
    valo.core().signup(&ip, &body.email, &body.password).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

pub async fn verify(
    State(valo): State<Valo>,
    Query(q): Query<VerifyQuery>,
) -> Result<StatusCode, ApiError> {
    valo.core().verify_email(&q.token).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn signin(
    State(valo): State<Valo>,
    State(config): State<AxumConfig>,
    ClientIp(ip): ClientIp,
    Json(body): Json<Credentials>,
) -> Result<Response, ApiError> {
    match valo.signin(&ip, &body.email, &body.password).await? {
        SigninOutcome::Authenticated(session) => Ok(issue_session(&config, session)),
        SigninOutcome::MfaRequired(mfa_token) => Ok(Json(serde_json::json!({
            "mfa_required": true,
            "mfa_token": mfa_token,
        }))
        .into_response()),
    }
}

#[derive(Deserialize, Default)]
pub struct RefreshBody {
    #[serde(default)]
    pub refresh_token: Option<String>,
}

pub async fn refresh(
    State(valo): State<Valo>,
    State(config): State<AxumConfig>,
    jar: CookieJar,
    body: Option<Json<RefreshBody>>,
) -> Result<Response, ApiError> {
    let from_body = body.and_then(|b| b.0.refresh_token);
    let from_cookie = jar.get("valo_refresh").map(|c| c.value().to_string());
    let token = refresh_token_from(from_body, from_cookie).ok_or(ApiError(valo_core::Error::InvalidToken))?;
    let session = valo.core().refresh(&token).await?;
    Ok(issue_session(&config, session))
}

pub async fn signout(
    State(valo): State<Valo>,
    jar: CookieJar,
    body: Option<Json<RefreshBody>>,
) -> Result<StatusCode, ApiError> {
    let from_body = body.and_then(|b| b.0.refresh_token);
    let from_cookie = jar.get("valo_refresh").map(|c| c.value().to_string());
    if let Some(token) = refresh_token_from(from_body, from_cookie) {
        valo.core().signout(&token).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn signout_all(
    State(valo): State<Valo>,
    user: AuthUser,
) -> Result<StatusCode, ApiError> {
    valo.core().signout_all(user.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
