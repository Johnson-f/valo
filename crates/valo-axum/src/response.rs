use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde_json::json;
use valo_core::Session;

use crate::config::{AxumConfig, TokenDelivery};

/// Build the HTTP response carrying a freshly-issued session, honoring the
/// configured token-delivery mode.
pub fn issue_session(config: &AxumConfig, session: Session) -> Response {
    match config.token_delivery {
        TokenDelivery::Bearer => Json(json!({
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "access_expires_in": session.access_expires_in,
        }))
        .into_response(),
        TokenDelivery::Cookie => {
            let access = build_cookie("valo_access", session.access_token, config.cookie_secure);
            let refresh = build_cookie("valo_refresh", session.refresh_token, config.cookie_secure);
            let jar = CookieJar::new().add(access).add(refresh);
            (jar, Json(json!({ "status": "ok" }))).into_response()
        }
    }
}

fn build_cookie(name: &str, value: String, secure: bool) -> Cookie<'static> {
    Cookie::build((name.to_string(), value))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .path("/")
        .build()
}

/// Resolve the refresh token from the request: an explicit body value takes
/// precedence, otherwise the `valo_refresh` cookie (cookie-mode clients).
pub fn refresh_token_from(body: Option<String>, cookie: Option<String>) -> Option<String> {
    body.filter(|s| !s.is_empty()).or(cookie)
}
