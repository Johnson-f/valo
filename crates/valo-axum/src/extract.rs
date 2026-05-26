use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;
use valo_core::Valo;

use crate::config::AxumConfig;

/// The client IP used for rate limiting: the trusted forwarded header if
/// configured, otherwise the socket peer address from `ConnectInfo`.
pub struct ClientIp(pub String);

impl<S> FromRequestParts<S> for ClientIp
where
    AxumConfig: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let config = AxumConfig::from_ref(state);
        if let Some(header) = &config.trusted_proxy_header {
            if let Some(value) = parts.headers.get(header).and_then(|v| v.to_str().ok()) {
                // X-Forwarded-For may be a comma list; the first entry is the client.
                let ip = value.split(',').next().unwrap_or(value).trim().to_string();
                if !ip.is_empty() {
                    return Ok(ClientIp(ip));
                }
            }
        }
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Ok(ClientIp(ip))
    }
}

/// An authenticated user, derived from a verified access token (Authorization
/// bearer header, or the `valo_access` cookie). In-process verification, no I/O.
pub struct AuthUser {
    pub user_id: Uuid,
    pub email: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    Valo: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let valo = Valo::from_ref(state);

        let token = bearer_from_header(parts)
            .or_else(|| cookie_token(parts, "valo_access"))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let claims = valo.verify_access_token(&token).map_err(|_| StatusCode::UNAUTHORIZED)?;
        Ok(AuthUser { user_id: claims.sub, email: claims.email })
    }
}

fn bearer_from_header(parts: &Parts) -> Option<String> {
    let value = parts.headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(|t| t.to_string())
}

fn cookie_token(parts: &Parts, name: &str) -> Option<String> {
    let jar = CookieJar::from_headers(&parts.headers);
    jar.get(name).map(|c| c.value().to_string())
}
