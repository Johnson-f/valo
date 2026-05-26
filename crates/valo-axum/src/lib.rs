//! Axum HTTP adapter for valo-core.

pub mod config;
pub mod error;
pub mod extract;
pub mod handlers;
pub mod response;

use axum::routing::{get, post};
use axum::Router;
use valo_core::Valo;

pub use config::{AxumConfig, TokenDelivery, ValoState};
pub use error::ApiError;
pub use extract::{AuthUser, ClientIp};

/// Builds an axum `Router` exposing valo's auth endpoints.
///
/// Serve the result with `into_make_service_with_connect_info::<SocketAddr>()`
/// so the rate limiter sees client IPs.
pub struct ValoRouter {
    valo: Valo,
    config: AxumConfig,
}

impl ValoRouter {
    pub fn new(valo: Valo) -> Self {
        Self { valo, config: AxumConfig::default() }
    }

    /// Return tokens as JSON bearer tokens (default) or as HttpOnly cookies.
    pub fn token_delivery(mut self, mode: TokenDelivery) -> Self {
        self.config.token_delivery = mode;
        self
    }

    /// Trust this header for the client IP (only behind a known proxy).
    pub fn trusted_proxy_header(mut self, header: &str) -> Self {
        self.config.trusted_proxy_header = Some(header.to_string());
        self
    }

    /// Set whether cookies carry `Secure` (default true; false only for local HTTP).
    pub fn cookie_secure(mut self, secure: bool) -> Self {
        self.config.cookie_secure = secure;
        self
    }

    /// Build the router with state applied. Mount it under any prefix via `Router::nest`.
    pub fn into_router(self) -> Router {
        let state = ValoState { valo: self.valo, config: self.config };
        Router::new()
            .route("/signup", post(handlers::password::signup))
            .route("/verify", get(handlers::password::verify))
            .route("/signin", post(handlers::password::signin))
            .route("/refresh", post(handlers::password::refresh))
            .route("/signout", post(handlers::password::signout))
            .route("/signout-all", post(handlers::password::signout_all))
            .route("/oauth/{provider}", get(handlers::oauth::begin))
            .route("/oauth/{provider}/callback", get(handlers::oauth::callback))
            .route("/mfa/enroll", post(handlers::mfa::enroll))
            .route("/mfa/confirm", post(handlers::mfa::confirm))
            .route("/mfa/complete", post(handlers::mfa::complete))
            .route("/mfa/disable", post(handlers::mfa::disable))
            .with_state(state)
    }
}
