use axum::extract::FromRef;
use valo_core::Valo;

/// How session tokens are returned to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenDelivery {
    /// Return `{ access_token, refresh_token, access_expires_in }` as JSON.
    Bearer,
    /// Set the access + refresh tokens as HttpOnly Secure SameSite=Strict cookies.
    Cookie,
}

/// Adapter configuration.
#[derive(Debug, Clone)]
pub struct AxumConfig {
    pub token_delivery: TokenDelivery,
    /// If set (e.g. "x-forwarded-for"), the client IP is read from this header
    /// instead of the socket peer address. Only enable behind a trusted proxy.
    pub trusted_proxy_header: Option<String>,
    /// Whether cookies carry the `Secure` attribute (set false only for local HTTP dev).
    pub cookie_secure: bool,
}

impl Default for AxumConfig {
    fn default() -> Self {
        Self {
            token_delivery: TokenDelivery::Bearer,
            trusted_proxy_header: None,
            cookie_secure: true,
        }
    }
}

/// Router state: a cloneable `Valo` handle plus the adapter config.
#[derive(Clone)]
pub struct ValoState {
    pub valo: Valo,
    pub config: AxumConfig,
}

impl FromRef<ValoState> for Valo {
    fn from_ref(state: &ValoState) -> Valo {
        state.valo.clone()
    }
}

impl FromRef<ValoState> for AxumConfig {
    fn from_ref(state: &ValoState) -> AxumConfig {
        state.config.clone()
    }
}
