//! Social-login providers. The `Provider` trait hides all oauth2 interaction so
//! the core can orchestrate the flow generically and tests can stub providers.

use async_trait::async_trait;
use oauth2::PkceCodeChallenge;

use crate::error::Result;

// enabled in Tasks 8/9
pub mod github;
pub mod google;

/// The identity a provider reports for the authenticated user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentity {
    /// Stable per-provider user id (e.g. Google `sub`, GitHub numeric id).
    pub provider_user_id: String,
    /// Verified email, if the provider returns one.
    pub email: Option<String>,
}

/// One social-login provider. Encapsulates the OAuth2 client + identity fetch.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Stable provider key, e.g. `"google"`.
    fn id(&self) -> &str;

    /// Build the authorization-redirect URL for the given CSRF `state` and PKCE
    /// challenge. The core has already persisted the matching PKCE verifier.
    fn authorize_url(&self, state: &str, pkce_challenge: PkceCodeChallenge) -> Result<String>;

    /// Exchange an authorization `code` (+ PKCE `verifier`) for an access token.
    /// `http` is a shared redirect-disabled client (SSRF-safe).
    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        http: &reqwest::Client,
    ) -> Result<String>;

    /// Fetch the user's identity using the access token.
    async fn fetch_identity(
        &self,
        access_token: &str,
        http: &reqwest::Client,
    ) -> Result<ProviderIdentity>;
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct TestProvider {
    pub id: String,
    pub identity: ProviderIdentity,
}

#[cfg(test)]
#[async_trait]
impl Provider for TestProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn authorize_url(&self, state: &str, _c: PkceCodeChallenge) -> Result<String> {
        Ok(format!("https://provider.test/authorize?state={state}"))
    }
    async fn exchange_code(&self, _c: &str, _v: &str, _h: &reqwest::Client) -> Result<String> {
        Ok("test-access-token".to_string())
    }
    async fn fetch_identity(&self, _t: &str, _h: &reqwest::Client) -> Result<ProviderIdentity> {
        Ok(self.identity.clone())
    }
}
