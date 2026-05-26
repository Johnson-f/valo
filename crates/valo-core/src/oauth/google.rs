use async_trait::async_trait;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::oauth::{Provider, ProviderIdentity};

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

/// A fully-configured Google OAuth client (auth + token endpoints set).
type GoogleClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

pub struct GoogleProvider {
    client: GoogleClient,
}

impl GoogleProvider {
    /// `redirect_url` must match the callback registered with Google, e.g.
    /// `https://app.example.com/auth/oauth/google/callback`.
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = BasicClient::new(ClientId::new(client_id.to_string()))
            .set_client_secret(ClientSecret::new(client_secret.to_string()))
            .set_auth_uri(AuthUrl::new(AUTH_URL.to_string()).map_err(|e| Error::OAuth(e.to_string()))?)
            .set_token_uri(TokenUrl::new(TOKEN_URL.to_string()).map_err(|e| Error::OAuth(e.to_string()))?)
            .set_redirect_uri(
                RedirectUrl::new(redirect_url.to_string()).map_err(|e| Error::OAuth(e.to_string()))?,
            );
        Ok(Self { client })
    }
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
}

fn parse_google_userinfo(body: &str) -> Result<ProviderIdentity> {
    let info: GoogleUserInfo =
        serde_json::from_str(body).map_err(|e| Error::OAuth(format!("bad userinfo: {e}")))?;
    // Only surface the email if Google asserts it is verified — account linking
    // keys on email, so an unverified address must never link to an account.
    let email = if info.email_verified { info.email } else { None };
    Ok(ProviderIdentity { provider_user_id: info.sub, email })
}

#[async_trait]
impl Provider for GoogleProvider {
    fn id(&self) -> &str {
        "google"
    }

    fn authorize_url(&self, state: &str, pkce_challenge: PkceCodeChallenge) -> Result<String> {
        let owned = state.to_string();
        let (url, _csrf) = self
            .client
            .authorize_url(move || CsrfToken::new(owned.clone()))
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();
        Ok(url.to_string())
    }

    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        http: &reqwest::Client,
    ) -> Result<String> {
        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
            .request_async(http)
            .await
            .map_err(|e| Error::OAuth(e.to_string()))?;
        Ok(token.access_token().secret().clone())
    }

    async fn fetch_identity(
        &self,
        access_token: &str,
        http: &reqwest::Client,
    ) -> Result<ProviderIdentity> {
        let body = http
            .get(USERINFO_URL)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| Error::OAuth(e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::OAuth(e.to_string()))?;
        parse_google_userinfo(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_google_userinfo() {
        let json = r#"{"sub":"108112345","email":"a@gmail.com","email_verified":true}"#;
        let id = parse_google_userinfo(json).unwrap();
        assert_eq!(id.provider_user_id, "108112345");
        assert_eq!(id.email.as_deref(), Some("a@gmail.com"));
    }

    #[test]
    fn drops_unverified_google_email() {
        // Unverified email must NOT be surfaced (would enable email-based
        // account-takeover via linking).
        let json = r#"{"sub":"9","email":"spoof@gmail.com","email_verified":false}"#;
        let id = parse_google_userinfo(json).unwrap();
        assert_eq!(id.provider_user_id, "9");
        assert_eq!(id.email, None);
    }

    #[test]
    fn google_provider_builds_and_has_id() {
        let p = GoogleProvider::new("cid", "secret", "https://app/cb").unwrap();
        assert_eq!(p.id(), "google");
    }
}
