use async_trait::async_trait;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::oauth::{Provider, ProviderIdentity};

const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const EMAILS_URL: &str = "https://api.github.com/user/emails";

type GithubClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

pub struct GithubProvider {
    client: GithubClient,
}

impl GithubProvider {
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
struct GithubUser {
    id: i64,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

fn parse_github_user(body: &str) -> Result<(String, Option<String>)> {
    let u: GithubUser =
        serde_json::from_str(body).map_err(|e| Error::OAuth(format!("bad user: {e}")))?;
    Ok((u.id.to_string(), u.email))
}

fn pick_primary_verified_email(body: &str) -> Result<Option<String>> {
    let emails: Vec<GithubEmail> =
        serde_json::from_str(body).map_err(|e| Error::OAuth(format!("bad emails: {e}")))?;
    Ok(emails
        .into_iter()
        .find(|e| e.primary && e.verified)
        .map(|e| e.email))
}

#[async_trait]
impl Provider for GithubProvider {
    fn id(&self) -> &str {
        "github"
    }

    fn authorize_url(&self, state: &str, pkce_challenge: PkceCodeChallenge) -> Result<String> {
        let owned = state.to_string();
        let (url, _csrf) = self
            .client
            .authorize_url(move || CsrfToken::new(owned.clone()))
            .add_scope(Scope::new("read:user".to_string()))
            .add_scope(Scope::new("user:email".to_string()))
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
        // GitHub requires a User-Agent header on all API requests.
        let user_body = http
            .get(USER_URL)
            .bearer_auth(access_token)
            .header(reqwest::header::USER_AGENT, "valo")
            .send()
            .await
            .map_err(|e| Error::OAuth(e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::OAuth(e.to_string()))?;
        // The /user response gives us the stable id. We deliberately IGNORE its
        // `email` (the public profile email is not guaranteed verified) and
        // always resolve the address through /user/emails, accepting only the
        // primary + verified one — account linking keys on email.
        let (provider_user_id, _unverified) = parse_github_user(&user_body)?;

        let emails_body = http
            .get(EMAILS_URL)
            .bearer_auth(access_token)
            .header(reqwest::header::USER_AGENT, "valo")
            .send()
            .await
            .map_err(|e| Error::OAuth(e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::OAuth(e.to_string()))?;
        let email = pick_primary_verified_email(&emails_body)?;

        Ok(ProviderIdentity { provider_user_id, email })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_github_user() {
        let (id, email) = parse_github_user(r#"{"id":42,"email":"a@b.com"}"#).unwrap();
        assert_eq!(id, "42");
        assert_eq!(email.as_deref(), Some("a@b.com"));
        let (id2, email2) = parse_github_user(r#"{"id":7,"email":null}"#).unwrap();
        assert_eq!(id2, "7");
        assert_eq!(email2, None);
    }

    #[test]
    fn picks_primary_verified_email() {
        let json = r#"[
            {"email":"alt@b.com","primary":false,"verified":true},
            {"email":"main@b.com","primary":true,"verified":true}
        ]"#;
        assert_eq!(pick_primary_verified_email(json).unwrap().as_deref(), Some("main@b.com"));

        let none = r#"[{"email":"x@b.com","primary":true,"verified":false}]"#;
        assert_eq!(pick_primary_verified_email(none).unwrap(), None);
    }

    #[test]
    fn github_provider_builds_and_has_id() {
        let p = GithubProvider::new("cid", "secret", "https://app/cb").unwrap();
        assert_eq!(p.id(), "github");
    }
}
