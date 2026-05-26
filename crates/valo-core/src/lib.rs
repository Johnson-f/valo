//! valo-core: framework-agnostic auth logic.

pub mod config;
pub mod core;
pub mod crypto;
pub mod db;
pub mod error;
pub mod jwt;
pub mod mail;
pub mod oauth;
pub mod redis_store;

use std::sync::Arc;

use redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;

pub use config::ValoBuilder;
pub use core::{Core, MfaEnrollment, Session, SigninOutcome};
pub use error::{Error, Result};
pub use jwt::Claims;

/// Public, cloneable handle. Clone is cheap (Arc + pools).
#[derive(Clone)]
pub struct Valo {
    inner: Arc<Core>,
}

impl Valo {
    pub fn builder() -> ValoBuilder {
        ValoBuilder::default()
    }

    /// Connect pools, run embedded migrations (advisory-locked), and assemble Core.
    pub async fn build_from(builder: ValoBuilder) -> Result<Self> {
        let pg_url = builder.postgres_url.expect("postgres(url) is required");
        let redis_url = builder.redis_url.expect("redis(url) is required");
        let jwt_key = builder
            .jwt_key
            .expect("a jwt key is required (jwt_secret or jwt_eddsa)");
        let mailer = builder.mailer.expect("mailer is required");

        let pg = PgPoolOptions::new().connect(&pg_url).await?;
        sqlx::migrate!("./migrations")
            .run(&pg)
            .await
            .map_err(|e| Error::Db(sqlx::Error::from(e)))?;

        let client = redis::Client::open(redis_url)?;
        let redis = ConnectionManager::new(client).await?;

        let ttl = builder.config.access_ttl_secs;
        let jwt = match jwt_key {
            config::JwtKey::Hs256(secret) => jwt::Jwt::new_hs256(&secret, ttl)?,
            config::JwtKey::Ed25519 { private_pem, public_pem } => {
                jwt::Jwt::new_eddsa(&private_pem, &public_pem, ttl)?
            }
        };

        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::OAuth(e.to_string()))?;
        let providers = builder
            .providers
            .into_iter()
            .map(|p| (p.id().to_string(), p))
            .collect();

        let core = Core {
            pg,
            redis,
            jwt,
            mailer,
            config: builder.config,
            http,
            providers,
        };
        Ok(Self {
            inner: Arc::new(core),
        })
    }

    /// Access the framework-free Core (the escape hatch).
    pub fn core(&self) -> &Core {
        &self.inner
    }

    /// In-process access-token verification. Zero I/O.
    pub fn verify_access_token(&self, token: &str) -> Result<Claims> {
        self.inner.jwt.verify(token)
    }

    /// Strict-mode access-token verification: stateless check PLUS a
    /// `token_version` lookup (one Redis hit, Postgres on miss) for instant
    /// revocation. Use this instead of `verify_access_token` when bans/global
    /// logout must take effect before the token's natural expiry.
    pub async fn verify_access_token_strict(&self, token: &str) -> Result<Claims> {
        self.inner.verify_access_token_strict(token).await
    }

    /// Begin an OAuth login; returns the provider authorization URL to redirect to.
    pub async fn begin_oauth(&self, provider_id: &str) -> Result<String> {
        self.inner.begin_oauth(provider_id).await
    }

    /// Complete an OAuth login from the callback's `code` + `state`; returns a Session.
    pub async fn complete_oauth(
        &self,
        provider_id: &str,
        code: &str,
        state: &str,
    ) -> Result<Session> {
        self.inner.complete_oauth(provider_id, code, state).await
    }

    /// Password signin. Returns `Authenticated(Session)` or, for MFA users,
    /// `MfaRequired(challenge_token)` to be completed via `complete_mfa`.
    pub async fn signin(&self, client_key: &str, email: &str, password: &str) -> Result<SigninOutcome> {
        self.inner.signin(client_key, email, password).await
    }

    pub async fn mfa_begin_enrollment(&self, user_id: uuid::Uuid) -> Result<MfaEnrollment> {
        self.inner.mfa_begin_enrollment(user_id).await
    }

    pub async fn mfa_confirm_enrollment(&self, user_id: uuid::Uuid, code: &str) -> Result<Vec<String>> {
        self.inner.mfa_confirm_enrollment(user_id, code).await
    }

    pub async fn complete_mfa(&self, challenge_token: &str, code: &str) -> Result<Session> {
        self.inner.complete_mfa(challenge_token, code).await
    }

    pub async fn mfa_disable(&self, user_id: uuid::Uuid, code: &str) -> Result<()> {
        self.inner.mfa_disable(user_id, code).await
    }
}

impl ValoBuilder {
    pub async fn build(self) -> Result<Valo> {
        Valo::build_from(self).await
    }
}

#[cfg(test)]
mod e2e {
    use super::*;
    use crate::mail::TestMailer;

    #[sqlx::test(migrations = "./migrations")]
    async fn full_signup_verify_signin_refresh_signout(pool: sqlx::PgPool) {
        // Build a Core directly against the test pool (build() needs live URLs).
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = redis::Client::open(url).unwrap();
        let redis = ConnectionManager::new(client).await.unwrap();
        let mailer = Arc::new(TestMailer::new());
        let config = config::CoreConfig {
            ip_attempt_limit: u32::MAX,
            email_attempt_limit: u32::MAX,
            ..config::CoreConfig::default()
        };
        let core = Core {
            pg: pool,
            redis,
            jwt: jwt::Jwt::new_hs256(b"0123456789abcdef0123456789abcdef", 900).unwrap(),
            mailer: mailer.clone(),
            config,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            providers: std::collections::HashMap::new(),
        };
        let valo = Valo {
            inner: Arc::new(core),
        };

        valo.core()
            .signup("test", "e2e@b.com", "hunter2hunter2")
            .await
            .unwrap();
        let raw = mailer
            .last_url()
            .split("token=")
            .nth(1)
            .unwrap()
            .to_string();
        valo.core().verify_email(&raw).await.unwrap();

        let s = match valo
            .core()
            .signin("test", "e2e@b.com", "hunter2hunter2")
            .await
            .unwrap()
        {
            crate::core::SigninOutcome::Authenticated(s) => s,
            crate::core::SigninOutcome::MfaRequired(_) => panic!("unexpected MFA challenge"),
        };
        let claims = valo.verify_access_token(&s.access_token).unwrap();
        assert_eq!(claims.email, "e2e@b.com");

        // strict verify via the public handle also accepts the fresh token
        valo.verify_access_token_strict(&s.access_token).await.unwrap();

        let s2 = valo.core().refresh(&s.refresh_token).await.unwrap();
        valo.core().signout(&s2.refresh_token).await.unwrap();
        assert!(valo.core().refresh(&s2.refresh_token).await.is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn oauth_via_valo_handle(pool: sqlx::PgPool) {
        use crate::oauth::{ProviderIdentity, TestProvider};
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = redis::Client::open(url).unwrap();
        let redis = ConnectionManager::new(client).await.unwrap();
        let mailer = Arc::new(crate::mail::TestMailer::new());
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut providers = std::collections::HashMap::new();
        providers.insert(
            "test".to_string(),
            Arc::new(TestProvider {
                id: "test".to_string(),
                identity: ProviderIdentity {
                    provider_user_id: "v-1".to_string(),
                    email: Some("vh@b.com".to_string()),
                },
            }) as Arc<dyn crate::oauth::Provider>,
        );
        let core = Core {
            pg: pool,
            redis,
            jwt: jwt::Jwt::new_hs256(b"0123456789abcdef0123456789abcdef", 900).unwrap(),
            mailer,
            config: config::CoreConfig::default(),
            http,
            providers,
        };
        let valo = Valo { inner: Arc::new(core) };

        let auth_url = valo.begin_oauth("test").await.unwrap();
        let state = auth_url.split("state=").nth(1).unwrap().to_string();
        let session = valo.complete_oauth("test", "code", &state).await.unwrap();
        assert!(valo.verify_access_token(&session.access_token).is_ok());
    }
}
