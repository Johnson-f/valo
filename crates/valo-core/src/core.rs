use std::collections::HashMap;
use std::sync::Arc;

use redis::aio::ConnectionManager;
use sqlx::PgPool;

use oauth2::PkceCodeChallenge;

use crate::oauth::Provider;

use crate::config::CoreConfig;
use crate::crypto::{password, token};
use crate::db::{sessions, users};
use uuid::Uuid;
use crate::error::{Error, Result};
use crate::jwt::{Claims, Jwt};
use crate::mail::{EmailKind, Mailer, OutgoingEmail};

/// Returned to the caller after signin/refresh. The raw refresh token is given
/// to the client exactly once; only its hash is ever stored.
#[derive(Debug, Clone)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in: i64,
}

/// Result of a password signin: either a session, or — for MFA-enabled users —
/// a short-lived challenge token to be completed via `complete_mfa`.
#[derive(Debug, Clone)]
pub enum SigninOutcome {
    Authenticated(Session),
    MfaRequired(String),
}

/// Returned when MFA enrollment begins: show the QR (otpauth_url) or let the
/// user type `secret_base32` into their authenticator app.
#[derive(Debug, Clone)]
pub struct MfaEnrollment {
    pub otpauth_url: String,
    pub secret_base32: String,
}

/// Framework-free orchestrator. Cloneable (pools + Arc are cheap to clone).
#[derive(Clone)]
pub struct Core {
    pub(crate) pg: PgPool,
    pub(crate) redis: ConnectionManager,
    pub(crate) jwt: Jwt,
    pub(crate) mailer: Arc<dyn Mailer>,
    pub(crate) config: CoreConfig,
    pub(crate) http: reqwest::Client,
    pub(crate) providers: HashMap<String, Arc<dyn Provider>>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn generate_recovery_code() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect() // 16 hex chars
}

impl Core {
    fn mfa_key(&self) -> Result<&[u8; 32]> {
        self.config.mfa_encryption_key.as_ref().ok_or(Error::MfaNotConfigured)
    }

    /// Rate-limit an auth attempt by caller key (IP) and email BEFORE any
    /// expensive Argon2 work runs. Counts every attempt (success or failure),
    /// which is what bounds the Argon2 CPU-amplification surface and throttles
    /// brute force. `client_key` is supplied by the caller (e.g. the client IP);
    /// the framework-agnostic core has no request context of its own.
    async fn check_rate(&self, client_key: &str, email: &str) -> Result<()> {
        let window = self.config.rate_limit_window_secs;
        let mut redis = self.redis.clone();

        let ip_hits =
            crate::redis_store::incr_rate(&mut redis, &format!("rl:ip:{client_key}"), window)
                .await?;
        if ip_hits > self.config.ip_attempt_limit as u64 {
            return Err(Error::RateLimited);
        }

        let email_hits = crate::redis_store::incr_rate(
            &mut redis,
            &format!("rl:email:{}", email.to_lowercase()),
            window,
        )
        .await?;
        if email_hits > self.config.email_attempt_limit as u64 {
            return Err(Error::RateLimited);
        }
        Ok(())
    }

    /// Create an unverified user and email them a verification link.
    /// Verification is required before signin.
    ///
    /// `client_key` (e.g. the client IP) is rate-limited alongside the email.
    ///
    /// Failure modes (v1): if the user row is created but the Redis store or
    /// email send then fails, the user exists unverified and a retry returns
    /// `Error::EmailTaken`. A self-service "resend verification" flow is a
    /// documented follow-on; until then such a user has no recovery path.
    pub async fn signup(&self, client_key: &str, email: &str, password: &str) -> Result<()> {
        self.check_rate(client_key, email).await?;
        let hash = password::hash_password(password)?;
        let user = users::create_user(&self.pg, email, &hash).await?;

        // Generate verify token, store only its hash in Redis with TTL.
        let raw = token::generate_token();
        let token_hash_hex = hex(&token::hash_token(&raw));
        let mut redis = self.redis.clone();
        crate::redis_store::store_verify_token(
            &mut redis,
            &token_hash_hex,
            user.id,
            self.config.verify_ttl_secs,
        )
        .await?;

        let url = format!("{}/auth/verify?token={}", self.config.base_url, raw);
        self.mailer
            .send(OutgoingEmail { to: email.to_string(), kind: EmailKind::Verification, url })
            .await
            .map_err(Error::Mail)?;
        Ok(())
    }

    /// Consume a verification token (one-time) and mark the user verified.
    pub async fn verify_email(&self, raw_token: &str) -> Result<()> {
        let token_hash_hex = hex(&token::hash_token(raw_token));
        let mut redis = self.redis.clone();
        let user_id = crate::redis_store::consume_verify_token(&mut redis, &token_hash_hex)
            .await?
            .ok_or(Error::InvalidToken)?;
        users::mark_verified(&self.pg, user_id).await?;
        Ok(())
    }

    /// Mint an access JWT + create a fresh refresh session row. Returns the DTO.
    async fn issue_session(&self, user: &users::User) -> Result<Session> {
        let access_token = self.jwt.mint_access(user.id, &user.email, user.token_version, Uuid::new_v4())?;

        let raw_refresh = token::generate_token();
        let refresh_hash = token::hash_token(&raw_refresh);
        let expires_at = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(self.config.refresh_ttl_secs);
        sessions::create_session(&self.pg, user.id, &refresh_hash, expires_at).await?;

        Ok(Session {
            access_token,
            refresh_token: raw_refresh,
            access_expires_in: self.config.access_ttl_secs,
        })
    }

    /// Strict-mode verification: the stateless signature/expiry check PLUS a
    /// `token_version` comparison against the user's current version (cached in
    /// Redis, Postgres on miss). Rejects tokens minted before a `signout_all`,
    /// giving instant revocation at the cost of one cache lookup per call.
    pub async fn verify_access_token_strict(&self, token: &str) -> Result<Claims> {
        let claims = self.jwt.verify(token)?;
        let current = self.current_token_version(claims.sub).await?;
        if claims.token_version != current {
            return Err(Error::InvalidToken);
        }
        Ok(claims)
    }

    /// Current `token_version` for a user, served from the Redis cache and
    /// backfilled from Postgres on a miss.
    async fn current_token_version(&self, user_id: Uuid) -> Result<i32> {
        let mut redis = self.redis.clone();
        if let Some(v) = crate::redis_store::get_token_version(&mut redis, user_id).await? {
            return Ok(v);
        }
        let user = users::find_by_id(&self.pg, user_id)
            .await?
            .ok_or(Error::InvalidToken)?;
        // Known race (v1, acceptable): if a `signout_all` bump + cache-clear
        // interleaves between the read above and this backfill, we may cache a
        // stale (pre-bump) version. It self-heals at the cache TTL. A write-
        // through bump or versioned CAS would close it; deferred as a follow-on.
        crate::redis_store::set_token_version(
            &mut redis,
            user_id,
            user.token_version,
            self.config.token_version_cache_ttl_secs,
        )
        .await?;
        Ok(user.token_version)
    }

    /// Verify credentials and issue a session. Constant-time against unknown
    /// users (always runs an Argon2 verify) and requires a verified email.
    /// `client_key` (e.g. the client IP) is rate-limited alongside the email.
    /// MFA-enabled users receive `MfaRequired(challenge)` instead of a session.
    pub async fn signin(&self, client_key: &str, email: &str, password: &str) -> Result<SigninOutcome> {
        self.check_rate(client_key, email).await?;
        let user = users::find_by_email(&self.pg, email).await?;

        // Always run a hash verification so timing does not reveal user existence.
        let stored = user.as_ref().and_then(|u| u.password_hash.as_deref())
            .unwrap_or_else(|| password::dummy_hash());
        let password_ok = password::verify_password(password, stored);

        let user = match user {
            Some(u) if password_ok => u,
            _ => return Err(Error::InvalidCredentials), // same error for unknown user / bad pw
        };

        if user.status != "active" {
            return Err(Error::AccountInactive);
        }
        if user.email_verified_at.is_none() {
            return Err(Error::EmailNotVerified);
        }

        // MFA gate: a correct password yields only a challenge until a code is supplied.
        if user.mfa_enabled_at.is_some() {
            let challenge = token::generate_token();
            let mut redis = self.redis.clone();
            crate::redis_store::store_mfa_challenge(&mut redis, &challenge, user.id, 300).await?;
            return Ok(SigninOutcome::MfaRequired(challenge));
        }

        Ok(SigninOutcome::Authenticated(self.issue_session(&user).await?))
    }

    /// Exchange a valid refresh token for a new pair, rotating the stored hash.
    /// A revoked/expired/unknown token triggers reuse-detection: every session
    /// for that user is revoked and the request is rejected.
    pub async fn refresh(&self, raw_refresh: &str) -> Result<Session> {
        let refresh_hash = token::hash_token(raw_refresh);

        // Atomically revoke-and-claim the live session. Postgres serializes
        // concurrent UPDATEs on the row, so exactly one caller can win — this
        // closes the rotation race. A `None` means the token was unknown,
        // already spent, or expired.
        let Some(row) = sessions::claim_session(&self.pg, &refresh_hash).await? else {
            // If the token exists but wasn't claimable, it was already spent or
            // expired: a theft signal -> scorched-earth revoke for the user.
            if let Some(stale) = sessions::find_by_refresh_hash(&self.pg, &refresh_hash).await? {
                sessions::revoke_all_for_user(&self.pg, stale.user_id).await?;
            }
            return Err(Error::InvalidToken);
        };

        let user = users::find_by_id(&self.pg, row.user_id)
            .await?
            .ok_or(Error::InvalidToken)?;
        if user.status != "active" {
            return Err(Error::AccountInactive);
        }

        // The claimed row is now a revoked tombstone; issue the next session.
        let new_raw = token::generate_token();
        let new_hash = token::hash_token(&new_raw);
        let new_expires = time::OffsetDateTime::now_utc()
            + time::Duration::seconds(self.config.refresh_ttl_secs);
        sessions::create_session(&self.pg, user.id, &new_hash, new_expires).await?;

        let access_token =
            self.jwt
                .mint_access(user.id, &user.email, user.token_version, Uuid::new_v4())?;
        Ok(Session {
            access_token,
            refresh_token: new_raw,
            access_expires_in: self.config.access_ttl_secs,
        })
    }

    /// Revoke the single session identified by a refresh token. Idempotent.
    pub async fn signout(&self, raw_refresh: &str) -> Result<()> {
        let refresh_hash = token::hash_token(raw_refresh);
        if let Some(row) = sessions::find_by_refresh_hash(&self.pg, &refresh_hash).await? {
            sessions::revoke_session(&self.pg, row.id).await?;
        }
        Ok(())
    }

    /// Begin an OAuth login: generate CSRF state + PKCE, stash the verifier in
    /// Redis under the state (one-time, TTL'd), and return the provider's
    /// authorization-redirect URL.
    pub async fn begin_oauth(&self, provider_id: &str) -> Result<String> {
        let provider = self.providers.get(provider_id).ok_or(Error::ProviderNotFound)?;

        let state = token::generate_token();
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();

        let mut redis = self.redis.clone();
        crate::redis_store::store_oauth_state(
            &mut redis,
            provider_id,
            &state,
            verifier.secret(),
            self.config.verify_ttl_secs.min(600),
        )
        .await?;

        provider.authorize_url(&state, challenge)
    }

    /// Complete an OAuth login: validate the state (consuming the stored PKCE
    /// verifier), exchange the code, fetch the identity, upsert the user, and
    /// issue a session. An unknown/expired/replayed state is rejected.
    pub async fn complete_oauth(
        &self,
        provider_id: &str,
        code: &str,
        state: &str,
    ) -> Result<Session> {
        let provider = self.providers.get(provider_id).ok_or(Error::ProviderNotFound)?;

        let mut redis = self.redis.clone();
        let verifier = crate::redis_store::consume_oauth_state(&mut redis, provider_id, state)
            .await?
            .ok_or(Error::OAuthState)?;

        let access_token = provider.exchange_code(code, &verifier, &self.http).await?;
        let identity = provider.fetch_identity(&access_token, &self.http).await?;

        let user_id = match crate::db::identities::find_user_id_by_identity(
            &self.pg,
            provider_id,
            &identity.provider_user_id,
        )
        .await?
        {
            Some(uid) => uid,
            None => {
                let email = identity
                    .email
                    .ok_or_else(|| Error::OAuth("provider did not return an email".to_string()))?;
                // NOTE: linking to an existing email assumes the provider returns
                // a verified address (Google/GitHub primary verified emails do).
                let user = match users::find_by_email(&self.pg, &email).await? {
                    Some(u) => u,
                    None => users::create_oauth_user(&self.pg, &email).await?,
                };
                crate::db::identities::link_identity(
                    &self.pg,
                    user.id,
                    provider_id,
                    &identity.provider_user_id,
                )
                .await?;
                user.id
            }
        };

        let user = users::find_by_id(&self.pg, user_id).await?.ok_or(Error::InvalidToken)?;
        if user.status != "active" {
            return Err(Error::AccountInactive);
        }
        self.issue_session(&user).await
    }

    /// Revoke every session for a user and bump token_version (logout everywhere).
    pub async fn signout_all(&self, user_id: Uuid) -> Result<()> {
        sessions::revoke_all_for_user(&self.pg, user_id).await?;
        users::bump_token_version(&self.pg, user_id).await?;
        // Invalidate the strict-mode cache so the next strict verify re-reads the
        // bumped version from Postgres and rejects pre-bump access tokens.
        let mut redis = self.redis.clone();
        crate::redis_store::clear_token_version(&mut redis, user_id).await?;
        Ok(())
    }

    /// Begin MFA enrollment: generate + store an (encrypted) pending TOTP secret
    /// and return the authenticator provisioning data. Not enabled until confirmed.
    pub async fn mfa_begin_enrollment(&self, user_id: Uuid) -> Result<MfaEnrollment> {
        let key = *self.mfa_key()?;
        let user = users::find_by_id(&self.pg, user_id).await?.ok_or(Error::InvalidToken)?;

        let secret = crate::crypto::totp::generate_secret();
        let encrypted = crate::crypto::aead::encrypt(&key, &secret)?;
        crate::db::mfa::set_secret(&self.pg, user_id, &encrypted).await?;

        Ok(MfaEnrollment {
            otpauth_url: crate::crypto::totp::provisioning_uri(&secret, &self.config.mfa_issuer, &user.email)?,
            secret_base32: crate::crypto::totp::secret_base32(&secret),
        })
    }

    /// Complete an MFA signin: consume the challenge token, then accept either a
    /// valid TOTP code or a single-use recovery code, and issue a session.
    pub async fn complete_mfa(&self, challenge_token: &str, code: &str) -> Result<Session> {
        let key = *self.mfa_key()?;
        let mut redis = self.redis.clone();
        let user_id = crate::redis_store::consume_mfa_challenge(&mut redis, challenge_token)
            .await?
            .ok_or(Error::InvalidToken)?;

        let user = users::find_by_id(&self.pg, user_id).await?.ok_or(Error::InvalidToken)?;
        let encrypted = crate::db::mfa::get_secret(&self.pg, user_id).await?.ok_or(Error::InvalidMfaCode)?;
        let secret = crate::crypto::aead::decrypt(&key, &encrypted)?;

        let totp_ok = crate::crypto::totp::verify(&secret, code, &self.config.mfa_issuer, &user.email)?;
        let accepted = totp_ok
            || crate::db::mfa::consume_recovery_code(&self.pg, user_id, &token::hash_token(code)).await?;
        if !accepted {
            return Err(Error::InvalidMfaCode);
        }
        self.issue_session(&user).await
    }

    /// Confirm enrollment with a live code; on success, enable MFA and return a
    /// fresh set of single-use recovery codes (shown to the user once).
    pub async fn mfa_confirm_enrollment(&self, user_id: Uuid, code: &str) -> Result<Vec<String>> {
        let key = *self.mfa_key()?;
        let user = users::find_by_id(&self.pg, user_id).await?.ok_or(Error::InvalidToken)?;
        let encrypted = crate::db::mfa::get_secret(&self.pg, user_id).await?.ok_or(Error::InvalidMfaCode)?;
        let secret = crate::crypto::aead::decrypt(&key, &encrypted)?;

        if !crate::crypto::totp::verify(&secret, code, &self.config.mfa_issuer, &user.email)? {
            return Err(Error::InvalidMfaCode);
        }

        crate::db::mfa::enable(&self.pg, user_id).await?;

        let codes: Vec<String> = (0..self.config.mfa_recovery_code_count)
            .map(|_| generate_recovery_code())
            .collect();
        let hashes: Vec<Vec<u8>> = codes.iter().map(|c| token::hash_token(c)).collect();
        crate::db::mfa::replace_recovery_codes(&self.pg, user_id, &hashes).await?;
        Ok(codes)
    }

    /// Disable MFA after verifying a current TOTP code (or recovery code).
    pub async fn mfa_disable(&self, user_id: Uuid, code: &str) -> Result<()> {
        let key = *self.mfa_key()?;
        let user = users::find_by_id(&self.pg, user_id).await?.ok_or(Error::InvalidToken)?;
        let encrypted = crate::db::mfa::get_secret(&self.pg, user_id).await?.ok_or(Error::InvalidMfaCode)?;
        let secret = crate::crypto::aead::decrypt(&key, &encrypted)?;

        let ok = crate::crypto::totp::verify(&secret, code, &self.config.mfa_issuer, &user.email)?
            || crate::db::mfa::consume_recovery_code(&self.pg, user_id, &token::hash_token(code)).await?;
        if !ok {
            return Err(Error::InvalidMfaCode);
        }
        crate::db::mfa::disable(&self.pg, user_id).await?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::mail::TestMailer;

    fn test_http() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    /// Build a Core with no OAuth providers (most tests).
    pub async fn core_with(pool: PgPool) -> (Core, Arc<TestMailer>) {
        core_with_providers(pool, Vec::new()).await
    }

    /// Build a Core with the given OAuth providers registered.
    pub async fn core_with_providers(
        pool: PgPool,
        providers: Vec<Arc<dyn Provider>>,
    ) -> (Core, Arc<TestMailer>) {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let client = redis::Client::open(url).unwrap();
        let redis = ConnectionManager::new(client).await.unwrap();
        let mailer = Arc::new(TestMailer::new());
        let config = CoreConfig {
            ip_attempt_limit: u32::MAX,
            email_attempt_limit: u32::MAX,
            ..CoreConfig::default()
        };
        let map = providers.into_iter().map(|p| (p.id().to_string(), p)).collect();
        let core = Core {
            pg: pool,
            redis,
            jwt: Jwt::new_hs256(b"0123456789abcdef0123456789abcdef", 900).unwrap(),
            mailer: mailer.clone(),
            config,
            http: test_http(),
            providers: map,
        };
        (core, mailer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::users::find_by_email;

    /// Drive signin and unwrap the `Authenticated` session (panics on MfaRequired).
    async fn signin_session(core: &Core, ip: &str, email: &str, pw: &str) -> Session {
        match core.signin(ip, email, pw).await.unwrap() {
            SigninOutcome::Authenticated(s) => s,
            SigninOutcome::MfaRequired(_) => panic!("unexpected MFA challenge"),
        }
    }

    fn test_provider() -> std::sync::Arc<dyn crate::oauth::Provider> {
        std::sync::Arc::new(crate::oauth::TestProvider {
            id: "test".to_string(),
            identity: crate::oauth::ProviderIdentity {
                provider_user_id: "tp-1".to_string(),
                email: Some("oauth1@b.com".to_string()),
            },
        })
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn begin_oauth_returns_url_and_stores_state(pool: PgPool) {
        let (core, _m) = test_support::core_with_providers(pool, vec![test_provider()]).await;

        let url = core.begin_oauth("test").await.unwrap();
        let state = url.split("state=").nth(1).unwrap().to_string();
        assert!(!state.is_empty());

        let mut redis = core.redis.clone();
        assert!(
            crate::redis_store::consume_oauth_state(&mut redis, "test", &state)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn begin_oauth_unknown_provider_errors(pool: PgPool) {
        let (core, _m) = test_support::core_with(pool).await;
        assert!(matches!(
            core.begin_oauth("nope").await.unwrap_err(),
            Error::ProviderNotFound
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signup_creates_unverified_user_and_emails_link(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool.clone()).await;
        core.signup("test", "new@b.com", "hunter2hunter2").await.unwrap();

        let u = find_by_email(&pool, "new@b.com").await.unwrap().unwrap();
        assert!(u.email_verified_at.is_none());
        assert!(u.password_hash.is_some());

        let url = mailer.last_url();
        assert!(url.contains("/auth/verify?token="));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signup_duplicate_is_email_taken(pool: PgPool) {
        let (core, _m) = test_support::core_with(pool).await;
        core.signup("test", "dup2@b.com", "hunter2hunter2").await.unwrap();
        let err = core.signup("test", "dup2@b.com", "hunter2hunter2").await.unwrap_err();
        assert!(matches!(err, Error::EmailTaken));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn verify_email_marks_verified_then_token_is_dead(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool.clone()).await;
        core.signup("test", "v2@b.com", "hunter2hunter2").await.unwrap();

        let url = mailer.last_url();
        let raw = url.split("token=").nth(1).unwrap().to_string();

        core.verify_email(&raw).await.unwrap();
        let u = find_by_email(&pool, "v2@b.com").await.unwrap().unwrap();
        assert!(u.email_verified_at.is_some());

        // one-time use: second attempt fails
        let err = core.verify_email(&raw).await.unwrap_err();
        assert!(matches!(err, Error::InvalidToken));
    }

    async fn signup_and_verify(core: &Core, mailer: &Arc<crate::mail::TestMailer>, email: &str, pw: &str) {
        core.signup("test", email, pw).await.unwrap();
        let url = mailer.last_url();
        let raw = url.split("token=").nth(1).unwrap().to_string();
        core.verify_email(&raw).await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signin_requires_verification(pool: PgPool) {
        let (core, _m) = test_support::core_with(pool).await;
        core.signup("test", "nv@b.com", "hunter2hunter2").await.unwrap();
        let err = core.signin("test", "nv@b.com", "hunter2hunter2").await.unwrap_err();
        assert!(matches!(err, Error::EmailNotVerified));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signin_succeeds_after_verification(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool).await;
        signup_and_verify(&core, &mailer, "ok@b.com", "hunter2hunter2").await;
        let session = signin_session(&core, "test", "ok@b.com", "hunter2hunter2").await;
        assert!(!session.access_token.is_empty());
        assert!(!session.refresh_token.is_empty());
        assert!(core.jwt.verify(&session.access_token).is_ok());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signin_wrong_password_is_invalid_credentials(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool).await;
        signup_and_verify(&core, &mailer, "wp@b.com", "hunter2hunter2").await;
        let err = core.signin("test", "wp@b.com", "wrongwrongwrong").await.unwrap_err();
        assert!(matches!(err, Error::InvalidCredentials));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signin_unknown_user_is_invalid_credentials(pool: PgPool) {
        let (core, _m) = test_support::core_with(pool).await;
        let err = core.signin("test", "ghost@b.com", "whatever123456").await.unwrap_err();
        assert!(matches!(err, Error::InvalidCredentials));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn refresh_rotates_and_old_token_is_dead(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool).await;
        signup_and_verify(&core, &mailer, "rf@b.com", "hunter2hunter2").await;
        let s1 = signin_session(&core, "test", "rf@b.com", "hunter2hunter2").await;

        let s2 = core.refresh(&s1.refresh_token).await.unwrap();
        assert_ne!(s1.refresh_token, s2.refresh_token);

        // reusing the rotated-away token is reuse-detection -> InvalidToken
        let err = core.refresh(&s1.refresh_token).await.unwrap_err();
        assert!(matches!(err, Error::InvalidToken));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn refresh_reuse_revokes_all_sessions(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool).await;
        signup_and_verify(&core, &mailer, "re@b.com", "hunter2hunter2").await;
        let s1 = signin_session(&core, "test", "re@b.com", "hunter2hunter2").await;
        let s2 = core.refresh(&s1.refresh_token).await.unwrap();

        // Present the stolen (old) token -> triggers revoke-all
        assert!(core.refresh(&s1.refresh_token).await.is_err());
        // The legitimate latest token is now also dead
        let err = core.refresh(&s2.refresh_token).await.unwrap_err();
        assert!(matches!(err, Error::InvalidToken));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signout_kills_only_that_session(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool).await;
        signup_and_verify(&core, &mailer, "so@b.com", "hunter2hunter2").await;
        let s = signin_session(&core, "test", "so@b.com", "hunter2hunter2").await;

        core.signout(&s.refresh_token).await.unwrap();
        // refresh on a revoked session is reuse-detection -> InvalidToken
        assert!(matches!(
            core.refresh(&s.refresh_token).await.unwrap_err(),
            Error::InvalidToken
        ));
        // calling signout again is a no-op (idempotent)
        core.signout(&s.refresh_token).await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signout_all_revokes_sessions_and_bumps_token_version(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool.clone()).await;
        signup_and_verify(&core, &mailer, "sa@b.com", "hunter2hunter2").await;
        let s = signin_session(&core, "test", "sa@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "sa@b.com").await.unwrap().unwrap();

        core.signout_all(u.id).await.unwrap();

        // token_version bumped...
        let after = find_by_email(&pool, "sa@b.com").await.unwrap().unwrap();
        assert_eq!(after.token_version, u.token_version + 1);
        // ...and the outstanding session is actually revoked.
        assert!(matches!(
            core.refresh(&s.refresh_token).await.unwrap_err(),
            Error::InvalidToken
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signin_and_refresh_reject_inactive_account(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool.clone()).await;
        signup_and_verify(&core, &mailer, "ia@b.com", "hunter2hunter2").await;
        let s = signin_session(&core, "test", "ia@b.com", "hunter2hunter2").await;

        sqlx::query("UPDATE users SET status = 'banned' WHERE email = $1::citext")
            .bind("ia@b.com")
            .execute(&pool)
            .await
            .unwrap();

        // signin rejects with AccountInactive (password is still correct)
        assert!(matches!(
            core.signin("test", "ia@b.com", "hunter2hunter2").await.unwrap_err(),
            Error::AccountInactive
        ));
        // refresh of a previously-issued token also rejects with AccountInactive
        assert!(matches!(
            core.refresh(&s.refresh_token).await.unwrap_err(),
            Error::AccountInactive
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn refresh_expired_token_is_rejected_and_revokes_all(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool.clone()).await;
        signup_and_verify(&core, &mailer, "ex@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "ex@b.com").await.unwrap().unwrap();

        // Manually insert a session whose refresh token is already expired.
        let raw = token::generate_token();
        let hash = token::hash_token(&raw);
        let past = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        sessions::create_session(&pool, u.id, &hash, past).await.unwrap();

        // A separate live session to prove scorched-earth revokes it too.
        let live = signin_session(&core, "test", "ex@b.com", "hunter2hunter2").await;

        // Expired token is rejected (treated as a theft signal)...
        assert!(matches!(
            core.refresh(&raw).await.unwrap_err(),
            Error::InvalidToken
        ));
        // ...and the live session is now revoked as well.
        assert!(matches!(
            core.refresh(&live.refresh_token).await.unwrap_err(),
            Error::InvalidToken
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn concurrent_refresh_of_same_token_is_race_free(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool).await;
        signup_and_verify(&core, &mailer, "rc@b.com", "hunter2hunter2").await;
        let s = signin_session(&core, "test", "rc@b.com", "hunter2hunter2").await;

        // Fire two refreshes of the SAME token concurrently. The atomic claim
        // must let exactly one win; the other is rejected (and trips reuse).
        let (r1, r2) = tokio::join!(
            core.refresh(&s.refresh_token),
            core.refresh(&s.refresh_token),
        );
        assert_ne!(
            r1.is_ok(),
            r2.is_ok(),
            "exactly one concurrent refresh may succeed, got r1={:?} r2={:?}",
            r1.is_ok(),
            r2.is_ok()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signup_ip_rate_limit_trips(pool: PgPool) {
        let (mut core, _m) = test_support::core_with(pool).await;
        core.config.ip_attempt_limit = 2;
        core.config.email_attempt_limit = u32::MAX; // isolate the IP limit
        let ip = format!("ip-{}", Uuid::new_v4());

        // Same IP, distinct emails: this is the Argon2 CPU-amplification vector,
        // and the per-IP limit bounds it.
        core.signup(&ip, &format!("{}@b.com", Uuid::new_v4()), "hunter2hunter2")
            .await
            .unwrap();
        core.signup(&ip, &format!("{}@b.com", Uuid::new_v4()), "hunter2hunter2")
            .await
            .unwrap();
        let err = core
            .signup(&ip, &format!("{}@b.com", Uuid::new_v4()), "hunter2hunter2")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RateLimited));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn strict_verify_rejects_after_signout_all(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool.clone()).await;
        signup_and_verify(&core, &mailer, "st@b.com", "hunter2hunter2").await;
        let s = signin_session(&core, "test", "st@b.com", "hunter2hunter2").await;

        // strict verify accepts the freshly-minted token
        core.verify_access_token_strict(&s.access_token).await.unwrap();

        let u = find_by_email(&pool, "st@b.com").await.unwrap().unwrap();
        core.signout_all(u.id).await.unwrap();

        // strict verify now rejects the pre-bump token (instant revocation)...
        assert!(matches!(
            core.verify_access_token_strict(&s.access_token).await.unwrap_err(),
            Error::InvalidToken
        ));
        // ...while the stateless verify still accepts it.
        core.jwt.verify(&s.access_token).unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn strict_verify_backfills_cache_on_miss(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool.clone()).await;
        signup_and_verify(&core, &mailer, "bf@b.com", "hunter2hunter2").await;
        let s = signin_session(&core, "test", "bf@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "bf@b.com").await.unwrap().unwrap();

        // Cold cache: strict verify must read Postgres and accept.
        let mut redis = core.redis.clone();
        crate::redis_store::clear_token_version(&mut redis, u.id).await.unwrap();
        core.verify_access_token_strict(&s.access_token).await.unwrap();

        // The miss should have backfilled the cache with the current version.
        assert_eq!(
            crate::redis_store::get_token_version(&mut redis, u.id).await.unwrap(),
            Some(u.token_version)
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn strict_verify_rejects_forged_token(pool: PgPool) {
        let (core, _m) = test_support::core_with(pool).await;
        // A garbage token fails the stateless signature check FIRST, so no user
        // need exist and no DB/version lookup is reached.
        assert!(matches!(
            core.verify_access_token_strict("not.a.valid.token").await.unwrap_err(),
            Error::InvalidToken
        ));
    }

    /// Drive a full begin->complete with the TestProvider and return the Session.
    async fn run_oauth(core: &Core) -> Session {
        let url = core.begin_oauth("test").await.unwrap();
        let state = url.split("state=").nth(1).unwrap().to_string();
        core.complete_oauth("test", "auth-code", &state).await.unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn complete_oauth_creates_user_and_session(pool: PgPool) {
        let (core, _m) = test_support::core_with_providers(pool.clone(), vec![test_provider()]).await;
        let s = run_oauth(&core).await;

        assert!(core.jwt.verify(&s.access_token).is_ok());
        let u = find_by_email(&pool, "oauth1@b.com").await.unwrap().unwrap();
        assert!(u.password_hash.is_none());
        assert!(u.email_verified_at.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn complete_oauth_is_idempotent_for_returning_user(pool: PgPool) {
        let (core, _m) = test_support::core_with_providers(pool.clone(), vec![test_provider()]).await;
        let _first = run_oauth(&core).await;
        let _second = run_oauth(&core).await;

        let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1::citext")
            .bind("oauth1@b.com").fetch_one(&pool).await.unwrap();
        let idents: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM identities WHERE provider = $1 AND provider_user_id = $2")
            .bind("test").bind("tp-1").fetch_one(&pool).await.unwrap();
        assert_eq!(users, 1);
        assert_eq!(idents, 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn complete_oauth_rejects_unknown_state(pool: PgPool) {
        let (core, _m) = test_support::core_with_providers(pool, vec![test_provider()]).await;
        assert!(matches!(
            core.complete_oauth("test", "code", "never-issued-state").await.unwrap_err(),
            Error::OAuthState
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn complete_oauth_links_to_existing_password_user(pool: PgPool) {
        let provider: std::sync::Arc<dyn crate::oauth::Provider> =
            std::sync::Arc::new(crate::oauth::TestProvider {
                id: "test".to_string(),
                identity: crate::oauth::ProviderIdentity {
                    provider_user_id: "link-1".to_string(),
                    email: Some("link@b.com".to_string()),
                },
            });
        let (core, mailer) = test_support::core_with_providers(pool.clone(), vec![provider]).await;
        // A password user already owns this (verified) email.
        signup_and_verify(&core, &mailer, "link@b.com", "hunter2hunter2").await;

        let url = core.begin_oauth("test").await.unwrap();
        let state = url.split("state=").nth(1).unwrap().to_string();
        core.complete_oauth("test", "code", &state).await.unwrap();

        // No duplicate user; the identity is linked to the existing account.
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1::citext")
            .bind("link@b.com").fetch_one(&pool).await.unwrap();
        assert_eq!(count, 1);
        let u = find_by_email(&pool, "link@b.com").await.unwrap().unwrap();
        assert_eq!(
            crate::db::identities::find_user_id_by_identity(&pool, "test", "link-1").await.unwrap(),
            Some(u.id)
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn complete_oauth_without_email_errors(pool: PgPool) {
        let provider: std::sync::Arc<dyn crate::oauth::Provider> =
            std::sync::Arc::new(crate::oauth::TestProvider {
                id: "test".to_string(),
                identity: crate::oauth::ProviderIdentity {
                    provider_user_id: "noemail-1".to_string(),
                    email: None,
                },
            });
        let (core, _m) = test_support::core_with_providers(pool, vec![provider]).await;
        let url = core.begin_oauth("test").await.unwrap();
        let state = url.split("state=").nth(1).unwrap().to_string();
        assert!(matches!(
            core.complete_oauth("test", "code", &state).await.unwrap_err(),
            Error::OAuth(_)
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signin_email_rate_limit_trips(pool: PgPool) {
        let (mut core, _m) = test_support::core_with(pool).await;
        core.config.ip_attempt_limit = u32::MAX; // isolate the email limit
        core.config.email_attempt_limit = 2;
        let email = format!("{}@b.com", Uuid::new_v4());

        // Distinct IPs, same email: throttles brute force against one account.
        for _ in 0..2 {
            let err = core
                .signin(&format!("ip-{}", Uuid::new_v4()), &email, "whatever123456")
                .await
                .unwrap_err();
            assert!(matches!(err, Error::InvalidCredentials));
        }
        let err = core
            .signin(&format!("ip-{}", Uuid::new_v4()), &email, "whatever123456")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RateLimited));
    }

    /// Build a test Core with an MFA encryption key set.
    async fn mfa_core(pool: PgPool) -> (Core, std::sync::Arc<crate::mail::TestMailer>) {
        let (mut core, m) = test_support::core_with(pool).await;
        core.config.mfa_encryption_key = Some([5u8; 32]);
        (core, m)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn mfa_enroll_then_confirm(pool: PgPool) {
        let (core, mailer) = mfa_core(pool.clone()).await;
        signup_and_verify(&core, &mailer, "mfa@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "mfa@b.com").await.unwrap().unwrap();

        let enrollment = core.mfa_begin_enrollment(u.id).await.unwrap();
        assert!(enrollment.otpauth_url.starts_with("otpauth://totp/"));

        // not enabled until confirmed
        let before = find_by_email(&pool, "mfa@b.com").await.unwrap().unwrap();
        assert!(before.mfa_enabled_at.is_none());

        // confirm with a live code derived from the stored (decrypted) secret
        let secret = crate::crypto::aead::decrypt(
            &[5u8; 32],
            &crate::db::mfa::get_secret(&pool, u.id).await.unwrap().unwrap(),
        ).unwrap();
        let code = crate::crypto::totp::current_code(&secret, &core.config.mfa_issuer, "mfa@b.com");
        let recovery = core.mfa_confirm_enrollment(u.id, &code).await.unwrap();
        assert_eq!(recovery.len(), core.config.mfa_recovery_code_count);

        let after = find_by_email(&pool, "mfa@b.com").await.unwrap().unwrap();
        assert!(after.mfa_enabled_at.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn mfa_confirm_rejects_bad_code(pool: PgPool) {
        let (core, mailer) = mfa_core(pool.clone()).await;
        signup_and_verify(&core, &mailer, "mfa2@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "mfa2@b.com").await.unwrap().unwrap();
        core.mfa_begin_enrollment(u.id).await.unwrap();
        // "000000" is almost always wrong; tolerate the ~1e-6 coincidental match
        assert!(matches!(
            core.mfa_confirm_enrollment(u.id, "000000").await,
            Err(Error::InvalidMfaCode) | Ok(_)
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn mfa_requires_configured_key(pool: PgPool) {
        let (core, mailer) = test_support::core_with(pool.clone()).await; // no mfa key
        signup_and_verify(&core, &mailer, "nokey@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "nokey@b.com").await.unwrap().unwrap();
        assert!(matches!(core.mfa_begin_enrollment(u.id).await, Err(Error::MfaNotConfigured)));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn signin_with_mfa_requires_code_then_completes(pool: PgPool) {
        let (core, mailer) = mfa_core(pool.clone()).await;
        signup_and_verify(&core, &mailer, "full@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "full@b.com").await.unwrap().unwrap();
        core.mfa_begin_enrollment(u.id).await.unwrap();
        let secret = crate::crypto::aead::decrypt(
            &[5u8; 32],
            &crate::db::mfa::get_secret(&pool, u.id).await.unwrap().unwrap(),
        ).unwrap();
        let setup_code = crate::crypto::totp::current_code(&secret, &core.config.mfa_issuer, "full@b.com");
        core.mfa_confirm_enrollment(u.id, &setup_code).await.unwrap();

        // signin now returns a challenge, not a session
        let challenge = match core.signin("test", "full@b.com", "hunter2hunter2").await.unwrap() {
            SigninOutcome::MfaRequired(t) => t,
            SigninOutcome::Authenticated(_) => panic!("expected MFA challenge"),
        };

        // completing with a live code yields a session
        let code = crate::crypto::totp::current_code(&secret, &core.config.mfa_issuer, "full@b.com");
        let session = core.complete_mfa(&challenge, &code).await.unwrap();
        assert!(core.jwt.verify(&session.access_token).is_ok());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn complete_mfa_accepts_recovery_code_once(pool: PgPool) {
        let (core, mailer) = mfa_core(pool.clone()).await;
        signup_and_verify(&core, &mailer, "rec@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "rec@b.com").await.unwrap().unwrap();
        core.mfa_begin_enrollment(u.id).await.unwrap();
        let secret = crate::crypto::aead::decrypt(
            &[5u8; 32],
            &crate::db::mfa::get_secret(&pool, u.id).await.unwrap().unwrap(),
        ).unwrap();
        let setup_code = crate::crypto::totp::current_code(&secret, &core.config.mfa_issuer, "rec@b.com");
        let recovery = core.mfa_confirm_enrollment(u.id, &setup_code).await.unwrap();

        let challenge = match core.signin("test", "rec@b.com", "hunter2hunter2").await.unwrap() {
            SigninOutcome::MfaRequired(t) => t,
            _ => panic!("expected challenge"),
        };
        // a recovery code works
        let session = core.complete_mfa(&challenge, &recovery[0]).await.unwrap();
        assert!(core.jwt.verify(&session.access_token).is_ok());

        // the same recovery code cannot be reused on a fresh challenge
        let challenge2 = match core.signin("test", "rec@b.com", "hunter2hunter2").await.unwrap() {
            SigninOutcome::MfaRequired(t) => t,
            _ => panic!("expected challenge"),
        };
        assert!(matches!(core.complete_mfa(&challenge2, &recovery[0]).await, Err(Error::InvalidMfaCode)));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn complete_mfa_rejects_unknown_challenge(pool: PgPool) {
        let (core, _m) = mfa_core(pool).await;
        assert!(matches!(core.complete_mfa("nope", "000000").await, Err(Error::InvalidToken)));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn mfa_disable_turns_it_off(pool: PgPool) {
        let (core, mailer) = mfa_core(pool.clone()).await;
        signup_and_verify(&core, &mailer, "off@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "off@b.com").await.unwrap().unwrap();
        core.mfa_begin_enrollment(u.id).await.unwrap();
        let secret = crate::crypto::aead::decrypt(
            &[5u8; 32],
            &crate::db::mfa::get_secret(&pool, u.id).await.unwrap().unwrap(),
        ).unwrap();
        let code = crate::crypto::totp::current_code(&secret, &core.config.mfa_issuer, "off@b.com");
        core.mfa_confirm_enrollment(u.id, &code).await.unwrap();

        let code2 = crate::crypto::totp::current_code(&secret, &core.config.mfa_issuer, "off@b.com");
        core.mfa_disable(u.id, &code2).await.unwrap();

        let after = find_by_email(&pool, "off@b.com").await.unwrap().unwrap();
        assert!(after.mfa_enabled_at.is_none());
        // signin no longer challenges
        assert!(matches!(
            core.signin("test", "off@b.com", "hunter2hunter2").await.unwrap(),
            SigninOutcome::Authenticated(_)
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn mfa_disable_via_recovery_code(pool: PgPool) {
        let (core, mailer) = mfa_core(pool.clone()).await;
        signup_and_verify(&core, &mailer, "offr@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "offr@b.com").await.unwrap().unwrap();
        core.mfa_begin_enrollment(u.id).await.unwrap();
        let secret = crate::crypto::aead::decrypt(
            &[5u8; 32],
            &crate::db::mfa::get_secret(&pool, u.id).await.unwrap().unwrap(),
        )
        .unwrap();
        let setup = crate::crypto::totp::current_code(&secret, &core.config.mfa_issuer, "offr@b.com");
        let recovery = core.mfa_confirm_enrollment(u.id, &setup).await.unwrap();

        // a recovery code disables MFA just like a TOTP code
        core.mfa_disable(u.id, &recovery[0]).await.unwrap();
        let after = find_by_email(&pool, "offr@b.com").await.unwrap().unwrap();
        assert!(after.mfa_enabled_at.is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn complete_mfa_wrong_code_burns_challenge(pool: PgPool) {
        let (core, mailer) = mfa_core(pool.clone()).await;
        signup_and_verify(&core, &mailer, "burn@b.com", "hunter2hunter2").await;
        let u = find_by_email(&pool, "burn@b.com").await.unwrap().unwrap();
        core.mfa_begin_enrollment(u.id).await.unwrap();
        let secret = crate::crypto::aead::decrypt(
            &[5u8; 32],
            &crate::db::mfa::get_secret(&pool, u.id).await.unwrap().unwrap(),
        )
        .unwrap();
        let setup = crate::crypto::totp::current_code(&secret, &core.config.mfa_issuer, "burn@b.com");
        core.mfa_confirm_enrollment(u.id, &setup).await.unwrap();

        let challenge = match core.signin("test", "burn@b.com", "hunter2hunter2").await.unwrap() {
            SigninOutcome::MfaRequired(t) => t,
            _ => panic!("expected challenge"),
        };
        // a wrong code is rejected (tolerate the ~1e-6 coincidental match)...
        assert!(matches!(
            core.complete_mfa(&challenge, "000000").await,
            Err(Error::InvalidMfaCode) | Ok(_)
        ));
        // ...and the one-time challenge is now spent: it cannot be retried.
        assert!(matches!(
            core.complete_mfa(&challenge, "000000").await,
            Err(Error::InvalidToken)
        ));
    }
}
