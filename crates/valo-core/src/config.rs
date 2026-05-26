use std::sync::Arc;

use crate::mail::Mailer;
use crate::oauth::Provider;

/// Resolved configuration shared by the Core. Built via `ValoBuilder`.
#[derive(Clone)]
pub struct CoreConfig {
    pub base_url: String,
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
    pub verify_ttl_secs: u64,
    /// Max signup/signin attempts per caller key (IP) within the window.
    pub ip_attempt_limit: u32,
    /// Max signup/signin attempts per email within the window.
    pub email_attempt_limit: u32,
    /// Rate-limit window in seconds (shared by both counters).
    pub rate_limit_window_secs: u64,
    /// TTL for the strict-mode `token_version` cache entries.
    pub token_version_cache_ttl_secs: u64,
    /// AES-256 key for encrypting TOTP secrets at rest. `None` disables MFA.
    pub mfa_encryption_key: Option<[u8; 32]>,
    /// Issuer label shown in authenticator apps.
    pub mfa_issuer: String,
    /// Number of single-use recovery codes generated on enrollment.
    pub mfa_recovery_code_count: usize,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:3000".to_string(),
            access_ttl_secs: 15 * 60,            // 15 minutes
            refresh_ttl_secs: 30 * 24 * 60 * 60, // 30 days
            verify_ttl_secs: 24 * 60 * 60,       // 24 hours
            ip_attempt_limit: 30,                // per IP per window
            email_attempt_limit: 10,             // per email per window
            rate_limit_window_secs: 60,
            token_version_cache_ttl_secs: 5 * 60, // 5 minutes
            mfa_encryption_key: None,
            mfa_issuer: "valo".to_string(),
            mfa_recovery_code_count: 10,
        }
    }
}

/// The signing-key material chosen on the builder, consumed by `build()`.
#[derive(Clone)]
pub(crate) enum JwtKey {
    Hs256(Vec<u8>),
    Ed25519 { private_pem: Vec<u8>, public_pem: Vec<u8> },
}

/// Fluent builder collecting user-supplied settings before `build()`.
#[derive(Default)]
pub struct ValoBuilder {
    pub(crate) postgres_url: Option<String>,
    pub(crate) redis_url: Option<String>,
    pub(crate) jwt_key: Option<JwtKey>,
    pub(crate) mailer: Option<Arc<dyn Mailer>>,
    pub(crate) providers: Vec<std::sync::Arc<dyn Provider>>,
    pub(crate) config: CoreConfig,
}

impl ValoBuilder {
    pub fn postgres(mut self, url: &str) -> Self {
        self.postgres_url = Some(url.to_string());
        self
    }
    pub fn redis(mut self, url: &str) -> Self {
        self.redis_url = Some(url.to_string());
        self
    }
    pub fn jwt_secret(mut self, secret: &str) -> Self {
        self.jwt_key = Some(JwtKey::Hs256(secret.as_bytes().to_vec()));
        self
    }
    /// Use EdDSA (Ed25519) signing instead of HS256. `private_pem` is a PKCS#8
    /// PEM (held only by the minter); `public_pem` an SPKI PEM (verifiers).
    pub fn jwt_eddsa(mut self, private_pem: &str, public_pem: &str) -> Self {
        self.jwt_key = Some(JwtKey::Ed25519 {
            private_pem: private_pem.as_bytes().to_vec(),
            public_pem: public_pem.as_bytes().to_vec(),
        });
        self
    }
    pub fn base_url(mut self, url: &str) -> Self {
        self.config.base_url = url.to_string();
        self
    }
    pub fn mailer<M: Mailer + 'static>(mut self, mailer: M) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }
    /// Register an OAuth provider (e.g. `GoogleProvider`, `GithubProvider`).
    pub fn provider<P: Provider + 'static>(mut self, provider: P) -> Self {
        self.providers.push(std::sync::Arc::new(provider));
        self
    }
    /// Override the auth-endpoint rate limits (per-IP, per-email, window seconds).
    pub fn rate_limits(mut self, ip_limit: u32, email_limit: u32, window_secs: u64) -> Self {
        self.config.ip_attempt_limit = ip_limit;
        self.config.email_attempt_limit = email_limit;
        self.config.rate_limit_window_secs = window_secs;
        self
    }
    /// Override the strict-mode `token_version` cache TTL (seconds).
    pub fn strict_cache_ttl(mut self, secs: u64) -> Self {
        self.config.token_version_cache_ttl_secs = secs;
        self
    }
    /// Enable MFA by setting the TOTP-secret encryption key. The passphrase is
    /// hashed (SHA-256) into a 32-byte AES-256 key. Without this, MFA methods
    /// return `Error::MfaNotConfigured`.
    pub fn mfa_encryption_key(mut self, passphrase: &str) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(passphrase.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        self.config.mfa_encryption_key = Some(key);
        self
    }
    /// Override the issuer label shown in authenticator apps (default "valo").
    pub fn mfa_issuer(mut self, issuer: &str) -> Self {
        self.config.mfa_issuer = issuer.to_string();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_secret_sets_hs256_key() {
        let b = ValoBuilder::default().jwt_secret("0123456789abcdef0123456789abcdef");
        assert!(matches!(b.jwt_key, Some(JwtKey::Hs256(_))));
    }

    #[test]
    fn jwt_eddsa_sets_ed25519_key() {
        let b = ValoBuilder::default().jwt_eddsa("PRIVATE", "PUBLIC");
        match b.jwt_key {
            Some(JwtKey::Ed25519 { private_pem, public_pem }) => {
                assert_eq!(private_pem, b"PRIVATE");
                assert_eq!(public_pem, b"PUBLIC");
            }
            _ => panic!("expected Ed25519 key"),
        }
    }
}
