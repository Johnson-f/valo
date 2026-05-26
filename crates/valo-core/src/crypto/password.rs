//! Argon2id password hashing.
//!
//! Uses `Argon2::default()`, which is Argon2id v19 with parameters
//! m=19456 KiB (19 MiB), t=2, p=1 — the OWASP-recommended *minimum* for
//! Argon2id. Making these parameters configurable (so operators can raise
//! the cost on capable hardware) is a deliberate follow-on; do not hand-tune
//! here. Because hashes are stored as PHC strings, parameters can be raised
//! later and old hashes still verify.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::sync::OnceLock;

use crate::error::{Error, Result};

/// Hash a plaintext password into an Argon2id PHC string (salt + params embedded).
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| Error::Hashing)
}

/// Constant-time verify of a password against a stored PHC hash.
pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    match PasswordHash::new(phc_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A real Argon2id hash of a random string, computed once. Verify against this
/// when the user does not exist so login timing is identical (anti-enumeration).
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password("valo-dummy-password-for-constant-time").expect("dummy hash")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrips() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn hash_is_argon2id_phc() {
        let hash = hash_password("x").unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn dummy_hash_is_stable_and_valid() {
        assert_eq!(dummy_hash(), dummy_hash());
        assert!(dummy_hash().starts_with("$argon2id$"));
        assert!(!verify_password("anything", dummy_hash()));
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(!verify_password("anything", "not-a-valid-phc-string"));
    }
}
