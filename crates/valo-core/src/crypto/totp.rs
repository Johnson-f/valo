use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::{Error, Result};

/// Build a standard SHA1/6-digit/30s TOTP for a raw secret. (SHA1 is what
/// authenticator apps expect.) `skew = 1` tolerates one 30s step of drift.
fn totp(secret: &[u8], issuer: &str, account: &str) -> Result<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_vec(),
        Some(issuer.to_string()), 
        account.to_string(),
    )
    .map_err(|_| Error::Encryption)
}

/// Generate a fresh random TOTP secret (raw bytes).
pub fn generate_secret() -> Vec<u8> {
    Secret::generate_secret().to_bytes().expect("generated secret is valid")
}

/// The `otpauth://` provisioning URI (QR-code content) for an authenticator app.
pub fn provisioning_uri(secret: &[u8], issuer: &str, account: &str) -> Result<String> {
    Ok(totp(secret, issuer, account)?.get_url())
}

/// Base32 representation of the secret, for manual entry into an app.
pub fn secret_base32(secret: &[u8]) -> String {
    Secret::Raw(secret.to_vec()).to_encoded().to_string()
}

/// Verify a user-supplied 6-digit code against the secret (current time ± skew).
pub fn verify(secret: &[u8], code: &str, issuer: &str, account: &str) -> Result<bool> {
    let t = totp(secret, issuer, account)?;
    Ok(t.check_current(code).unwrap_or(false))
}

#[cfg(test)]
pub(crate) fn current_code(secret: &[u8], issuer: &str, account: &str) -> String {
    totp(secret, issuer, account).unwrap().generate_current().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_verifies_its_own_current_code() {
        let secret = generate_secret();
        let code = current_code(&secret, "valo", "a@b.com");
        assert!(verify(&secret, &code, "valo", "a@b.com").unwrap());
    }

    #[test]
    fn wrong_code_fails() {
        let secret = generate_secret();
        let code = current_code(&secret, "valo", "a@b.com");
        let bad = if code == "123456" { "654321" } else { "123456" };
        assert!(!verify(&secret, bad, "valo", "a@b.com").unwrap());
    }

    #[test]
    fn provisioning_uri_is_otpauth() {
        let secret = generate_secret();
        let uri = provisioning_uri(&secret, "valo", "a@b.com").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(!secret_base32(&secret).is_empty());
    }
}
