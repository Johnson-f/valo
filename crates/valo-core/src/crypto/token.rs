use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a 256-bit, URL-safe, unguessable bearer token (raw value, give to user).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 the raw token for storage. We never persist the raw bearer value.
pub fn hash_token(raw: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_nonempty() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert!(a.len() >= 43); // 32 bytes base64url-no-pad
    }

    #[test]
    fn hash_is_deterministic_and_32_bytes() {
        let t = generate_token();
        assert_eq!(hash_token(&t), hash_token(&t));
        assert_eq!(hash_token(&t).len(), 32);
    }
}
