use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

/// Access-token claims. Verified in-process with zero I/O.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,           // user id
    pub email: String,
    pub token_version: i32,  // for future strict-mode revocation
    pub jti: Uuid,           // unique token id (future denylist)
    pub iat: i64,            // issued-at (unix seconds)
    pub exp: i64,            // expiry (unix seconds)
}

/// JWT signer/verifier. Supports HS256 and EdDSA (Ed25519).
#[derive(Clone)]
pub struct Jwt {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    algorithm: Algorithm,
    kid: String,
    access_ttl_secs: i64,
}

impl Jwt {
    /// Build from a shared secret. Rejects secrets weaker than 32 bytes.
    pub fn new_hs256(secret: &[u8], access_ttl_secs: i64) -> Result<Self> {
        if secret.len() < 32 {
            return Err(Error::WeakSecret);
        }
        let mut validation = Validation::new(Algorithm::HS256);
        // Exact expiry: safe because verify is in-process (no clock skew vs. the
        // minter). If tokens are ever verified cross-service, add a small leeway.
        validation.leeway = 0;
        Ok(Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            validation,
            algorithm: Algorithm::HS256,
            // Stamped into the header for future key rotation; informational in v1
            // (verify does not yet match on kid).
            kid: "v1".to_string(),
            access_ttl_secs,
        })
    }

    /// Build an EdDSA (Ed25519) signer/verifier. `private_pem` is a PKCS#8 PEM
    /// (signing key), `public_pem` an SPKI PEM (verification key). Lets a fleet
    /// verify with the public key while only the minter holds the private key.
    pub fn new_eddsa(private_pem: &[u8], public_pem: &[u8], access_ttl_secs: i64) -> Result<Self> {
        let encoding = EncodingKey::from_ed_pem(private_pem)?;
        let decoding = DecodingKey::from_ed_pem(public_pem)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 0;
        Ok(Self {
            encoding,
            decoding,
            validation,
            algorithm: Algorithm::EdDSA,
            kid: "v1".to_string(),
            access_ttl_secs,
        })
    }

    /// Mint an access token for a user. `jti` should be a fresh Uuid::new_v4().
    pub fn mint_access(&self, user_id: Uuid, email: &str, token_version: i32, jti: Uuid) -> Result<String> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            sub: user_id,
            email: email.to_string(),
            token_version,
            jti,
            iat: now,
            exp: now + self.access_ttl_secs,
        };
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        Ok(encode(&header, &claims, &self.encoding)?)
    }

    /// Verify signature + expiry. Pure CPU, no DB/Redis.
    pub fn verify(&self, token: &str) -> Result<Claims> {
        decode::<Claims>(token, &self.decoding, &self.validation)
            .map(|data| data.claims)
            .map_err(|_| Error::InvalidToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ED_PRIV: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKz4c5WnQ39PwISjYat8ie6LahOWlLU4KNh+wLK92SQk\n-----END PRIVATE KEY-----\n";
    const TEST_ED_PUB: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaRrudsQhitz97wRSJvem3RwX7eJTChO+fuoukbQJ34c=\n-----END PUBLIC KEY-----\n";

    fn eddsa() -> Jwt {
        Jwt::new_eddsa(TEST_ED_PRIV, TEST_ED_PUB, 900).unwrap()
    }

    #[test]
    fn eddsa_mint_then_verify_roundtrips() {
        let j = eddsa();
        let uid = Uuid::new_v4();
        let jti = Uuid::new_v4();
        let token = j.mint_access(uid, "a@b.com", 3, jti).unwrap();
        let claims = j.verify(&token).unwrap();
        assert_eq!(claims.sub, uid);
        assert_eq!(claims.token_version, 3);
        assert_eq!(claims.jti, jti);
    }

    #[test]
    fn eddsa_rejects_tampered_token() {
        let j = eddsa();
        let token = j.mint_access(Uuid::new_v4(), "a@b.com", 0, Uuid::new_v4()).unwrap();
        assert!(matches!(j.verify(&format!("{token}x")), Err(Error::InvalidToken)));
    }

    #[test]
    fn algorithms_do_not_cross_verify() {
        let hs = Jwt::new_hs256(b"0123456789abcdef0123456789abcdef", 900).unwrap();
        let ed = eddsa();
        let hs_token = hs.mint_access(Uuid::new_v4(), "a@b.com", 0, Uuid::new_v4()).unwrap();
        let ed_token = ed.mint_access(Uuid::new_v4(), "a@b.com", 0, Uuid::new_v4()).unwrap();
        assert!(matches!(ed.verify(&hs_token), Err(Error::InvalidToken)));
        assert!(matches!(hs.verify(&ed_token), Err(Error::InvalidToken)));
    }

    fn jwt() -> Jwt {
        Jwt::new_hs256(b"0123456789abcdef0123456789abcdef", 900).unwrap()
    }

    #[test]
    fn rejects_short_secret() {
        assert!(matches!(Jwt::new_hs256(b"short", 900), Err(Error::WeakSecret)));
    }

    #[test]
    fn mint_then_verify_roundtrips() {
        let j = jwt();
        let uid = Uuid::new_v4();
        let jti = Uuid::new_v4();
        let token = j.mint_access(uid, "a@b.com", 7, jti).unwrap();
        let claims = j.verify(&token).unwrap();
        assert_eq!(claims.sub, uid);
        assert_eq!(claims.email, "a@b.com");
        assert_eq!(claims.token_version, 7);
        assert_eq!(claims.jti, jti);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn rejects_tampered_token() {
        let j = jwt();
        let token = j.mint_access(Uuid::new_v4(), "a@b.com", 0, Uuid::new_v4()).unwrap();
        let tampered = format!("{}x", token);
        assert!(matches!(j.verify(&tampered), Err(Error::InvalidToken)));
    }

    #[test]
    fn rejects_expired_token() {
        // ttl = -10s => already expired on mint
        let j = Jwt::new_hs256(b"0123456789abcdef0123456789abcdef", -10).unwrap();
        let token = j.mint_access(Uuid::new_v4(), "a@b.com", 0, Uuid::new_v4()).unwrap();
        assert!(matches!(j.verify(&token), Err(Error::InvalidToken)));
    }
}
