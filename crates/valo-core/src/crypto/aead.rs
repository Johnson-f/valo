use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::error::{Error, Result};

/// Encrypt `plaintext` with AES-256-GCM under `key` (32 bytes). Returns
/// `nonce(12) || ciphertext` so the nonce travels with the data.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    // `key.into()` uses the `From<&[u8; 32]> for &GenericArray<u8, U32>` impl,
    // avoiding the deprecated `GenericArray::from_slice`.
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| Error::Encryption)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a `nonce(12) || ciphertext` blob produced by `encrypt`.
pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 12 {
        return Err(Error::Encryption);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    // Convert `&[u8]` → `&[u8; 12]` → `&GenericArray<u8, U12>` (no deprecated path).
    let nonce_arr: &[u8; 12] = nonce_bytes.try_into().map_err(|_| Error::Encryption)?;
    let nonce = <&Nonce<_>>::from(nonce_arr);
    cipher.decrypt(nonce, ciphertext).map_err(|_| Error::Encryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let key = [7u8; 32];
        let blob = encrypt(&key, b"top secret").unwrap();
        assert_ne!(blob, b"top secret");
        assert_eq!(decrypt(&key, &blob).unwrap(), b"top secret");
    }

    #[test]
    fn wrong_key_fails() {
        let blob = encrypt(&[1u8; 32], b"x").unwrap();
        assert!(matches!(decrypt(&[2u8; 32], &blob), Err(Error::Encryption)));
    }

    #[test]
    fn tampered_blob_fails() {
        let key = [3u8; 32];
        let mut blob = encrypt(&key, b"hello").unwrap();
        *blob.last_mut().unwrap() ^= 0xff;
        assert!(matches!(decrypt(&key, &blob), Err(Error::Encryption)));
    }

    #[test]
    fn nonce_makes_ciphertext_unique() {
        let key = [9u8; 32];
        assert_ne!(encrypt(&key, b"same").unwrap(), encrypt(&key, b"same").unwrap());
    }
}
