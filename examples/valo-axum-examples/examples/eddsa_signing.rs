//! EdDSA (Ed25519) session signing, self-verifying. Mints a throwaway keypair
//! at startup (PKCS#8 + SPKI PEM), builds Valo with `jwt_eddsa`, signs in, and
//! confirms the issued access token verifies — proving the asymmetric path
//! (private key mints, public key verifies) works end to end.
//!
//! Prereq: throwaway containers up. Run:
//!   cargo run -p valo-axum-examples --example eddsa_signing

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use valo_axum_examples::common::{self, CapturingMailer};
use valo_core::{SigninOutcome, Valo};

/// Mint a dev-only Ed25519 keypair as (private PKCS#8 PEM, public SPKI PEM).
fn dev_keypair() -> (String, String) {
    let signing = SigningKey::generate(&mut OsRng);
    let private_pem = signing.to_pkcs8_pem(LineEnding::LF).expect("pkcs8 pem").to_string();
    let public_pem = signing.verifying_key().to_public_key_pem(LineEnding::LF).expect("spki pem");
    (private_pem, public_pem)
}

#[tokio::main]
async fn main() {
    let (db, redis) = common::db_urls();
    let (private_pem, public_pem) = dev_keypair();
    let mailer = CapturingMailer::new();
    let valo = Valo::builder()
        .postgres(&db)
        .redis(&redis)
        // EdDSA instead of HS256: private key mints, public key verifies.
        .jwt_eddsa(&private_pem, &public_pem)
        .base_url("http://example.test")
        .mailer(mailer.clone())
        .build()
        .await
        .expect("build valo");

    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let pw = "hunter2hunter2";
    valo.core().signup("127.0.0.1", &email, pw).await.expect("signup");
    valo.core().verify_email(&mailer.last_token()).await.expect("verify");
    let session = match valo.signin("127.0.0.1", &email, pw).await.expect("signin") {
        SigninOutcome::Authenticated(s) => s,
        SigninOutcome::MfaRequired(_) => panic!("MFA not enabled in this example"),
    };

    // The EdDSA-signed access token verifies with the public key.
    let claims = valo.verify_access_token(&session.access_token).expect("eddsa token verifies");
    assert_eq!(claims.email, email, "claims carry the signed-in email");

    println!("eddsa_signing: OK");
}
