//! Strict-mode revocation, self-verifying. A freshly minted access token passes
//! BOTH stateless verification and strict verification. After a global logout
//! (`signout_all`, which bumps the user's token_version), the SAME token still
//! passes stateless verification (it hasn't expired) but is rejected by strict
//! verification — instant revocation, before natural expiry.
//!
//! Prereq: throwaway containers up. Run:
//!   cargo run -p valo-axum-examples --example strict_revocation

use valo_axum_examples::common::{self, CapturingMailer};
use valo_core::{SigninOutcome, Valo};

#[tokio::main]
async fn main() {
    let (db, redis) = common::db_urls();
    let mailer = CapturingMailer::new();
    let valo = Valo::builder()
        .postgres(&db)
        .redis(&redis)
        .jwt_secret("dev-only-secret-change-me-at-least-32-bytes")
        .base_url("http://example.test")
        .mailer(mailer.clone())
        .build()
        .await
        .expect("build valo");

    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let pw = "hunter2hunter2";

    // Set up a verified, signed-in user (driving Core directly, no HTTP).
    valo.core().signup("127.0.0.1", &email, pw).await.expect("signup");
    valo.core().verify_email(&mailer.last_token()).await.expect("verify");
    let session = match valo.signin("127.0.0.1", &email, pw).await.expect("signin") {
        SigninOutcome::Authenticated(s) => s,
        SigninOutcome::MfaRequired(_) => panic!("MFA not enabled in this example"),
    };

    // Fresh token passes both stateless and strict verification.
    let claims = valo.verify_access_token(&session.access_token).expect("stateless verify ok");
    valo.verify_access_token_strict(&session.access_token).await.expect("strict verify ok");

    // Global logout bumps the user's token_version.
    valo.core().signout_all(claims.sub).await.expect("signout_all");

    // Stateless still accepts (token not expired); strict now REJECTS it.
    assert!(
        valo.verify_access_token(&session.access_token).is_ok(),
        "stateless verify still accepts the unexpired token"
    );
    assert!(
        valo.verify_access_token_strict(&session.access_token).await.is_err(),
        "strict verify must reject after signout_all"
    );

    println!("strict_revocation: OK");
}
