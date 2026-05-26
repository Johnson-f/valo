//! MFA / TOTP end to end, self-verifying:
//!   signup+verify+signin (get access token) -> enroll (get secret) ->
//!   confirm with a computed TOTP code (get recovery codes) ->
//!   signin again now returns mfa_required -> complete with a fresh TOTP code.
//! We compute TOTP codes locally with `totp-rs`, matching valo's SHA1/6/30 setup.
//!
//! Prereq: throwaway containers up. Run:
//!   cargo run -p valo-axum-examples --example mfa_totp

use totp_rs::{Algorithm, Secret, TOTP};
use valo_axum::{TokenDelivery, ValoRouter};
use valo_axum_examples::common::{self, CapturingMailer};
use valo_core::Valo;

/// Current 6-digit code for a base32 secret, matching valo-core's TOTP params.
fn current_code(secret_base32: &str) -> String {
    let bytes = Secret::Encoded(secret_base32.to_string()).to_bytes().expect("valid base32 secret");
    // totp-rs 5.7.1 TOTP::new always takes 7 args (issuer + account_name are
    // required by the struct but irrelevant for code generation; we pass None/"").
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, String::new())
        .expect("totp params valid");
    totp.generate_current().expect("generate code")
}

#[tokio::main]
async fn main() {
    let (db, redis) = common::db_urls();
    let mailer = CapturingMailer::new();
    let valo = Valo::builder()
        .postgres(&db)
        .redis(&redis)
        .jwt_secret("dev-only-secret-change-me-at-least-32-bytes")
        .base_url("http://example.test")
        // MFA requires an encryption key for the TOTP secret at rest.
        .mfa_encryption_key("dev-only-mfa-passphrase-change-me")
        .mailer(mailer.clone())
        .build()
        .await
        .expect("build valo");

    let router = ValoRouter::new(valo).token_delivery(TokenDelivery::Bearer).into_router();
    let base = common::serve(router).await;
    let http = reqwest::Client::new();
    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let pw = "hunter2hunter2";

    // Signup + verify + first signin (no MFA yet) to get an access token.
    http.post(format!("{base}/signup"))
        .json(&serde_json::json!({ "email": email, "password": pw }))
        .send()
        .await
        .unwrap();
    http.get(format!("{base}/verify?token={}", mailer.last_token())).send().await.unwrap();
    let signin: serde_json::Value = http
        .post(format!("{base}/signin"))
        .json(&serde_json::json!({ "email": email, "password": pw }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access = signin["access_token"].as_str().expect("first signin returns a session").to_string();

    // Enroll -> get the shared secret (otpauth_url + secret_base32).
    let enroll: serde_json::Value = http
        .post(format!("{base}/mfa/enroll"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let secret_base32 = enroll["secret_base32"].as_str().expect("enroll returns secret").to_string();

    // Confirm enrollment with a computed code -> recovery codes returned.
    let r = http
        .post(format!("{base}/mfa/confirm"))
        .bearer_auth(&access)
        .json(&serde_json::json!({ "code": current_code(&secret_base32) }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "mfa/confirm should return 200");
    let recovery = r.json::<serde_json::Value>().await.unwrap();
    assert!(
        recovery["recovery_codes"].as_array().is_some_and(|c| !c.is_empty()),
        "confirm should return recovery codes"
    );

    // Now signin returns an MFA challenge instead of a session.
    let challenge: serde_json::Value = http
        .post(format!("{base}/signin"))
        .json(&serde_json::json!({ "email": email, "password": pw }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(challenge["mfa_required"], serde_json::json!(true), "signin should now require MFA");
    let mfa_token = challenge["mfa_token"].as_str().expect("challenge has mfa_token").to_string();

    // Complete the challenge with a fresh TOTP code -> a real session.
    let r = http
        .post(format!("{base}/mfa/complete"))
        .json(&serde_json::json!({ "mfa_token": mfa_token, "code": current_code(&secret_base32) }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "mfa/complete should return 200");
    let session = r.json::<serde_json::Value>().await.unwrap();
    assert!(
        !session["access_token"].as_str().unwrap_or("").is_empty(),
        "mfa/complete should issue an access token"
    );

    println!("mfa_totp: OK");
}
