//! End-to-end password auth over HTTP, self-verifying (asserts every step;
//! exits non-zero on failure):
//!   signup -> verify -> signin -> refresh (rotation) -> reuse rejected -> signout
//!
//! Prereq: throwaway containers up (`docker start valo-postgres valo-redis`).
//! Run:    cargo run -p valo-axum-examples --example password_flow

use valo_axum::{TokenDelivery, ValoRouter};
use valo_axum_examples::common::{self, CapturingMailer};
use valo_core::Valo;

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

    let router = ValoRouter::new(valo).token_delivery(TokenDelivery::Bearer).into_router();
    let base = common::serve(router).await;
    let http = reqwest::Client::new();
    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let pw = "hunter2hunter2";

    // 1. signup -> 204, and an email is captured.
    let r = http
        .post(format!("{base}/signup"))
        .json(&serde_json::json!({ "email": email, "password": pw }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204, "signup should return 204");

    // 2. verify with the token from the captured email -> 204.
    let token = mailer.last_token();
    let r = http.get(format!("{base}/verify?token={token}")).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 204, "verify should return 204");

    // 3. signin -> 200 with access + refresh tokens.
    let r = http
        .post(format!("{base}/signin"))
        .json(&serde_json::json!({ "email": email, "password": pw }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "signin should return 200");
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(!body["access_token"].as_str().unwrap().is_empty(), "access token present");
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    // 4. refresh -> a NEW refresh token (rotation).
    let r = http
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "refresh should return 200");
    let new_refresh =
        r.json::<serde_json::Value>().await.unwrap()["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh, new_refresh, "refresh token should rotate");

    // 5. reusing the rotated-away token is rejected (reuse detection) -> 401.
    let r = http
        .post(format!("{base}/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "reused refresh token must be rejected");

    // 6. signout the live session -> 204.
    let r = http
        .post(format!("{base}/signout"))
        .json(&serde_json::json!({ "refresh_token": new_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204, "signout should return 204");

    println!("password_flow: OK");
}
