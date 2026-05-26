//! Per-IP rate limiting, self-verifying. With the IP attempt limit set to 2,
//! the first two signin attempts fail auth (401) and the third trips the
//! limiter (429) BEFORE any password hashing happens.
//!
//! Prereq: throwaway containers up. Run:
//!   cargo run -p valo-axum-examples --example rate_limiting

use valo_axum::{TokenDelivery, ValoRouter};
use valo_axum_examples::common::{self, CapturingMailer};
use valo_core::Valo;

#[tokio::main]
async fn main() {
    let (db, redis) = common::db_urls();
    let valo = Valo::builder()
        .postgres(&db)
        .redis(&redis)
        .jwt_secret("dev-only-secret-change-me-at-least-32-bytes")
        .base_url("http://example.test")
        .mailer(CapturingMailer::new())
        // ip_limit = 2, generous email_limit, 60s window: the IP cap trips first.
        .rate_limits(2, 100, 60)
        .build()
        .await
        .expect("build valo");

    let router = ValoRouter::new(valo).token_delivery(TokenDelivery::Bearer).into_router();
    let base = common::serve(router).await;
    let http = reqwest::Client::new();
    // A unique email so this run's counter is independent of prior runs.
    let email = format!("ghost-{}@example.com", uuid::Uuid::new_v4());

    let mut statuses = Vec::new();
    for _ in 0..3 {
        let r = http
            .post(format!("{base}/signin"))
            .json(&serde_json::json!({ "email": email, "password": "whatever123456" }))
            .send()
            .await
            .unwrap();
        statuses.push(r.status().as_u16());
    }

    // First two: unauthorized (no such user). Third: rate-limited.
    assert_eq!(statuses[0], 401, "1st attempt should be 401 (bad creds)");
    assert_eq!(statuses[1], 401, "2nd attempt should be 401 (bad creds)");
    assert_eq!(statuses[2], 429, "3rd attempt should be 429 (rate limited)");

    println!("rate_limiting: OK (statuses = {statuses:?})");
}
