//! Cookie token delivery, self-verifying: signin sets HttpOnly `valo_access` /
//! `valo_refresh` cookies, and a protected route authenticates from the cookie
//! alone (reqwest's cookie store replays them automatically).
//!
//! Prereq: throwaway containers up. Run:
//!   cargo run -p valo-axum-examples --example cookie_mode

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

    // Cookie delivery; cookie_secure(false) because this demo is plain HTTP.
    let router = ValoRouter::new(valo)
        .token_delivery(TokenDelivery::Cookie)
        .cookie_secure(false)
        .into_router();
    let base = common::serve(router).await;
    // cookie_store(true) makes reqwest persist + replay Set-Cookie across calls.
    let http = reqwest::Client::builder().cookie_store(true).build().unwrap();
    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let pw = "hunter2hunter2";

    http.post(format!("{base}/signup"))
        .json(&serde_json::json!({ "email": email, "password": pw }))
        .send()
        .await
        .unwrap();
    let token = mailer.last_token();
    http.get(format!("{base}/verify?token={token}")).send().await.unwrap();

    // signin -> 200, sets the auth cookies (captured by the cookie store).
    let r = http
        .post(format!("{base}/signin"))
        .json(&serde_json::json!({ "email": email, "password": pw }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "cookie-mode signin should return 200");
    let set_cookies: Vec<String> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    assert!(
        set_cookies.iter().any(|c| c.starts_with("valo_access=") && c.contains("HttpOnly")),
        "expected an HttpOnly valo_access cookie"
    );
    assert!(
        set_cookies.iter().any(|c| c.starts_with("valo_refresh=")),
        "expected a valo_refresh cookie"
    );

    // Protected route via cookie alone -> 204 (no Authorization header sent).
    let r = http.post(format!("{base}/signout-all")).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 204, "cookie should authenticate the protected route");

    println!("cookie_mode: OK");
}
