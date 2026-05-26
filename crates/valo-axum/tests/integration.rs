use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use valo_axum::{TokenDelivery, ValoRouter};
use valo_core::mail::{Mailer, OutgoingEmail};
use valo_core::Valo;

/// Records sent emails so tests can recover the verification URL.
#[derive(Clone, Default)]
struct RecordingMailer {
    sent: Arc<Mutex<Vec<OutgoingEmail>>>,
}

#[async_trait::async_trait]
impl Mailer for RecordingMailer {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String> {
        self.sent.lock().unwrap().push(email);
        Ok(())
    }
}

async fn build(delivery: TokenDelivery) -> (axum::Router, RecordingMailer) {
    let mailer = RecordingMailer::default();
    let valo = Valo::builder()
        .postgres(&std::env::var("DATABASE_URL").unwrap())
        .redis(&std::env::var("REDIS_URL").unwrap())
        .jwt_secret("0123456789abcdef0123456789abcdef")
        .mailer(mailer.clone())
        .build()
        .await
        .unwrap();
    let router = ValoRouter::new(valo)
        .token_delivery(delivery)
        .into_router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9000))));
    (router, mailer)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn signup_verify_signin_bearer_flow() {
    let (router, mailer) = build(TokenDelivery::Bearer).await;
    let email = format!("{}@b.com", uuid::Uuid::new_v4());

    let resp = router.clone().oneshot(post_json("/signup", serde_json::json!({"email": email, "password": "hunter2hunter2"}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let url = mailer.sent.lock().unwrap().last().unwrap().url.clone();
    let token = url.split("token=").nth(1).unwrap().to_string();

    let resp = router.clone().oneshot(Request::builder().uri(format!("/verify?token={token}")).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = router.clone().oneshot(post_json("/signin", serde_json::json!({"email": email, "password": "hunter2hunter2"}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let access = json["access_token"].as_str().unwrap().to_string();
    assert!(!access.is_empty());

    let resp = router.clone().oneshot(
        Request::builder().method("POST").uri("/signout-all")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn signin_bad_credentials_is_401() {
    let (router, _m) = build(TokenDelivery::Bearer).await;
    let resp = router.oneshot(post_json("/signin", serde_json::json!({"email": "ghost@b.com", "password": "whatever123456"}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signout_all_without_token_is_401() {
    let (router, _m) = build(TokenDelivery::Bearer).await;
    let resp = router.oneshot(Request::builder().method("POST").uri("/signout-all").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signin_cookie_mode_sets_cookies() {
    let (router, mailer) = build(TokenDelivery::Cookie).await;
    let email = format!("{}@b.com", uuid::Uuid::new_v4());
    router.clone().oneshot(post_json("/signup", serde_json::json!({"email": email, "password": "hunter2hunter2"}))).await.unwrap();
    let url = mailer.sent.lock().unwrap().last().unwrap().url.clone();
    let token = url.split("token=").nth(1).unwrap().to_string();
    router.clone().oneshot(Request::builder().uri(format!("/verify?token={token}")).body(Body::empty()).unwrap()).await.unwrap();

    let resp = router.oneshot(post_json("/signin", serde_json::json!({"email": email, "password": "hunter2hunter2"}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).collect();
    assert!(set_cookies.iter().any(|c| c.starts_with("valo_access=") && c.contains("HttpOnly")));
    assert!(set_cookies.iter().any(|c| c.starts_with("valo_refresh=")));
}

/// Helper: signup + verify a fresh user, returning the email.
async fn signup_and_verify(router: &axum::Router, mailer: &RecordingMailer, email: &str) {
    router
        .clone()
        .oneshot(post_json("/signup", serde_json::json!({"email": email, "password": "hunter2hunter2"})))
        .await
        .unwrap();
    let url = mailer.sent.lock().unwrap().last().unwrap().url.clone();
    let token = url.split("token=").nth(1).unwrap().to_string();
    router
        .clone()
        .oneshot(Request::builder().uri(format!("/verify?token={token}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn refresh_rotates_and_rejects_reuse() {
    let (router, mailer) = build(TokenDelivery::Bearer).await;
    let email = format!("{}@b.com", uuid::Uuid::new_v4());
    signup_and_verify(&router, &mailer, &email).await;

    let resp = router
        .clone()
        .oneshot(post_json("/signin", serde_json::json!({"email": email, "password": "hunter2hunter2"})))
        .await
        .unwrap();
    let refresh = body_json(resp).await["refresh_token"].as_str().unwrap().to_string();

    // refresh -> a new, different refresh token
    let resp = router
        .clone()
        .oneshot(post_json("/refresh", serde_json::json!({"refresh_token": refresh})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let new_refresh = body_json(resp).await["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh, new_refresh);

    // reusing the rotated-away token is rejected (reuse detection) -> 401
    let resp = router
        .oneshot(post_json("/refresh", serde_json::json!({"refresh_token": refresh})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cookie_mode_authuser_via_cookie() {
    let (router, mailer) = build(TokenDelivery::Cookie).await;
    let email = format!("{}@b.com", uuid::Uuid::new_v4());
    signup_and_verify(&router, &mailer, &email).await;

    let resp = router
        .clone()
        .oneshot(post_json("/signin", serde_json::json!({"email": email, "password": "hunter2hunter2"})))
        .await
        .unwrap();
    let set_cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("valo_access="))
        .unwrap()
        .to_string();
    // "valo_access=<value>" (drop the attributes after the first ';')
    let access_pair = set_cookie.split(';').next().unwrap().to_string();

    // a protected route authenticates via the access cookie -> 204
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/signout-all")
                .header("cookie", access_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}
