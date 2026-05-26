//! OAuth wiring (Google + GitHub), env-gated. This one needs REAL credentials
//! and a browser, so it can't self-test. It registers whichever providers have
//! credentials in the environment, prints the authorize URLs, and serves the
//! router so you can click through. With no credentials set it explains what to
//! do and exits 0.
//!
//! Register the apps first (Google: console.cloud.google.com/apis/credentials,
//! GitHub: github.com/settings/developers), with these exact redirect URIs:
//!
//! ```text
//! http://127.0.0.1:4000/oauth/google/callback
//! http://127.0.0.1:4000/oauth/github/callback
//! ```
//!
//! Then run:
//!
//! ```text
//! export GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...
//! export GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=...
//! docker start valo-postgres valo-redis
//! cargo run -p valo-axum-examples --example oauth_providers
//! ```
//!
//! Open `http://127.0.0.1:4000/oauth/google` (or `.../github`) in a browser.

use std::net::SocketAddr;

use valo_axum::{TokenDelivery, ValoRouter};
use valo_axum_examples::common::{self, CapturingMailer};
use valo_core::oauth::github::GithubProvider;
use valo_core::oauth::google::GoogleProvider;
use valo_core::Valo;

const BASE: &str = "http://127.0.0.1:4000";

#[tokio::main]
async fn main() {
    let (db, redis) = common::db_urls();

    let mut builder = Valo::builder()
        .postgres(&db)
        .redis(&redis)
        .jwt_secret("dev-only-secret-change-me-at-least-32-bytes")
        .base_url(BASE)
        .mailer(CapturingMailer::new());

    let mut enabled: Vec<&str> = Vec::new();

    if let (Ok(id), Ok(secret)) =
        (std::env::var("GOOGLE_CLIENT_ID"), std::env::var("GOOGLE_CLIENT_SECRET"))
    {
        let redirect = format!("{BASE}/oauth/google/callback");
        builder = builder.provider(GoogleProvider::new(&id, &secret, &redirect).expect("google"));
        enabled.push("google");
    }
    if let (Ok(id), Ok(secret)) =
        (std::env::var("GITHUB_CLIENT_ID"), std::env::var("GITHUB_CLIENT_SECRET"))
    {
        let redirect = format!("{BASE}/oauth/github/callback");
        builder = builder.provider(GithubProvider::new(&id, &secret, &redirect).expect("github"));
        enabled.push("github");
    }

    if enabled.is_empty() {
        println!(
            "oauth_providers: no OAuth credentials found.\n\
             Set GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET and/or GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET,\n\
             register {BASE}/oauth/<provider>/callback as the redirect URI, then re-run.\n\
             Nothing to serve — exiting."
        );
        return;
    }

    let valo = builder.build().await.expect("build valo");
    let router = ValoRouter::new(valo).token_delivery(TokenDelivery::Bearer).into_router();

    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind 4000");
    println!("oauth_providers: serving on {BASE}; enabled providers: {enabled:?}");
    for p in &enabled {
        println!("  open {BASE}/oauth/{p} in a browser to start the {p} login");
    }
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
