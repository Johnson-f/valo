//! Runnable valo-axum demo server.
//!
//! Boots a `Valo` instance (Postgres + Redis) behind a `ValoRouter` and serves
//! it on `http://127.0.0.1:4000` (override with `PORT`). The router is nested
//! under `/auth`, matching the `{base_url}/auth/verify?token=...` links that
//! valo-core generates — so the verification link printed by `StdoutMailer` is
//! directly clickable.
//!
//! It also demonstrates **custom email templates**: `branded` overrides the
//! built-in copy (falling back to `default_template` for kinds it doesn't
//! customize). `StdoutMailer` renders through it so you see the branded subject
//! + HTML in the console; `resend_with_branded_templates` (behind `--features
//! resend`) shows the same closure applied to a real provider via `with_templates`.
//!
//! Run (Postgres on :5440 + Redis on :6390 — `DATABASE_URL`/`REDIS_URL` come
//! from the workspace `.cargo/config.toml`):
//!
//!     cargo run -p valo-axum-examples
//!
//! Then follow `examples/valo-axum-examples/README.md` for the curl walkthrough.

use std::net::SocketAddr;

use async_trait::async_trait;
use axum::Router;
use valo_axum::{TokenDelivery, ValoRouter};
use valo_core::mail::{default_template, EmailKind, Mailer, OutgoingEmail};
use valo_core::Valo;

/// A custom email template: branded copy for verification, with a fall-back to
/// valo's `default_template` for anything we don't override. This closure shape
/// (`Fn(&EmailKind, &str) -> (subject, html)`) is exactly what the built-in
/// providers accept via `.with_templates(...)`.
fn branded(kind: &EmailKind, url: &str) -> (String, String) {
    match kind {
        EmailKind::Verification => (
            "Welcome to Acme — confirm your email".to_string(),
            format!(
                "<div style=\"font-family:sans-serif\">\
                 <h1>Welcome to Acme 👋</h1>\
                 <p>Confirm your email to finish signing up:</p>\
                 <p><a href=\"{url}\">Verify my email</a></p></div>"
            ),
        ),
        // Not customized here — use valo's built-in copy.
        _ => default_template(kind, url),
    }
}

/// Demo mailer: renders each email through `branded` and prints the result to
/// stdout (instead of sending), so you can see the templated output and grab the
/// verification link from the console.
struct StdoutMailer;

#[async_trait]
impl Mailer for StdoutMailer {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String> {
        let (subject, html) = branded(&email.kind, &email.url);
        println!(
            "\n📧  email [{:?}] -> {}\n    subject: {subject}\n    link:    {}\n    html:    {html}\n",
            email.kind, email.to, email.url
        );
        Ok(())
    }
}

/// Demonstrates `with_templates` on a real built-in provider — the same `branded`
/// closure, applied to Resend. Compiled only under `--features resend`; never
/// called (swap it in for `StdoutMailer` with a real API key to send for real).
#[cfg(feature = "resend")]
#[allow(dead_code)]
fn resend_with_branded_templates(api_key: &str) -> valo_core::mail::ResendMailer {
    valo_core::mail::ResendMailer::new(api_key, "no-reply@acme.test").with_templates(branded)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .expect("set DATABASE_URL (e.g. postgres://valo:valo@127.0.0.1:5440/valo)");
    let redis_url = std::env::var("REDIS_URL")
        .expect("set REDIS_URL (e.g. redis://127.0.0.1:6390)");
    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(4000);
    let base_url = format!("http://127.0.0.1:{port}");

    // Build the auth engine. Migrations run automatically on build().
    let valo = Valo::builder()
        .postgres(&database_url)
        .redis(&redis_url)
        .jwt_secret("dev-only-secret-change-me-at-least-32-bytes")
        .mfa_encryption_key("dev-only-mfa-passphrase-change-me")
        .base_url(&base_url)
        .mailer(StdoutMailer)
        .build()
        .await?;

    // Bearer-token mode (JSON). Flip to cookies with:
    //   .token_delivery(TokenDelivery::Cookie)
    // `cookie_secure(false)` is only because this demo serves plain HTTP on localhost.
    let auth = ValoRouter::new(valo)
        .token_delivery(TokenDelivery::Bearer)
        .cookie_secure(false)
        .into_router();

    // Nest under /auth so routes are /auth/signup, /auth/verify, ... — matching the
    // `{base_url}/auth/verify` links valo-core builds.
    let app = Router::new().nest("/auth", auth);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("valo-axum demo listening on {base_url}");
    println!(
        "signup: curl -XPOST {base_url}/auth/signup -H 'content-type: application/json' -d '{{\"email\":\"me@example.com\",\"password\":\"hunter2hunter2\"}}'"
    );

    // ConnectInfo is required so the rate limiter sees per-client IPs.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
