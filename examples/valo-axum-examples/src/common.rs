//! Boilerplate shared by the example binaries: an in-memory mailer, env DB URL
//! reading, and an ephemeral-port server launcher.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use valo_core::mail::{Mailer, OutgoingEmail};

/// A `Mailer` that records every outgoing email in memory instead of sending,
/// so an example can recover the verification/reset token from the URL.
#[derive(Clone, Default)]
pub struct CapturingMailer {
    pub sent: Arc<Mutex<Vec<OutgoingEmail>>>,
}

impl CapturingMailer {
    pub fn new() -> Self {
        Self::default()
    }

    /// URL of the most recently captured email (panics if none captured yet).
    pub fn last_url(&self) -> String {
        self.sent.lock().unwrap().last().expect("an email was captured").url.clone()
    }

    /// The `token=` query value from the most recently captured email.
    pub fn last_token(&self) -> String {
        self.last_url().split("token=").nth(1).expect("captured url has a token").to_string()
    }
}

#[async_trait]
impl Mailer for CapturingMailer {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String> {
        self.sent.lock().unwrap().push(email);
        Ok(())
    }
}

/// Read `DATABASE_URL` / `REDIS_URL` (injected by the workspace
/// `.cargo/config.toml`, pointing at the throwaway containers).
pub fn db_urls() -> (String, String) {
    let db = std::env::var("DATABASE_URL")
        .expect("set DATABASE_URL (e.g. postgres://valo:valo@127.0.0.1:5440/valo)");
    let redis = std::env::var("REDIS_URL").expect("set REDIS_URL (e.g. redis://127.0.0.1:6390)");
    (db, redis)
}

/// Bind the router to an ephemeral local port, serve it in a background task
/// (with `ConnectInfo` so the rate limiter sees client IPs), and return the
/// base URL, e.g. `http://127.0.0.1:53124`.
pub async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind ephemeral port");
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    base
}
