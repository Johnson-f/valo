# valo Feature Examples Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one focused, runnable example binary per valo feature (password auth, cookie delivery, rate limiting, strict revocation, EdDSA signing, MFA/TOTP, OAuth, custom email templates, mailer providers), each self-verifying where possible, so adopters can `cargo run --example <name>` to see any feature end to end.

**Architecture:** Examples live in the existing `examples/valo-axum-examples` package as `examples/*.rs` files (each becomes `cargo run --example <name>`). A new library target (`src/lib.rs` + `src/common.rs`) holds shared boilerplate — a `CapturingMailer` (records emails in memory so an example can recover the verification token without sending), env-based DB URL reading, and an ephemeral-port `serve` helper. Self-verifying examples spin up the real router on `127.0.0.1:0`, drive it with a `reqwest` client, and `assert` every step (process exits non-zero on failure). OAuth and real-mailer examples can't self-test (they need a browser / real credentials), so they construct the feature, print instructions, and exit 0 cleanly when credentials are absent.

**Tech Stack:** Rust (edition 2024), valo-core + valo-axum (path deps), axum 0.8, tokio, reqwest (rustls, no OpenSSL), totp-rs 5.7 (for the MFA example to compute codes), ed25519-dalek 2 (for the EdDSA example to mint a dev keypair), uuid, serde_json.

---

## CRITICAL standing constraints (read before starting)

1. **NEVER run any git operations** (no `git add`, `git commit`, `git diff`, `git log`, `git status`, `git show`). The user has a standing instruction against this. This plan therefore contains **no commit steps** — each task ends with a verification checkpoint instead. Do not add git commands.
2. **All-rustls, no OpenSSL.** Every new dependency must avoid pulling `openssl-sys`. `reqwest` and `totp-rs` are added with `default-features = false` and explicit rustls/feature selection for this reason. After adding deps, the plan verifies with `cargo tree -i openssl-sys` (expected: "package ID not found", i.e. nothing depends on it).
3. **Throwaway containers only.** The self-verifying examples need Postgres on `:5440` and Redis on `:6390`. These are the dedicated containers `valo-postgres` / `valo-redis`. Before running any example that builds a `Valo`, ensure they are up: `docker start valo-postgres valo-redis`. `DATABASE_URL` / `REDIS_URL` are injected by the workspace `.cargo/config.toml`, so no manual export is needed when running via cargo from the repo root.
4. **Never assume crate APIs.** Two examples use crates not already wired into valo (`totp-rs` code generation in Task 7, `ed25519-dalek` PEM export in Task 8). The exact method/trait paths MUST be confirmed against the installed version's docs before finalizing — each task flags this and gives a fallback.

---

## File Structure

- `examples/valo-axum-examples/Cargo.toml` — add `[lib]`-implied target by creating `src/lib.rs`; add deps (`reqwest`, `uuid`, `serde_json`, `totp-rs`, `ed25519-dalek`, `rand`) and feature flags for the optional mailer providers.
- `examples/valo-axum-examples/src/lib.rs` — `pub mod common;` (turns the package into a library so examples can `use valo_axum_examples::common::...`).
- `examples/valo-axum-examples/src/common.rs` — `CapturingMailer`, `db_urls()`, `serve(router) -> String`.
- `examples/valo-axum-examples/examples/password_flow.rs` — signup→verify→signin→refresh→reuse-reject→signout (HTTP, self-verifying).
- `examples/valo-axum-examples/examples/cookie_mode.rs` — cookie token delivery + protected route via cookie (HTTP, self-verifying).
- `examples/valo-axum-examples/examples/rate_limiting.rs` — per-IP limit trips a 429 (HTTP, self-verifying).
- `examples/valo-axum-examples/examples/strict_revocation.rs` — strict verify + `signout_all` instant revocation (core handle, self-verifying).
- `examples/valo-axum-examples/examples/mfa_totp.rs` — enroll→confirm→MFA-gated signin→complete (HTTP + totp-rs, self-verifying).
- `examples/valo-axum-examples/examples/eddsa_signing.rs` — EdDSA-signed sessions (core handle + ed25519-dalek keygen, self-verifying).
- `examples/valo-axum-examples/examples/custom_templates.rs` — `default_template` + branded closure + `with_templates` shape (self-verifying assertions; provider call feature-gated).
- `examples/valo-axum-examples/examples/oauth_providers.rs` — env-gated Google/GitHub wiring + live server for a browser click-through (manual, exits cleanly without creds).
- `examples/valo-axum-examples/examples/mailer_providers.rs` — feature-gated construction of Resend/SendGrid/SES/SMTP mailers (compile-checks the provider APIs).
- `examples/valo-axum-examples/README.md` — replace/extend with an index table of every example.

**Verified API surface (do not re-derive):**
- `Valo::builder()` → `ValoBuilder` with `.postgres(&str)`, `.redis(&str)`, `.jwt_secret(&str)`, `.jwt_eddsa(private_pem: &str, public_pem: &str)`, `.base_url(&str)`, `.mailer(M)`, `.provider(P)`, `.rate_limits(ip_limit: u32, email_limit: u32, window_secs: u64)`, `.strict_cache_ttl(u64)`, `.mfa_encryption_key(&str)`, `.mfa_issuer(&str)`; `.build().await -> Result<Valo>`.
- `Valo`: `.core() -> &Core`, `.verify_access_token(&str) -> Result<Claims>`, `.verify_access_token_strict(&str).await -> Result<Claims>`, `.signin(client_key, email, password).await -> Result<SigninOutcome>`, `.begin_oauth(provider_id).await -> Result<String>`, `.complete_oauth(provider_id, code, state).await -> Result<Session>`, `.mfa_begin_enrollment(Uuid).await -> Result<MfaEnrollment>`, `.mfa_confirm_enrollment(Uuid, code).await -> Result<Vec<String>>`, `.complete_mfa(challenge_token, code).await -> Result<Session>`, `.mfa_disable(Uuid, code).await -> Result<()>`.
- `Core`: `.signup(client_key, email, password).await -> Result<()>`, `.verify_email(raw_token).await -> Result<()>`, `.refresh(raw_refresh).await -> Result<Session>`, `.signout(raw_refresh).await -> Result<()>`, `.signout_all(user_id: Uuid).await -> Result<()>`.
- `SigninOutcome::Authenticated(Session)` | `SigninOutcome::MfaRequired(String)`.
- `Session { access_token: String, refresh_token: String, access_expires_in: i64 }`.
- `MfaEnrollment { otpauth_url: String, secret_base32: String }`.
- `Claims { sub: uuid::Uuid, email: String, iat: i64, exp: i64, .. }` (`sub` is a `Uuid`, not a string).
- `valo_core::mail::{Mailer, OutgoingEmail { to, kind, url }, EmailKind::{Verification, PasswordReset}, default_template(&EmailKind, &str) -> (String, String)}`.
- `valo_core::oauth::google::GoogleProvider::new(client_id, client_secret, redirect_url) -> Result<Self>` (same shape for `valo_core::oauth::github::GithubProvider::new`).
- `valo_axum::{ValoRouter, TokenDelivery::{Bearer, Cookie}}`; `ValoRouter::new(valo).token_delivery(..).cookie_secure(bool).into_router() -> axum::Router`. Routes (unprefixed): `POST /signup`, `GET /verify?token=`, `POST /signin`, `POST /refresh`, `POST /signout`, `POST /signout-all`, `GET /oauth/{provider}`, `GET /oauth/{provider}/callback`, `POST /mfa/enroll`, `POST /mfa/confirm`, `POST /mfa/complete`, `POST /mfa/disable`.
- HTTP shapes: signup/signin body `{"email","password"}`; signup→`204`; verify→`204`; signin (Bearer)→`200 {"access_token","refresh_token","access_expires_in"}`; signin when MFA enrolled→`200 {"mfa_required":true,"mfa_token":"..."}`; refresh body `{"refresh_token"}`→`200` (new tokens); signout body `{"refresh_token"}`→`204`; signout-all needs `Authorization: Bearer <access>` (or `valo_access` cookie)→`204`; mfa/enroll (auth'd)→`200 {"otpauth_url","secret_base32"}`; mfa/confirm body `{"code"}`→`200 {"recovery_codes":[...]}`; mfa/complete body `{"mfa_token","code"}`→`200` session.
- The verification URL valo builds is `{base_url}/auth/verify?token=<token>`; examples only extract the `token=` value and call their own `/verify` route, so `base_url` host is irrelevant to the self-tests.

---

## Task 1: Library target, shared helpers, and dependencies

**Files:**
- Modify: `examples/valo-axum-examples/Cargo.toml`
- Create: `examples/valo-axum-examples/src/lib.rs`
- Create: `examples/valo-axum-examples/src/common.rs`

- [ ] **Step 1: Add dependencies + feature flags to `Cargo.toml`**

Replace the entire contents of `examples/valo-axum-examples/Cargo.toml` with:

```toml
[package]
name = "valo-axum-examples"
version = "0.1.0"
edition = "2024"
publish = false

[features]
# Each enables the matching built-in mailer in valo-core, exercised by the
# `mailer_providers` example (and the Resend snippet in src/main.rs).
resend = ["valo-core/resend"]
sendgrid = ["valo-core/sendgrid"]
ses = ["valo-core/ses"]
smtp = ["valo-core/smtp"]

[dependencies]
valo-core = { path = "../../crates/valo-core" }
valo-axum = { path = "../../crates/valo-axum" }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
# rustls only — never pull OpenSSL. cookie_store powers the cookie_mode example.
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "cookies"] }
# default-features = false drops the `otpauth` feature so TOTP::new is the
# 5-arg form (algorithm, digits, skew, step, secret) used by the mfa example.
totp-rs = { version = "5.7", default-features = false }
# Mints a throwaway Ed25519 keypair (PKCS#8/SPKI PEM) for the eddsa example.
ed25519-dalek = { version = "2", features = ["pkcs8", "rand_core"] }
rand = "0.8"
```

NOTE: `reqwest 0.12` and `rand 0.8` are the versions already resolved in the workspace `Cargo.lock` for valo-core's tree; if `cargo build` reports a version conflict, match whatever `grep -E '^name = "(reqwest|rand|ed25519-dalek)"' -A1 Cargo.lock` shows for the existing lock entries rather than forcing a new major.

- [ ] **Step 2: Create the library target `src/lib.rs`**

```rust
//! Shared helpers for the valo example binaries. Adding this lib target lets the
//! `examples/*.rs` files `use valo_axum_examples::common::...`.

pub mod common;
```

- [ ] **Step 3: Create `src/common.rs` with the shared helpers**

```rust
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
```

- [ ] **Step 4: Verify it compiles and pulls no OpenSSL**

Run: `cargo build -p valo-axum-examples --lib`
Expected: compiles clean (the existing `src/main.rs` binary still builds too).

Run: `cargo tree -i openssl-sys -p valo-axum-examples`
Expected: `error: package ID specification ... did not match any packages` OR `nothing depends on openssl-sys` — i.e. NO openssl in the tree. If openssl-sys appears, a dep brought it in (most likely a missing `default-features = false`); fix the offending dependency before proceeding.

- [ ] **Step 5: Checkpoint (no git — per standing constraint)**

Confirm `cargo build -p valo-axum-examples --lib` is green and openssl-sys is absent. Do NOT commit.

---

## Batch A (parallel-safe): Tasks 2–10

Tasks 2 through 10 each create a single, independent `examples/<name>.rs` file and touch nothing else. They may be dispatched in parallel after Task 1 is green. Each ends by running/building that one example. The only shared file (`Cargo.toml`) is already finalized in Task 1, so there is no write contention.

---

## Task 2: `password_flow` example (HTTP, self-verifying)

**Files:**
- Create: `examples/valo-axum-examples/examples/password_flow.rs`

- [ ] **Step 1: Write the example**

```rust
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
```

- [ ] **Step 2: Run it (containers must be up)**

Run: `docker start valo-postgres valo-redis && cargo run -p valo-axum-examples --example password_flow`
Expected: prints `password_flow: OK` and exits 0. Any assertion failure panics (non-zero exit) and names the failed step.

- [ ] **Step 3: Checkpoint** — example prints OK. Do NOT commit.

---

## Task 3: `cookie_mode` example (HTTP, self-verifying)

**Files:**
- Create: `examples/valo-axum-examples/examples/cookie_mode.rs`

- [ ] **Step 1: Write the example**

```rust
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
```

- [ ] **Step 2: Run it**

Run: `docker start valo-postgres valo-redis && cargo run -p valo-axum-examples --example cookie_mode`
Expected: prints `cookie_mode: OK`, exits 0.

- [ ] **Step 3: Checkpoint** — Do NOT commit.

---

## Task 4: `rate_limiting` example (HTTP, self-verifying)

**Files:**
- Create: `examples/valo-axum-examples/examples/rate_limiting.rs`

- [ ] **Step 1: Write the example**

```rust
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
```

NOTE: the per-IP counter lives in Redis keyed by client IP for a 60s window. Because every run uses the same loopback IP, re-running this example within the same 60s window may make the FIRST request already 429. If the assertions ever flake for that reason, flush the throwaway Redis (`docker exec valo-redis redis-cli FLUSHALL`) between runs, or wait out the window. The CI invocation in Task 12 runs it once on a fresh container, so this is only a local re-run concern — leave the assertions strict.

- [ ] **Step 2: Run it (on a fresh/clean Redis window)**

Run: `docker start valo-postgres valo-redis && docker exec valo-redis redis-cli FLUSHALL && cargo run -p valo-axum-examples --example rate_limiting`
Expected: prints `rate_limiting: OK (statuses = [401, 401, 429])`, exits 0.

- [ ] **Step 3: Checkpoint** — Do NOT commit.

---

## Task 5: `strict_revocation` example (core handle, self-verifying)

**Files:**
- Create: `examples/valo-axum-examples/examples/strict_revocation.rs`

- [ ] **Step 1: Write the example**

```rust
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
```

- [ ] **Step 2: Run it**

Run: `docker start valo-postgres valo-redis && cargo run -p valo-axum-examples --example strict_revocation`
Expected: prints `strict_revocation: OK`, exits 0.

- [ ] **Step 3: Checkpoint** — Do NOT commit.

---

## Task 6: `mfa_totp` example (HTTP + totp-rs, self-verifying)

**Files:**
- Create: `examples/valo-axum-examples/examples/mfa_totp.rs`

- [ ] **Step 1: Confirm the totp-rs code-generation API**

valo-core's TOTP is `Algorithm::SHA1`, 6 digits, 30s step, skew 1 (verified in `crates/valo-core/src/crypto/totp.rs`). With `totp-rs` built `default-features = false`, the constructor is the 5-arg form: `TOTP::new(Algorithm, digits: usize, skew: u8, step: u64, secret: Vec<u8>)`, and the current code comes from `.generate_current() -> Result<String, _>`. The secret bytes come from the base32 string via `Secret::Encoded(secret_base32).to_bytes().unwrap()`. If `default-features = false` still requires issuer/account (i.e. the `otpauth` feature is on by a transitive default), use `TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret_bytes)` instead (the `_unchecked` constructor never takes issuer/account). Confirm against the resolved `totp-rs` version in `Cargo.lock` before finalizing.

- [ ] **Step 2: Write the example**

```rust
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
    // If this 5-arg form fails to compile, see Task 6 Step 1 (use new_unchecked).
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes).expect("totp params valid");
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
```

NOTE on timing: enrollment and completion compute a code at slightly different wall-clock moments; valo verifies with `skew = 1` (±1 step), so a code generated up to ~30s earlier still validates. No artificial sleeps needed.

- [ ] **Step 3: Run it**

Run: `docker start valo-postgres valo-redis && cargo run -p valo-axum-examples --example mfa_totp`
Expected: prints `mfa_totp: OK`, exits 0.

- [ ] **Step 4: Checkpoint** — Do NOT commit.

---

## Task 7: `eddsa_signing` example (core handle + ed25519-dalek, self-verifying)

**Files:**
- Create: `examples/valo-axum-examples/examples/eddsa_signing.rs`

- [ ] **Step 1: Confirm the ed25519-dalek PEM-export API**

The example mints a throwaway Ed25519 keypair and serializes it to the PEM forms `jwt_eddsa(private_pem, public_pem)` expects: a PKCS#8 private PEM and an SPKI public PEM. With `ed25519-dalek = { features = ["pkcs8", "rand_core"] }`, the intended calls are `SigningKey::generate(&mut OsRng)`, then `signing_key.to_pkcs8_pem(LineEnding::LF)` (from the `pkcs8::EncodePrivateKey` trait) and `signing_key.verifying_key().to_public_key_pem(LineEnding::LF)` (from `pkcs8::EncodePublicKey` / `spki::EncodePublicKey`). The traits and `LineEnding` are re-exported under `ed25519_dalek::pkcs8::*`. Confirm the exact paths against the resolved `ed25519-dalek` version's docs before finalizing; if `to_public_key_pem` is gated behind a separate `spki` re-export, import it from `ed25519_dalek::pkcs8::spki::EncodePublicKey`.

- [ ] **Step 2: Write the example**

```rust
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
```

- [ ] **Step 3: Run it**

Run: `docker start valo-postgres valo-redis && cargo run -p valo-axum-examples --example eddsa_signing`
Expected: prints `eddsa_signing: OK`, exits 0. If it fails to COMPILE on the PEM-export imports, fix the trait paths per Step 1 (the runtime logic is correct).

- [ ] **Step 4: Checkpoint** — Do NOT commit.

---

## Task 8: `custom_templates` example (self-verifying)

**Files:**
- Create: `examples/valo-axum-examples/examples/custom_templates.rs`

- [ ] **Step 1: Write the example**

```rust
//! Custom email templates, self-verifying. Shows the closure shape the built-in
//! providers accept via `.with_templates(...)`: `Fn(&EmailKind, &str) ->
//! (subject, html)`. A `branded` closure overrides the Verification copy and
//! falls back to valo's `default_template` for other kinds. Under
//! `--features resend`, the same closure is attached to a real ResendMailer.
//!
//! Run (no DB/Redis needed — pure template logic):
//!   cargo run -p valo-axum-examples --example custom_templates
//!   cargo run -p valo-axum-examples --example custom_templates --features resend

use valo_core::mail::{default_template, EmailKind};

/// Branded Verification copy; everything else falls back to valo's default.
fn branded(kind: &EmailKind, url: &str) -> (String, String) {
    match kind {
        EmailKind::Verification => (
            "Welcome to Acme — confirm your email".to_string(),
            format!("<h1>Welcome to Acme</h1><p><a href=\"{url}\">Verify my email</a></p>"),
        ),
        _ => default_template(kind, url),
    }
}

fn main() {
    // 1. The default template covers both kinds.
    let (subj, html) = default_template(&EmailKind::Verification, "https://app/verify?token=abc");
    assert_eq!(subj, "Verify your email");
    assert!(html.contains("https://app/verify?token=abc"));

    // 2. The branded closure overrides Verification...
    let (subj, html) = branded(&EmailKind::Verification, "https://app/verify?token=abc");
    assert_eq!(subj, "Welcome to Acme — confirm your email");
    assert!(html.contains("Welcome to Acme"));
    assert!(html.contains("https://app/verify?token=abc"));

    // 3. ...and falls back to the default for PasswordReset.
    let (subj, _html) = branded(&EmailKind::PasswordReset, "https://app/reset?token=xyz");
    assert_eq!(subj, "Reset your password");

    // 4. Under --features resend, attach the same closure to a real provider.
    //    (Constructed only; not sent — no network, no API key needed.)
    #[cfg(feature = "resend")]
    {
        let _mailer = valo_core::mail::ResendMailer::new("re_dev_key", "no-reply@acme.test")
            .with_templates(branded);
        println!("custom_templates: resend provider built with branded templates");
    }

    println!("custom_templates: OK");
}
```

- [ ] **Step 2: Run it (default build, then with the resend feature)**

Run: `cargo run -p valo-axum-examples --example custom_templates`
Expected: prints `custom_templates: OK`, exits 0.

Run: `cargo run -p valo-axum-examples --example custom_templates --features resend`
Expected: prints the resend line AND `custom_templates: OK`, exits 0.

- [ ] **Step 3: Checkpoint** — Do NOT commit.

---

## Task 9: `oauth_providers` example (env-gated, manual)

**Files:**
- Create: `examples/valo-axum-examples/examples/oauth_providers.rs`

- [ ] **Step 1: Write the example**

```rust
//! OAuth wiring (Google + GitHub), env-gated. This one needs REAL credentials
//! and a browser, so it can't self-test. It registers whichever providers have
//! credentials in the environment, prints the authorize URLs, and serves the
//! router so you can click through. With no credentials set it explains what to
//! do and exits 0.
//!
//! Register the apps first:
//!   - Google: https://console.cloud.google.com/apis/credentials  (OAuth client)
//!   - GitHub: https://github.com/settings/developers              (OAuth App)
//!   Authorized redirect/callback URIs (must match exactly):
//!     http://127.0.0.1:4000/oauth/google/callback
//!     http://127.0.0.1:4000/oauth/github/callback
//!
//! Then run:
//!   export GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...
//!   export GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=...
//!   docker start valo-postgres valo-redis
//!   cargo run -p valo-axum-examples --example oauth_providers
//! Open http://127.0.0.1:4000/oauth/google (or .../github) in a browser.

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
```

- [ ] **Step 2: Verify it builds, and runs cleanly with no credentials**

Run: `cargo build -p valo-axum-examples --example oauth_providers`
Expected: compiles clean.

Run (no OAuth env vars set): `docker start valo-postgres valo-redis && cargo run -p valo-axum-examples --example oauth_providers`
Expected: prints the "no OAuth credentials found" guidance and exits 0 (does NOT bind a port or hang).

- [ ] **Step 3: Checkpoint** — Do NOT commit. (Live browser click-through is optional and requires real apps; not part of automated verification.)

---

## Task 10: `mailer_providers` example (feature-gated construction)

**Files:**
- Create: `examples/valo-axum-examples/examples/mailer_providers.rs`

- [ ] **Step 1: Write the example**

```rust
//! Built-in mailer providers. Each provider lives behind its own feature flag
//! and needs real credentials to actually send, so this example only CONSTRUCTS
//! whichever providers are enabled (compile-checking their public API) and
//! prints what it built. No network calls are made.
//!
//! Run with any combination of features:
//!   cargo run -p valo-axum-examples --example mailer_providers --features resend
//!   cargo run -p valo-axum-examples --example mailer_providers --features "resend smtp"
//!   cargo run -p valo-axum-examples --example mailer_providers \
//!       --features "resend sendgrid ses smtp"
//! With no mailer features it prints guidance and exits 0.

fn main() {
    let mut built: Vec<&str> = Vec::new();

    #[cfg(feature = "resend")]
    {
        let _m = valo_core::mail::ResendMailer::new("re_dev_key", "no-reply@example.test");
        built.push("resend");
    }
    #[cfg(feature = "sendgrid")]
    {
        let _m = valo_core::mail::SendgridMailer::new("SG.dev_key", "no-reply@example.test");
        built.push("sendgrid");
    }
    #[cfg(feature = "smtp")]
    {
        let _m = valo_core::mail::SmtpMailer::new(
            "smtp.example.com",
            "user",
            "pass",
            "App <no-reply@example.com>",
        )
        .expect("smtp transport config");
        built.push("smtp");
    }
    // SES needs an async AWS client; construct it under tokio when enabled.
    #[cfg(feature = "ses")]
    {
        built.push("ses");
    }

    if built.is_empty() {
        println!(
            "mailer_providers: no mailer features enabled.\n\
             Re-run with e.g. --features resend (or sendgrid/ses/smtp)."
        );
        return;
    }
    println!("mailer_providers: constructed providers -> {built:?}");
}
```

NOTE on `ses`: `SesMailer::from_env` is `async` and reads the AWS credential chain, so it isn't constructed in this sync `main`. The `ses` feature still compile-checks the SES module via valo-core. If you want to additionally exercise `SesMailer::new` here, convert `main` to `#[tokio::main] async fn main()` and call `valo_core::mail::SesMailer::from_env("no-reply@example.test").await` under `#[cfg(feature = "ses")]` — but that requires AWS config present, so it is intentionally left out of the default verification path.

VERIFY the constructor signatures before finalizing: confirm `SendgridMailer::new(api_key, from)` and `ResendMailer::new(api_key, from)` argument order against `crates/valo-core/src/mail/sendgrid.rs` and `resend.rs` (SMTP and SES are already confirmed: `SmtpMailer::new(host, username, password, from) -> Result`, `SesMailer::new(client, from)` / `from_env(from).await`). Adjust the calls if the resend/sendgrid signatures differ.

- [ ] **Step 2: Verify it builds and runs per feature**

Run: `cargo run -p valo-axum-examples --example mailer_providers`
Expected: prints the "no mailer features enabled" guidance, exits 0.

Run: `cargo run -p valo-axum-examples --example mailer_providers --features "resend smtp"`
Expected: prints `mailer_providers: constructed providers -> ["resend", "smtp"]`, exits 0.

Run (confirm no OpenSSL crept in via a provider): `cargo tree -i openssl-sys -p valo-axum-examples --features "resend sendgrid ses smtp"`
Expected: nothing depends on openssl-sys.

- [ ] **Step 3: Checkpoint** — Do NOT commit.

---

## Task 11: README index of examples

**Files:**
- Modify: `examples/valo-axum-examples/README.md`

- [ ] **Step 1: Add an examples index near the top of the README**

Insert this section after the README's existing intro/title (keep the existing curl walkthrough for the `src/main.rs` kitchen-sink server below it):

```markdown
## Feature examples

Each file under `examples/` is a focused, runnable demonstration of one valo
feature. Most are **self-verifying**: they spin up the real router on an
ephemeral port, drive it, assert every step, and exit non-zero on failure.

Start the throwaway containers first (Postgres :5440, Redis :6390):

    docker start valo-postgres valo-redis

| Example | What it shows | Self-verifying | Run |
| --- | --- | --- | --- |
| `password_flow` | signup → verify → signin → refresh (rotation) → reuse-rejection → signout | yes | `cargo run -p valo-axum-examples --example password_flow` |
| `cookie_mode` | HttpOnly cookie token delivery; protected route via cookie | yes | `cargo run -p valo-axum-examples --example cookie_mode` |
| `rate_limiting` | per-IP limiter trips a 429 before password hashing | yes¹ | `cargo run -p valo-axum-examples --example rate_limiting` |
| `strict_revocation` | strict verify + `signout_all` instant revocation | yes | `cargo run -p valo-axum-examples --example strict_revocation` |
| `mfa_totp` | TOTP enroll → confirm → MFA-gated signin → complete | yes | `cargo run -p valo-axum-examples --example mfa_totp` |
| `eddsa_signing` | EdDSA-signed sessions (asymmetric keypair) | yes | `cargo run -p valo-axum-examples --example eddsa_signing` |
| `custom_templates` | branded email templates + `with_templates` | yes | `cargo run -p valo-axum-examples --example custom_templates` |
| `oauth_providers` | Google/GitHub wiring; live browser click-through | no² | `cargo run -p valo-axum-examples --example oauth_providers` |
| `mailer_providers` | construct Resend/SendGrid/SES/SMTP mailers | no³ | `cargo run -p valo-axum-examples --example mailer_providers --features resend` |

¹ Re-running within the 60s rate-limit window can pre-trip the limiter; flush
the throwaway Redis between local runs: `docker exec valo-redis redis-cli FLUSHALL`.
² Needs real OAuth credentials + a browser; prints guidance and exits cleanly
without them.
³ Needs provider feature flags (`--features resend|sendgrid|ses|smtp`) and real
keys to send; the example only constructs the providers.
```

- [ ] **Step 2: Verify the table matches reality**

Confirm every example name in the table corresponds to a file created in Tasks 2–10 and every run command is correct. No code to run here.

- [ ] **Step 3: Checkpoint** — Do NOT commit.

---

## Task 12: Full verification sweep

**Files:** none (verification only)

- [ ] **Step 1: Build everything, including all examples and optional features**

Run: `cargo build -p valo-axum-examples --examples`
Expected: every example compiles.

Run: `cargo build -p valo-axum-examples --examples --features "resend sendgrid ses smtp"`
Expected: every example compiles with all mailer providers enabled.

- [ ] **Step 2: Clippy is clean on the examples package**

Run: `cargo clippy -p valo-axum-examples --examples --all-features -- -D warnings`
Expected: no warnings, no errors.

- [ ] **Step 3: Run every self-verifying example against fresh containers**

Run:
```bash
docker start valo-postgres valo-redis
docker exec valo-redis redis-cli FLUSHALL
for ex in password_flow cookie_mode rate_limiting strict_revocation mfa_totp eddsa_signing custom_templates; do
  echo "=== $ex ===";
  cargo run -q -p valo-axum-examples --example "$ex" || { echo "FAILED: $ex"; exit 1; };
done
echo "=== oauth_providers (no-creds path) ==="
cargo run -q -p valo-axum-examples --example oauth_providers
echo "=== mailer_providers (with features) ==="
cargo run -q -p valo-axum-examples --example mailer_providers --features "resend smtp"
```
Expected: each self-verifying example prints `<name>: OK`; `oauth_providers` prints the no-credentials guidance and exits; `mailer_providers` prints the constructed list. The loop exits 0.

- [ ] **Step 4: Confirm no OpenSSL anywhere in the examples tree**

Run: `cargo tree -i openssl-sys -p valo-axum-examples --all-features`
Expected: nothing depends on openssl-sys (all-rustls maintained).

- [ ] **Step 5: Final checkpoint** — Report results to the user. Do NOT commit (standing constraint: the user runs git themselves).

---

## Self-Review notes

- **Spec coverage:** password auth (T2), token delivery modes Bearer+Cookie (T2/T3), rate limiting (T4), strict revocation + `signout_all` (T5), MFA/TOTP full lifecycle (T6), EdDSA signing (T7), custom email templates + `with_templates` (T8), OAuth Google/GitHub wiring (T9), all four mailer providers (T10), plus a discoverability README (T11) and a full verification sweep (T12). Every public builder method and every router route is exercised by at least one example.
- **No git:** all commit steps intentionally removed and replaced with checkpoints, per the user's standing instruction.
- **Type consistency:** `CapturingMailer`, `common::serve`, `common::db_urls`, `mailer.last_token()` are defined once (T1) and used verbatim by every example. `Claims.sub` is used as a `Uuid` (T5), matching the verified struct. `SigninOutcome` matched exhaustively everywhere it's used.
- **Assumption flags:** two crate APIs not already in valo are explicitly flagged for verification before finalizing — `totp-rs` code generation (T6 Step 1, with `new_unchecked` fallback) and `ed25519-dalek` PEM export (T7 Step 1). The resend/sendgrid constructor signatures are flagged for confirmation in T10.
- **All-rustls:** new deps pinned with `default-features = false` + explicit rustls features; verified with `cargo tree -i openssl-sys` in T1, T10, and T12.
