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
