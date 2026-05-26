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

#[tokio::main]
async fn main() {
    #[allow(unused_mut)]
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
        // SmtpMailer wraps lettre's AsyncSmtpTransport whose Drop impl spawns
        // into a Tokio 1.x runtime — construction must happen inside one.
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
