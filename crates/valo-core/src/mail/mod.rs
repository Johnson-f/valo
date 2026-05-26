use std::sync::Mutex;

use async_trait::async_trait;

#[cfg(feature = "resend")]
pub mod resend;
#[cfg(feature = "resend")]
pub use resend::ResendMailer;

#[cfg(feature = "sendgrid")]
pub mod sendgrid;
#[cfg(feature = "sendgrid")]
pub use sendgrid::SendgridMailer;

#[cfg(feature = "ses")]
pub mod ses;
#[cfg(feature = "ses")]
pub use ses::SesMailer;

#[cfg(feature = "smtp")]
pub mod smtp;
#[cfg(feature = "smtp")]
pub use smtp::SmtpMailer;

/// Which transactional email is being sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailKind {
    Verification,
    PasswordReset,
}

/// A fully-formed email the app must deliver. valo builds `url` with the token baked in.
#[derive(Debug, Clone)]
pub struct OutgoingEmail {
    pub to: String,
    pub kind: EmailKind,
    pub url: String,
}

/// Delivery seam. Apps implement this (or use a built-in provider, follow-on plan).
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String>;
}

/// In-memory mailer for tests: records every email sent.
#[derive(Default)]
pub struct TestMailer {
    pub sent: Mutex<Vec<OutgoingEmail>>,
}

impl TestMailer {
    pub fn new() -> Self {
        Self::default()
    }
    /// Return the last URL sent (panics if none) — convenient in flow tests.
    pub fn last_url(&self) -> String {
        self.sent.lock().unwrap().last().expect("an email was sent").url.clone()
    }
}

#[async_trait]
impl Mailer for TestMailer {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String> {
        self.sent.lock().unwrap().push(email);
        Ok(())
    }
}

/// A subject + HTML-body renderer for a transactional email, keyed by kind + URL.
/// The built-in providers default to [`default_template`]; override per provider
/// via their `with_templates` method to supply your own branded HTML.
pub type EmailTemplate = Box<dyn Fn(&EmailKind, &str) -> (String, String) + Send + Sync>;

/// The default subject + HTML body for a transactional email. Built-in providers
/// use this unless overridden; call it from a custom template to fall back to or
/// compose with the defaults. (The `Mailer` trait only carries the kind + URL,
/// not a rendered message, so providers render here.)
pub fn default_template(kind: &EmailKind, url: &str) -> (String, String) {
    match kind {
        EmailKind::Verification => (
            "Verify your email".to_string(),
            format!("<p>Confirm your email address by clicking <a href=\"{url}\">this link</a>.</p>"),
        ),
        EmailKind::PasswordReset => (
            "Reset your password".to_string(),
            format!("<p>Reset your password using <a href=\"{url}\">this link</a>. If you did not request this, you can ignore this email.</p>"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mailer_records_sends() {
        let m = TestMailer::new();
        m.send(OutgoingEmail {
            to: "a@b.com".into(),
            kind: EmailKind::Verification,
            url: "https://x/verify?token=abc".into(),
        })
        .await
        .unwrap();
        assert_eq!(m.sent.lock().unwrap().len(), 1);
        assert_eq!(m.last_url(), "https://x/verify?token=abc");
    }

    #[test]
    fn default_template_covers_both_kinds() {
        let (subj, html) = default_template(&EmailKind::Verification, "https://app/verify?token=abc");
        assert_eq!(subj, "Verify your email");
        assert!(html.contains("https://app/verify?token=abc"));

        let (subj, html) = default_template(&EmailKind::PasswordReset, "https://app/reset?token=xyz");
        assert_eq!(subj, "Reset your password");
        assert!(html.contains("https://app/reset?token=xyz"));
    }

    #[test]
    fn email_template_can_be_a_custom_closure() {
        let custom: EmailTemplate = Box::new(|_kind, url| ("Hi".into(), format!("go: {url}")));
        let (subj, html) = custom(&EmailKind::Verification, "https://x/v?token=1");
        assert_eq!(subj, "Hi");
        assert_eq!(html, "go: https://x/v?token=1");
    }
}
