use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message as LettreMessage, Tokio1Executor};

use crate::mail::{default_template, EmailKind, EmailTemplate, Mailer, OutgoingEmail};

/// Sends transactional email over SMTP using `lettre` (async, rustls). Works
/// with any SMTP relay (Mailgun/SES-SMTP/Postmark/Gmail/etc). Construct with the
/// relay host, username/password, and a `from` address (e.g. "App <no-reply@x.com>").
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
    templates: EmailTemplate,
}

impl SmtpMailer {
    pub fn new(host: &str, username: &str, password: &str, from: &str) -> Result<Self, String> {
        let creds = Credentials::new(username.to_string(), password.to_string());
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| e.to_string())?
            .credentials(creds)
            .build();
        Ok(Self { transport, from: from.to_string(), templates: Box::new(default_template) })
    }

    /// Override the default subject/body templates with your own renderer.
    pub fn with_templates<F>(mut self, render: F) -> Self
    where
        F: Fn(&EmailKind, &str) -> (String, String) + Send + Sync + 'static,
    {
        self.templates = Box::new(render);
        self
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String> {
        let (subject, html) = (self.templates)(&email.kind, &email.url);
        let message = LettreMessage::builder()
            .from(self.from.parse().map_err(|e: lettre::address::AddressError| e.to_string())?)
            .to(email.to.parse().map_err(|e: lettre::address::AddressError| e.to_string())?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html)
            .map_err(|e| e.to_string())?;
        self.transport.send(message).await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn _assert_impls_mailer<M: Mailer>() {}

    #[tokio::test]
    async fn smtp_mailer_implements_mailer() {
        _assert_impls_mailer::<SmtpMailer>();
        // relay() builds a transport config without connecting; drop inside a
        // tokio runtime so the pool's internal spawn in Drop doesn't panic.
        let _ = SmtpMailer::new("smtp.example.com", "user", "pass", "App <no-reply@example.com>").unwrap();
    }
}
