use async_trait::async_trait;
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::Resend;

use crate::mail::{default_template, EmailKind, EmailTemplate, Mailer, OutgoingEmail};

/// Sends transactional email via Resend (https://resend.com) using the official
/// `resend-rs` crate. Construct with your API key and a verified `from` address.
pub struct ResendMailer {
    client: Resend,
    from: String,
    templates: EmailTemplate,
}

impl ResendMailer {
    pub fn new(api_key: &str, from: &str) -> Self {
        Self {
            client: Resend::new(api_key),
            from: from.to_string(),
            templates: Box::new(default_template),
        }
    }

    /// Override the default subject/body templates with your own renderer
    /// (e.g. branded HTML). Call `valo_core::mail::default_template` inside it to
    /// fall back to the built-in copy for kinds you don't customize.
    pub fn with_templates<F>(mut self, render: F) -> Self
    where
        F: Fn(&EmailKind, &str) -> (String, String) + Send + Sync + 'static,
    {
        self.templates = Box::new(render);
        self
    }
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String> {
        let (subject, html) = (self.templates)(&email.kind, &email.url);
        let options =
            CreateEmailBaseOptions::new(&self.from, [email.to.as_str()], &subject).with_html(&html);
        self.client
            .emails
            .send(options)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn _assert_impls_mailer<M: Mailer>() {}

    #[test]
    fn resend_mailer_implements_mailer() {
        _assert_impls_mailer::<ResendMailer>();
        // construction does no I/O; the template override is composable
        let _ = ResendMailer::new("re_test_key", "noreply@example.com")
            .with_templates(|kind, url| match kind {
                EmailKind::Verification => ("Welcome!".into(), format!("verify: {url}")),
                _ => default_template(kind, url),
            });
    }
}
