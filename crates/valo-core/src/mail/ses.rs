use async_trait::async_trait;
use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};
use aws_sdk_sesv2::Client;

use crate::mail::{default_template, EmailKind, EmailTemplate, Mailer, OutgoingEmail};

/// Sends transactional email via Amazon SES v2 using the official
/// `aws-sdk-sesv2` crate. Build with a pre-configured SES `Client` (see
/// `from_env`) and a verified `from` address.
pub struct SesMailer {
    client: Client,
    from: String,
    templates: EmailTemplate,
}

impl SesMailer {
    /// Build from an already-configured SES client.
    pub fn new(client: Client, from: &str) -> Self {
        Self { client, from: from.to_string(), templates: Box::new(default_template) }
    }

    /// Convenience: load AWS config from the standard environment/credential
    /// chain. AWS SDK 1.x requires an explicit behavior version.
    pub async fn from_env(from: &str) -> Self {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        Self::new(Client::new(&config), from)
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
impl Mailer for SesMailer {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String> {
        let (subject, html) = (self.templates)(&email.kind, &email.url);

        let subject_content = Content::builder()
            .data(subject)
            .charset("UTF-8")
            .build()
            .map_err(|e| e.to_string())?;
        let html_content = Content::builder()
            .data(html)
            .charset("UTF-8")
            .build()
            .map_err(|e| e.to_string())?;

        let body = Body::builder().html(html_content).build();
        let message = Message::builder().subject(subject_content).body(body).build();
        let content = EmailContent::builder().simple(message).build();
        let destination = Destination::builder().to_addresses(email.to).build();

        self.client
            .send_email()
            .from_email_address(&self.from)
            .destination(destination)
            .content(content)
            .send()
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
    fn ses_mailer_implements_mailer() {
        _assert_impls_mailer::<SesMailer>();
    }
}
