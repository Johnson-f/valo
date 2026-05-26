use async_trait::async_trait;
use serde_json::json;

use crate::mail::{default_template, EmailKind, EmailTemplate, Mailer, OutgoingEmail};

const SEND_URL: &str = "https://api.sendgrid.com/v3/mail/send";

/// Sends transactional email via SendGrid's v3 Mail Send API using the core
/// `reqwest` client (rustls). Construct with your API key and a verified `from`.
pub struct SendgridMailer {
    http: reqwest::Client,
    api_key: String,
    from: String,
    templates: EmailTemplate,
}

impl SendgridMailer {
    pub fn new(api_key: &str, from: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: api_key.to_string(),
            from: from.to_string(),
            templates: Box::new(default_template),
        }
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
impl Mailer for SendgridMailer {
    async fn send(&self, email: OutgoingEmail) -> Result<(), String> {
        let (subject, html) = (self.templates)(&email.kind, &email.url);
        let body = json!({
            "personalizations": [{ "to": [{ "email": email.to }] }],
            "from": { "email": self.from },
            "subject": subject,
            "content": [{ "type": "text/html", "value": html }],
        });
        let resp = self
            .http
            .post(SEND_URL)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(format!("sendgrid returned {status}: {detail}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn _assert_impls_mailer<M: Mailer>() {}

    #[test]
    fn sendgrid_mailer_implements_mailer() {
        _assert_impls_mailer::<SendgridMailer>();
        let _ = SendgridMailer::new("SG.test", "noreply@example.com");
    }
}
