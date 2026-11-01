//! Development log transport (NTF-03): writes e-mail metadata and the text
//! body to the log with links and codes redacted. Refused in production
//! and staging (also by `AppConfig::validate` for production).

use async_trait::async_trait;
use authn_core::config::Environment;
use authn_core::error::AuthError;
use authn_core::ports::{EmailMessage, EmailTransport};

use super::{is_development, redact_secrets};
use crate::error::NotifyError;

/// Logs e-mails (development only).
#[derive(Debug, Clone, Copy)]
pub struct LogEmailTransport {
    _private: (),
}

impl LogEmailTransport {
    /// The transport; fails outside development/test.
    pub fn new(environment: Environment) -> Result<Self, NotifyError> {
        if !is_development(environment) {
            return Err(NotifyError::config(
                "notify.email.transport = \"log\" is only allowed in development and test",
            ));
        }
        Ok(Self { _private: () })
    }
}

#[async_trait]
impl EmailTransport for LogEmailTransport {
    async fn send(&self, message: &EmailMessage) -> Result<(), AuthError> {
        tracing::info!(
            to = %message.to.masked(),
            subject = %message.subject,
            outbox_id = ?message.outbox_id,
            html = message.html_body.is_some(),
            body = %redact_secrets(&message.text_body),
            "e-mail (log transport, secrets redacted)"
        );
        Ok(())
    }
}
