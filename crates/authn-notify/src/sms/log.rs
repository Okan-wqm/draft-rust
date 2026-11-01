//! Development SMS sender: logs the masked number and the text with codes
//! redacted. Refused outside development/test.

use async_trait::async_trait;
use authn_core::config::Environment;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{SmsMessage, SmsReceipt, SmsSender};

use super::is_valid_body;
use crate::email::{is_development, redact_secrets};
use crate::error::NotifyError;

/// Logs SMS messages (development only).
#[derive(Debug, Clone, Copy)]
pub struct LogSmsSender {
    _private: (),
}

impl LogSmsSender {
    /// The sender; fails outside development/test.
    pub fn new(environment: Environment) -> Result<Self, NotifyError> {
        if !is_development(environment) {
            return Err(NotifyError::config(
                "notify.sms.provider = \"log\" is only allowed in development and test",
            ));
        }
        Ok(Self { _private: () })
    }
}

#[async_trait]
impl SmsSender for LogSmsSender {
    fn is_configured(&self) -> bool {
        true
    }

    async fn send(&self, message: &SmsMessage) -> Result<SmsReceipt, AuthError> {
        if !is_valid_body(message.body.expose()) {
            return Err(AuthError::new(codes::notify::DELIVERY_REJECTED)
                .with_context("SMS body is empty, too long or contains control characters"));
        }
        tracing::info!(
            to = %message.to.masked(),
            text = %redact_secrets(message.body.expose()),
            "SMS (log sender, code redacted)"
        );
        Ok(SmsReceipt::default())
    }
}
