//! SMS delivery (NTF-04, MFA-06). Owner of this file: authn-notify.
//!
//! Implementations: a generic HTTP provider adapter and a log/test sender.
//! When no provider is configured the `sms` feature behaves as disabled:
//! [`SmsSender::is_configured`] returns `false` and MFA must not offer SMS.
//! SMS pumping protection (country allow-list, budgets) is enforced by
//! `authn-mfa` *before* calling the sender.

use std::fmt;

use async_trait::async_trait;

use crate::domain::PhoneNumber;
use crate::error::AuthError;
use crate::secret::SensitiveString;

/// Sends SMS messages.
#[async_trait]
pub trait SmsSender: Send + Sync {
    /// Whether a real provider is configured.
    fn is_configured(&self) -> bool;

    /// Sends one message.
    async fn send(&self, message: &SmsMessage) -> Result<SmsReceipt, AuthError>;
}

/// An SMS to send.
#[derive(Clone, PartialEq, Eq)]
pub struct SmsMessage {
    /// Destination (E.164).
    pub to: PhoneNumber,
    /// Message text (contains the OTP).
    pub body: SensitiveString,
}

impl fmt::Debug for SmsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmsMessage")
            .field("to", &self.to)
            .finish_non_exhaustive()
    }
}

/// Provider acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmsReceipt {
    /// Provider-side message id, if returned.
    pub provider_message_id: Option<String>,
}
