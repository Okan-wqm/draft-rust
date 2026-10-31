//! Raw e-mail delivery (NTF-03). Owner of this file: authn-notify.
//!
//! Implementations: SMTP via `lettre` with mandatory STARTTLS/TLS, a
//! development log transport (refused in production configuration), and the
//! recording fake in `authn-testkit`. Called by the outbox worker, never on
//! the request path.

use std::fmt;

use async_trait::async_trait;

use crate::domain::EmailAddress;
use crate::error::AuthError;
use crate::id::OutboxMessageId;

/// Delivers a fully rendered e-mail.
#[async_trait]
pub trait EmailTransport: Send + Sync {
    /// Sends one message. Errors are retried by the outbox worker.
    async fn send(&self, message: &EmailMessage) -> Result<(), AuthError>;
}

/// A rendered e-mail.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailMessage {
    /// Recipient.
    pub to: EmailAddress,
    /// Recipient display name.
    pub to_name: Option<String>,
    /// Subject line.
    pub subject: String,
    /// Plain-text body.
    pub text_body: String,
    /// HTML body.
    pub html_body: Option<String>,
    /// Outbox message id, usable as idempotency key / Message-ID seed.
    pub outbox_id: Option<OutboxMessageId>,
}

impl fmt::Debug for EmailMessage {
    /// Bodies contain links and codes: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailMessage")
            .field("to", &self.to)
            .field("subject", &self.subject)
            .field("outbox_id", &self.outbox_id)
            .finish_non_exhaustive()
    }
}
