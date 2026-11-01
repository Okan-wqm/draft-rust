//! Delivery of one notification outbox row (NTF-03, NTF-04).
//!
//! [`NotificationDeliverer`] does not depend on `authn-audit`: it receives
//! the fields of a claimed outbox row as a [`DeliveryRequest`] and reports
//! the outcome as `Ok(())` or a [`DeliveryFailure`]. `authn-server`
//! registers a small bridge (an `authn_audit::OutboxHandler` for the
//! `notification` topic prefix) that maps
//! [`DeliveryFailure::Retry`] → `HandlerError::Retry` and
//! [`DeliveryFailure::Permanent`] → `HandlerError::Permanent` (see
//! `README.md`).
//!
//! Classification:
//!
//! | Situation | Outcome |
//! |-----------|---------|
//! | Transport timeout, connection/TLS failure, SMTP 4xx, SMTP auth failure, SMS 408/425/429/5xx (`service_unavailable`) | `Retry` (with the provider's `Retry-After` when known) |
//! | KEK of the sealed payload not configured (yet / any more) | `Retry` |
//! | SMTP 5xx (bad recipient, policy rejection), SMS 4xx (`delivery_rejected`) | `Permanent` |
//! | No SMS provider (`sms_unavailable`) | `Permanent` |
//! | Unknown topic, malformed / unsupported payload, missing or tampered sealed payload, payload mismatch | `Permanent` |
//! | Link or code already expired at delivery time | `Permanent` (never send a dead link) |
//! | Template or token/code format error | `Permanent` |
//!
//! Reasons are static strings: no address, token, code or provider message
//! ever reaches `outbox.last_error` or the logs.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use authn_core::error::{AuthError, codes};
use authn_core::id::OutboxMessageId;
use authn_core::ports::{
    Clock, EmailMessage, EmailTransport, Notification, SmsMessage, SmsNotification, SmsSender,
};
use authn_crypto::CryptoError;
use authn_crypto::envelope::EnvelopeCipher;
use serde_json::Value;
use zeroize::Zeroize;

use crate::outbox::{
    Channel, EMAIL_TOPIC, PAYLOAD_VERSION, PublicPayload, SMS_TOPIC, SealedDocument, SealedMessage,
    sealed_payload_context,
};
use crate::sanitize::{self, MAX_NAME_CHARS};
use crate::templates::{TemplateRenderer, deliver_before, sms_deliver_before};

/// The fields of a claimed outbox row.
#[derive(Clone, Copy)]
pub struct DeliveryRequest<'a> {
    /// Message id (`outbox.id`): AAD of the sealed payload and Message-ID
    /// seed.
    pub id: OutboxMessageId,
    /// Topic (`notification.email` / `notification.sms`).
    pub topic: &'a str,
    /// Non-secret payload (`outbox.payload`).
    pub payload: &'a Value,
    /// Sealed payload (`outbox.sealed_payload`).
    pub sealed_payload: Option<&'a [u8]>,
    /// Attempt number of this delivery (1 = first).
    pub attempt: u32,
    /// Attempts before the dead-letter state.
    pub max_attempts: u32,
}

impl fmt::Debug for DeliveryRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryRequest")
            .field("id", &self.id)
            .field("topic", &self.topic)
            .field("sealed_len", &self.sealed_payload.map(<[u8]>::len))
            .field("attempt", &self.attempt)
            .field("max_attempts", &self.max_attempts)
            .finish_non_exhaustive()
    }
}

/// Why a notification was not delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryFailure {
    /// Temporary: try again later.
    Retry {
        /// Static, non-secret reason (stored in `outbox.last_error`).
        reason: &'static str,
        /// Provider-requested delay, if any.
        retry_after: Option<Duration>,
    },
    /// Can never succeed: dead-letter now.
    Permanent {
        /// Static, non-secret reason.
        reason: &'static str,
    },
}

impl DeliveryFailure {
    const fn retry(reason: &'static str) -> Self {
        Self::Retry {
            reason,
            retry_after: None,
        }
    }

    const fn permanent(reason: &'static str) -> Self {
        Self::Permanent { reason }
    }

    /// Whether the worker should try again.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Retry { .. })
    }

    /// The static reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Retry { reason, .. } | Self::Permanent { reason } => reason,
        }
    }

    /// Maps a transport error: `delivery_rejected` / `sms_unavailable` are
    /// permanent, everything else is retried.
    #[must_use]
    pub fn from_transport_error(err: &AuthError) -> Self {
        if err.is(codes::notify::DELIVERY_REJECTED) {
            Self::permanent("rejected by the provider")
        } else if err.is(codes::notify::SMS_UNAVAILABLE) {
            Self::permanent("no SMS provider configured")
        } else {
            Self::Retry {
                reason: "temporary delivery failure",
                retry_after: err.retry_after(),
            }
        }
    }
}

fn open_error(err: CryptoError) -> DeliveryFailure {
    match err {
        // Configuration (KEK removed or not yet deployed) or transient:
        // an operator can fix it, so keep the message.
        CryptoError::UnknownKey | CryptoError::WorkerUnavailable | CryptoError::Rng => {
            DeliveryFailure::retry("sealing key unavailable")
        }
        _ => DeliveryFailure::permanent("sealed payload cannot be opened"),
    }
}

/// Unseals, renders and sends notification outbox rows.
pub struct NotificationDeliverer {
    cipher: EnvelopeCipher,
    renderer: Arc<TemplateRenderer>,
    email: Arc<dyn EmailTransport>,
    sms: Arc<dyn SmsSender>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for NotificationDeliverer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationDeliverer")
            .field("renderer", &self.renderer)
            .field("sms_configured", &self.sms.is_configured())
            .finish_non_exhaustive()
    }
}

impl NotificationDeliverer {
    /// Creates the deliverer.
    #[must_use]
    pub fn new(
        cipher: EnvelopeCipher,
        renderer: Arc<TemplateRenderer>,
        email: Arc<dyn EmailTransport>,
        sms: Arc<dyn SmsSender>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            cipher,
            renderer,
            email,
            sms,
            clock,
        }
    }

    /// Whether `topic` is delivered by this crate.
    #[must_use]
    pub fn handles(topic: &str) -> bool {
        topic == EMAIL_TOPIC || topic == SMS_TOPIC
    }

    /// Delivers one message. Idempotency: e-mails carry
    /// `Message-ID: <outbox id@domain>`, stable across retries.
    pub async fn deliver(&self, request: DeliveryRequest<'_>) -> Result<(), DeliveryFailure> {
        let result = self.try_deliver(&request).await;
        let channel = match request.topic {
            SMS_TOPIC => "sms",
            _ => "email",
        };
        match &result {
            Ok(()) => {
                metrics::counter!("authn_notifications_delivered_total", "channel" => channel)
                    .increment(1);
            }
            Err(failure) => {
                let class = if failure.is_retryable() {
                    "retry"
                } else {
                    "permanent"
                };
                metrics::counter!(
                    "authn_notification_failures_total",
                    "channel" => channel,
                    "class" => class
                )
                .increment(1);
                tracing::warn!(
                    outbox_id = %request.id,
                    channel,
                    attempt = request.attempt,
                    max_attempts = request.max_attempts,
                    class,
                    reason = failure.reason(),
                    "notification not delivered"
                );
            }
        }
        result
    }

    async fn try_deliver(&self, request: &DeliveryRequest<'_>) -> Result<(), DeliveryFailure> {
        let channel = match request.topic {
            EMAIL_TOPIC => Channel::Email,
            SMS_TOPIC => Channel::Sms,
            _ => return Err(DeliveryFailure::permanent("unknown notification topic")),
        };
        let payload: PublicPayload = serde_json::from_value(request.payload.clone())
            .map_err(|_| DeliveryFailure::permanent("malformed payload"))?;
        if payload.v != PAYLOAD_VERSION {
            return Err(DeliveryFailure::permanent("unsupported payload version"));
        }
        if payload.channel != channel {
            return Err(DeliveryFailure::permanent("payload does not match topic"));
        }
        let sealed = request
            .sealed_payload
            .ok_or(DeliveryFailure::permanent("missing sealed payload"))?;
        let context = sealed_payload_context(request.id)
            .map_err(|_| DeliveryFailure::permanent("invalid message id"))?;
        let plaintext = self
            .cipher
            .open(sealed, &context)
            .await
            .map_err(open_error)?;
        let document: SealedDocument = serde_json::from_slice(plaintext.expose())
            .map_err(|_| DeliveryFailure::permanent("malformed sealed payload"))?;
        drop(plaintext);
        if document.v != PAYLOAD_VERSION {
            return Err(DeliveryFailure::permanent("unsupported payload version"));
        }
        if document.message.channel() != channel {
            return Err(DeliveryFailure::permanent("payload does not match topic"));
        }
        match document.message {
            SealedMessage::Email(notification) => {
                if notification.kind.template_name() != payload.template {
                    return Err(DeliveryFailure::permanent(
                        "payload does not match template",
                    ));
                }
                self.deliver_email(request.id, &notification).await
            }
            SealedMessage::Sms(sms) => {
                if sms.kind.template_name() != payload.template {
                    return Err(DeliveryFailure::permanent(
                        "payload does not match template",
                    ));
                }
                self.deliver_sms(&sms).await
            }
        }
    }

    async fn deliver_email(
        &self,
        id: OutboxMessageId,
        notification: &Notification,
    ) -> Result<(), DeliveryFailure> {
        let now = self.clock.now();
        if deliver_before(&notification.kind).is_some_and(|deadline| now >= deadline) {
            return Err(DeliveryFailure::permanent("expired before delivery"));
        }
        let mut rendered = self
            .renderer
            .render_email(notification, now)
            .map_err(|_| DeliveryFailure::permanent("rendering failed"))?;
        let mut message = EmailMessage {
            to: notification.recipient.email.clone(),
            to_name: notification
                .recipient
                .display_name
                .as_deref()
                .map(|name| sanitize::header_value(name, MAX_NAME_CHARS))
                .filter(|name| !name.is_empty()),
            subject: std::mem::take(&mut rendered.subject),
            text_body: std::mem::take(&mut rendered.text),
            html_body: Some(std::mem::take(&mut rendered.html)),
            outbox_id: Some(id),
        };
        let result = self.email.send(&message).await;
        message.text_body.zeroize();
        if let Some(html) = message.html_body.as_mut() {
            html.zeroize();
        }
        result.map_err(|err| DeliveryFailure::from_transport_error(&err))
    }

    async fn deliver_sms(&self, sms: &SmsNotification) -> Result<(), DeliveryFailure> {
        let now = self.clock.now();
        if now >= sms_deliver_before(&sms.kind) {
            return Err(DeliveryFailure::permanent("expired before delivery"));
        }
        if !self.sms.is_configured() {
            return Err(DeliveryFailure::permanent("no SMS provider configured"));
        }
        let body = self
            .renderer
            .render_sms(sms, now)
            .map_err(|_| DeliveryFailure::permanent("rendering failed"))?;
        let message = SmsMessage {
            to: sms.to.clone(),
            body,
        };
        self.sms
            .send(&message)
            .await
            .map(|_| ())
            .map_err(|err| DeliveryFailure::from_transport_error(&err))
    }
}
