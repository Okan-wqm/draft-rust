//! The [`Notifier`] port backed by the transactional outbox (NTF-01,
//! NTF-03, AUD-06).
//!
//! `notify_in_tx` writes **one `outbox` row in the caller's transaction**:
//! the message exists exactly when the state change commits, and the
//! request never waits for SMTP or an SMS provider. Delivery happens later
//! in the outbox worker of `authn-audit` through
//! [`NotificationDeliverer`](crate::NotificationDeliverer) (at least once,
//! retried with backoff, dead-lettered after `notify.max_attempts`).
//!
//! Row layout (topic `notification.email` or `notification.sms`):
//!
//! * `payload` (plain `jsonb`) holds only non-secret routing metadata:
//!   format version, channel, template name, locale, user id and the
//!   **masked** recipient (`a***@example.com`, `+90*******233`).
//! * `sealed_payload` holds the whole notification — recipient address,
//!   display name, tokens, codes — sealed with envelope encryption
//!   (CRY-08). The AAD is `outbox.sealed_payload#<row id>`, so a sealed
//!   payload copied into another row does not open. `authn-audit` wipes the
//!   column when the row is delivered (schema check
//!   `outbox_sealed_wiped_check`).
//!
//! Defence in depth against mail / SMS bombing: user-triggerable kinds
//! (codes, links, invitations, registration notices) are limited per
//! recipient (`notify.recipient_limit`). Excess messages are dropped
//! **silently** — returning an error would let an attacker learn that an
//! address has an account (the producer's response would differ). Security
//! alerts (password changed, new device, MFA changes…) are never throttled.
//!
//! * The recipient is the address with its sub-address tag removed
//!   (`victim+1@example.com` and `victim+2@example.com` share one budget),
//!   otherwise plus-addressing would defeat the limit entirely.
//! * Each message that grants access (password reset, magic link, login
//!   code, MFA codes by e-mail or SMS) has a **budget of its own**; the
//!   remaining kinds (verification, registration notice, invitation,
//!   ownership transfer, phone verification) share one. Otherwise an
//!   attacker could exhaust a victim's shared budget with cheap
//!   registration attempts and silently suppress the victim's sign-in and
//!   second-factor codes (lock-out).

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use authn_core::config::notify::NotifyConfig;
use authn_core::domain::{EmailAddress, Locale};
use authn_core::error::AuthError;
use authn_core::id::{OutboxMessageId, UserId};
use authn_core::ports::{
    Clock, Notification, NotificationKind, Notifier, RateLimitKey, RateLimitPolicy, RateLimiter,
    SmsNotification, SmsNotificationKind,
};
use authn_crypto::CryptoError;
use authn_crypto::envelope::{EnvelopeCipher, EnvelopeContext};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::links::is_valid_token;
use crate::templates::{is_valid_code, secret_parts, sms_code};

/// Topic prefix of every notification message (register the deliverer
/// bridge for it).
pub const NOTIFICATION_TOPIC_PREFIX: &str = "notification";
/// Topic of e-mail notifications.
pub const EMAIL_TOPIC: &str = "notification.email";
/// Topic of SMS notifications.
pub const SMS_TOPIC: &str = "notification.sms";

/// Format version of `payload` and of the sealed document.
pub(crate) const PAYLOAD_VERSION: u8 = 1;
/// Largest sealed document (serialized notification).
pub(crate) const MAX_SEALED_PLAINTEXT: usize = 32 * 1024;
/// Rate-limit action of the per-recipient limit (shared budget of the
/// non-access kinds).
pub const RECIPIENT_LIMIT_ACTION: &str = "notify_recipient";

/// AAD of a sealed notification: table `outbox`, column `sealed_payload`,
/// row = the message id.
pub fn sealed_payload_context(id: OutboxMessageId) -> Result<EnvelopeContext, CryptoError> {
    EnvelopeContext::new("outbox", "sealed_payload", id)
}

/// Delivery channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Channel {
    Email,
    Sms,
}

impl Channel {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }

    pub(crate) const fn topic(self) -> &'static str {
        match self {
            Self::Email => EMAIL_TOPIC,
            Self::Sms => SMS_TOPIC,
        }
    }
}

/// The non-secret `outbox.payload` of a notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicPayload {
    pub(crate) v: u8,
    pub(crate) channel: Channel,
    pub(crate) template: String,
    pub(crate) locale: Locale,
    pub(crate) user_id: Option<UserId>,
    /// Masked recipient, for operators.
    pub(crate) recipient: String,
}

/// The sealed document.
#[derive(Serialize, Deserialize)]
pub(crate) struct SealedDocument {
    pub(crate) v: u8,
    pub(crate) message: SealedMessage,
}

/// The sealed message, tagged by channel.
#[derive(Serialize, Deserialize)]
#[serde(tag = "channel", content = "data", rename_all = "snake_case")]
pub(crate) enum SealedMessage {
    Email(Notification),
    Sms(SmsNotification),
}

impl SealedMessage {
    pub(crate) const fn channel(&self) -> Channel {
        match self {
            Self::Email(_) => Channel::Email,
            Self::Sms(_) => Channel::Sms,
        }
    }
}

/// The per-recipient budget (rate-limit action) of a kind, or `None` when
/// the kind is never throttled. Kinds an unauthenticated or low-privileged
/// party can trigger repeatedly are limited; access-granting kinds have a
/// budget of their own so that cheap kinds cannot starve them.
fn limit_action(kind: &NotificationKind) -> Option<&'static str> {
    match kind {
        NotificationKind::EmailVerification { .. }
        | NotificationKind::RegistrationAttempt
        | NotificationKind::EmailChangeVerification { .. }
        | NotificationKind::Invitation { .. }
        | NotificationKind::OrgOwnershipTransfer { .. } => Some(RECIPIENT_LIMIT_ACTION),
        NotificationKind::PasswordReset { .. } => Some("notify_recipient_password_reset"),
        NotificationKind::MagicLink { .. } => Some("notify_recipient_magic_link"),
        NotificationKind::LoginCode { .. } => Some("notify_recipient_login_code"),
        NotificationKind::MfaEmailCode { .. } => Some("notify_recipient_mfa_email_code"),
        NotificationKind::PasswordChanged { .. }
        | NotificationKind::EmailChanged { .. }
        | NotificationKind::MfaFactorAdded { .. }
        | NotificationKind::MfaFactorRemoved { .. }
        | NotificationKind::MfaReset { .. }
        | NotificationKind::RecoveryCodeUsed { .. }
        | NotificationKind::NewDeviceLogin { .. }
        | NotificationKind::SuspiciousLoginBlocked { .. }
        | NotificationKind::AccountDeletionScheduled { .. }
        | NotificationKind::AccountDeletionCancelled { .. }
        | NotificationKind::ImpersonationStarted { .. } => None,
    }
}

/// [`limit_action`] for SMS: the second-factor code has its own budget so
/// that phone verifications (which anyone with an account can aim at any
/// number) cannot starve it.
const fn sms_limit_action(kind: &SmsNotificationKind) -> &'static str {
    match kind {
        SmsNotificationKind::MfaSmsCode { .. } => "notify_recipient_mfa_sms_code",
        SmsNotificationKind::PhoneVerification { .. } => RECIPIENT_LIMIT_ACTION,
    }
}

/// The mailbox a per-recipient budget is keyed on: the normalized address
/// with its sub-address tag (`+…`) removed, so plus-addressing cannot
/// multiply the budget of one inbox.
fn limit_mailbox(email: &EmailAddress) -> String {
    let normalized = email.normalized();
    match normalized.rsplit_once('@') {
        Some((local, domain)) => {
            let base = local.split_once('+').map_or(local, |(base, _)| base);
            let base = if base.is_empty() { local } else { base };
            format!("{base}@{domain}")
        }
        None => normalized.to_owned(),
    }
}

fn malformed(what: &'static str) -> AuthError {
    AuthError::internal(what)
}

/// Producers must hand over well-formed secrets; a malformed one is a bug
/// that would otherwise only surface at delivery time.
fn validate_email(notification: &Notification) -> Result<(), AuthError> {
    let parts = secret_parts(&notification.kind);
    if !parts.tokens.iter().all(|t| is_valid_token(t.expose())) {
        return Err(malformed("notification token has an invalid format"));
    }
    if !parts.codes.iter().all(|c| is_valid_code(c.expose())) {
        return Err(malformed("notification code has an invalid format"));
    }
    Ok(())
}

/// Enqueues notifications into the outbox. Cheap to clone.
#[derive(Clone)]
pub struct OutboxNotifier {
    pool: PgPool,
    cipher: EnvelopeCipher,
    clock: Arc<dyn Clock>,
    max_attempts: u32,
    recipient_limit: Option<(Arc<dyn RateLimiter>, RateLimitPolicy)>,
}

impl fmt::Debug for OutboxNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboxNotifier")
            .field("max_attempts", &self.max_attempts)
            .field(
                "recipient_limit",
                &self.recipient_limit.as_ref().map(|(_, policy)| policy),
            )
            .finish_non_exhaustive()
    }
}

impl OutboxNotifier {
    /// A notifier with 10 delivery attempts and no recipient limit.
    #[must_use]
    pub fn new(pool: PgPool, cipher: EnvelopeCipher, clock: Arc<dyn Clock>) -> Self {
        Self {
            pool,
            cipher,
            clock,
            max_attempts: 10,
            recipient_limit: None,
        }
    }

    /// Everything from `[notify]`: attempts and the per-recipient limit.
    #[must_use]
    pub fn from_config(
        config: &NotifyConfig,
        pool: PgPool,
        cipher: EnvelopeCipher,
        clock: Arc<dyn Clock>,
        rate_limiter: Arc<dyn RateLimiter>,
    ) -> Self {
        Self::new(pool, cipher, clock)
            .with_max_attempts(config.max_attempts)
            .with_recipient_limit(rate_limiter, config.recipient_limit)
    }

    /// Delivery attempts before the dead-letter state (clamped to 1–100).
    #[must_use]
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts.clamp(1, 100);
        self
    }

    /// Limits user-triggerable messages per recipient.
    #[must_use]
    pub fn with_recipient_limit(
        mut self,
        rate_limiter: Arc<dyn RateLimiter>,
        policy: RateLimitPolicy,
    ) -> Self {
        self.recipient_limit = Some((rate_limiter, policy));
        self
    }

    /// `true` when the message may be enqueued. Limiter failures fail open
    /// (a notification is worth more than a perfect limit).
    async fn admit(&self, key: RateLimitKey, channel: Channel, template: &'static str) -> bool {
        let Some((limiter, policy)) = &self.recipient_limit else {
            return true;
        };
        match limiter.check(&key, *policy, 1).await {
            Ok(decision) if decision.allowed => true,
            Ok(_) => {
                tracing::warn!(
                    channel = channel.as_str(),
                    template,
                    "notification dropped: per-recipient limit reached"
                );
                metrics::counter!(
                    "authn_notifications_dropped_total",
                    "channel" => channel.as_str(),
                    "reason" => "recipient_limit"
                )
                .increment(1);
                false
            }
            Err(err) => {
                tracing::warn!(error = %err, "recipient limit check failed; enqueuing anyway");
                true
            }
        }
    }

    /// Enqueues an e-mail in the caller's transaction. Returns the outbox
    /// id, or `None` when the per-recipient limit dropped the message.
    pub async fn enqueue_email(
        &self,
        conn: &mut PgConnection,
        notification: &Notification,
    ) -> Result<Option<OutboxMessageId>, AuthError> {
        validate_email(notification)?;
        let template = notification.kind.template_name();
        if let Some(action) = limit_action(&notification.kind) {
            let key = RateLimitKey::account(action, &limit_mailbox(&notification.recipient.email));
            if !self.admit(key, Channel::Email, template).await {
                return Ok(None);
            }
        }
        let payload = PublicPayload {
            v: PAYLOAD_VERSION,
            channel: Channel::Email,
            template: template.to_owned(),
            locale: notification.locale,
            user_id: notification.recipient.user_id,
            recipient: notification.recipient.email.masked(),
        };
        let document = SealedDocument {
            v: PAYLOAD_VERSION,
            message: SealedMessage::Email(notification.clone()),
        };
        self.insert(conn, &payload, &document).await.map(Some)
    }

    /// Enqueues an SMS in the caller's transaction. Returns the outbox id,
    /// or `None` when the per-recipient limit dropped the message.
    pub async fn enqueue_sms(
        &self,
        conn: &mut PgConnection,
        sms: &SmsNotification,
    ) -> Result<Option<OutboxMessageId>, AuthError> {
        if !is_valid_code(sms_code(&sms.kind).expose()) {
            return Err(malformed("SMS code has an invalid format"));
        }
        let template = sms.kind.template_name();
        let key = RateLimitKey::phone(sms_limit_action(&sms.kind), &sms.to);
        if !self.admit(key, Channel::Sms, template).await {
            return Ok(None);
        }
        let payload = PublicPayload {
            v: PAYLOAD_VERSION,
            channel: Channel::Sms,
            template: template.to_owned(),
            locale: sms.locale,
            user_id: sms.user_id,
            recipient: sms.to.masked(),
        };
        let document = SealedDocument {
            v: PAYLOAD_VERSION,
            message: SealedMessage::Sms(sms.clone()),
        };
        self.insert(conn, &payload, &document).await.map(Some)
    }

    /// Enqueues an SMS in its own transaction.
    pub async fn notify_sms(&self, sms: SmsNotification) -> Result<(), AuthError> {
        let mut tx = authn_store::begin(&self.pool).await?;
        self.enqueue_sms(&mut tx, &sms).await?;
        authn_store::commit(tx).await
    }

    async fn insert(
        &self,
        conn: &mut PgConnection,
        payload: &PublicPayload,
        document: &SealedDocument,
    ) -> Result<OutboxMessageId, AuthError> {
        let id = OutboxMessageId::generate();
        let sealed = self.seal(id, document).await?;
        let now: OffsetDateTime = self.clock.now();
        let max_attempts = i32::try_from(self.max_attempts)
            .map_err(|_| AuthError::internal("outbox max_attempts out of range"))?;
        sqlx::query(
            "INSERT INTO outbox (id, topic, org_id, payload, sealed_payload, status, attempts, \
             max_attempts, available_at, created_at) \
             VALUES ($1, $2, NULL, $3, $4, 'pending', 0, $5, $6, $6)",
        )
        .bind(id)
        .bind(payload.channel.topic())
        .bind(sqlx::types::Json(payload))
        .bind(sealed.as_slice())
        .bind(max_attempts)
        .bind(now)
        .execute(conn)
        .await?;
        metrics::counter!(
            "authn_notifications_enqueued_total",
            "channel" => payload.channel.as_str()
        )
        .increment(1);
        Ok(id)
    }

    async fn seal(
        &self,
        id: OutboxMessageId,
        document: &SealedDocument,
    ) -> Result<Vec<u8>, AuthError> {
        let plaintext = serialize_bounded(document)?;
        let context = sealed_payload_context(id)?;
        Ok(self.cipher.seal(&plaintext, &context).await?)
    }
}

/// A writer into a pre-sized buffer that refuses to grow it: a reallocation
/// would leave an unzeroized copy of the clear-text secrets on the heap.
struct BoundedWriter<'a>(&'a mut Vec<u8>);

impl std::io::Write for BoundedWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(data.len()) > self.0.capacity() {
            return Err(std::io::Error::other("sealed document too large"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serializes the sealed document into a zeroizing buffer of exactly
/// [`MAX_SEALED_PLAINTEXT`] bytes capacity (never reallocated).
fn serialize_bounded(document: &SealedDocument) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(MAX_SEALED_PLAINTEXT));
    match serde_json::to_writer(BoundedWriter(&mut plaintext), document) {
        Ok(()) => Ok(plaintext),
        Err(err) if err.is_io() => Err(AuthError::internal("notification is too large")),
        Err(_) => Err(AuthError::internal("notification serialization failed")),
    }
}

#[async_trait]
impl Notifier for OutboxNotifier {
    async fn notify(&self, notification: Notification) -> Result<(), AuthError> {
        let mut tx = authn_store::begin(&self.pool).await?;
        self.enqueue_email(&mut tx, &notification).await?;
        authn_store::commit(tx).await
    }

    async fn notify_in_tx(
        &self,
        conn: &mut PgConnection,
        notification: Notification,
    ) -> Result<(), AuthError> {
        self.enqueue_email(conn, &notification).await.map(|_| ())
    }

    async fn notify_sms_in_tx(
        &self,
        conn: &mut PgConnection,
        sms: SmsNotification,
    ) -> Result<(), AuthError> {
        self.enqueue_sms(conn, &sms).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use authn_core::domain::{EmailAddress, Locale};
    use authn_core::ports::Recipient;
    use authn_core::secret::SensitiveString;

    use super::*;

    fn document(org_name_len: usize) -> SealedDocument {
        SealedDocument {
            v: PAYLOAD_VERSION,
            message: SealedMessage::Email(Notification {
                recipient: Recipient {
                    email: EmailAddress::parse("ada@example.com").unwrap(),
                    user_id: None,
                    display_name: None,
                },
                locale: Locale::En,
                kind: NotificationKind::Invitation {
                    org_name: "x".repeat(org_name_len),
                    inviter_name: None,
                    token: SensitiveString::new("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde"),
                    expires_at: time::OffsetDateTime::UNIX_EPOCH,
                },
            }),
        }
    }

    /// Security review: an oversized notification is refused without the
    /// clear-text buffer ever being reallocated (no unzeroized copy).
    #[test]
    fn ntf_01_sealed_plaintext_buffer_never_grows() {
        let ok = serialize_bounded(&document(100)).unwrap();
        assert_eq!(ok.capacity(), MAX_SEALED_PLAINTEXT);
        let mut buffer = Vec::with_capacity(16);
        let mut writer = BoundedWriter(&mut buffer);
        assert!(std::io::Write::write_all(&mut writer, &[0_u8; 17]).is_err());
        assert_eq!(buffer.capacity(), 16, "the buffer must not be reallocated");
        let err = serialize_bounded(&document(MAX_SEALED_PLAINTEXT)).unwrap_err();
        assert!(format!("{err:?}").contains("too large"), "{err:?}");
    }

    #[test]
    fn ntf_01_limit_mailbox_folds_sub_addresses() {
        let mailbox = |s: &str| limit_mailbox(&EmailAddress::parse(s).unwrap());
        assert_eq!(mailbox("Victim+tag@Example.com"), "victim@example.com");
        assert_eq!(mailbox("victim+a+b@example.com"), "victim@example.com");
        assert_eq!(mailbox("victim@example.com"), "victim@example.com");
        assert_eq!(mailbox("+only@example.com"), "+only@example.com");
    }
}
