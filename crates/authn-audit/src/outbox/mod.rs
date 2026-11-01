//! Transactional outbox (AUD-06).
//!
//! * Producers write messages **in their own transaction**
//!   ([`OutboxRepository::enqueue`], [`OutboxEventPublisher`]): a message
//!   exists exactly when the state change commits.
//! * The [`OutboxWorker`] claims due messages with
//!   `FOR UPDATE SKIP LOCKED` (safe with many instances), hands each to the
//!   [`OutboxHandler`] registered for the longest matching topic prefix and
//!   records the outcome: delivered (sealed payload wiped), retried with
//!   exponential backoff + jitter, or moved to the dead-letter state after
//!   `max_attempts`.
//! * Delivery is **at least once**: a handler may see a message again after
//!   a crash or an expired lease. [`OutboxMessage::idempotency_key`] is
//!   stable across attempts.
//!
//! Topics used by this crate: [`DOMAIN_EVENT_TOPIC`] (fan-out to webhooks)
//! and `webhook.delivery`. `authn-notify` enqueues `notification.*` topics
//! itself; the server registers a bridge handler for them.

mod publisher;
mod worker;

use std::fmt;

use authn_core::error::AuthError;
use authn_core::id::{OrgId, OutboxMessageId};
use serde_json::Value;
use sqlx::{PgConnection, PgExecutor, PgPool};
use time::OffsetDateTime;
use zeroize::Zeroize;

pub use publisher::{DOMAIN_EVENT_TOPIC, MAX_DOMAIN_EVENT_BYTES, OutboxEventPublisher};
pub use worker::{
    BatchReport, HandlerError, OutboxHandler, OutboxHandlers, OutboxWorker, backoff_delay, jittered,
};

use crate::sanitize::is_identifier;

/// Maximum length of a topic.
pub const MAX_TOPIC_LEN: usize = 128;

/// Whether `topic` is a valid topic or topic prefix
/// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`, ≤ 128 bytes).
#[must_use]
pub fn is_valid_topic(topic: &str) -> bool {
    topic.len() <= MAX_TOPIC_LEN && topic.split('.').all(|segment| is_identifier(segment, 128))
}

/// Envelope-encrypted secret part of a message (tokens, codes). Opaque to
/// this crate; the producer chooses the AAD (recommended: table `outbox`,
/// column `sealed_payload`, row = message id). Zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPayload(Vec<u8>);

impl SealedPayload {
    /// Wraps envelope bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The envelope bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SealedPayload {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SealedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedPayload({} bytes)", self.0.len())
    }
}

/// A claimed message as seen by a handler.
#[derive(Debug, Clone)]
pub struct OutboxMessage {
    /// Message id; also the idempotency key.
    pub id: OutboxMessageId,
    /// Topic.
    pub topic: String,
    /// Organization scope, if any.
    pub org_id: Option<OrgId>,
    /// Non-secret payload.
    pub payload: Value,
    /// Envelope-encrypted secret payload, if any.
    pub sealed_payload: Option<SealedPayload>,
    /// Attempt number of this delivery (1 = first).
    pub attempts: u32,
    /// Attempts before the dead-letter state.
    pub max_attempts: u32,
    /// When the message was enqueued.
    pub created_at: OffsetDateTime,
}

impl OutboxMessage {
    /// Stable across retries and redeliveries of the same message
    /// (receivers deduplicate on it).
    #[must_use]
    pub fn idempotency_key(&self) -> OutboxMessageId {
        self.id
    }

    /// Whether a failure of this attempt moves the message to the
    /// dead-letter state.
    #[must_use]
    pub fn is_last_attempt(&self) -> bool {
        self.attempts >= self.max_attempts
    }
}

/// A message to enqueue.
#[derive(Debug, Clone)]
pub struct NewOutboxMessage {
    /// Id (UUIDv7). Enqueuing the same id twice is a no-op (idempotent
    /// producers).
    pub id: OutboxMessageId,
    /// Topic (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`).
    pub topic: String,
    /// Organization scope.
    pub org_id: Option<OrgId>,
    /// Non-secret JSON object.
    pub payload: Value,
    /// Envelope-encrypted secrets, wiped after delivery.
    pub sealed_payload: Option<SealedPayload>,
    /// Attempts before the dead-letter state (1–100).
    pub max_attempts: u32,
    /// Earliest delivery time.
    pub available_at: OffsetDateTime,
    /// Enqueue time (from the injected clock).
    pub created_at: OffsetDateTime,
}

/// Message counts by state (for the `authn_outbox_queue_depth` gauge,
/// OPS-04).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboxDepth {
    /// Waiting for delivery (including retries).
    pub pending: u64,
    /// Claimed by a worker.
    pub processing: u64,
    /// In the dead-letter state.
    pub dead: u64,
}

/// Queries on `outbox`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutboxRepository;

impl OutboxRepository {
    /// Enqueues a message in the caller's transaction. Returns `false` when
    /// a message with the same id already exists.
    pub async fn enqueue(
        conn: &mut PgConnection,
        message: &NewOutboxMessage,
    ) -> Result<bool, AuthError> {
        if !is_valid_topic(&message.topic) {
            return Err(AuthError::internal("invalid outbox topic"));
        }
        if !message.payload.is_object() {
            return Err(AuthError::internal("outbox payload must be a JSON object"));
        }
        let max_attempts = i32::try_from(message.max_attempts.clamp(1, 100))
            .map_err(|_| AuthError::internal("outbox max_attempts"))?;
        let result = sqlx::query(
            "INSERT INTO outbox (id, topic, org_id, payload, sealed_payload, status, attempts, \
             max_attempts, available_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6, $7, $8) ON CONFLICT (id) DO NOTHING",
        )
        .bind(message.id)
        .bind(&message.topic)
        .bind(message.org_id)
        .bind(sqlx::types::Json(&message.payload))
        .bind(message.sealed_payload.as_ref().map(SealedPayload::as_bytes))
        .bind(max_attempts)
        .bind(message.available_at)
        .bind(message.created_at)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Moves a dead-letter message back to `pending` with a fresh attempt
    /// budget (operator action). Returns whether a message was requeued.
    pub async fn requeue_dead(
        conn: &mut PgConnection,
        id: OutboxMessageId,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        let result = sqlx::query(
            "UPDATE outbox SET status = 'pending', attempts = 0, available_at = $2, \
             last_error = NULL, locked_until = NULL, locked_by = NULL \
             WHERE id = $1 AND status = 'dead'",
        )
        .bind(id)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Message counts by state.
    pub async fn depth<'e>(executor: impl PgExecutor<'e>) -> Result<OutboxDepth, AuthError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT status, count(*) FROM outbox \
             WHERE status IN ('pending', 'processing', 'dead') GROUP BY status",
        )
        .fetch_all(executor)
        .await?;
        let mut depth = OutboxDepth::default();
        for (status, count) in rows {
            let count = u64::try_from(count).unwrap_or(0);
            match status.as_str() {
                "pending" => depth.pending = count,
                "processing" => depth.processing = count,
                "dead" => depth.dead = count,
                _ => {}
            }
        }
        Ok(depth)
    }

    /// Deletes delivered messages older than `delivered_before` and
    /// dead-letter messages created before `dead_before` (OPS-06). Returns
    /// the number of deleted messages.
    pub async fn purge(
        pool: &PgPool,
        delivered_before: OffsetDateTime,
        dead_before: OffsetDateTime,
    ) -> Result<u64, AuthError> {
        let result = sqlx::query(
            "DELETE FROM outbox WHERE (status = 'delivered' AND delivered_at < $1) \
             OR (status = 'dead' AND created_at < $2)",
        )
        .bind(delivered_before)
        .bind(dead_before)
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aud_06_topic_validation() {
        for ok in [
            "domain_event",
            "webhook.delivery",
            "notification.email",
            "a.b2.c_d",
        ] {
            assert!(is_valid_topic(ok), "{ok}");
        }
        for bad in ["", "Webhook", "webhook.", ".x", "a..b", "a b", "a-b", "1a"] {
            assert!(!is_valid_topic(bad), "{bad}");
        }
        assert!(!is_valid_topic(&"a".repeat(129)));
    }

    #[test]
    fn aud_06_sealed_payload_debug_is_redacted() {
        let sealed = SealedPayload::new(b"secret-envelope".to_vec());
        assert_eq!(format!("{sealed:?}"), "SealedPayload(15 bytes)");
    }
}
