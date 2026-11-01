//! [`OutboxEventPublisher`]: the `EventPublisher` port (AUD-06).

use std::sync::Arc;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::OutboxMessageId;
use authn_core::ports::{Clock, DomainEvent, EventPublisher};
use sqlx::PgConnection;

use super::{NewOutboxMessage, OutboxRepository};

/// Topic of domain events (fanned out to webhooks by
/// [`crate::webhooks::WebhookFanout`]).
pub const DOMAIN_EVENT_TOPIC: &str = "domain_event";

/// Largest serialized domain event accepted (64 KiB). Domain events carry
/// ids and minimal data; anything larger is a producer bug.
pub const MAX_DOMAIN_EVENT_BYTES: usize = 64 * 1024;

/// Writes domain events to the outbox in the caller's transaction.
///
/// The outbox message id equals the event id, so publishing the same event
/// twice (a retried producer) enqueues it once.
#[derive(Clone)]
pub struct OutboxEventPublisher {
    clock: Arc<dyn Clock>,
    max_attempts: u32,
}

impl std::fmt::Debug for OutboxEventPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxEventPublisher")
            .field("max_attempts", &self.max_attempts)
            .finish_non_exhaustive()
    }
}

impl OutboxEventPublisher {
    /// Creates the publisher; `max_attempts` is `audit.outbox.max_attempts`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, max_attempts: u32) -> Self {
        Self {
            clock,
            max_attempts,
        }
    }
}

#[async_trait]
impl EventPublisher for OutboxEventPublisher {
    async fn publish(&self, conn: &mut PgConnection, event: DomainEvent) -> Result<(), AuthError> {
        let payload = serde_json::to_value(&event)
            .map_err(|e| AuthError::internal("domain event not serializable").with_source(e))?;
        let size = serde_json::to_vec(&payload).map_or(usize::MAX, |v| v.len());
        if size > MAX_DOMAIN_EVENT_BYTES {
            return Err(AuthError::internal("domain event payload too large"));
        }
        let now = self.clock.now();
        let inserted = OutboxRepository::enqueue(
            conn,
            &NewOutboxMessage {
                id: OutboxMessageId::from_uuid(event.id.as_uuid()),
                topic: DOMAIN_EVENT_TOPIC.to_owned(),
                org_id: event.org_id,
                payload,
                sealed_payload: None,
                max_attempts: self.max_attempts,
                available_at: now,
                created_at: now,
            },
        )
        .await?;
        if !inserted {
            tracing::debug!(event.id = %event.id, "domain event already in the outbox");
        }
        Ok(())
    }
}
