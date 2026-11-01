//! Domain event → webhook deliveries (AUD-06, AUD-07): the `domain_event`
//! outbox handler.
//!
//! For an organization-scoped event, one `webhook_deliveries` row and one
//! `webhook.delivery` outbox message are created per active endpoint
//! subscribed to the event type — in one transaction, idempotently
//! (`UNIQUE (endpoint_id, event_id)`), so a retried fan-out never sends an
//! event twice to the same endpoint.

use std::sync::Arc;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::{OrgId, WebhookDeliveryId, WebhookEndpointId};
use authn_core::ports::{Clock, DomainEvent};
use serde_json::{Value, json};
use sqlx::PgPool;
use time::format_description::well_known::Rfc3339;

use super::endpoints::enqueue_delivery;
use crate::outbox::{DOMAIN_EVENT_TOPIC, HandlerError, OutboxHandler, OutboxMessage};

/// The JSON body delivered to receivers (Standard Webhooks layout:
/// `type`, `timestamp`, `data`, plus the event id and scope).
pub fn webhook_body(event: &DomainEvent) -> Result<Value, AuthError> {
    let timestamp = event
        .occurred_at
        .format(&Rfc3339)
        .map_err(|e| AuthError::internal("event timestamp").with_source(e))?;
    Ok(json!({
        "id": event.id,
        "type": event.kind.as_str(),
        "timestamp": timestamp,
        "organization_id": event.org_id,
        "user_id": event.user_id,
        "data": event.data,
    }))
}

/// The `domain_event` outbox handler.
#[derive(Clone)]
pub struct WebhookFanout {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    max_attempts: u32,
}

impl std::fmt::Debug for WebhookFanout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookFanout").finish_non_exhaustive()
    }
}

impl WebhookFanout {
    /// Creates the handler; `max_attempts` is `audit.webhooks.max_attempts`.
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, max_attempts: u32) -> Self {
        Self {
            pool,
            clock,
            max_attempts,
        }
    }

    async fn fan_out(&self, org: OrgId, event: &DomainEvent) -> Result<usize, AuthError> {
        let body = webhook_body(event)?;
        let now = self.clock.now();
        let mut tx = self.pool.begin().await?;
        let endpoints: Vec<WebhookEndpointId> = sqlx::query_scalar(
            "SELECT id FROM webhook_endpoints \
             WHERE org_id = $1 AND status = 'active' AND $2 = ANY(event_types) ORDER BY id",
        )
        .bind(org)
        .bind(event.kind.as_str())
        .fetch_all(&mut *tx)
        .await?;
        let mut created = 0;
        for endpoint in endpoints {
            let inserted: Option<WebhookDeliveryId> = sqlx::query_scalar(
                "INSERT INTO webhook_deliveries (id, endpoint_id, org_id, event_id, event_type, \
                 payload, status, attempts, next_attempt_at, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, $7, $7) \
                 ON CONFLICT (endpoint_id, event_id) DO NOTHING RETURNING id",
            )
            .bind(WebhookDeliveryId::generate())
            .bind(endpoint)
            .bind(org)
            .bind(event.id)
            .bind(event.kind.as_str())
            .bind(sqlx::types::Json(&body))
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(delivery) = inserted {
                enqueue_delivery(&mut tx, org, delivery, self.max_attempts, now).await?;
                created += 1;
            }
        }
        tx.commit().await?;
        Ok(created)
    }
}

#[async_trait]
impl OutboxHandler for WebhookFanout {
    async fn handle(&self, message: &OutboxMessage) -> Result<(), HandlerError> {
        if message.topic != DOMAIN_EVENT_TOPIC {
            return Err(HandlerError::permanent("unknown domain event topic"));
        }
        let event: DomainEvent = serde_json::from_value(message.payload.clone())
            .map_err(|_| HandlerError::permanent("malformed domain event"))?;
        let Some(org) = event.org_id else {
            // Webhooks are per organization; nothing else consumes the
            // event yet.
            return Ok(());
        };
        match self.fan_out(org, &event).await {
            Ok(created) => {
                tracing::debug!(event.id = %event.id, deliveries = created, "domain event fanned out");
                Ok(())
            }
            Err(err) => {
                tracing::warn!(event.id = %event.id, error = %err, "webhook fan-out failed");
                Err(HandlerError::retry("fan-out failed"))
            }
        }
    }
}
