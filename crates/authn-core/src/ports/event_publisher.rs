//! Domain events through the transactional outbox (AUD-06, AUD-07). Owner of
//! this file: authn-audit.
//!
//! Events are written in the caller's transaction (exactly when the state
//! change commits) and delivered at least once by the background worker,
//! e.g. to organization webhooks. Payloads carry ids and minimal,
//! non-secret data.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use time::OffsetDateTime;

use crate::error::AuthError;
use crate::id::{EventId, OrgId, UserId};

/// Publishes domain events.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Writes the event to the outbox inside the caller's transaction.
    async fn publish(&self, conn: &mut PgConnection, event: DomainEvent) -> Result<(), AuthError>;
}

text_enum! {
    /// Domain event types; also the webhook subscription names (AUD-07).
    pub enum DomainEventKind {
        /// A user registered.
        UserCreated => "user.created",
        /// Profile or status changed.
        UserUpdated => "user.updated",
        /// E-mail changed.
        UserEmailChanged => "user.email_changed",
        /// User deleted.
        UserDeleted => "user.deleted",
        /// Session created.
        SessionCreated => "session.created",
        /// Session revoked.
        SessionRevoked => "session.revoked",
        /// Organization created.
        OrganizationCreated => "organization.created",
        /// Organization updated.
        OrganizationUpdated => "organization.updated",
        /// Organization deleted.
        OrganizationDeleted => "organization.deleted",
        /// Member added.
        MemberAdded => "member.added",
        /// Member removed.
        MemberRemoved => "member.removed",
        /// Member role changed.
        MemberRoleChanged => "member.role_changed",
        /// Invitation created.
        InvitationCreated => "invitation.created",
        /// Invitation accepted.
        InvitationAccepted => "invitation.accepted",
        /// Invitation revoked.
        InvitationRevoked => "invitation.revoked",
        /// API key created.
        ApiKeyCreated => "api_key.created",
        /// API key revoked.
        ApiKeyRevoked => "api_key.revoked",
    }
}

/// A domain event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainEvent {
    /// Event id; also the webhook `webhook-id` (idempotency key).
    pub id: EventId,
    /// Event type.
    pub kind: DomainEventKind,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// Organization scope (webhooks are per organization).
    pub org_id: Option<OrgId>,
    /// Affected user.
    pub user_id: Option<UserId>,
    /// Event data (no secrets).
    pub data: serde_json::Value,
}

impl DomainEvent {
    /// Creates an event with a fresh id.
    #[must_use]
    pub fn new(
        kind: DomainEventKind,
        occurred_at: OffsetDateTime,
        data: serde_json::Value,
    ) -> Self {
        Self {
            id: EventId::generate(),
            kind,
            occurred_at,
            org_id: None,
            user_id: None,
            data,
        }
    }
}
