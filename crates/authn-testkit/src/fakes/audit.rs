use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{AuditSink, DomainEvent, EventPublisher, SecurityEvent, SecurityEventKind};
use sqlx::PgConnection;

use super::lock;

/// Records security events in memory.
#[derive(Debug, Default)]
pub struct RecordingAuditSink {
    events: Mutex<Vec<SecurityEvent>>,
}

impl RecordingAuditSink {
    /// All recorded events, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<SecurityEvent> {
        lock(&self.events).clone()
    }

    /// Recorded events of one kind.
    #[must_use]
    pub fn of_kind(&self, kind: SecurityEventKind) -> Vec<SecurityEvent> {
        lock(&self.events)
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect()
    }

    /// Drains the recording.
    pub fn take(&self) -> Vec<SecurityEvent> {
        std::mem::take(&mut *lock(&self.events))
    }
}

#[async_trait]
impl AuditSink for RecordingAuditSink {
    async fn record(&self, event: SecurityEvent) -> Result<(), AuthError> {
        lock(&self.events).push(event);
        Ok(())
    }

    async fn record_in_tx(
        &self,
        _conn: &mut PgConnection,
        event: SecurityEvent,
    ) -> Result<(), AuthError> {
        lock(&self.events).push(event);
        Ok(())
    }
}

/// Records published domain events in memory.
#[derive(Debug, Default)]
pub struct RecordingEventPublisher {
    events: Mutex<Vec<DomainEvent>>,
}

impl RecordingEventPublisher {
    /// All recorded events, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<DomainEvent> {
        lock(&self.events).clone()
    }

    /// Drains the recording.
    pub fn take(&self) -> Vec<DomainEvent> {
        std::mem::take(&mut *lock(&self.events))
    }
}

#[async_trait]
impl EventPublisher for RecordingEventPublisher {
    async fn publish(&self, _conn: &mut PgConnection, event: DomainEvent) -> Result<(), AuthError> {
        lock(&self.events).push(event);
        Ok(())
    }
}
