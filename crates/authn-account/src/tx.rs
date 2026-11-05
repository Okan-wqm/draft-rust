//! [`AccountTx`]: a database transaction that also carries the audit events
//! of the operation (ARC-06, AUD-01).
//!
//! Audit events are queued while the business statements run and recorded
//! with `AuditSink::record_in_tx` right before `COMMIT` (the audit port asks
//! for appends "as late as possible", because they serialize on the hash
//! chain head). The only way to commit is [`AccountTx::commit`], so a
//! state change can never commit without its audit events; dropping the
//! value rolls the transaction back and discards the queued events.

use std::sync::Arc;

use authn_core::error::AuthError;
use authn_core::ports::{AuditSink, SecurityEvent};
use authn_store::PgTx;
use sqlx::{PgConnection, PgPool};

/// A transaction with queued audit events.
pub(crate) struct AccountTx {
    tx: PgTx,
    audit: Arc<dyn AuditSink>,
    events: Vec<SecurityEvent>,
}

impl AccountTx {
    /// Begins a `READ COMMITTED` transaction.
    pub(crate) async fn begin(pool: &PgPool, audit: Arc<dyn AuditSink>) -> Result<Self, AuthError> {
        Ok(Self {
            tx: authn_store::begin(pool).await?,
            audit,
            events: Vec::new(),
        })
    }

    /// The connection of the transaction.
    pub(crate) fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Queues an audit event (recorded at commit).
    pub(crate) fn audit(&mut self, event: SecurityEvent) {
        self.events.push(event);
    }

    /// Records the queued events now, inside the transaction. Needed before
    /// statements that must see them (account purge: record, then
    /// pseudonymise, then delete).
    pub(crate) async fn flush_audit(&mut self) -> Result<(), AuthError> {
        for event in std::mem::take(&mut self.events) {
            self.audit.record_in_tx(&mut self.tx, event).await?;
        }
        Ok(())
    }

    /// Records the queued audit events and commits.
    pub(crate) async fn commit(mut self) -> Result<(), AuthError> {
        self.flush_audit().await?;
        authn_store::commit(self.tx).await
    }

    /// Rolls back, discarding the queued audit events.
    pub(crate) async fn rollback(self) -> Result<(), AuthError> {
        self.tx.rollback().await?;
        Ok(())
    }
}
