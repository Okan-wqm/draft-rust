//! Recording and disabled transports.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{EmailMessage, EmailTransport};

/// A failure to inject into the next send of a recording transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedFailure {
    /// `service_unavailable` (retried by the outbox).
    Temporary,
    /// `delivery_rejected` (dead-lettered).
    Permanent,
}

impl InjectedFailure {
    pub(crate) fn into_error(self) -> AuthError {
        match self {
            Self::Temporary => AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("injected temporary failure"),
            Self::Permanent => AuthError::new(codes::notify::DELIVERY_REJECTED)
                .with_context("injected permanent failure"),
        }
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Records every sent message in memory (tests, previews). Failures can be
/// queued with [`MemoryEmailTransport::fail_next`].
#[derive(Debug, Default)]
pub struct MemoryEmailTransport {
    sent: Mutex<Vec<EmailMessage>>,
    failures: Mutex<VecDeque<InjectedFailure>>,
}

impl MemoryEmailTransport {
    /// An empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Messages sent so far.
    #[must_use]
    pub fn messages(&self) -> Vec<EmailMessage> {
        lock(&self.sent).clone()
    }

    /// Drains the recorded messages.
    pub fn take(&self) -> Vec<EmailMessage> {
        std::mem::take(&mut *lock(&self.sent))
    }

    /// Makes the next send fail with `failure` (queued, one per send).
    pub fn fail_next(&self, failure: InjectedFailure) {
        lock(&self.failures).push_back(failure);
    }
}

#[async_trait]
impl EmailTransport for MemoryEmailTransport {
    async fn send(&self, message: &EmailMessage) -> Result<(), AuthError> {
        if let Some(failure) = lock(&self.failures).pop_front() {
            return Err(failure.into_error());
        }
        lock(&self.sent).push(message.clone());
        Ok(())
    }
}

/// Drops every message (`transport = "disabled"`; refused in production).
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledEmailTransport;

#[async_trait]
impl EmailTransport for DisabledEmailTransport {
    async fn send(&self, message: &EmailMessage) -> Result<(), AuthError> {
        tracing::debug!(outbox_id = ?message.outbox_id, "e-mail dropped (transport disabled)");
        Ok(())
    }
}
