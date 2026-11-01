//! Recording and disabled SMS senders.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{SmsMessage, SmsReceipt, SmsSender};

use super::is_valid_body;
use crate::email::InjectedFailure;
use crate::email::memory_lock as lock;

/// Records SMS messages in memory (tests). Failures can be queued with
/// [`MemorySmsSender::fail_next`].
#[derive(Debug, Default)]
pub struct MemorySmsSender {
    sent: Mutex<Vec<SmsMessage>>,
    failures: Mutex<VecDeque<InjectedFailure>>,
    counter: AtomicU64,
}

impl MemorySmsSender {
    /// An empty sender.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Messages sent so far.
    #[must_use]
    pub fn messages(&self) -> Vec<SmsMessage> {
        lock(&self.sent).clone()
    }

    /// Drains the recorded messages.
    pub fn take(&self) -> Vec<SmsMessage> {
        std::mem::take(&mut *lock(&self.sent))
    }

    /// Makes the next send fail with `failure`.
    pub fn fail_next(&self, failure: InjectedFailure) {
        lock(&self.failures).push_back(failure);
    }
}

#[async_trait]
impl SmsSender for MemorySmsSender {
    fn is_configured(&self) -> bool {
        true
    }

    async fn send(&self, message: &SmsMessage) -> Result<SmsReceipt, AuthError> {
        if !is_valid_body(message.body.expose()) {
            return Err(AuthError::new(codes::notify::DELIVERY_REJECTED)
                .with_context("SMS body is empty, too long or contains control characters"));
        }
        if let Some(failure) = lock(&self.failures).pop_front() {
            return Err(failure.into_error());
        }
        lock(&self.sent).push(message.clone());
        let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(SmsReceipt {
            provider_message_id: Some(format!("memory-{n}")),
        })
    }
}

/// No provider configured: `is_configured() == false` and every send fails
/// with `sms_unavailable` (ARC-11: SMS behaves as disabled).
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledSmsSender;

#[async_trait]
impl SmsSender for DisabledSmsSender {
    fn is_configured(&self) -> bool {
        false
    }

    async fn send(&self, _message: &SmsMessage) -> Result<SmsReceipt, AuthError> {
        Err(AuthError::new(codes::notify::SMS_UNAVAILABLE)
            .with_context("no SMS provider configured"))
    }
}
