use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{EmailMessage, EmailTransport, SmsMessage, SmsReceipt, SmsSender};

use super::lock;

/// Records rendered e-mails; can be switched to fail.
#[derive(Debug, Default)]
pub struct RecordingEmailTransport {
    sent: Mutex<Vec<EmailMessage>>,
    failing: AtomicBool,
}

impl RecordingEmailTransport {
    /// All sent messages.
    #[must_use]
    pub fn recorded(&self) -> Vec<EmailMessage> {
        lock(&self.sent).clone()
    }

    /// Makes subsequent sends fail with `service_unavailable`.
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
}

#[async_trait]
impl EmailTransport for RecordingEmailTransport {
    async fn send(&self, message: &EmailMessage) -> Result<(), AuthError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("fake transport failure"));
        }
        lock(&self.sent).push(message.clone());
        Ok(())
    }
}

/// Records SMS messages; configured (`is_configured() == true`) by default.
#[derive(Debug)]
pub struct RecordingSmsSender {
    sent: Mutex<Vec<SmsMessage>>,
    configured: AtomicBool,
}

impl Default for RecordingSmsSender {
    fn default() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            configured: AtomicBool::new(true),
        }
    }
}

impl RecordingSmsSender {
    /// All sent messages.
    #[must_use]
    pub fn recorded(&self) -> Vec<SmsMessage> {
        lock(&self.sent).clone()
    }

    /// Simulates a missing provider (ARC-11 `sms` feature disabled at runtime).
    pub fn set_configured(&self, configured: bool) {
        self.configured.store(configured, Ordering::SeqCst);
    }
}

#[async_trait]
impl SmsSender for RecordingSmsSender {
    fn is_configured(&self) -> bool {
        self.configured.load(Ordering::SeqCst)
    }

    async fn send(&self, message: &SmsMessage) -> Result<SmsReceipt, AuthError> {
        if !self.is_configured() {
            return Err(AuthError::internal("sms sender not configured"));
        }
        let mut sent = lock(&self.sent);
        sent.push(message.clone());
        Ok(SmsReceipt {
            provider_message_id: Some(format!("fake-{}", sent.len())),
        })
    }
}
