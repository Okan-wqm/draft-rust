use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{Notification, Notifier, SmsNotification};
use sqlx::PgConnection;

use super::lock;

/// Records notifications in memory (no outbox, no delivery).
///
/// E-mail notifications (`notify`, `notify_in_tx`) and SMS notifications
/// (`notify_sms_in_tx`) are recorded separately. SMS support is on by
/// default; [`set_sms_available(false)`](Self::set_sms_available) makes
/// `notify_sms_in_tx` fail with `sms_unavailable` like a deployment without
/// an SMS provider (the port's default behaviour).
#[derive(Debug)]
pub struct RecordingNotifier {
    sent: Mutex<Vec<Notification>>,
    sms: Mutex<Vec<SmsNotification>>,
    sms_available: Mutex<bool>,
}

impl Default for RecordingNotifier {
    fn default() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            sms: Mutex::new(Vec::new()),
            sms_available: Mutex::new(true),
        }
    }
}

impl RecordingNotifier {
    /// All recorded e-mail notifications, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<Notification> {
        lock(&self.sent).clone()
    }

    /// E-mail notifications for one template (`password_reset`, `login_code`…).
    #[must_use]
    pub fn with_template(&self, template: &str) -> Vec<Notification> {
        lock(&self.sent)
            .iter()
            .filter(|n| n.kind.template_name() == template)
            .cloned()
            .collect()
    }

    /// The most recent e-mail notification, if any.
    #[must_use]
    pub fn last(&self) -> Option<Notification> {
        lock(&self.sent).last().cloned()
    }

    /// Drains the e-mail recording.
    pub fn take(&self) -> Vec<Notification> {
        std::mem::take(&mut *lock(&self.sent))
    }

    /// All recorded SMS notifications, in order.
    #[must_use]
    pub fn recorded_sms(&self) -> Vec<SmsNotification> {
        lock(&self.sms).clone()
    }

    /// SMS notifications for one template (`mfa_sms_code`,
    /// `phone_verification`).
    #[must_use]
    pub fn sms_with_template(&self, template: &str) -> Vec<SmsNotification> {
        lock(&self.sms)
            .iter()
            .filter(|n| n.kind.template_name() == template)
            .cloned()
            .collect()
    }

    /// The most recent SMS notification, if any.
    #[must_use]
    pub fn last_sms(&self) -> Option<SmsNotification> {
        lock(&self.sms).last().cloned()
    }

    /// Drains the SMS recording.
    pub fn take_sms(&self) -> Vec<SmsNotification> {
        std::mem::take(&mut *lock(&self.sms))
    }

    /// Switches SMS support on (default) or off (`sms_unavailable`).
    pub fn set_sms_available(&self, available: bool) {
        *lock(&self.sms_available) = available;
    }
}

#[async_trait]
impl Notifier for RecordingNotifier {
    async fn notify(&self, notification: Notification) -> Result<(), AuthError> {
        lock(&self.sent).push(notification);
        Ok(())
    }

    async fn notify_in_tx(
        &self,
        _conn: &mut PgConnection,
        notification: Notification,
    ) -> Result<(), AuthError> {
        lock(&self.sent).push(notification);
        Ok(())
    }

    async fn notify_sms_in_tx(
        &self,
        _conn: &mut PgConnection,
        sms: SmsNotification,
    ) -> Result<(), AuthError> {
        if !*lock(&self.sms_available) {
            return Err(AuthError::new(codes::notify::SMS_UNAVAILABLE)
                .with_context("RecordingNotifier: SMS switched off"));
        }
        lock(&self.sms).push(sms);
        Ok(())
    }
}
