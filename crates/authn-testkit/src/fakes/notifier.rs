use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{Notification, Notifier};
use sqlx::PgConnection;

use super::lock;

/// Records notifications in memory (no outbox, no delivery).
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    sent: Mutex<Vec<Notification>>,
}

impl RecordingNotifier {
    /// All recorded notifications, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<Notification> {
        lock(&self.sent).clone()
    }

    /// Notifications for one template (`password_reset`, `login_code`…).
    #[must_use]
    pub fn with_template(&self, template: &str) -> Vec<Notification> {
        lock(&self.sent)
            .iter()
            .filter(|n| n.kind.template_name() == template)
            .cloned()
            .collect()
    }

    /// The most recent notification, if any.
    #[must_use]
    pub fn last(&self) -> Option<Notification> {
        lock(&self.sent).last().cloned()
    }

    /// Drains the recording.
    pub fn take(&self) -> Vec<Notification> {
        std::mem::take(&mut *lock(&self.sent))
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
}
