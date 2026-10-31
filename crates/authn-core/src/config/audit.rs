//! `[audit]` — audit log, outbox worker, webhooks (owner: authn-audit).
//! AUD-04 … AUD-07.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, days, hours, mins, secs};

/// Outbox worker (AUD-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutboxConfig {
    /// Poll interval. Default `1s`.
    #[serde(with = "super::duration")]
    pub poll_interval: Duration,
    /// Messages claimed per batch. Default 100.
    pub batch_size: u32,
    /// Attempts before the dead-letter state. Default 10.
    pub max_attempts: u32,
    /// First retry delay (doubles each attempt). Default `2s`.
    #[serde(with = "super::duration")]
    pub backoff_base: Duration,
    /// Retry delay cap. Default `1h`.
    #[serde(with = "super::duration")]
    pub backoff_max: Duration,
    /// Lease of a claimed message. Default `60s`.
    #[serde(with = "super::duration")]
    pub lease: Duration,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            poll_interval: secs(1),
            batch_size: 100,
            max_attempts: 10,
            backoff_base: secs(2),
            backoff_max: hours(1),
            lease: secs(60),
        }
    }
}

/// Webhooks (AUD-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookConfig {
    /// Delivery timeout. Default `10s`.
    #[serde(with = "super::duration")]
    pub timeout: Duration,
    /// Delivery attempts. Default 8.
    pub max_attempts: u32,
    /// Old secret remains valid after rotation. Default `24h`.
    #[serde(with = "super::duration")]
    pub secret_rotation_overlap: Duration,
    /// Endpoints per organization. Default 10.
    pub max_endpoints_per_org: u32,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            timeout: secs(10),
            max_attempts: 8,
            secret_rotation_overlap: hours(24),
            max_endpoints_per_org: 10,
        }
    }
}

/// `[audit]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Retention of audit events (AUD-05). Default `400d`.
    #[serde(with = "super::duration")]
    pub retention: Duration,
    /// Window of the user's own security events (AUD-04). Default `90d`.
    #[serde(with = "super::duration")]
    pub user_visible_window: Duration,
    /// Outbox worker.
    pub outbox: OutboxConfig,
    /// Webhooks.
    pub webhooks: WebhookConfig,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            retention: days(400),
            user_visible_window: days(90),
            outbox: OutboxConfig::default(),
            webhooks: WebhookConfig::default(),
        }
    }
}

impl AuditConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require(
            self.retention >= self.user_visible_window,
            "audit.retention",
            "must be at least user_visible_window",
        );
        p.require_range(self.retention, days(30), days(3650), "audit.retention");
        let o = &self.outbox;
        p.require_range(
            o.poll_interval,
            Duration::from_millis(100),
            mins(1),
            "audit.outbox.poll_interval",
        );
        p.require(
            (1..=1000).contains(&o.batch_size),
            "audit.outbox.batch_size",
            "must be 1-1000",
        );
        p.require(
            (1..=100).contains(&o.max_attempts),
            "audit.outbox.max_attempts",
            "must be 1-100",
        );
        p.require(
            o.backoff_base <= o.backoff_max,
            "audit.outbox.backoff_base",
            "must be <= backoff_max",
        );
        p.require_range(o.lease, secs(5), mins(30), "audit.outbox.lease");
        let w = &self.webhooks;
        p.require_range(w.timeout, secs(1), mins(1), "audit.webhooks.timeout");
        p.require(
            (1..=50).contains(&w.max_attempts),
            "audit.webhooks.max_attempts",
            "must be 1-50",
        );
        p.require_range(
            w.secret_rotation_overlap,
            Duration::ZERO,
            days(7),
            "audit.webhooks.secret_rotation_overlap",
        );
    }
}
