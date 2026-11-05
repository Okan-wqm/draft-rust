//! `[audit]` — audit log, outbox worker, webhooks (owner: authn-audit).
//! AUD-04 … AUD-07.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, days, hours, mins, secs};
use crate::ports::RateLimitPolicy;

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
    /// First retry delay (doubles each attempt, with jitter). Default `2s`.
    #[serde(with = "super::duration")]
    pub backoff_base: Duration,
    /// Retry delay cap. Default `1h`.
    #[serde(with = "super::duration")]
    pub backoff_max: Duration,
    /// Lease of a claimed message. Default `60s`.
    #[serde(with = "super::duration")]
    pub lease: Duration,
    /// Messages of one batch handled concurrently. Default 16.
    pub concurrency: u32,
    /// Delivered messages are deleted after this period. Default `7d`.
    #[serde(with = "super::duration")]
    pub delivered_retention: Duration,
    /// Dead-letter messages are deleted after this period. Default `30d`.
    #[serde(with = "super::duration")]
    pub dead_retention: Duration,
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
            concurrency: 16,
            delivered_retention: days(7),
            dead_retention: days(30),
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
    /// First retry delay of a failed delivery (doubles each attempt, with
    /// jitter; a receiver's `Retry-After` is honoured up to `backoff_max`).
    /// Default `1m`.
    #[serde(with = "super::duration")]
    pub backoff_base: Duration,
    /// Retry delay cap. Default `6h`.
    #[serde(with = "super::duration")]
    pub backoff_max: Duration,
    /// Consecutive failed attempts before an endpoint is disabled
    /// automatically (together with `disable_after`). Default 20.
    pub disable_after_failures: u32,
    /// Minimum duration of uninterrupted failures before an endpoint is
    /// disabled automatically. Default `24h`.
    #[serde(with = "super::duration")]
    pub disable_after: Duration,
    /// Finished delivery records (history) are deleted after. Default `30d`.
    #[serde(with = "super::duration")]
    pub delivery_retention: Duration,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            timeout: secs(10),
            max_attempts: 8,
            secret_rotation_overlap: hours(24),
            max_endpoints_per_org: 10,
            backoff_base: mins(1),
            backoff_max: hours(6),
            disable_after_failures: 20,
            disable_after: hours(24),
            delivery_retention: days(30),
        }
    }
}

/// Rate limits of the audit / webhook endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditRateLimits {
    /// Security-event / audit-log listings per principal. Default 60 per
    /// minute.
    pub events_read: RateLimitPolicy,
    /// Webhook endpoint changes per organization. Default 60 per hour.
    pub webhook_write: RateLimitPolicy,
    /// Manual webhook redeliveries per organization. Default 30 per hour.
    pub webhook_redeliver: RateLimitPolicy,
}

impl Default for AuditRateLimits {
    fn default() -> Self {
        Self {
            events_read: RateLimitPolicy::new(60, mins(1)),
            webhook_write: RateLimitPolicy::new(60, hours(1)),
            webhook_redeliver: RateLimitPolicy::new(30, hours(1)),
        }
    }
}

/// `[audit.chain]` — keyed audit hash chain (AUD-02, K-77).
///
/// New events are chained with `HMAC-SHA-256(K_v, prev_hash ‖ record)`,
/// where `K_v` is version `key_version` of the chain key derived from
/// `crypto.hmac_root_key` (`KeyPurpose::AuditChain`). Older versions stay
/// derivable, so earlier events keep verifying after a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditChainConfig {
    /// Chain key version for new events (`1..=32767`). Rotation: increase
    /// by one and restart; events already written are never re-hashed.
    /// Default `1`.
    pub key_version: u16,
    /// The last sequence number that may still be an unkeyed (legacy
    /// SHA-256) event, i.e. the `seq` before the `chain_key_switch`
    /// checkpoint logged at the first keyed event. When set, verification
    /// rejects every unkeyed event after it, which also catches an attacker
    /// who rewrote the whole chain into the unkeyed form. Pin it (outside
    /// the database) after the upgrade. Default: unset (an unkeyed prefix
    /// before the first keyed event is accepted and reported).
    pub legacy_until_seq: Option<i64>,
}

impl Default for AuditChainConfig {
    fn default() -> Self {
        Self {
            key_version: 1,
            legacy_until_seq: None,
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
    /// Rate limits of the HTTP endpoints.
    pub rate_limits: AuditRateLimits,
    /// Keyed hash chain (K-77).
    pub chain: AuditChainConfig,
    /// Interval of the scheduled chain checkpoint (K-107): at most one
    /// `scheduled` checkpoint of the chain head per interval across every
    /// instance; its `seq:hash` is logged as an external anchor.
    /// `1h`–`7d`. Default `24h`.
    #[serde(with = "super::duration")]
    pub checkpoint_interval: Duration,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            retention: days(400),
            user_visible_window: days(90),
            outbox: OutboxConfig::default(),
            webhooks: WebhookConfig::default(),
            rate_limits: AuditRateLimits::default(),
            chain: AuditChainConfig::default(),
            checkpoint_interval: hours(24),
        }
    }
}

fn require_policy(p: &mut ConfigProblems, policy: RateLimitPolicy, key: &str) {
    p.require(
        (1..=1_000_000).contains(&policy.limit),
        key,
        "limit must be between 1 and 1000000",
    );
    p.require_range(policy.period, secs(1), days(7), key);
}

impl AuditConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require(
            (1..=32_767).contains(&self.chain.key_version),
            "audit.chain.key_version",
            "must be between 1 and 32767",
        );
        p.require(
            self.chain.legacy_until_seq.is_none_or(|seq| seq >= 0),
            "audit.chain.legacy_until_seq",
            "must not be negative",
        );
        p.require(
            self.retention >= self.user_visible_window,
            "audit.retention",
            "must be at least user_visible_window",
        );
        p.require_range(self.retention, days(30), days(3650), "audit.retention");
        p.require_range(
            self.checkpoint_interval,
            hours(1),
            days(7),
            "audit.checkpoint_interval",
        );
        p.require_range(
            self.user_visible_window,
            days(1),
            days(3650),
            "audit.user_visible_window",
        );
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
        p.require_range(
            o.backoff_base,
            Duration::from_millis(100),
            hours(1),
            "audit.outbox.backoff_base",
        );
        p.require_range(o.backoff_max, secs(1), days(1), "audit.outbox.backoff_max");
        p.require_range(o.lease, secs(5), mins(30), "audit.outbox.lease");
        p.require(
            (1..=256).contains(&o.concurrency),
            "audit.outbox.concurrency",
            "must be 1-256",
        );
        p.require_range(
            o.delivered_retention,
            hours(1),
            days(365),
            "audit.outbox.delivered_retention",
        );
        p.require_range(
            o.dead_retention,
            days(1),
            days(365),
            "audit.outbox.dead_retention",
        );
        let w = &self.webhooks;
        p.require_range(w.timeout, secs(1), mins(1), "audit.webhooks.timeout");
        p.require(
            w.timeout < o.lease,
            "audit.webhooks.timeout",
            "must be shorter than audit.outbox.lease",
        );
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
        p.require(
            (1..=100).contains(&w.max_endpoints_per_org),
            "audit.webhooks.max_endpoints_per_org",
            "must be 1-100",
        );
        p.require(
            w.backoff_base <= w.backoff_max,
            "audit.webhooks.backoff_base",
            "must be <= backoff_max",
        );
        p.require_range(
            w.backoff_base,
            secs(1),
            hours(1),
            "audit.webhooks.backoff_base",
        );
        p.require_range(
            w.backoff_max,
            secs(1),
            days(1),
            "audit.webhooks.backoff_max",
        );
        p.require(
            (1..=10_000).contains(&w.disable_after_failures),
            "audit.webhooks.disable_after_failures",
            "must be 1-10000",
        );
        p.require_range(
            w.disable_after,
            Duration::ZERO,
            days(30),
            "audit.webhooks.disable_after",
        );
        p.require_range(
            w.delivery_retention,
            days(1),
            days(365),
            "audit.webhooks.delivery_retention",
        );
        let r = &self.rate_limits;
        require_policy(p, r.events_read, "audit.rate_limits.events_read");
        require_policy(p, r.webhook_write, "audit.rate_limits.webhook_write");
        require_policy(
            p,
            r.webhook_redeliver,
            "audit.rate_limits.webhook_redeliver",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aud_05_defaults_are_valid() {
        let mut p = ConfigProblems::default();
        AuditConfig::default().validate(&mut p);
        assert!(p.is_empty(), "{:?}", p.problems());
    }

    /// The commented `[audit]` lines of `config/example.toml`, uncommented.
    #[test]
    fn aud_06_documented_example_parses_to_the_defaults() {
        use figment::Figment;
        use figment::providers::{Format, Toml};
        let toml = r#"
            retention = "400d"
            user_visible_window = "90d"
            outbox = { poll_interval = "1s", batch_size = 100, max_attempts = 10, backoff_base = "2s", backoff_max = "1h", lease = "60s", concurrency = 16, delivered_retention = "7d", dead_retention = "30d" }
            webhooks = { timeout = "10s", max_attempts = 8, secret_rotation_overlap = "24h", max_endpoints_per_org = 10, backoff_base = "1m", backoff_max = "6h", disable_after_failures = 20, disable_after = "24h", delivery_retention = "30d" }
            rate_limits = { events_read = { limit = 60, period = "1m" }, webhook_write = { limit = 60, period = "1h" }, webhook_redeliver = { limit = 30, period = "1h" } }
            checkpoint_interval = "24h"
        "#;
        let parsed: AuditConfig = Figment::new().merge(Toml::string(toml)).extract().unwrap();
        assert_eq!(parsed, AuditConfig::default());
    }

    #[test]
    fn aud_06_invalid_values_are_reported_by_key() {
        let mut config = AuditConfig::default();
        config.outbox.concurrency = 0;
        config.webhooks.timeout = mins(5);
        config.rate_limits.events_read.limit = 0;
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        let text = p.problems().join("\n");
        assert!(text.contains("audit.outbox.concurrency"), "{text}");
        assert!(text.contains("audit.webhooks.timeout"), "{text}");
        assert!(text.contains("audit.rate_limits.events_read"), "{text}");
    }

    #[test]
    fn k_107_checkpoint_interval_is_bounded() {
        for (interval, valid) in [
            (mins(59), false),
            (hours(1), true),
            (hours(24), true),
            (days(7), true),
            (days(8), false),
        ] {
            let config = AuditConfig {
                checkpoint_interval: interval,
                ..AuditConfig::default()
            };
            let mut p = ConfigProblems::default();
            config.validate(&mut p);
            assert_eq!(p.is_empty(), valid, "{interval:?}: {:?}", p.problems());
            if !valid {
                assert!(
                    p.problems()
                        .join("\n")
                        .contains("audit.checkpoint_interval")
                );
            }
        }
    }
}
