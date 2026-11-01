//! Throttled security auditing.
//!
//! Abuse events (CAPTCHA failures, soft locks, rate-limit trips) are caused
//! by the attacker. Writing one audit row per denied request would let an
//! attacker amplify every cheap request into a durable database write, so
//! these events are recorded at most once per throttle window and key.

use std::sync::Arc;
use std::time::Duration;

use authn_core::ports::{AuditSink, RateLimitKey, RateLimitPolicy, RateLimiter, SecurityEvent};

/// Records `event` unless an event with the same throttle `key` was
/// recorded within `window`. Failures are logged, never propagated: the
/// protective decision must not depend on the audit store.
pub async fn record_throttled(
    limiter: &Arc<dyn RateLimiter>,
    audit: &Arc<dyn AuditSink>,
    key: &RateLimitKey,
    window: Duration,
    event: SecurityEvent,
) {
    let first = limiter
        .check(key, RateLimitPolicy::new(1, window), 1)
        .await
        .map_or(true, |d| d.allowed);
    if !first {
        return;
    }
    let kind = event.kind;
    if let Err(err) = audit.record(event).await {
        tracing::error!(error = %err, kind = %kind, "failed to record security event");
    }
}

#[cfg(test)]
mod tests {
    use authn_core::ports::{Clock, SecurityEventKind};
    use authn_testkit::TestPorts;

    use super::*;

    #[tokio::test]
    async fn prt_01_abuse_events_are_audited_once_per_window() {
        let ports = TestPorts::new();
        let limiter: Arc<dyn RateLimiter> = ports.rate_limiter.clone();
        let audit: Arc<dyn AuditSink> = ports.audit.clone();
        let key = RateLimitKey::ip("audit_captcha_failed", "198.51.100.3".parse().unwrap());
        for _ in 0..50 {
            let event = SecurityEvent::new(SecurityEventKind::CaptchaFailed, ports.clock.now());
            record_throttled(&limiter, &audit, &key, Duration::from_secs(900), event).await;
        }
        assert_eq!(
            ports.audit.of_kind(SecurityEventKind::CaptchaFailed).len(),
            1
        );
        ports.clock.advance(Duration::from_secs(900));
        let event = SecurityEvent::new(SecurityEventKind::CaptchaFailed, ports.clock.now());
        record_throttled(&limiter, &audit, &key, Duration::from_secs(900), event).await;
        assert_eq!(
            ports.audit.of_kind(SecurityEventKind::CaptchaFailed).len(),
            2
        );
    }
}
