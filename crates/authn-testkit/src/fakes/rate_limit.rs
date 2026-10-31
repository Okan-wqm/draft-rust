use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use time::OffsetDateTime;

use super::lock;

/// Always allows.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllRateLimiter;

#[async_trait]
impl RateLimiter for AllowAllRateLimiter {
    async fn check(
        &self,
        _key: &RateLimitKey,
        policy: RateLimitPolicy,
        _cost: u32,
    ) -> Result<RateLimitDecision, AuthError> {
        Ok(RateLimitDecision::allow(policy.limit))
    }

    async fn peek(
        &self,
        _key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError> {
        Ok(RateLimitDecision::allow(policy.limit))
    }

    async fn reset(&self, _key: &RateLimitKey) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Always denies with the configured `retry_after` (default 60 s).
#[derive(Debug, Clone, Copy)]
pub struct DenyAllRateLimiter {
    /// Reported `Retry-After`.
    pub retry_after: Duration,
}

impl Default for DenyAllRateLimiter {
    fn default() -> Self {
        Self {
            retry_after: Duration::from_secs(60),
        }
    }
}

#[async_trait]
impl RateLimiter for DenyAllRateLimiter {
    async fn check(
        &self,
        _key: &RateLimitKey,
        _policy: RateLimitPolicy,
        _cost: u32,
    ) -> Result<RateLimitDecision, AuthError> {
        Ok(RateLimitDecision::deny(self.retry_after))
    }

    async fn peek(
        &self,
        _key: &RateLimitKey,
        _policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError> {
        Ok(RateLimitDecision::deny(self.retry_after))
    }

    async fn reset(&self, _key: &RateLimitKey) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Deterministic fixed-window limiter driven by an injected clock: a window
/// starts at the first hit of a key and lasts `policy.period`.
pub struct InMemoryRateLimiter {
    clock: Arc<dyn Clock>,
    windows: Mutex<HashMap<String, (OffsetDateTime, u32)>>,
}

impl std::fmt::Debug for InMemoryRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryRateLimiter")
            .finish_non_exhaustive()
    }
}

impl InMemoryRateLimiter {
    /// A limiter using `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Units consumed in the current window of `key`.
    #[must_use]
    pub fn used(&self, key: &RateLimitKey) -> u32 {
        lock(&self.windows)
            .get(&key.canonical())
            .map_or(0, |(_, used)| *used)
    }

    fn decide(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
        consume: bool,
    ) -> RateLimitDecision {
        let now = self.clock.now();
        let mut windows = lock(&self.windows);
        let entry = windows.entry(key.canonical()).or_insert((now, 0));
        if now - entry.0 >= policy.period {
            *entry = (now, 0);
        }
        let used = entry.1;
        if used.saturating_add(cost) > policy.limit {
            let elapsed = now - entry.0;
            let remaining = policy.period.saturating_sub(elapsed.unsigned_abs());
            return RateLimitDecision::deny(remaining.max(Duration::from_secs(1)));
        }
        if consume {
            entry.1 = used + cost;
        }
        RateLimitDecision::allow(policy.limit - used - if consume { cost } else { 0 })
    }
}

#[async_trait]
impl RateLimiter for InMemoryRateLimiter {
    async fn check(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
    ) -> Result<RateLimitDecision, AuthError> {
        Ok(self.decide(key, policy, cost, true))
    }

    async fn peek(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError> {
        Ok(self.decide(key, policy, 1, false))
    }

    async fn reset(&self, key: &RateLimitKey) -> Result<(), AuthError> {
        lock(&self.windows).remove(&key.canonical());
        Ok(())
    }
}
