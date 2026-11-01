//! In-process GCRA rate limiter (PRT-01): single instance, development and
//! tests. Refused in production by configuration validation because every
//! instance would keep its own budget.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};

use super::gcra::{self, Outcome, Plan};
use crate::keys::KeyHasher;

/// Number of shards; [`MemoryRateLimiter::shard`] relies on it being 16.
const SHARDS: usize = 16;
/// Expired entries of a shard are swept every this many operations.
const SWEEP_EVERY: u64 = 1024;
/// Default bound on live keys per shard (16 shards → ~1M keys).
const DEFAULT_MAX_KEYS_PER_SHARD: usize = 65_536;

type Shard = HashMap<[u8; 32], i64>;

/// GCRA state in process memory, sharded to limit lock contention.
///
/// Keys are stored as keyed hashes, never in clear text. Memory is bounded:
/// expired entries are swept periodically and, when a shard is still full,
/// *new* keys are denied (fail closed) instead of growing without bound.
pub struct MemoryRateLimiter {
    clock: Arc<dyn Clock>,
    hasher: KeyHasher,
    shards: [Mutex<Shard>; SHARDS],
    max_keys_per_shard: usize,
    ops: AtomicU64,
}

impl std::fmt::Debug for MemoryRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryRateLimiter")
            .field("max_keys_per_shard", &self.max_keys_per_shard)
            .finish_non_exhaustive()
    }
}

impl MemoryRateLimiter {
    /// A limiter using `clock` and `hasher`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, hasher: KeyHasher) -> Self {
        Self::with_capacity(clock, hasher, DEFAULT_MAX_KEYS_PER_SHARD)
    }

    /// A limiter with an explicit bound on live keys per shard (16 shards).
    #[must_use]
    pub fn with_capacity(
        clock: Arc<dyn Clock>,
        hasher: KeyHasher,
        max_keys_per_shard: usize,
    ) -> Self {
        Self {
            clock,
            hasher,
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            max_keys_per_shard: max_keys_per_shard.max(1),
            ops: AtomicU64::new(0),
        }
    }

    /// Number of live (non-expired) keys; for tests and metrics.
    #[must_use]
    pub fn live_keys(&self) -> usize {
        let now = gcra::unix_micros(self.clock.now());
        self.shards
            .iter()
            .map(|s| lock(s).values().filter(|tat| **tat > now).count())
            .sum()
    }

    fn shard(&self, hash: &[u8; 32]) -> &Mutex<Shard> {
        let [first, ..] = *hash;
        // SHARDS is 16: the mask keeps the index in bounds by construction.
        &self.shards[usize::from(first & 0x0f)]
    }

    fn decide(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
        consume: bool,
    ) -> Result<RateLimitDecision, AuthError> {
        let params = match gcra::plan(policy, cost)? {
            Plan::Reject(decision) => return Ok(decision),
            Plan::Gcra(params) => params,
        };
        let hash = self.hasher.rate_limit_key(key);
        let now = gcra::unix_micros(self.clock.now());
        let sweep = self
            .ops
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(SWEEP_EVERY);
        let mut shard = lock(self.shard(&hash));
        if sweep {
            shard.retain(|_, tat| *tat > now);
        }
        let stored = shard.get(&hash).copied().filter(|tat| *tat > now);
        let outcome = gcra::decide(stored, now, params);
        if consume && let Outcome::Allow { new_tat, .. } = outcome {
            if stored.is_none()
                && !shard.contains_key(&hash)
                && shard.len() >= self.max_keys_per_shard
            {
                shard.retain(|_, tat| *tat > now);
                if shard.len() >= self.max_keys_per_shard {
                    tracing::warn!("in-memory rate limiter full; denying new key");
                    return Ok(RateLimitDecision::deny(policy.period));
                }
            }
            shard.insert(hash, new_tat);
        }
        Ok(outcome.decision())
    }
}

fn lock(m: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[async_trait]
impl RateLimiter for MemoryRateLimiter {
    async fn check(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
    ) -> Result<RateLimitDecision, AuthError> {
        self.decide(key, policy, cost, true)
    }

    async fn peek(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError> {
        self.decide(key, policy, 1, false)
    }

    async fn reset(&self, key: &RateLimitKey) -> Result<(), AuthError> {
        let hash = self.hasher.rate_limit_key(key);
        lock(self.shard(&hash)).remove(&hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use authn_testkit::FakeClock;

    use super::*;
    use crate::keys::test_support::hasher;

    fn limiter() -> (Arc<FakeClock>, MemoryRateLimiter) {
        let clock = Arc::new(FakeClock::new());
        (clock.clone(), MemoryRateLimiter::new(clock, hasher()))
    }

    #[tokio::test]
    async fn prt_01_memory_limiter_enforces_policy_and_recovers() {
        let (clock, limiter) = limiter();
        let key = RateLimitKey::ip("login", "198.51.100.7".parse().unwrap());
        let policy = RateLimitPolicy::new(3, Duration::from_secs(30));
        for remaining in [2, 1, 0] {
            let d = limiter.check(&key, policy, 1).await.unwrap();
            assert_eq!(d, RateLimitDecision::allow(remaining));
        }
        let denied = limiter.check(&key, policy, 1).await.unwrap();
        assert_eq!(denied, RateLimitDecision::deny(Duration::from_secs(10)));
        // Denials do not consume.
        assert_eq!(limiter.peek(&key, policy).await.unwrap(), denied);
        clock.advance(Duration::from_secs(10));
        assert!(limiter.check(&key, policy, 1).await.unwrap().allowed);
        limiter.reset(&key).await.unwrap();
        assert_eq!(
            limiter.peek(&key, policy).await.unwrap(),
            RateLimitDecision::allow(2)
        );
    }

    #[tokio::test]
    async fn prt_02_keys_are_isolated_by_dimension() {
        let (_clock, limiter) = limiter();
        let policy = RateLimitPolicy::new(1, Duration::from_secs(60));
        let ip = "203.0.113.9".parse().unwrap();
        let keys = [
            RateLimitKey::ip("login", ip),
            RateLimitKey::account("login", "a@example.com"),
            RateLimitKey::ip_account("login", ip, "a@example.com"),
            RateLimitKey::endpoint("login"),
            RateLimitKey::global("login"),
            RateLimitKey::ip("register", ip),
        ];
        for key in &keys {
            assert!(limiter.check(key, policy, 1).await.unwrap().allowed);
        }
        for key in &keys {
            assert!(!limiter.check(key, policy, 1).await.unwrap().allowed);
        }
    }

    #[tokio::test]
    async fn prt_01_memory_is_bounded_and_fails_closed_for_new_keys() {
        let clock = Arc::new(FakeClock::new());
        let limiter = MemoryRateLimiter::with_capacity(clock.clone(), hasher(), 1);
        let policy = RateLimitPolicy::new(5, Duration::from_secs(60));
        let mut denied_new = 0;
        for i in 0..64 {
            let key = RateLimitKey::account("x", &format!("user{i}"));
            if !limiter.check(&key, policy, 1).await.unwrap().allowed {
                denied_new += 1;
            }
        }
        assert!(limiter.live_keys() <= SHARDS);
        assert!(denied_new >= 64 - SHARDS);
        // Once entries expire, the space is reclaimed.
        clock.advance(Duration::from_secs(61));
        assert_eq!(limiter.live_keys(), 0);
        assert!(
            limiter
                .check(&RateLimitKey::account("x", "fresh"), policy, 1)
                .await
                .unwrap()
                .allowed
        );
    }

    #[tokio::test]
    async fn prt_01_memory_limiter_is_atomic_under_concurrency() {
        let (_clock, limiter) = limiter();
        let limiter = Arc::new(limiter);
        let key = RateLimitKey::endpoint("burst");
        let policy = RateLimitPolicy::new(25, Duration::from_secs(60));
        let mut tasks = Vec::new();
        for _ in 0..200 {
            let limiter = limiter.clone();
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                limiter.check(&key, policy, 1).await.unwrap().allowed
            }));
        }
        let mut allowed = 0;
        for task in tasks {
            allowed += usize::from(task.await.unwrap());
        }
        assert_eq!(allowed, 25);
    }
}
