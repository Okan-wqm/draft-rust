//! The Generic Cell Rate Algorithm shared by every backend (PRT-01).
//!
//! A policy of `limit` units per `period` gives an emission interval
//! `T = period / limit` and a burst of `limit`. The only state per key is
//! the *theoretical arrival time* (TAT). A request of `cost` units at `now`
//! is admitted iff `max(TAT, now) + cost·T − now ≤ period`; admitting it
//! moves TAT to that value. A denial carries the exact wait until the
//! request would be admitted (`Retry-After`, PRT-04).
//!
//! All arithmetic is in whole microseconds (the precision of PostgreSQL
//! `timestamptz`) with saturating `i64` operations, so the memory,
//! PostgreSQL and Redis backends compute identical decisions.

use std::time::Duration;

use authn_core::error::AuthError;
use authn_core::ports::{RateLimitDecision, RateLimitPolicy};
use time::OffsetDateTime;

/// Microseconds since the Unix epoch (saturating).
#[must_use]
pub fn unix_micros(t: OffsetDateTime) -> i64 {
    let micros = t.unix_timestamp_nanos() / 1_000;
    i64::try_from(micros).unwrap_or(if micros < 0 { i64::MIN } else { i64::MAX })
}

/// The instant `micros` µs after the Unix epoch.
pub fn from_unix_micros(micros: i64) -> Result<OffsetDateTime, AuthError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000)
        .map_err(|_| AuthError::internal("rate-limit timestamp out of range"))
}

fn duration_micros(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

fn micros_duration(us: i64) -> Duration {
    Duration::from_micros(u64::try_from(us.max(1)).unwrap_or(1))
}

/// Parameters of one decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcraParams {
    /// Emission interval `T` (µs, ≥ 1).
    pub emission_us: i64,
    /// Period = burst tolerance + `T` (µs).
    pub period_us: i64,
    /// `cost · T` (µs).
    pub increment_us: i64,
    /// The policy limit (upper bound of `remaining`).
    pub limit: u32,
}

/// What a backend has to do for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Decide with GCRA using these parameters.
    Gcra(GcraParams),
    /// The cost can never be admitted (cost > limit or limit 0): deny
    /// without touching storage.
    Reject(RateLimitDecision),
}

/// Validates a policy / cost pair and derives the GCRA parameters.
pub fn plan(policy: RateLimitPolicy, cost: u32) -> Result<Plan, AuthError> {
    let period_us = duration_micros(policy.period);
    if period_us <= 0 {
        return Err(AuthError::internal("rate-limit policy with a zero period"));
    }
    if policy.limit == 0 || cost > policy.limit {
        return Ok(Plan::Reject(RateLimitDecision::deny(policy.period)));
    }
    // Rounding T *up* keeps the sustained rate at or below the policy and
    // makes the burst exactly `limit` (with T rounded down, `limit + 1`
    // requests could fit into `period`). The effective period is `limit·T`.
    let limit = i64::from(policy.limit);
    let emission_us = period_us.saturating_add(limit - 1) / limit;
    let emission_us = emission_us.max(1);
    Ok(Plan::Gcra(GcraParams {
        emission_us,
        period_us: emission_us.saturating_mul(limit),
        increment_us: emission_us.saturating_mul(i64::from(cost)),
        limit: policy.limit,
    }))
}

/// The outcome of [`decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Admitted; store `new_tat`.
    Allow {
        /// New theoretical arrival time (µs since epoch).
        new_tat: i64,
        /// Units still available.
        remaining: u32,
    },
    /// Denied; storage is unchanged.
    Deny {
        /// Wait until the request would be admitted (µs, ≥ 1).
        retry_after_us: i64,
    },
}

impl Outcome {
    /// The port-level decision.
    #[must_use]
    pub fn decision(self) -> RateLimitDecision {
        match self {
            Self::Allow { remaining, .. } => RateLimitDecision::allow(remaining),
            Self::Deny { retry_after_us } => {
                RateLimitDecision::deny(micros_duration(retry_after_us))
            }
        }
    }
}

/// One GCRA step. `stored_tat` is `None` for an unknown (or expired) key.
#[must_use]
pub fn decide(stored_tat: Option<i64>, now_us: i64, p: GcraParams) -> Outcome {
    let tat = stored_tat.map_or(now_us, |t| t.max(now_us));
    let new_tat = tat.saturating_add(p.increment_us);
    let ahead = new_tat.saturating_sub(now_us);
    if ahead > p.period_us {
        return Outcome::Deny {
            retry_after_us: ahead.saturating_sub(p.period_us).max(1),
        };
    }
    Outcome::Allow {
        new_tat,
        remaining: remaining_after(new_tat, now_us, p),
    }
}

/// Units still available when the TAT is `tat`.
#[must_use]
pub fn remaining_after(tat: i64, now_us: i64, p: GcraParams) -> u32 {
    let ahead = tat.saturating_sub(now_us).max(0);
    let free = p.period_us.saturating_sub(ahead).max(0) / p.emission_us;
    u32::try_from(free).unwrap_or(u32::MAX).min(p.limit)
}

/// The decision a denied conditional update implies, given the stored TAT
/// that blocked it (used by the PostgreSQL backend).
#[must_use]
pub fn denial_for(stored_tat: i64, now_us: i64, p: GcraParams) -> RateLimitDecision {
    match decide(Some(stored_tat), now_us, p) {
        Outcome::Deny { retry_after_us } => {
            RateLimitDecision::deny(micros_duration(retry_after_us))
        }
        // Storage said "denied": never report an admission, whatever the
        // local arithmetic says.
        Outcome::Allow { .. } => RateLimitDecision::deny(micros_duration(p.emission_us)),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn params(limit: u32, period: Duration, cost: u32) -> GcraParams {
        match plan(RateLimitPolicy::new(limit, period), cost).unwrap() {
            Plan::Gcra(p) => p,
            Plan::Reject(_) => panic!("rejected"),
        }
    }

    #[test]
    fn prt_01_burst_of_limit_then_denial_with_exact_retry_after() {
        let p = params(10, Duration::from_secs(60), 1);
        let now = 1_000_000_000;
        let mut tat = None;
        for i in 0..10 {
            match decide(tat, now, p) {
                Outcome::Allow { new_tat, remaining } => {
                    assert_eq!(remaining, 9 - i);
                    tat = Some(new_tat);
                }
                Outcome::Deny { .. } => panic!("denied at {i}"),
            }
        }
        let Outcome::Deny { retry_after_us } = decide(tat, now, p) else {
            panic!("11th request admitted");
        };
        assert_eq!(retry_after_us, 6_000_000, "one emission interval");
        // After one emission interval exactly one more unit is available.
        assert!(matches!(
            decide(tat, now + 6_000_000, p),
            Outcome::Allow { remaining: 0, .. }
        ));
    }

    #[test]
    fn prt_01_cost_above_limit_is_rejected_without_state() {
        let plan = plan(RateLimitPolicy::new(3, Duration::from_secs(1)), 4).unwrap();
        assert_eq!(
            plan,
            Plan::Reject(RateLimitDecision::deny(Duration::from_secs(1)))
        );
        assert!(plan_zero_period_is_internal_error());
    }

    fn plan_zero_period_is_internal_error() -> bool {
        plan(RateLimitPolicy::new(3, Duration::ZERO), 1).is_err()
    }

    #[test]
    fn prt_04_retry_after_is_never_zero() {
        let p = params(1, Duration::from_micros(1), 1);
        let Outcome::Allow { new_tat, .. } = decide(None, 10, p) else {
            panic!()
        };
        let d = decide(Some(new_tat), 10, p).decision();
        assert!(!d.allowed);
        assert!(d.retry_after.unwrap() >= Duration::from_micros(1));
    }

    #[test]
    fn micros_round_trip() {
        let t = time::macros::datetime!(2026-01-01 00:00:00.123456 UTC);
        assert_eq!(from_unix_micros(unix_micros(t)).unwrap(), t);
    }

    proptest! {
        /// GCRA conformance (PRT-01): between any two admitted requests at
        /// `t_i ≤ t_j`, at most `limit + (t_j − t_i) / T` units were
        /// admitted — a burst of `limit`, then one unit per emission
        /// interval — whatever the arrival pattern.
        #[test]
        fn prt_01_never_admits_more_than_burst_plus_rate(
            limit in 1_u32..20,
            period_ms in 1_u64..10_000,
            gaps in proptest::collection::vec(0_i64..2_000_000, 1..200),
        ) {
            let p = params(limit, Duration::from_millis(period_ms), 1);
            let mut tat = None;
            let mut now = 0_i64;
            let mut admitted: Vec<i64> = Vec::new();
            for gap in gaps {
                now += gap;
                if let Outcome::Allow { new_tat, .. } = decide(tat, now, p) {
                    tat = Some(new_tat);
                    admitted.push(now);
                }
            }
            for i in 0..admitted.len() {
                for j in i..admitted.len() {
                    let count = i64::try_from(j - i + 1).unwrap();
                    let bound = i64::from(limit) + (admitted[j] - admitted[i]) / p.emission_us;
                    prop_assert!(count <= bound, "{count} > {bound}");
                }
            }
        }

        /// With no time passing, exactly `limit` unit requests are admitted.
        #[test]
        fn prt_01_burst_is_exactly_limit(limit in 1_u32..200, period_ms in 1_u64..100_000) {
            let p = params(limit, Duration::from_millis(period_ms), 1);
            let mut tat = None;
            let mut admitted = 0_u32;
            for _ in 0..(limit + 5) {
                if let Outcome::Allow { new_tat, .. } = decide(tat, 42, p) {
                    tat = Some(new_tat);
                    admitted += 1;
                }
            }
            prop_assert_eq!(admitted, limit);
        }

        /// A denied request is admitted exactly `retry_after` later.
        #[test]
        fn prt_04_retry_after_is_exact(limit in 1_u32..20, period_ms in 1_u64..10_000, n in 1_usize..50) {
            let p = params(limit, Duration::from_millis(period_ms), 1);
            let mut tat = None;
            let now = 5_000_000;
            for _ in 0..n {
                match decide(tat, now, p) {
                    Outcome::Allow { new_tat, .. } => tat = Some(new_tat),
                    Outcome::Deny { retry_after_us } => {
                        let later = decide(tat, now + retry_after_us, p);
                        prop_assert!(matches!(later, Outcome::Allow { .. }), "not admitted after retry_after");
                        if retry_after_us > 1 {
                            let early = decide(tat, now + retry_after_us - 1, p);
                            prop_assert!(matches!(early, Outcome::Deny { .. }), "admitted early");
                        }
                        break;
                    }
                }
            }
        }
    }
}
