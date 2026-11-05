//! Rate limiting (PRT-01, PRT-02, PRT-04). Owner of this file: authn-protect.
//!
//! Semantics required from implementations (memory, PostgreSQL, Redis):
//! * `check` is atomic: concurrent calls for the same key never admit more
//!   than the policy allows (GCRA or sliding window).
//! * Keys are stored hashed (keyed hash) — never raw e-mails or IPs.
//! * Denials carry `retry_after`; callers answer `429` + `Retry-After`
//!   (PRT-04) via [`RateLimitDecision::into_result`], never by sleeping.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;

use crate::domain::PhoneNumber;
use crate::error::{AuthError, codes};
use crate::id::{OrgId, UserId};

/// Rate limiter backend.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Consumes `cost` units if allowed and reports the decision.
    async fn check(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
    ) -> Result<RateLimitDecision, AuthError>;

    /// Reports the decision `check(key, policy, 1)` would make, without
    /// consuming anything.
    async fn peek(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError>;

    /// Forgets all state for a key (e.g. failure counter after success).
    async fn reset(&self, key: &RateLimitKey) -> Result<(), AuthError>;

    /// Runs `steps` in order, as [`RateLimiter::check`] / [`RateLimiter::peek`]
    /// would one after another, and returns one decision per step **that
    /// ran**: after a step with [`RateLimitStep::stop_if_denied`] is denied,
    /// the remaining steps do not run (nothing is consumed for them) and
    /// the result is shorter than `steps`.
    ///
    /// Every step keeps the atomicity of `check` (concurrent chains never
    /// admit more than a policy allows); the chain as a whole is not one
    /// transaction across keys, exactly like the sequence of single calls
    /// it replaces. Backends may run the chain in one round trip (K-128);
    /// the default runs the single calls.
    async fn check_chain(
        &self,
        steps: &[RateLimitStep<'_>],
    ) -> Result<Vec<RateLimitDecision>, AuthError> {
        let mut decisions = Vec::with_capacity(steps.len());
        for step in steps {
            let decision = match step.mode {
                StepMode::Check { cost } => self.check(step.key, step.policy, cost).await?,
                StepMode::Peek => self.peek(step.key, step.policy).await?,
            };
            let stop = step.stop_if_denied && !decision.allowed;
            decisions.push(decision);
            if stop {
                break;
            }
        }
        Ok(decisions)
    }

    /// [`RateLimiter::peek`] of several keys (one round trip where the
    /// backend supports it). Decisions in the order of `keys`.
    async fn peek_many(
        &self,
        keys: &[(&RateLimitKey, RateLimitPolicy)],
    ) -> Result<Vec<RateLimitDecision>, AuthError> {
        let mut decisions = Vec::with_capacity(keys.len());
        for (key, policy) in keys {
            decisions.push(self.peek(key, *policy).await?);
        }
        Ok(decisions)
    }

    /// [`RateLimiter::reset`] of several keys (one round trip where the
    /// backend supports it).
    async fn reset_many(&self, keys: &[&RateLimitKey]) -> Result<(), AuthError> {
        for key in keys {
            self.reset(key).await?;
        }
        Ok(())
    }
}

/// What one [`RateLimitStep`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepMode {
    /// [`RateLimiter::check`] with this cost.
    Check {
        /// Units to consume.
        cost: u32,
    },
    /// [`RateLimiter::peek`] (consumes nothing).
    Peek,
}

/// One step of [`RateLimiter::check_chain`].
#[derive(Debug, Clone, Copy)]
pub struct RateLimitStep<'a> {
    /// The key.
    pub key: &'a RateLimitKey,
    /// The policy.
    pub policy: RateLimitPolicy,
    /// Check (consume) or peek.
    pub mode: StepMode,
    /// A denial of this step ends the chain: later steps do not run.
    pub stop_if_denied: bool,
}

impl<'a> RateLimitStep<'a> {
    /// A consuming step (cost 1) that ends the chain when denied.
    #[must_use]
    pub fn check(key: &'a RateLimitKey, policy: RateLimitPolicy) -> Self {
        Self {
            key,
            policy,
            mode: StepMode::Check { cost: 1 },
            stop_if_denied: true,
        }
    }

    /// A non-consuming step that ends the chain when denied.
    #[must_use]
    pub fn peek(key: &'a RateLimitKey, policy: RateLimitPolicy) -> Self {
        Self {
            key,
            policy,
            mode: StepMode::Peek,
            stop_if_denied: true,
        }
    }

    /// Sets whether a denial ends the chain.
    #[must_use]
    pub fn stop_if_denied(mut self, stop: bool) -> Self {
        self.stop_if_denied = stop;
        self
    }
}

text_enum! {
    /// Dimension a limit applies to (PRT-02).
    pub enum RateLimitScope {
        /// Client IP (IPv6 aggregated to /64).
        Ip => "ip",
        /// Account: normalized e-mail or user id.
        Account => "account",
        /// IP + account pair.
        IpAccount => "ip_account",
        /// Whole endpoint.
        Endpoint => "endpoint",
        /// Organization.
        Org => "org",
        /// Phone number (SMS pumping, MFA-06).
        Phone => "phone",
        /// Global budget.
        Global => "global",
    }
}

/// A rate-limit key: `action` (e.g. `login`, `password_reset`) + scope +
/// subject. Construct with the helpers so subjects are normalized.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RateLimitKey {
    action: &'static str,
    scope: RateLimitScope,
    subject: String,
}

impl RateLimitKey {
    /// Per client IP. IPv6 addresses are aggregated to their /64 because a
    /// single client typically controls a whole /64; IPv4-mapped IPv6 is
    /// treated as IPv4.
    #[must_use]
    pub fn ip(action: &'static str, ip: IpAddr) -> Self {
        Self {
            action,
            scope: RateLimitScope::Ip,
            subject: ip_subject(ip),
        }
    }

    /// Per account, by normalized e-mail (`EmailAddress::normalized`) or user
    /// id string. Use the same form consistently for one action.
    #[must_use]
    pub fn account(action: &'static str, account: &str) -> Self {
        Self {
            action,
            scope: RateLimitScope::Account,
            subject: account.to_owned(),
        }
    }

    /// Per user id.
    #[must_use]
    pub fn user(action: &'static str, user: UserId) -> Self {
        Self::account(action, &user.to_string())
    }

    /// Per (IP, account) pair.
    #[must_use]
    pub fn ip_account(action: &'static str, ip: IpAddr, account: &str) -> Self {
        Self {
            action,
            scope: RateLimitScope::IpAccount,
            subject: format!("{}|{account}", ip_subject(ip)),
        }
    }

    /// Per endpoint (whole action).
    #[must_use]
    pub fn endpoint(action: &'static str) -> Self {
        Self {
            action,
            scope: RateLimitScope::Endpoint,
            subject: String::new(),
        }
    }

    /// Per organization.
    #[must_use]
    pub fn org(action: &'static str, org: OrgId) -> Self {
        Self {
            action,
            scope: RateLimitScope::Org,
            subject: org.to_string(),
        }
    }

    /// Per phone number.
    #[must_use]
    pub fn phone(action: &'static str, phone: &PhoneNumber) -> Self {
        Self {
            action,
            scope: RateLimitScope::Phone,
            subject: phone.as_str().to_owned(),
        }
    }

    /// Global budget for an action.
    #[must_use]
    pub fn global(action: &'static str) -> Self {
        Self {
            action,
            scope: RateLimitScope::Global,
            subject: String::new(),
        }
    }

    /// The action name.
    #[must_use]
    pub fn action(&self) -> &'static str {
        self.action
    }

    /// The scope.
    #[must_use]
    pub fn scope(&self) -> RateLimitScope {
        self.scope
    }

    /// Canonical string `action|scope|subject`. Contains personal data:
    /// implementations hash it before storing and never log it.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!("{}|{}|{}", self.action, self.scope.as_str(), self.subject)
    }
}

fn ip_subject(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// `limit` units per `period` (burst = `limit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitPolicy {
    /// Units allowed per period (also the burst size).
    pub limit: u32,
    /// The period.
    #[serde(with = "crate::config::duration")]
    pub period: Duration,
}

impl RateLimitPolicy {
    /// Convenience constructor.
    #[must_use]
    pub const fn new(limit: u32, period: Duration) -> Self {
        Self { limit, period }
    }
}

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Units still available after this decision.
    pub remaining: u32,
    /// When denied: how long until one unit is available.
    pub retry_after: Option<Duration>,
}

impl RateLimitDecision {
    /// An allowing decision.
    #[must_use]
    pub const fn allow(remaining: u32) -> Self {
        Self {
            allowed: true,
            remaining,
            retry_after: None,
        }
    }

    /// A denying decision.
    #[must_use]
    pub const fn deny(retry_after: Duration) -> Self {
        Self {
            allowed: false,
            remaining: 0,
            retry_after: Some(retry_after),
        }
    }

    /// `Ok(self)` when allowed, otherwise a `rate_limited` error carrying
    /// `Retry-After` (PRT-04).
    pub fn into_result(self) -> Result<Self, AuthError> {
        if self.allowed {
            Ok(self)
        } else {
            Err(AuthError::new(codes::common::RATE_LIMITED)
                .with_retry_after(self.retry_after.unwrap_or(Duration::from_secs(1))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prt_02_ipv6_keys_aggregate_to_slash_64() {
        let a = RateLimitKey::ip("login", "2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = RateLimitKey::ip("login", "2001:db8:1:2:bbbb::2".parse().unwrap());
        let c = RateLimitKey::ip("login", "2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mapped = RateLimitKey::ip("login", "::ffff:192.0.2.1".parse().unwrap());
        let v4 = RateLimitKey::ip("login", "192.0.2.1".parse().unwrap());
        assert_eq!(mapped, v4);
    }

    #[test]
    fn prt_02_keys_are_namespaced_by_action_and_scope() {
        let a = RateLimitKey::account("login", "alice@example.com");
        let b = RateLimitKey::account("password_reset", "alice@example.com");
        assert_ne!(a.canonical(), b.canonical());
        assert_eq!(a.canonical(), "login|account|alice@example.com");
        assert_eq!(RateLimitKey::global("sms").canonical(), "sms|global|");
    }

    #[test]
    fn prt_04_denied_decision_maps_to_429_with_retry_after() {
        let err = RateLimitDecision::deny(Duration::from_secs(30))
            .into_result()
            .unwrap_err();
        assert_eq!(err.code(), codes::common::RATE_LIMITED);
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
        assert!(RateLimitDecision::allow(3).into_result().is_ok());
    }
}
