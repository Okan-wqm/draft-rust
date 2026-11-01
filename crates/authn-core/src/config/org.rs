//! `[org]` — organizations, invitations, API keys (owner: authn-org).
//! ORG-01 … ORG-12.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, days, hours, mins, secs};
use super::password::validate_policy;
use crate::ports::RateLimitPolicy;

/// API key settings (ORG-08).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiKeyConfig {
    /// Environment label in the key prefix (`ak_<env>_…`). Default `live`.
    /// Keys of another environment are rejected before any database work.
    pub environment: String,
    /// Maximum lifetime; expiry is mandatory. Default `365d`.
    #[serde(with = "super::duration")]
    pub max_lifetime: Duration,
    /// Lifetime when the client does not choose. Default `90d`.
    #[serde(with = "super::duration")]
    pub default_lifetime: Duration,
    /// Overlap during rotation. Default `24h`.
    #[serde(with = "super::duration")]
    pub rotation_grace: Duration,
    /// `last_used_at` / `last_used_ip` are written at most once per key per
    /// interval (keeps hot keys from turning every request into a write).
    /// Default `1m`.
    #[serde(with = "super::duration")]
    pub last_used_update_interval: Duration,
    /// Failed authentications with well-formed keys (unknown, revoked,
    /// expired) per client IP before `429`; also bounds the audit events
    /// written for them. Default 30 per 15 minutes.
    pub auth_failures_per_ip: RateLimitPolicy,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            environment: "live".to_owned(),
            max_lifetime: days(365),
            default_lifetime: days(90),
            rotation_grace: hours(24),
            last_used_update_interval: mins(1),
            auth_failures_per_ip: RateLimitPolicy::new(30, mins(15)),
        }
    }
}

/// Per-organization resource limits (abuse / DoS bounds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OrgLimits {
    /// Custom roles per organization. Default 50.
    pub custom_roles: u32,
    /// Domains per organization. Default 20.
    pub domains: u32,
    /// Service accounts per organization. Default 100.
    pub service_accounts: u32,
    /// Active (not revoked) API keys per organization. Default 500.
    pub api_keys: u32,
    /// Pending invitations per organization. Default 1000.
    pub pending_invitations: u32,
}

impl Default for OrgLimits {
    fn default() -> Self {
        Self {
            custom_roles: 50,
            domains: 20,
            service_accounts: 100,
            api_keys: 500,
            pending_invitations: 1000,
        }
    }
}

/// `[org]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OrgConfig {
    /// Invitation lifetime. Default `7d`.
    #[serde(with = "super::duration")]
    pub invitation_ttl: Duration,
    /// Invitation (re)sends per organization. Default 50 per hour.
    pub invitation_sends_per_org: RateLimitPolicy,
    /// Minimum time between two sends of the same invitation. Default `1m`.
    #[serde(with = "super::duration")]
    pub invitation_resend_cooldown: Duration,
    /// Invitation e-mails (new + resend) per organization and recipient
    /// address; bounds mail bombing through revoke / re-invite cycles.
    /// Default 5 per day.
    pub invitation_sends_per_recipient: RateLimitPolicy,
    /// Organizations a user may create. Default 10 per day.
    pub creates_per_user: RateLimitPolicy,
    /// Invitation preview / acceptance and ownership-transfer acceptance
    /// attempts per user. Default 30 per hour.
    pub token_attempts_per_user: RateLimitPolicy,
    /// DNS TXT record label (ORG-06). Default `_authn-verification`.
    pub domain_verification_label: String,
    /// Domain verification checks (DNS lookups) per organization. Default
    /// 30 per hour.
    pub domain_checks_per_org: RateLimitPolicy,
    /// Timeout of one DNS TXT lookup (ORG-06). Default `5s`.
    #[serde(with = "super::duration")]
    pub dns_timeout: Duration,
    /// Ownership transfer acceptance window (ORG-11). Default `7d`.
    #[serde(with = "super::duration")]
    pub ownership_transfer_ttl: Duration,
    /// Ownership transfer requests per organization. Default 10 per hour.
    pub ownership_transfers_per_org: RateLimitPolicy,
    /// Organization deletion grace period (ORG-12). Default `30d`.
    #[serde(with = "super::duration")]
    pub deletion_grace_period: Duration,
    /// Resource limits.
    pub limits: OrgLimits,
    /// API keys.
    pub api_keys: ApiKeyConfig,
}

impl Default for OrgConfig {
    fn default() -> Self {
        Self {
            invitation_ttl: days(7),
            invitation_sends_per_org: RateLimitPolicy::new(50, hours(1)),
            invitation_resend_cooldown: mins(1),
            invitation_sends_per_recipient: RateLimitPolicy::new(5, days(1)),
            creates_per_user: RateLimitPolicy::new(10, days(1)),
            token_attempts_per_user: RateLimitPolicy::new(30, hours(1)),
            domain_verification_label: "_authn-verification".to_owned(),
            domain_checks_per_org: RateLimitPolicy::new(30, hours(1)),
            dns_timeout: secs(5),
            ownership_transfer_ttl: days(7),
            ownership_transfers_per_org: RateLimitPolicy::new(10, hours(1)),
            deletion_grace_period: days(30),
            limits: OrgLimits::default(),
            api_keys: ApiKeyConfig::default(),
        }
    }
}

impl OrgConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require_range(
            self.invitation_ttl,
            hours(1),
            days(30),
            "org.invitation_ttl",
        );
        validate_policy(
            p,
            &self.invitation_sends_per_org,
            "org.invitation_sends_per_org",
        );
        p.require_range(
            self.invitation_resend_cooldown,
            Duration::ZERO,
            hours(1),
            "org.invitation_resend_cooldown",
        );
        validate_policy(
            p,
            &self.invitation_sends_per_recipient,
            "org.invitation_sends_per_recipient",
        );
        validate_policy(p, &self.creates_per_user, "org.creates_per_user");
        validate_policy(
            p,
            &self.token_attempts_per_user,
            "org.token_attempts_per_user",
        );
        p.require(
            self.domain_verification_label
                .strip_prefix('_')
                .is_some_and(|rest| {
                    (1..=62).contains(&rest.len())
                        && rest
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                }),
            "org.domain_verification_label",
            "must be an underscore label like _authn-verification",
        );
        validate_policy(p, &self.domain_checks_per_org, "org.domain_checks_per_org");
        p.require_range(self.dns_timeout, secs(1), secs(30), "org.dns_timeout");
        p.require_range(
            self.ownership_transfer_ttl,
            hours(1),
            days(30),
            "org.ownership_transfer_ttl",
        );
        validate_policy(
            p,
            &self.ownership_transfers_per_org,
            "org.ownership_transfers_per_org",
        );
        p.require_range(
            self.deletion_grace_period,
            Duration::ZERO,
            days(365),
            "org.deletion_grace_period",
        );
        let l = &self.limits;
        for (value, key, max) in [
            (l.custom_roles, "org.limits.custom_roles", 1000),
            (l.domains, "org.limits.domains", 1000),
            (l.service_accounts, "org.limits.service_accounts", 10_000),
            (l.api_keys, "org.limits.api_keys", 100_000),
            (
                l.pending_invitations,
                "org.limits.pending_invitations",
                100_000,
            ),
        ] {
            p.require(
                (1..=max).contains(&value),
                key,
                "must be at least 1 and within the documented maximum",
            );
        }
        let k = &self.api_keys;
        p.require(
            !k.environment.is_empty()
                && k.environment.len() <= 8
                && k.environment.bytes().all(|b| b.is_ascii_lowercase()),
            "org.api_keys.environment",
            "must be 1-8 lowercase letters",
        );
        p.require_range(
            k.max_lifetime,
            days(1),
            days(365),
            "org.api_keys.max_lifetime",
        );
        p.require(
            k.default_lifetime <= k.max_lifetime && !k.default_lifetime.is_zero(),
            "org.api_keys.default_lifetime",
            "must be > 0 and <= max_lifetime",
        );
        p.require_range(
            k.rotation_grace,
            Duration::ZERO,
            days(7),
            "org.api_keys.rotation_grace",
        );
        p.require_range(
            k.last_used_update_interval,
            Duration::ZERO,
            hours(1),
            "org.api_keys.last_used_update_interval",
        );
        validate_policy(
            p,
            &k.auth_failures_per_ip,
            "org.api_keys.auth_failures_per_ip",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(config: &OrgConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    #[test]
    fn org_05_08_defaults_follow_the_specification_and_validate() {
        let c = OrgConfig::default();
        assert_eq!(c.invitation_ttl, days(7));
        assert_eq!(c.api_keys.max_lifetime, days(365));
        assert_eq!(c.api_keys.environment, "live");
        assert_eq!(
            c.invitation_sends_per_recipient,
            RateLimitPolicy::new(5, days(1))
        );
        assert!(problems(&c).is_empty(), "{:?}", problems(&c));
    }

    #[test]
    fn org_08_invalid_values_are_reported_by_key() {
        let mut c = OrgConfig::default();
        c.api_keys.environment = "LIVE_1".to_owned();
        c.api_keys.default_lifetime = days(400);
        c.limits.api_keys = 0;
        c.dns_timeout = Duration::ZERO;
        c.domain_verification_label = "authn".to_owned();
        let found = problems(&c);
        for key in [
            "org.api_keys.environment",
            "org.api_keys.default_lifetime",
            "org.limits.api_keys",
            "org.dns_timeout",
            "org.domain_verification_label",
        ] {
            assert!(found.iter().any(|p| p.starts_with(key)), "{key}: {found:?}");
        }
    }
}
