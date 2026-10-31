//! `[org]` — organizations, invitations, API keys (owner: authn-org).
//! ORG-05, ORG-06, ORG-08, ORG-11, ORG-12.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, days, hours};
use super::password::validate_policy;
use crate::ports::RateLimitPolicy;

/// API key settings (ORG-08).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiKeyConfig {
    /// Environment label in the key prefix (`ak_<env>_…`). Default `live`.
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
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            environment: "live".to_owned(),
            max_lifetime: days(365),
            default_lifetime: days(90),
            rotation_grace: hours(24),
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
    /// DNS TXT record label (ORG-06). Default `_authn-verification`.
    pub domain_verification_label: String,
    /// Ownership transfer acceptance window (ORG-11). Default `7d`.
    #[serde(with = "super::duration")]
    pub ownership_transfer_ttl: Duration,
    /// Organization deletion grace period (ORG-12). Default `30d`.
    #[serde(with = "super::duration")]
    pub deletion_grace_period: Duration,
    /// API keys.
    pub api_keys: ApiKeyConfig,
}

impl Default for OrgConfig {
    fn default() -> Self {
        Self {
            invitation_ttl: days(7),
            invitation_sends_per_org: RateLimitPolicy::new(50, hours(1)),
            domain_verification_label: "_authn-verification".to_owned(),
            ownership_transfer_ttl: days(7),
            deletion_grace_period: days(30),
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
        p.require_range(
            self.ownership_transfer_ttl,
            hours(1),
            days(30),
            "org.ownership_transfer_ttl",
        );
        p.require_range(
            self.deletion_grace_period,
            Duration::ZERO,
            days(365),
            "org.deletion_grace_period",
        );
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
    }
}
