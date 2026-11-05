//! `[admin]` — platform admin API (owner: authn-admin). ADM-01, ADM-04.

use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

use super::common::{ConfigProblems, hours, mins};

/// `[admin]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Optional client IP allow-list for `/v1/admin` (ADM-01). Default: any.
    pub ip_allow_list: Vec<IpNet>,
    /// Step-up window for every admin operation (ADM-01). Default `10m`.
    #[serde(with = "super::duration")]
    pub step_up_max_age: Duration,
    /// Impersonation default duration (ADM-04). Default `15m`.
    #[serde(with = "super::duration")]
    pub impersonation_default_ttl: Duration,
    /// Impersonation maximum duration. Default `60m`.
    #[serde(with = "super::duration")]
    pub impersonation_max_ttl: Duration,
    /// Four-eyes approval of critical operations (K-66): emergency
    /// operations and actions on another platform admin need the approval
    /// of a second platform admin. Unset: on in `production` and `staging`,
    /// off in `development` and `test` (`authn_admin::AdminSettings`);
    /// `false` is refused in `production`.
    pub four_eyes: Option<bool>,
    /// Lifetime of a four-eyes approval request (K-66). Default `30m`,
    /// 5 min – 2 h.
    #[serde(with = "super::duration")]
    pub four_eyes_approval_ttl: Duration,
    /// Most pending four-eyes requests one admin may have at a time (K-66,
    /// K-74: approval fatigue). Default 3, allowed
    /// [`MAX_PENDING_REQUESTS_RANGE`].
    pub four_eyes_max_pending_requests: u32,
    /// Most four-eyes requests one admin may raise per hour, decided ones
    /// included (K-66, K-74). Default 10, allowed
    /// [`MAX_REQUESTS_PER_HOUR_RANGE`] and at least
    /// `four_eyes_max_pending_requests`.
    pub four_eyes_max_requests_per_hour: u32,
}

/// Allowed values of `admin.four_eyes_max_pending_requests` (K-74): at
/// least one request (0 would make four-eyes operations impossible), at
/// most 10 (more prompts invite approval fatigue).
pub const MAX_PENDING_REQUESTS_RANGE: std::ops::RangeInclusive<u32> = 1..=10;

/// Allowed values of `admin.four_eyes_max_requests_per_hour` (K-74).
pub const MAX_REQUESTS_PER_HOUR_RANGE: std::ops::RangeInclusive<u32> = 1..=60;

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            ip_allow_list: Vec::new(),
            step_up_max_age: mins(10),
            impersonation_default_ttl: mins(15),
            impersonation_max_ttl: mins(60),
            four_eyes: None,
            four_eyes_approval_ttl: mins(30),
            four_eyes_max_pending_requests: 3,
            four_eyes_max_requests_per_hour: 10,
        }
    }
}

impl AdminConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require_range(
            self.step_up_max_age,
            mins(1),
            hours(1),
            "admin.step_up_max_age",
        );
        p.require_range(
            self.impersonation_max_ttl,
            mins(1),
            mins(60),
            "admin.impersonation_max_ttl",
        );
        p.require_range(
            self.four_eyes_approval_ttl,
            mins(5),
            hours(2),
            "admin.four_eyes_approval_ttl",
        );
        p.require(
            MAX_PENDING_REQUESTS_RANGE.contains(&self.four_eyes_max_pending_requests),
            "admin.four_eyes_max_pending_requests",
            "must be between 1 and 10",
        );
        p.require(
            MAX_REQUESTS_PER_HOUR_RANGE.contains(&self.four_eyes_max_requests_per_hour),
            "admin.four_eyes_max_requests_per_hour",
            "must be between 1 and 60",
        );
        p.require(
            self.four_eyes_max_requests_per_hour >= self.four_eyes_max_pending_requests,
            "admin.four_eyes_max_requests_per_hour",
            "must be >= four_eyes_max_pending_requests",
        );
        p.require(
            !self.impersonation_default_ttl.is_zero()
                && self.impersonation_default_ttl <= self.impersonation_max_ttl,
            "admin.impersonation_default_ttl",
            "must be > 0 and <= impersonation_max_ttl",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(config: &AdminConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    /// K-74: the four-eyes request caps are configurable within sane
    /// bounds; out-of-range values (0 included) and an hourly cap below the
    /// pending cap are refused, so a mistake fails closed at start-up.
    #[test]
    fn adm_06_k74_approval_request_caps_are_validated() {
        let defaults = AdminConfig::default();
        assert_eq!(defaults.four_eyes_max_pending_requests, 3);
        assert_eq!(defaults.four_eyes_max_requests_per_hour, 10);
        assert!(problems(&defaults).is_empty(), "{:?}", problems(&defaults));
        let with = |pending: u32, per_hour: u32| AdminConfig {
            four_eyes_max_pending_requests: pending,
            four_eyes_max_requests_per_hour: per_hour,
            ..AdminConfig::default()
        };
        for (pending, per_hour) in [(1, 1), (10, 60), (2, 5)] {
            let found = problems(&with(pending, per_hour));
            assert!(found.is_empty(), "{pending}/{per_hour}: {found:?}");
        }
        for (pending, per_hour, key) in [
            (0, 10, "admin.four_eyes_max_pending_requests"),
            (11, 20, "admin.four_eyes_max_pending_requests"),
            (3, 0, "admin.four_eyes_max_requests_per_hour"),
            (3, 61, "admin.four_eyes_max_requests_per_hour"),
            (5, 4, "admin.four_eyes_max_requests_per_hour"),
        ] {
            let found = problems(&with(pending, per_hour));
            assert!(
                found.iter().any(|p| p.starts_with(key)),
                "{pending}/{per_hour}: {found:?}"
            );
        }
    }

    /// K-74: the keys are read from TOML; misspelt keys stay refused.
    #[test]
    fn adm_06_k74_approval_request_caps_are_read_from_toml() {
        use figment::Figment;
        use figment::providers::{Format, Toml};
        let config: AdminConfig = Figment::from(Toml::string(
            "four_eyes_max_pending_requests = 2\nfour_eyes_max_requests_per_hour = 6\n",
        ))
        .extract()
        .unwrap();
        assert_eq!(config.four_eyes_max_pending_requests, 2);
        assert_eq!(config.four_eyes_max_requests_per_hour, 6);
        assert!(
            Figment::from(Toml::string("four_eyes_max_pending = 2\n"))
                .extract::<AdminConfig>()
                .is_err()
        );
    }
}
