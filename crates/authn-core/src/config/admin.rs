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
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            ip_allow_list: Vec::new(),
            step_up_max_age: mins(10),
            impersonation_default_ttl: mins(15),
            impersonation_max_ttl: mins(60),
            four_eyes: None,
            four_eyes_approval_ttl: mins(30),
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
            !self.impersonation_default_ttl.is_zero()
                && self.impersonation_default_ttl <= self.impersonation_max_ttl,
            "admin.impersonation_default_ttl",
            "must be > 0 and <= impersonation_max_ttl",
        );
    }
}
