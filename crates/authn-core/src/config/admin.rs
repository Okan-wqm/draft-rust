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
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            ip_allow_list: Vec::new(),
            step_up_max_age: mins(10),
            impersonation_default_ttl: mins(15),
            impersonation_max_ttl: mins(60),
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
        p.require(
            !self.impersonation_default_ttl.is_zero()
                && self.impersonation_default_ttl <= self.impersonation_max_ttl,
            "admin.impersonation_default_ttl",
            "must be > 0 and <= impersonation_max_ttl",
        );
    }
}
