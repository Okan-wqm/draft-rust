//! Runtime settings of the admin API (`[admin]`, ADM-01, ADM-04).

use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::admin::AdminConfig;
use ipnet::IpNet;

/// Settings of [`crate::AdminService`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSettings {
    /// Optional client IP allow-list for `/v1/admin` (ADM-01). Empty = any.
    pub ip_allow_list: Vec<IpNet>,
    /// Maximum age of the last (re-)authentication for every admin request
    /// (ADM-01, default 10 minutes).
    pub step_up_max_age: Duration,
    /// Impersonation duration when none is requested (ADM-04, default 15
    /// minutes).
    pub impersonation_default_ttl: Duration,
    /// Longest impersonation (ADM-04, default and hard cap 60 minutes).
    pub impersonation_max_ttl: Duration,
    /// Most events one audit export returns (ADM-07).
    pub audit_export_max_events: u32,
    /// Accounts processed per transaction by the bulk "force password
    /// reset" emergency operation (ADM-06).
    pub bulk_batch_size: u32,
}

/// Hard cap of an impersonation (ADM-04): never longer than 60 minutes,
/// whatever the configuration says.
pub const IMPERSONATION_HARD_CAP: Duration = Duration::from_secs(60 * 60);

impl AdminSettings {
    /// Settings from `[admin]`.
    #[must_use]
    pub fn from_config(config: &AdminConfig) -> Self {
        let max = config.impersonation_max_ttl.min(IMPERSONATION_HARD_CAP);
        Self {
            ip_allow_list: config.ip_allow_list.clone(),
            step_up_max_age: config.step_up_max_age,
            impersonation_default_ttl: config.impersonation_default_ttl.min(max),
            impersonation_max_ttl: max,
            audit_export_max_events: 5_000,
            bulk_batch_size: 500,
        }
    }

    /// Settings from the whole application configuration.
    #[must_use]
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self::from_config(&config.admin)
    }
}

impl Default for AdminSettings {
    fn default() -> Self {
        Self::from_config(&AdminConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adm_04_impersonation_ttl_never_exceeds_one_hour() {
        let config = AdminConfig {
            impersonation_max_ttl: Duration::from_secs(3 * 3600),
            impersonation_default_ttl: Duration::from_secs(2 * 3600),
            ..AdminConfig::default()
        };
        let settings = AdminSettings::from_config(&config);
        assert_eq!(settings.impersonation_max_ttl, IMPERSONATION_HARD_CAP);
        assert_eq!(settings.impersonation_default_ttl, IMPERSONATION_HARD_CAP);
        let defaults = AdminSettings::default();
        assert_eq!(defaults.impersonation_default_ttl, Duration::from_secs(900));
        assert_eq!(defaults.step_up_max_age, Duration::from_secs(600));
    }
}
