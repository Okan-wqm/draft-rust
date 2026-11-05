//! Runtime settings of the admin API (`[admin]`, ADM-01, ADM-04).

use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::admin::{
    AdminConfig, MAX_PENDING_REQUESTS_RANGE, MAX_REQUESTS_PER_HOUR_RANGE,
};
use authn_core::config::common::Environment;
use authn_core::ports::RateLimitPolicy;
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
    /// Emergency operations per admin (K-08; default 3 per hour).
    pub emergency_per_admin: RateLimitPolicy,
    /// Emergency operations of all admins together, break-glass accounts
    /// excepted (K-08; default 6 per hour).
    pub emergency_global: RateLimitPolicy,
    /// Minimum time between two runs of the **same** emergency operation by
    /// any admin, break-glass accounts excepted (K-08; default 5 minutes).
    pub emergency_cooldown: Duration,
    /// Actions on another platform admin (suspend, revoke sessions, unlock)
    /// per acting admin (K-08; default 3 per hour).
    pub admin_target_per_admin: RateLimitPolicy,
    /// Actions on platform admins by all admins together, break-glass
    /// accounts excepted (K-08; default 10 per hour).
    pub admin_target_global: RateLimitPolicy,
    /// Audit chain verifications per admin (K-09; default 5 per hour).
    pub audit_verify_per_admin: RateLimitPolicy,
    /// Longest time one chain verification holds the single cluster-wide
    /// slot if its instance dies (K-09; default 15 minutes).
    pub audit_verify_lease: Duration,
    /// Lifetime of a break-glass passkey enrollment link (K-11; default 30
    /// minutes, at most [`ENROLLMENT_LINK_HARD_CAP`]).
    pub enrollment_link_ttl: Duration,
    /// Enrollment-link requests (options / verify) per client IP (K-11;
    /// default 20 per 15 minutes).
    pub enrollment_per_ip: RateLimitPolicy,
    /// Four-eyes approval of critical operations (K-66; default on in
    /// production and staging).
    pub four_eyes: bool,
    /// Lifetime of an approval request (K-66; default 30 minutes).
    pub four_eyes_approval_ttl: Duration,
    /// Most pending approval requests per requester (K-66, K-74; default
    /// 3, `admin.four_eyes_max_pending_requests`). 0 refuses every request
    /// (fails closed).
    pub four_eyes_max_pending_requests: u32,
    /// Most approval requests per requester per hour, decided ones included
    /// (K-66, K-74; default 10, `admin.four_eyes_max_requests_per_hour`).
    /// 0 refuses every request (fails closed).
    pub four_eyes_max_requests_per_hour: u32,
}

/// Longest lifetime of a break-glass passkey enrollment link (K-11).
pub const ENROLLMENT_LINK_HARD_CAP: Duration = Duration::from_secs(24 * 60 * 60);

const HOUR: Duration = Duration::from_secs(60 * 60);

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
            emergency_per_admin: RateLimitPolicy::new(3, HOUR),
            emergency_global: RateLimitPolicy::new(6, HOUR),
            emergency_cooldown: Duration::from_secs(5 * 60),
            admin_target_per_admin: RateLimitPolicy::new(3, HOUR),
            admin_target_global: RateLimitPolicy::new(10, HOUR),
            audit_verify_per_admin: RateLimitPolicy::new(5, HOUR),
            audit_verify_lease: Duration::from_secs(15 * 60),
            enrollment_link_ttl: Duration::from_secs(30 * 60),
            enrollment_per_ip: RateLimitPolicy::new(20, Duration::from_secs(15 * 60)),
            // Without the environment (see `from_app_config`): on unless
            // explicitly switched off.
            four_eyes: config.four_eyes.unwrap_or(true),
            four_eyes_approval_ttl: config.four_eyes_approval_ttl,
            // K-74: never above the validated maximum, even for a
            // configuration that skipped `AppConfig::load` validation
            // (0 stays 0 and refuses every request).
            four_eyes_max_pending_requests: config
                .four_eyes_max_pending_requests
                .min(*MAX_PENDING_REQUESTS_RANGE.end()),
            four_eyes_max_requests_per_hour: config
                .four_eyes_max_requests_per_hour
                .min(*MAX_REQUESTS_PER_HOUR_RANGE.end()),
        }
    }

    /// Settings from the whole application configuration. An unset
    /// `admin.four_eyes` is on in `production` and `staging` and off in
    /// `development` and `test` (K-66).
    #[must_use]
    pub fn from_app_config(config: &AppConfig) -> Self {
        let mut settings = Self::from_config(&config.admin);
        settings.four_eyes = config.admin.four_eyes.unwrap_or(matches!(
            config.server.environment,
            Environment::Production | Environment::Staging
        ));
        settings
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

    /// K-74: the approval request caps come from `[admin]`.
    #[test]
    fn adm_06_k74_approval_request_caps_come_from_the_configuration() {
        let defaults = AdminSettings::default();
        assert_eq!(defaults.four_eyes_max_pending_requests, 3);
        assert_eq!(defaults.four_eyes_max_requests_per_hour, 10);
        let mut config = authn_testkit::config::test_config();
        config.admin.four_eyes_max_pending_requests = 1;
        config.admin.four_eyes_max_requests_per_hour = 2;
        let settings = AdminSettings::from_app_config(&config);
        assert_eq!(settings.four_eyes_max_pending_requests, 1);
        assert_eq!(settings.four_eyes_max_requests_per_hour, 2);
    }

    /// K-74 audit: an `[admin]` section that never went through
    /// `AppConfig::load` validation (built in code by an embedder or a
    /// test) cannot raise the caps above the validated maximum (10 pending,
    /// 60 per hour), as the impersonation lifetime is capped.
    #[test]
    fn adm_06_k74_approval_request_caps_never_exceed_the_validated_maximum() {
        let config = AdminConfig {
            four_eyes_max_pending_requests: 1_000,
            four_eyes_max_requests_per_hour: u32::MAX,
            ..AdminConfig::default()
        };
        let settings = AdminSettings::from_config(&config);
        assert_eq!(settings.four_eyes_max_pending_requests, 10);
        assert_eq!(settings.four_eyes_max_requests_per_hour, 60);
        // 0 stays 0 (fails closed).
        let closed = AdminSettings::from_config(&AdminConfig {
            four_eyes_max_pending_requests: 0,
            ..AdminConfig::default()
        });
        assert_eq!(closed.four_eyes_max_pending_requests, 0);
    }

    #[test]
    fn adm_06_k66_four_eyes_defaults_on_in_production_and_staging() {
        let mut config = authn_testkit::config::test_config();
        for (environment, on) in [
            (Environment::Production, true),
            (Environment::Staging, true),
            (Environment::Development, false),
            (Environment::Test, false),
        ] {
            config.server.environment = environment;
            config.admin.four_eyes = None;
            let settings = AdminSettings::from_app_config(&config);
            assert_eq!(settings.four_eyes, on, "{environment:?}");
            assert_eq!(settings.four_eyes_approval_ttl, Duration::from_secs(1800));
            config.admin.four_eyes = Some(!on);
            assert_eq!(AdminSettings::from_app_config(&config).four_eyes, !on);
        }
    }
}
