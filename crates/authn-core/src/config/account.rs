//! `[account]` — registration, verification, lifecycle (owner:
//! authn-account). ACC-04, ACC-05, ACC-07, ACC-09 … ACC-13.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::common::{CaptchaPolicy, ConfigProblems, days, hours, mins, secs};
use super::password::validate_policy;
use crate::ports::RateLimitPolicy;

text_enum! {
    /// What an unverified account may do (ACC-05).
    #[derive(Default)]
    pub enum UnverifiedLoginPolicy {
        /// Login refused until the e-mail is verified (default).
        #[default]
        Block => "block",
        /// Login allowed with the `verify_email` required action.
        Limited => "limited",
    }
}

/// E-mail verification (ACC-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VerificationConfig {
    /// Link lifetime. Default `24h`.
    #[serde(with = "super::duration")]
    pub link_ttl: Duration,
    /// Code lifetime. Default `15m`.
    #[serde(with = "super::duration")]
    pub code_ttl: Duration,
    /// Wrong code attempts. Default 5.
    pub code_max_attempts: u32,
    /// Minimum time between two sends. Default `60s`.
    #[serde(with = "super::duration")]
    pub resend_cooldown: Duration,
    /// Sends per account per hour. Default 5.
    pub max_sends_per_hour: u32,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            link_ttl: hours(24),
            code_ttl: mins(15),
            code_max_attempts: 5,
            resend_cooldown: secs(60),
            max_sends_per_hour: 5,
        }
    }
}

/// `[account]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountConfig {
    /// E-mail verification.
    pub verification: VerificationConfig,
    /// Unverified account login policy. Default `block`.
    pub unverified_login: UnverifiedLoginPolicy,
    /// Purge never-verified accounts after. Default `7d`.
    #[serde(with = "super::duration")]
    pub unverified_purge_after: Duration,
    /// Validity of the "revert e-mail change" link (ACC-07). Default `7d`.
    #[serde(with = "super::duration")]
    pub email_change_revert_ttl: Duration,
    /// Grace period before deletion is final (ACC-09). Default `30d`.
    #[serde(with = "super::duration")]
    pub deletion_grace_period: Duration,
    /// Disposable-domain block list file (ACC-12). Default: disabled.
    pub disposable_domains_file: Option<PathBuf>,
    /// CAPTCHA on registration (ACC-13). Default `risk_based`.
    pub registration_captcha: CaptchaPolicy,
    /// Registrations per IP. Default 10 per hour.
    pub registration_per_ip: RateLimitPolicy,
    /// Require accepting the current terms at registration (ACC-11).
    /// Default `false`.
    pub require_terms_acceptance: bool,
    /// Ask again at login when a new terms version requires it. Default
    /// `true`.
    pub reaccept_terms_on_new_version: bool,
    /// Data exports per user (ACC-10). Default 2 per day.
    pub export_per_user: RateLimitPolicy,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            verification: VerificationConfig::default(),
            unverified_login: UnverifiedLoginPolicy::Block,
            unverified_purge_after: days(7),
            email_change_revert_ttl: days(7),
            deletion_grace_period: days(30),
            disposable_domains_file: None,
            registration_captcha: CaptchaPolicy::RiskBased,
            registration_per_ip: RateLimitPolicy::new(10, hours(1)),
            require_terms_acceptance: false,
            reaccept_terms_on_new_version: true,
            export_per_user: RateLimitPolicy::new(2, days(1)),
        }
    }
}

impl AccountConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        let v = &self.verification;
        p.require_range(
            v.link_ttl,
            mins(15),
            days(7),
            "account.verification.link_ttl",
        );
        p.require_range(
            v.code_ttl,
            mins(1),
            hours(1),
            "account.verification.code_ttl",
        );
        p.require(
            (1..=10).contains(&v.code_max_attempts),
            "account.verification.code_max_attempts",
            "must be between 1 and 10",
        );
        p.require_range(
            v.resend_cooldown,
            secs(10),
            hours(1),
            "account.verification.resend_cooldown",
        );
        p.require(
            (1..=100).contains(&v.max_sends_per_hour),
            "account.verification.max_sends_per_hour",
            "must be between 1 and 100",
        );
        p.require_range(
            self.unverified_purge_after,
            days(1),
            days(365),
            "account.unverified_purge_after",
        );
        p.require_range(
            self.email_change_revert_ttl,
            days(1),
            days(30),
            "account.email_change_revert_ttl",
        );
        p.require_range(
            self.deletion_grace_period,
            Duration::ZERO,
            days(365),
            "account.deletion_grace_period",
        );
        validate_policy(p, &self.registration_per_ip, "account.registration_per_ip");
        validate_policy(p, &self.export_per_user, "account.export_per_user");
    }
}
