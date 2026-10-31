//! `[password]` — password policy, breach check, reset (owner:
//! authn-password). PWD-01 … PWD-08.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use url::Url;

use super::common::{ConfigProblems, hours, mins, secs};
use crate::ports::RateLimitPolicy;

/// HIBP / offline breach check (PWD-03).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BreachCheckConfig {
    /// Query HIBP Pwned Passwords. Default `true`.
    pub enabled: bool,
    /// HIBP range API base. Default `https://api.pwnedpasswords.com/range/`.
    pub hibp_range_url: String,
    /// Request timeout. Default `3s`.
    #[serde(with = "super::duration")]
    pub timeout: Duration,
    /// Accept the password (and log a warning) when HIBP is unreachable.
    /// Default `true` (fail-open).
    pub fail_open: bool,
    /// Optional offline list (one SHA-1 hex per line, `HASH:COUNT` allowed).
    pub offline_list_file: Option<PathBuf>,
}

impl Default for BreachCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hibp_range_url: "https://api.pwnedpasswords.com/range/".to_owned(),
            timeout: secs(3),
            fail_open: true,
            offline_list_file: None,
        }
    }
}

/// Password reset (PWD-07, PWD-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PasswordResetConfig {
    /// Link token lifetime. Default `30m`.
    #[serde(with = "super::duration")]
    pub token_ttl: Duration,
    /// Offer a 6-digit code for mobile clients. Default `true`.
    pub code_enabled: bool,
    /// Code lifetime. Default `15m`.
    #[serde(with = "super::duration")]
    pub code_ttl: Duration,
    /// Wrong code attempts before the code is burned. Default 5.
    pub code_max_attempts: u32,
    /// Requests per e-mail. Default 3 per hour.
    pub per_email: RateLimitPolicy,
    /// Requests per IP. Default 20 per hour.
    pub per_ip: RateLimitPolicy,
}

impl Default for PasswordResetConfig {
    fn default() -> Self {
        Self {
            token_ttl: mins(30),
            code_enabled: true,
            code_ttl: mins(15),
            code_max_attempts: 5,
            per_email: RateLimitPolicy::new(3, hours(1)),
            per_ip: RateLimitPolicy::new(20, hours(1)),
        }
    }
}

/// `[password]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PasswordConfig {
    /// Minimum length in characters after NFKC. Default 12 (15 recommended
    /// for single-factor accounts).
    pub min_length: u32,
    /// Maximum length in characters after NFKC (DoS guard). Default 128.
    pub max_length: u32,
    /// Minimum zxcvbn score (0–4). Default 3.
    pub min_strength_score: u8,
    /// Service name given to zxcvbn as a user input. Default
    /// `rust-authentication`.
    pub service_name: String,
    /// Breach check.
    pub breach_check: BreachCheckConfig,
    /// Reset flow.
    pub reset: PasswordResetConfig,
    /// Rate limit of the live strength-check endpoint per IP (PWD-05).
    /// Default 30 per minute.
    pub check_endpoint_per_ip: RateLimitPolicy,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            min_strength_score: 3,
            service_name: "rust-authentication".to_owned(),
            breach_check: BreachCheckConfig::default(),
            reset: PasswordResetConfig::default(),
            check_endpoint_per_ip: RateLimitPolicy::new(30, mins(1)),
        }
    }
}

impl PasswordConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require(
            (8..=64).contains(&self.min_length),
            "password.min_length",
            "must be between 8 and 64 (NIST SP 800-63B)",
        );
        p.require(
            (64..=1024).contains(&self.max_length) && self.max_length >= self.min_length,
            "password.max_length",
            "must be between 64 and 1024 and >= min_length",
        );
        p.require(
            self.min_strength_score <= 4,
            "password.min_strength_score",
            "must be 0-4",
        );
        let url_ok = Url::parse(&self.breach_check.hibp_range_url).is_ok_and(|u| {
            u.scheme() == "https"
                || u.host_str() == Some("127.0.0.1")
                || u.host_str() == Some("localhost")
        });
        p.require(
            url_ok,
            "password.breach_check.hibp_range_url",
            "must be an https URL",
        );
        p.require_range(
            self.breach_check.timeout,
            Duration::from_millis(100),
            secs(30),
            "password.breach_check.timeout",
        );
        p.require_range(
            self.reset.token_ttl,
            mins(5),
            hours(24),
            "password.reset.token_ttl",
        );
        p.require_range(
            self.reset.code_ttl,
            mins(1),
            hours(1),
            "password.reset.code_ttl",
        );
        p.require(
            (1..=10).contains(&self.reset.code_max_attempts),
            "password.reset.code_max_attempts",
            "must be between 1 and 10",
        );
        validate_policy(p, &self.reset.per_email, "password.reset.per_email");
        validate_policy(p, &self.reset.per_ip, "password.reset.per_ip");
        validate_policy(
            p,
            &self.check_endpoint_per_ip,
            "password.check_endpoint_per_ip",
        );
    }
}

/// Shared check for rate-limit policies.
pub(crate) fn validate_policy(p: &mut ConfigProblems, policy: &RateLimitPolicy, key: &str) {
    p.require(
        policy.limit >= 1 && !policy.period.is_zero(),
        key,
        "limit must be >= 1 and period > 0",
    );
}
