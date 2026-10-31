//! `[protect]` — abuse protection, web security, risk, outbound HTTP
//! (owner: authn-protect). PRT-01 … PRT-10, PRT-12, RSK-01 … RSK-03.
//! Request limits (PRT-11) live in `[server.limits]`.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::common::{CaptchaPolicy, ConfigProblems, days, hours, mins, secs};
use super::password::validate_policy;
use crate::ports::{CaptchaProvider, RateLimitPolicy};
use crate::secret::SecretString;

text_enum! {
    /// Rate-limit storage (PRT-01).
    #[derive(Default)]
    pub enum RateLimitBackend {
        /// Per-process memory (single instance / tests).
        Memory => "memory",
        /// PostgreSQL (default, distributed).
        #[default]
        Postgres => "postgres",
        /// Redis (`redis` cargo feature).
        Redis => "redis",
    }
}

/// Rate limits (PRT-01 … PRT-04).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Backend. Default `postgres`.
    pub backend: RateLimitBackend,
    /// Redis URL when `backend = "redis"`.
    pub redis_url: Option<SecretString>,
    /// Failed logins per account before CAPTCHA. Default 10 per 15m.
    pub login_per_account_captcha: RateLimitPolicy,
    /// Failed logins per account before the soft lock (PRT-03). Default 50
    /// per hour.
    pub login_per_account_soft_lock: RateLimitPolicy,
    /// Login attempts per IP. Default 100 per 15m.
    pub login_per_ip: RateLimitPolicy,
    /// Soft lock duration. Default `1h`.
    #[serde(with = "super::duration")]
    pub soft_lock_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            backend: RateLimitBackend::Postgres,
            redis_url: None,
            login_per_account_captcha: RateLimitPolicy::new(10, mins(15)),
            login_per_account_soft_lock: RateLimitPolicy::new(50, hours(1)),
            login_per_ip: RateLimitPolicy::new(100, mins(15)),
            soft_lock_duration: hours(1),
        }
    }
}

/// CAPTCHA (PRT-05).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptchaConfig {
    /// Provider. Default `disabled`.
    pub provider: CaptchaProvider,
    /// When CAPTCHA is demanded on login. Default `risk_based`.
    pub login_policy: CaptchaPolicy,
    /// Public site key (Turnstile / hCaptcha).
    pub site_key: Option<String>,
    /// Secret key (Turnstile / hCaptcha).
    pub secret_key: Option<SecretString>,
    /// Override of the provider verification URL (tests only).
    pub verify_url: Option<String>,
    /// Proof-of-work difficulty in leading zero bits. Default 18.
    pub pow_difficulty: u8,
    /// Proof-of-work challenge lifetime. Default `5m`.
    #[serde(with = "super::duration")]
    pub pow_ttl: Duration,
    /// Treat an unreachable provider as passed. Default `false`.
    pub fail_open: bool,
}

impl Default for CaptchaConfig {
    fn default() -> Self {
        Self {
            provider: CaptchaProvider::Disabled,
            login_policy: CaptchaPolicy::RiskBased,
            site_key: None,
            secret_key: None,
            verify_url: None,
            pow_difficulty: 18,
            pow_ttl: mins(5),
            fail_open: false,
        }
    }
}

/// Security headers (PRT-07).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityHeadersConfig {
    /// HSTS max-age. Default 2 years.
    #[serde(with = "super::duration")]
    pub hsts_max_age: Duration,
    /// HSTS includeSubDomains. Default `true`.
    pub hsts_include_subdomains: bool,
    /// HSTS preload. Default `false`.
    pub hsts_preload: bool,
    /// `Permissions-Policy` value.
    pub permissions_policy: String,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            hsts_max_age: days(730),
            hsts_include_subdomains: true,
            hsts_preload: false,
            permissions_policy: "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()".to_owned(),
        }
    }
}

/// CORS (PRT-08).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CorsConfig {
    /// Exact allowed origins. Default none (CORS disabled).
    pub allowed_origins: Vec<String>,
    /// Preflight cache. Default `10m`.
    #[serde(with = "super::duration")]
    pub max_age: Duration,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            max_age: mins(10),
        }
    }
}

text_enum! {
    /// Reaction to a medium-risk login (RSK-03).
    #[derive(Default)]
    pub enum MediumRiskAction {
        /// Require MFA if enrolled, otherwise e-mail confirmation.
        #[default]
        StepUp => "step_up",
        /// Allow (log only).
        Allow => "allow",
    }
}

text_enum! {
    /// Reaction to a high-risk login (RSK-03).
    #[derive(Default)]
    pub enum HighRiskAction {
        /// Block and notify the user.
        #[default]
        Block => "block",
        /// Treat like medium risk.
        StepUp => "step_up",
    }
}

/// Risk evaluation (RSK-01 … RSK-03).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RiskConfig {
    /// Evaluate risk at login. Default `true`.
    pub enabled: bool,
    /// Optional file with TOR exit / proxy CIDRs.
    pub anonymizing_networks_file: Option<PathBuf>,
    /// Window for counting recent failures. Default `1h`.
    #[serde(with = "super::duration")]
    pub failure_window: Duration,
    /// Failures in the window that raise the risk. Default 5.
    pub failure_threshold: u32,
    /// Medium-risk reaction. Default `step_up`.
    pub medium_action: MediumRiskAction,
    /// High-risk reaction. Default `block`.
    pub high_action: HighRiskAction,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            anonymizing_networks_file: None,
            failure_window: hours(1),
            failure_threshold: 5,
            medium_action: MediumRiskAction::StepUp,
            high_action: HighRiskAction::Block,
        }
    }
}

/// Outbound HTTP (PRT-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutboundHttpConfig {
    /// Default timeout. Default `10s`.
    #[serde(with = "super::duration")]
    pub timeout: Duration,
    /// Response size limit. Default 1 MiB.
    pub max_response_bytes: usize,
    /// Allow private / loopback destinations for user-supplied URLs.
    /// **Tests only**; rejected in production. Default `false`.
    pub allow_private_networks: bool,
}

impl Default for OutboundHttpConfig {
    fn default() -> Self {
        Self {
            timeout: secs(10),
            max_response_bytes: 1024 * 1024,
            allow_private_networks: false,
        }
    }
}

/// `[protect]` section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectConfig {
    /// Rate limits.
    pub rate_limit: RateLimitConfig,
    /// CAPTCHA.
    pub captcha: CaptchaConfig,
    /// Security headers.
    pub security_headers: SecurityHeadersConfig,
    /// CORS.
    pub cors: CorsConfig,
    /// Accepted `Host` values (PRT-09). Default empty = host of
    /// `server.public_base_url` only.
    pub allowed_hosts: Vec<String>,
    /// Absolute redirect targets allowed by exact match (PRT-10).
    pub redirect_allow_list: Vec<String>,
    /// Risk evaluation.
    pub risk: RiskConfig,
    /// Outbound HTTP.
    pub outbound: OutboundHttpConfig,
}

impl ProtectConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        let r = &self.rate_limit;
        p.require(
            r.backend != RateLimitBackend::Redis || r.redis_url.is_some(),
            "protect.rate_limit.redis_url",
            "required when backend = \"redis\"",
        );
        validate_policy(
            p,
            &r.login_per_account_captcha,
            "protect.rate_limit.login_per_account_captcha",
        );
        validate_policy(
            p,
            &r.login_per_account_soft_lock,
            "protect.rate_limit.login_per_account_soft_lock",
        );
        validate_policy(p, &r.login_per_ip, "protect.rate_limit.login_per_ip");
        p.require_range(
            r.soft_lock_duration,
            mins(1),
            days(1),
            "protect.rate_limit.soft_lock_duration",
        );

        let c = &self.captcha;
        if matches!(
            c.provider,
            CaptchaProvider::Turnstile | CaptchaProvider::HCaptcha
        ) {
            p.require(
                c.site_key.is_some(),
                "protect.captcha.site_key",
                "required for the provider",
            );
            p.require(
                c.secret_key.is_some(),
                "protect.captcha.secret_key",
                "required for the provider",
            );
        }
        p.require(
            (8..=32).contains(&c.pow_difficulty),
            "protect.captcha.pow_difficulty",
            "must be 8-32",
        );
        p.require_range(c.pow_ttl, secs(30), mins(30), "protect.captcha.pow_ttl");

        p.require(
            self.security_headers.hsts_max_age >= days(365),
            "protect.security_headers.hsts_max_age",
            "must be at least 1 year",
        );
        for (i, origin) in self.cors.allowed_origins.iter().enumerate() {
            p.require(
                super::session::is_origin(origin),
                &format!("protect.cors.allowed_origins[{i}]"),
                "must be an exact origin (no wildcard, no path) (PRT-08)",
            );
        }
        p.require_range(
            self.cors.max_age,
            Duration::ZERO,
            hours(2),
            "protect.cors.max_age",
        );
        for (i, target) in self.redirect_allow_list.iter().enumerate() {
            p.require(
                url::Url::parse(target)
                    .is_ok_and(|u| u.fragment().is_none() && !target.contains('*')),
                &format!("protect.redirect_allow_list[{i}]"),
                "must be an absolute URL without fragment or wildcard",
            );
        }
        p.require_range(
            self.risk.failure_window,
            mins(1),
            days(1),
            "protect.risk.failure_window",
        );
        p.require(
            self.risk.failure_threshold >= 1,
            "protect.risk.failure_threshold",
            "must be >= 1",
        );
        p.require_range(
            self.outbound.timeout,
            secs(1),
            mins(2),
            "protect.outbound.timeout",
        );
        p.require(
            (1024..=50 * 1024 * 1024).contains(&self.outbound.max_response_bytes),
            "protect.outbound.max_response_bytes",
            "must be between 1 KiB and 50 MiB",
        );
    }
}
