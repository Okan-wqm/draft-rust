//! `[mfa]` — second factors (owner: authn-mfa). MFA-01 … MFA-09.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, days, hours, mins, secs};
use super::password::validate_policy;
use crate::ports::RateLimitPolicy;

/// TOTP (MFA-01).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TotpConfig {
    /// Issuer shown in authenticator apps. Default `rust-authentication`.
    pub issuer: String,
    /// Digits. Default 6.
    pub digits: u32,
    /// Time step. Default `30s`.
    #[serde(with = "super::duration")]
    pub period: Duration,
    /// Accepted steps before/after the current one. Default 1.
    pub skew_steps: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: "rust-authentication".to_owned(),
            digits: 6,
            period: secs(30),
            skew_steps: 1,
        }
    }
}

/// Recovery codes (MFA-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryCodesConfig {
    /// Codes per batch. Default 10.
    pub count: u32,
}

impl Default for RecoveryCodesConfig {
    fn default() -> Self {
        Self { count: 10 }
    }
}

/// E-mail OTP as a backup factor (MFA-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmailOtpConfig {
    /// Offer the factor. Default `true`.
    pub enabled: bool,
    /// Code lifetime. Default `10m`.
    #[serde(with = "super::duration")]
    pub ttl: Duration,
    /// Attempts per code. Default 5.
    pub max_attempts: u32,
    /// Minimum time between sends. Default `60s`.
    #[serde(with = "super::duration")]
    pub resend_cooldown: Duration,
}

impl Default for EmailOtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: mins(10),
            max_attempts: 5,
            resend_cooldown: secs(60),
        }
    }
}

/// SMS OTP (MFA-06). Disabled unless countries are allowed and an SMS
/// provider is configured in `[notify.sms]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmsOtpConfig {
    /// Allowed E.164 country calling codes without `+` (e.g. `["90"]`).
    /// Default empty = SMS factor unavailable.
    pub allowed_country_codes: Vec<String>,
    /// Code lifetime. Default `10m`.
    #[serde(with = "super::duration")]
    pub ttl: Duration,
    /// Attempts per code. Default 5.
    pub max_attempts: u32,
    /// Messages per phone number. Default 5 per hour.
    pub per_number: RateLimitPolicy,
    /// Messages per IP. Default 10 per hour.
    pub per_ip: RateLimitPolicy,
    /// Global daily SMS budget (pumping protection). Default 1000 per day.
    pub global_daily_budget: RateLimitPolicy,
}

impl Default for SmsOtpConfig {
    fn default() -> Self {
        Self {
            allowed_country_codes: Vec::new(),
            ttl: mins(10),
            max_attempts: 5,
            per_number: RateLimitPolicy::new(5, hours(1)),
            per_ip: RateLimitPolicy::new(10, hours(1)),
            global_daily_budget: RateLimitPolicy::new(1000, days(1)),
        }
    }
}

/// Trusted devices (MFA-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustedDeviceConfig {
    /// Offer "don't ask again on this device". Default `true`.
    pub enabled: bool,
    /// Lifetime. Default `30d`.
    #[serde(with = "super::duration")]
    pub ttl: Duration,
}

impl Default for TrustedDeviceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: days(30),
        }
    }
}

/// `[mfa]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MfaConfig {
    /// TOTP.
    pub totp: TotpConfig,
    /// Recovery codes.
    pub recovery_codes: RecoveryCodesConfig,
    /// E-mail OTP.
    pub email_otp: EmailOtpConfig,
    /// SMS OTP.
    pub sms: SmsOtpConfig,
    /// Failed verifications per factor before a temporary lock (MFA-03).
    /// Default 5.
    pub max_failed_attempts: u32,
    /// Failed verifications per user across factors. Default 10 per 15m.
    pub per_user_failures: RateLimitPolicy,
    /// Lock duration after exhaustion. Default `15m`.
    #[serde(with = "super::duration")]
    pub lockout_duration: Duration,
    /// Trusted devices.
    pub trusted_device: TrustedDeviceConfig,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            totp: TotpConfig::default(),
            recovery_codes: RecoveryCodesConfig::default(),
            email_otp: EmailOtpConfig::default(),
            sms: SmsOtpConfig::default(),
            max_failed_attempts: 5,
            per_user_failures: RateLimitPolicy::new(10, mins(15)),
            lockout_duration: mins(15),
            trusted_device: TrustedDeviceConfig::default(),
        }
    }
}

impl MfaConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require(
            !self.totp.issuer.trim().is_empty(),
            "mfa.totp.issuer",
            "must not be empty",
        );
        p.require(
            matches!(self.totp.digits, 6 | 8),
            "mfa.totp.digits",
            "must be 6 or 8",
        );
        p.require_range(self.totp.period, secs(15), secs(120), "mfa.totp.period");
        p.require(
            self.totp.skew_steps <= 2,
            "mfa.totp.skew_steps",
            "must be 0, 1 or 2",
        );
        p.require(
            (5..=20).contains(&self.recovery_codes.count),
            "mfa.recovery_codes.count",
            "must be between 5 and 20",
        );
        p.require_range(self.email_otp.ttl, mins(1), mins(30), "mfa.email_otp.ttl");
        p.require(
            (1..=10).contains(&self.email_otp.max_attempts),
            "mfa.email_otp.max_attempts",
            "must be between 1 and 10",
        );
        for (i, cc) in self.sms.allowed_country_codes.iter().enumerate() {
            p.require(
                (1..=3).contains(&cc.len())
                    && cc.bytes().all(|b| b.is_ascii_digit())
                    && !cc.starts_with('0'),
                &format!("mfa.sms.allowed_country_codes[{i}]"),
                "must be a calling code like \"90\" (no '+')",
            );
        }
        p.require_range(self.sms.ttl, mins(1), mins(30), "mfa.sms.ttl");
        p.require(
            (1..=10).contains(&self.sms.max_attempts),
            "mfa.sms.max_attempts",
            "must be between 1 and 10",
        );
        validate_policy(p, &self.sms.per_number, "mfa.sms.per_number");
        validate_policy(p, &self.sms.per_ip, "mfa.sms.per_ip");
        validate_policy(
            p,
            &self.sms.global_daily_budget,
            "mfa.sms.global_daily_budget",
        );
        p.require(
            (1..=20).contains(&self.max_failed_attempts),
            "mfa.max_failed_attempts",
            "must be between 1 and 20",
        );
        validate_policy(p, &self.per_user_failures, "mfa.per_user_failures");
        p.require_range(
            self.lockout_duration,
            mins(1),
            hours(24),
            "mfa.lockout_duration",
        );
        p.require_range(
            self.trusted_device.ttl,
            days(1),
            days(90),
            "mfa.trusted_device.ttl",
        );
    }
}
