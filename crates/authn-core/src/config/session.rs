//! `[session]` — login, sessions and tokens (owner: authn-session).
//! SES-02 … SES-07, SES-13, SES-14, SES-18, SES-19.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, days, hours, mins, secs};
use super::password::validate_policy;
use crate::ports::RateLimitPolicy;

/// Idle + absolute lifetime pair. The absolute lifetime is never extended
/// by activity or rotation (SES-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifetime {
    /// Expires after this much inactivity.
    #[serde(with = "super::duration")]
    pub idle_timeout: Duration,
    /// Expires this long after creation, regardless of activity.
    #[serde(with = "super::duration")]
    pub absolute_timeout: Duration,
}

impl Lifetime {
    /// Convenience constructor.
    #[must_use]
    pub const fn new(idle_timeout: Duration, absolute_timeout: Duration) -> Self {
        Self {
            idle_timeout,
            absolute_timeout,
        }
    }

    fn validate(&self, p: &mut ConfigProblems, key: &str) {
        p.require(
            !self.idle_timeout.is_zero() && self.idle_timeout <= self.absolute_timeout,
            key,
            "idle_timeout must be > 0 and <= absolute_timeout",
        );
        p.require(
            self.absolute_timeout <= days(400),
            key,
            "absolute_timeout must be <= 400d",
        );
    }
}

/// `[session]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    /// Browser session. Default idle `2h`, absolute `12h`.
    pub web: Lifetime,
    /// "Remember me" browser session. Default idle `14d`, absolute `30d`.
    pub remember_me: Lifetime,
    /// "Not my device" (SES-07): browser-session cookie, short lifetime.
    /// Default idle `30m`, absolute `4h`.
    pub shared_device: Lifetime,
    /// Native refresh-token family. Default idle `30d`, absolute `90d`.
    pub refresh_token: Lifetime,
    /// JWT access token lifetime (SES-05). Default `10m`.
    #[serde(with = "super::duration")]
    pub access_token_ttl: Duration,
    /// Refresh rotation race tolerance (SES-05). Default `0s` (off), max
    /// `10s`.
    #[serde(with = "super::duration")]
    pub refresh_reuse_grace: Duration,
    /// JWT `iss`. Default: `server.public_base_url`.
    pub issuer: Option<String>,
    /// JWT `aud` values. Default `["rust-authentication"]`.
    pub audiences: Vec<String>,
    /// MFA / required-action challenge lifetime (SES-02). Default `5m`.
    #[serde(with = "super::duration")]
    pub mfa_challenge_ttl: Duration,
    /// Attempts per challenge. Default 5.
    pub challenge_max_attempts: u32,
    /// Step-up window (SES-13). Default `10m`.
    #[serde(with = "super::duration")]
    pub step_up_max_age: Duration,
    /// Concurrent sessions per user (SES-14). Default unlimited; when set
    /// the oldest session is revoked.
    pub max_concurrent_sessions: Option<u32>,
    /// Origins allowed for state-changing cookie requests (SES-04). Default
    /// empty = only `server.public_base_url`'s origin.
    pub csrf_allowed_origins: Vec<String>,
    /// Magic link lifetime (SES-18). Default `15m`.
    #[serde(with = "super::duration")]
    pub magic_link_ttl: Duration,
    /// Passwordless e-mail code lifetime (SES-19). Default `10m`.
    #[serde(with = "super::duration")]
    pub email_code_ttl: Duration,
    /// Passwordless e-mail code attempts. Default 5.
    pub email_code_max_attempts: u32,
    /// Introspection (SES-10) per API key. Default 600 per minute.
    pub introspection_per_client: RateLimitPolicy,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            web: Lifetime::new(hours(2), hours(12)),
            remember_me: Lifetime::new(days(14), days(30)),
            shared_device: Lifetime::new(mins(30), hours(4)),
            refresh_token: Lifetime::new(days(30), days(90)),
            access_token_ttl: mins(10),
            refresh_reuse_grace: Duration::ZERO,
            issuer: None,
            audiences: vec!["rust-authentication".to_owned()],
            mfa_challenge_ttl: mins(5),
            challenge_max_attempts: 5,
            step_up_max_age: mins(10),
            max_concurrent_sessions: None,
            csrf_allowed_origins: Vec::new(),
            magic_link_ttl: mins(15),
            email_code_ttl: mins(10),
            email_code_max_attempts: 5,
            introspection_per_client: RateLimitPolicy::new(600, mins(1)),
        }
    }
}

impl SessionConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        self.web.validate(p, "session.web");
        self.remember_me.validate(p, "session.remember_me");
        self.shared_device.validate(p, "session.shared_device");
        self.refresh_token.validate(p, "session.refresh_token");
        p.require(
            self.shared_device.absolute_timeout <= self.web.absolute_timeout,
            "session.shared_device",
            "must not outlive a normal web session (SES-07)",
        );
        p.require_range(
            self.access_token_ttl,
            mins(1),
            hours(1),
            "session.access_token_ttl",
        );
        p.require_range(
            self.refresh_reuse_grace,
            Duration::ZERO,
            secs(10),
            "session.refresh_reuse_grace",
        );
        p.require(
            !self.audiences.is_empty(),
            "session.audiences",
            "at least one audience is required",
        );
        p.require_range(
            self.mfa_challenge_ttl,
            mins(1),
            mins(15),
            "session.mfa_challenge_ttl",
        );
        p.require(
            (1..=10).contains(&self.challenge_max_attempts),
            "session.challenge_max_attempts",
            "must be between 1 and 10",
        );
        p.require_range(
            self.step_up_max_age,
            mins(1),
            hours(1),
            "session.step_up_max_age",
        );
        p.require(
            self.max_concurrent_sessions.is_none_or(|n| n >= 1),
            "session.max_concurrent_sessions",
            "must be >= 1 when set",
        );
        for (i, origin) in self.csrf_allowed_origins.iter().enumerate() {
            p.require(
                is_origin(origin),
                &format!("session.csrf_allowed_origins[{i}]"),
                "must be an origin like https://app.example.com (no path, no wildcard)",
            );
        }
        p.require_range(
            self.magic_link_ttl,
            mins(1),
            hours(1),
            "session.magic_link_ttl",
        );
        p.require_range(
            self.email_code_ttl,
            mins(1),
            mins(30),
            "session.email_code_ttl",
        );
        p.require(
            (1..=10).contains(&self.email_code_max_attempts),
            "session.email_code_max_attempts",
            "must be between 1 and 10",
        );
        validate_policy(
            p,
            &self.introspection_per_client,
            "session.introspection_per_client",
        );
    }
}

/// Whether `s` is a serialized origin: `scheme://host[:port]`, no path,
/// query, fragment, credentials or wildcard.
#[must_use]
pub fn is_origin(s: &str) -> bool {
    let Ok(url) = url::Url::parse(s) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && !s.contains('*')
        && url.path() == "/"
        && !s.ends_with('/')
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}
