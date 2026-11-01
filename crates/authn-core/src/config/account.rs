//! `[account]` — registration, verification, lifecycle (owner:
//! authn-account). ACC-04, ACC-05, ACC-07, ACC-09 … ACC-13.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;

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

text_enum! {
    /// Legal documents whose acceptance is recorded (ACC-11). Stored in
    /// `terms_versions.document`.
    pub enum TermsDocument {
        /// Terms of service.
        TermsOfService => "terms_of_service",
        /// Privacy policy (KVKK "aydınlatma metni" / GDPR notice).
        PrivacyPolicy => "privacy_policy",
    }
}

/// Longest accepted terms version label (characters, `terms_versions`).
pub const MAX_TERMS_VERSION_CHARS: usize = 64;
/// Longest accepted terms URL (bytes).
pub const MAX_TERMS_URL_BYTES: usize = 2048;
/// Upper bound of `account.display_name_max_chars` (database limit).
pub const DISPLAY_NAME_HARD_LIMIT: u32 = 128;

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
    /// Code submissions per address across all codes (re-sending a code
    /// must not multiply the guesses). Default 10 per hour.
    pub code_attempts_per_email: RateLimitPolicy,
    /// Unauthenticated verification attempts (link or code) per client IP.
    /// Default 30 per hour.
    pub verify_per_ip: RateLimitPolicy,
    /// Unauthenticated "resend verification" requests per client IP.
    /// Default 20 per hour.
    pub resend_per_ip: RateLimitPolicy,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            link_ttl: hours(24),
            code_ttl: mins(15),
            code_max_attempts: 5,
            resend_cooldown: secs(60),
            max_sends_per_hour: 5,
            code_attempts_per_email: RateLimitPolicy::new(10, hours(1)),
            verify_per_ip: RateLimitPolicy::new(30, hours(1)),
            resend_per_ip: RateLimitPolicy::new(20, hours(1)),
        }
    }
}

/// A published version of a legal document (ACC-11). Versions listed here
/// are inserted into `terms_versions` at start-up when missing; published
/// versions are immutable.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TermsVersionConfig {
    /// Which document.
    pub document: TermsDocument,
    /// Version label (1–64 printable characters), e.g. `2026-11`.
    pub version: String,
    /// Where the text is published (`https://…`).
    pub url: Option<String>,
    /// Publication time (RFC 3339 string). The newest published version of
    /// a document is its current version.
    #[serde(with = "time::serde::rfc3339")]
    pub published_at: OffsetDateTime,
    /// Users must accept this version again at their next login (when
    /// `account.reaccept_terms_on_new_version` is on). Default `false`.
    #[serde(default)]
    pub requires_reacceptance: bool,
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
    /// With `registration_captcha = "risk_based"`: registrations per IP
    /// allowed without a CAPTCHA; further ones in the window require one.
    /// Default 3 per hour.
    pub registration_captcha_free_per_ip: RateLimitPolicy,
    /// "Someone tried to register with your address" notices per address
    /// (mail-bombing guard, ACC-02). Default 3 per day.
    pub registration_notice_per_email: RateLimitPolicy,
    /// E-mail change requests per user (ACC-07). Default 5 per day.
    pub email_change_per_user: RateLimitPolicy,
    /// Unauthenticated link actions (confirm e-mail change, revert, cancel
    /// deletion) per client IP. Default 30 per hour.
    pub link_actions_per_ip: RateLimitPolicy,
    /// Longest display name in characters after normalization (ACC-08).
    /// Default 64, at most 128.
    pub display_name_max_chars: u32,
    /// Require accepting the current terms at registration (ACC-11).
    /// Default `false`.
    pub require_terms_acceptance: bool,
    /// Ask again at login when a new terms version requires it. Default
    /// `true`.
    pub reaccept_terms_on_new_version: bool,
    /// Published terms / privacy-policy versions (ACC-11). Default none.
    pub terms: Vec<TermsVersionConfig>,
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
            registration_captcha_free_per_ip: RateLimitPolicy::new(3, hours(1)),
            registration_notice_per_email: RateLimitPolicy::new(3, days(1)),
            email_change_per_user: RateLimitPolicy::new(5, days(1)),
            link_actions_per_ip: RateLimitPolicy::new(30, hours(1)),
            display_name_max_chars: 64,
            require_terms_acceptance: false,
            reaccept_terms_on_new_version: true,
            terms: Vec::new(),
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
        validate_policy(
            p,
            &v.code_attempts_per_email,
            "account.verification.code_attempts_per_email",
        );
        validate_policy(p, &v.verify_per_ip, "account.verification.verify_per_ip");
        validate_policy(p, &v.resend_per_ip, "account.verification.resend_per_ip");
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
        validate_policy(
            p,
            &self.registration_captcha_free_per_ip,
            "account.registration_captcha_free_per_ip",
        );
        validate_policy(
            p,
            &self.registration_notice_per_email,
            "account.registration_notice_per_email",
        );
        validate_policy(
            p,
            &self.email_change_per_user,
            "account.email_change_per_user",
        );
        validate_policy(p, &self.link_actions_per_ip, "account.link_actions_per_ip");
        validate_policy(p, &self.export_per_user, "account.export_per_user");
        p.require(
            (1..=DISPLAY_NAME_HARD_LIMIT).contains(&self.display_name_max_chars),
            "account.display_name_max_chars",
            "must be between 1 and 128",
        );
        if let Some(path) = &self.disposable_domains_file {
            p.require(
                !path.as_os_str().is_empty(),
                "account.disposable_domains_file",
                "must not be empty",
            );
        }
        self.validate_terms(p);
    }

    fn validate_terms(&self, p: &mut ConfigProblems) {
        let mut seen = std::collections::HashSet::new();
        for (i, terms) in self.terms.iter().enumerate() {
            let key = format!("account.terms[{i}]");
            let chars = terms.version.chars().count();
            p.require(
                (1..=MAX_TERMS_VERSION_CHARS).contains(&chars)
                    && terms.version.trim() == terms.version
                    && !terms.version.chars().any(char::is_control),
                &format!("{key}.version"),
                "must be 1-64 printable characters without surrounding whitespace",
            );
            if let Some(url) = &terms.url {
                p.require(
                    is_valid_terms_url(url),
                    &format!("{key}.url"),
                    "must be an absolute http(s) URL without whitespace (at most 2048 bytes)",
                );
            }
            p.require(
                seen.insert((terms.document, terms.version.as_str())),
                &format!("{key}.version"),
                "duplicate document/version pair",
            );
        }
    }
}

/// Whether `url` is acceptable as a terms URL (also the
/// `terms_versions_url_check` database constraint).
#[must_use]
pub fn is_valid_terms_url(url: &str) -> bool {
    url.len() <= MAX_TERMS_URL_BYTES
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
        && url::Url::parse(url)
            .is_ok_and(|u| matches!(u.scheme(), "https" | "http") && u.host().is_some())
        && (url.starts_with("https://") || url.starts_with("http://"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(config: &AccountConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    fn terms(version: &str, url: Option<&str>) -> TermsVersionConfig {
        TermsVersionConfig {
            document: TermsDocument::TermsOfService,
            version: version.to_owned(),
            url: url.map(str::to_owned),
            published_at: OffsetDateTime::UNIX_EPOCH,
            requires_reacceptance: false,
        }
    }

    #[test]
    fn acc_11_defaults_are_valid_and_match_the_spec() {
        let c = AccountConfig::default();
        assert!(problems(&c).is_empty(), "{:?}", problems(&c));
        assert_eq!(c.verification.link_ttl, hours(24));
        assert_eq!(c.verification.code_ttl, mins(15));
        assert_eq!(c.verification.code_max_attempts, 5);
        assert_eq!(c.verification.resend_cooldown, secs(60));
        assert_eq!(c.unverified_purge_after, days(7));
        assert_eq!(c.email_change_revert_ttl, days(7));
        assert_eq!(c.deletion_grace_period, days(30));
        assert!(c.disposable_domains_file.is_none());
        assert_eq!(c.unverified_login, UnverifiedLoginPolicy::Block);
    }

    #[test]
    fn acc_11_terms_entries_are_validated() {
        let c = AccountConfig {
            terms: vec![
                terms("2026-01", Some("https://example.com/terms")),
                terms("2026-01", None),
                terms(" padded", None),
                terms("", None),
                terms("v2", Some("javascript:alert(1)")),
                terms("v3", Some("https://example.com/a b")),
            ],
            ..AccountConfig::default()
        };
        let problems = problems(&c);
        assert!(
            problems.iter().any(|p| p.contains("duplicate")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("account.terms[2].version"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("account.terms[3].version"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("account.terms[4].url"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("account.terms[5].url"))
        );
        assert!(!problems.iter().any(|p| p.starts_with("account.terms[0]")));
    }

    #[test]
    fn acc_08_display_name_limit_is_bounded() {
        let mut c = AccountConfig {
            display_name_max_chars: 0,
            ..AccountConfig::default()
        };
        assert!(!problems(&c).is_empty());
        c.display_name_max_chars = 129;
        assert!(!problems(&c).is_empty());
        c.display_name_max_chars = 128;
        assert!(problems(&c).is_empty());
    }

    #[test]
    fn acc_11_terms_deserialize_from_toml_style_values() {
        let value = serde_json::json!({
            "document": "privacy_policy",
            "version": "2026-11",
            "url": "https://example.com/privacy",
            "published_at": "2026-11-01T00:00:00Z",
            "requires_reacceptance": true
        });
        let t: TermsVersionConfig = serde_json::from_value(value).unwrap();
        assert_eq!(t.document, TermsDocument::PrivacyPolicy);
        assert!(t.requires_reacceptance);
    }
}
