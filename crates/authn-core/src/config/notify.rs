//! `[notify]` — e-mail and SMS delivery, templates, link paths (owner:
//! authn-notify). NTF-01 … NTF-04.
//!
//! Environment-dependent rules that need `server.environment` (the log
//! transports, `disabled` e-mail transport and the extra CA certificate are
//! development-only) are enforced fail-fast by the `authn-notify` builders
//! at startup; see `crates/authn-notify/README.md`.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, days, hours, mins, secs};
use crate::domain::EmailAddress;
use crate::ports::RateLimitPolicy;
use crate::secret::SecretString;

text_enum! {
    /// E-mail transport (NTF-03).
    #[derive(Default)]
    pub enum EmailTransportKind {
        /// SMTP with mandatory TLS.
        #[default]
        Smtp => "smtp",
        /// Writes e-mails to the log (development only; secrets redacted).
        Log => "log",
        /// Drops e-mails (tests).
        Disabled => "disabled",
    }
}

text_enum! {
    /// SMTP TLS mode. Plain-text SMTP is not supported.
    #[derive(Default)]
    pub enum SmtpTls {
        /// STARTTLS (port 587).
        #[default]
        Starttls => "starttls",
        /// Implicit TLS (port 465).
        Tls => "tls",
    }
}

/// SMTP server.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    /// Host name (certificate is verified against it).
    pub host: String,
    /// Port. Default 587.
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    /// TLS mode. Default `starttls`.
    #[serde(default)]
    pub tls: SmtpTls,
    /// User name.
    pub username: Option<String>,
    /// Password.
    pub password: Option<SecretString>,
    /// Connection / command timeout. Default `10s`.
    #[serde(default = "default_smtp_timeout", with = "super::duration")]
    pub timeout: Duration,
    /// Additional trusted root certificate (PEM file), e.g. the self-signed
    /// certificate of the docker-compose Mailpit. **Development and test
    /// environments only**: refused at startup otherwise. Default: none
    /// (only the platform trust store).
    pub extra_ca_file: Option<PathBuf>,
    /// Name sent in `EHLO`. Default: the domain of
    /// `notify.email.from_address` (the machine host name is never sent: it
    /// would leak into `Received:` headers).
    pub hello_name: Option<String>,
}

const fn default_smtp_port() -> u16 {
    587
}

const fn default_smtp_timeout() -> Duration {
    secs(10)
}

/// E-mail settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmailConfig {
    /// Transport. Default `smtp`.
    pub transport: EmailTransportKind,
    /// Sender address. Default `no-reply@localhost.localdomain` (must be
    /// changed for real deliveries).
    pub from_address: String,
    /// Sender display name. Default `rust-authentication`.
    pub from_name: String,
    /// SMTP server (required for `smtp`).
    pub smtp: Option<SmtpConfig>,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            transport: EmailTransportKind::Smtp,
            from_address: "no-reply@localhost.localdomain".to_owned(),
            from_name: "rust-authentication".to_owned(),
            smtp: None,
        }
    }
}

/// Front-end paths appended to `server.public_base_url` when building links
/// (NTF-02). The token is appended by authn-notify (as URL fragment
/// `#token=…` so it never reaches server logs or `Referer`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LinkPaths {
    /// Default `/verify-email`.
    pub email_verification: String,
    /// Default `/reset-password`.
    pub password_reset: String,
    /// Default `/forgot-password` (used in "registration attempt" mails).
    pub password_reset_request: String,
    /// Default `/login`.
    pub sign_in: String,
    /// Default `/email-change/verify`.
    pub email_change_verification: String,
    /// Default `/email-change/revert`.
    pub email_change_revert: String,
    /// Default `/magic-link`.
    pub magic_link: String,
    /// Default `/invitations/accept`.
    pub invitation: String,
    /// Default `/account/deletion/cancel`.
    pub account_deletion_cancel: String,
    /// Default `/security/not-me`.
    pub not_me: String,
    /// Default `/organizations/ownership/accept`.
    pub org_ownership_transfer: String,
}

impl Default for LinkPaths {
    fn default() -> Self {
        Self {
            email_verification: "/verify-email".to_owned(),
            password_reset: "/reset-password".to_owned(),
            password_reset_request: "/forgot-password".to_owned(),
            sign_in: "/login".to_owned(),
            email_change_verification: "/email-change/verify".to_owned(),
            email_change_revert: "/email-change/revert".to_owned(),
            magic_link: "/magic-link".to_owned(),
            invitation: "/invitations/accept".to_owned(),
            account_deletion_cancel: "/account/deletion/cancel".to_owned(),
            not_me: "/security/not-me".to_owned(),
            org_ownership_transfer: "/organizations/ownership/accept".to_owned(),
        }
    }
}

impl LinkPaths {
    fn all(&self) -> [(&'static str, &str); 11] {
        [
            ("email_verification", &self.email_verification),
            ("password_reset", &self.password_reset),
            ("password_reset_request", &self.password_reset_request),
            ("sign_in", &self.sign_in),
            ("email_change_verification", &self.email_change_verification),
            ("email_change_revert", &self.email_change_revert),
            ("magic_link", &self.magic_link),
            ("invitation", &self.invitation),
            ("account_deletion_cancel", &self.account_deletion_cancel),
            ("not_me", &self.not_me),
            ("org_ownership_transfer", &self.org_ownership_transfer),
        ]
    }
}

text_enum! {
    /// SMS provider (NTF-04).
    #[derive(Default)]
    pub enum SmsProviderKind {
        /// No provider: the SMS factor is unavailable.
        #[default]
        None => "none",
        /// Generic HTTP provider.
        Http => "http",
        /// Log sender (development only; codes redacted).
        Log => "log",
    }
}

/// Placeholder for the destination number in
/// [`SmsConfig::http_body_template`].
pub const SMS_PLACEHOLDER_TO: &str = "{{to}}";
/// Placeholder for the message text in [`SmsConfig::http_body_template`].
pub const SMS_PLACEHOLDER_TEXT: &str = "{{text}}";
/// Placeholder for the sender id in [`SmsConfig::http_body_template`].
pub const SMS_PLACEHOLDER_SENDER_ID: &str = "{{sender_id}}";

/// SMS settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmsConfig {
    /// Provider. Default `none`.
    pub provider: SmsProviderKind,
    /// HTTP endpoint (for `http`).
    pub http_url: Option<String>,
    /// API key / bearer token (for `http`).
    pub http_api_key: Option<SecretString>,
    /// Request header carrying the API key. Default `authorization`.
    pub http_auth_header: String,
    /// Scheme written before the API key in that header (`Bearer`, `Basic`,
    /// `Token`…); empty = the raw key. Default `Bearer`.
    pub http_auth_scheme: String,
    /// JSON request body. String values may contain the placeholders
    /// `{{to}}` (E.164 number), `{{text}}` (message) and `{{sender_id}}`;
    /// they are substituted in the *parsed* JSON tree, so values are always
    /// correctly escaped (no JSON injection). Default
    /// `{"to":"{{to}}","text":"{{text}}","from":"{{sender_id}}"}`.
    pub http_body_template: String,
    /// JSON pointer (RFC 6901) of the provider message id in the response
    /// body, e.g. `/message_id`. Default: none.
    pub http_message_id_pointer: Option<String>,
    /// Sender id / originator.
    pub sender_id: Option<String>,
    /// Request timeout. Default `10s`.
    #[serde(with = "super::duration")]
    pub timeout: Duration,
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            provider: SmsProviderKind::None,
            http_url: None,
            http_api_key: None,
            http_auth_header: "authorization".to_owned(),
            http_auth_scheme: "Bearer".to_owned(),
            http_body_template: r#"{"to":"{{to}}","text":"{{text}}","from":"{{sender_id}}"}"#
                .to_owned(),
            http_message_id_pointer: None,
            sender_id: None,
            timeout: secs(10),
        }
    }
}

/// `[notify]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    /// Product name shown in messages. Default `rust-authentication`.
    pub app_name: String,
    /// E-mail.
    pub email: EmailConfig,
    /// Template override directory (NTF-02). Default: built-in templates.
    /// Layout: `<dir>/<locale>/email/<name>.{subject.txt,txt,html}` and
    /// `<dir>/<locale>/sms/<name>.txt`; every file is validated at startup.
    pub template_dir: Option<PathBuf>,
    /// Link paths.
    pub links: LinkPaths,
    /// SMS.
    pub sms: SmsConfig,
    /// Delivery attempts per message before the dead-letter state (outbox).
    /// Default 10.
    pub max_attempts: u32,
    /// Defence in depth against mail/SMS bombing: at most this many
    /// *user-triggerable* messages (codes, links, invitations, registration
    /// notices) per recipient mailbox (sub-address `+tag` folded) or number
    /// and per budget: password reset, magic link, login code and the MFA
    /// codes each have their own budget, the other kinds share one (so
    /// cheap kinds cannot starve sign-in codes). Excess messages are
    /// dropped silently (never an error: that would reveal account
    /// existence). Security alerts are never throttled. Default 30 per `1h`.
    pub recipient_limit: RateLimitPolicy,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            app_name: "rust-authentication".to_owned(),
            email: EmailConfig::default(),
            template_dir: None,
            links: LinkPaths::default(),
            sms: SmsConfig::default(),
            max_attempts: 10,
            recipient_limit: RateLimitPolicy::new(30, hours(1)),
        }
    }
}

/// Whether `value` is safe to place into a mail header / message line:
/// no control characters (CR, LF, NUL…), no Unicode line separators and no
/// bidirectional overrides.
fn is_header_safe(value: &str) -> bool {
    !value.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            )
    })
}

/// Whether `name` is a plausible host name for `EHLO` (LDH labels).
fn is_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Whether the SMS body template is a JSON object using `{{to}}` and
/// `{{text}}` in string values.
fn is_valid_sms_body_template(template: &str) -> bool {
    fn strings(value: &serde_json::Value, out: &mut String) {
        match value {
            serde_json::Value::String(s) => out.push_str(s),
            serde_json::Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
            serde_json::Value::Object(map) => map.values().for_each(|v| strings(v, out)),
            _ => {}
        }
    }
    if template.len() > 8 * 1024 {
        return false;
    }
    match serde_json::from_str::<serde_json::Value>(template) {
        Ok(value @ serde_json::Value::Object(_)) => {
            let mut all = String::new();
            strings(&value, &mut all);
            all.contains(SMS_PLACEHOLDER_TO) && all.contains(SMS_PLACEHOLDER_TEXT)
        }
        _ => false,
    }
}

impl NotifyConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require(
            !self.app_name.trim().is_empty()
                && self.app_name.chars().count() <= 64
                && is_header_safe(&self.app_name),
            "notify.app_name",
            "must be 1-64 characters without control characters",
        );
        p.require(
            (1..=100).contains(&self.max_attempts),
            "notify.max_attempts",
            "must be between 1 and 100",
        );
        p.require(
            (1..=1_000_000).contains(&self.recipient_limit.limit),
            "notify.recipient_limit",
            "limit must be between 1 and 1000000",
        );
        p.require_range(
            self.recipient_limit.period,
            secs(1),
            days(7),
            "notify.recipient_limit",
        );
        let e = &self.email;
        p.require(
            EmailAddress::parse(&e.from_address).is_ok(),
            "notify.email.from_address",
            "must be a valid e-mail address",
        );
        p.require(
            !e.from_name.contains(['\r', '\n', '<', '>', '"'])
                && is_header_safe(&e.from_name)
                && e.from_name.chars().count() <= 64,
            "notify.email.from_name",
            "must be at most 64 characters without line breaks, angle brackets or quotes",
        );
        if e.transport == EmailTransportKind::Smtp {
            match &e.smtp {
                None => p.push("notify.email.smtp", "required when transport = \"smtp\""),
                Some(smtp) => {
                    p.require(
                        !smtp.host.trim().is_empty(),
                        "notify.email.smtp.host",
                        "must not be empty",
                    );
                    p.require(smtp.port != 0, "notify.email.smtp.port", "must not be 0");
                    p.require(
                        smtp.username.is_some() == smtp.password.is_some(),
                        "notify.email.smtp",
                        "username and password must be set together",
                    );
                    p.require(
                        smtp.username.as_deref().is_none_or(is_header_safe),
                        "notify.email.smtp.username",
                        "must not contain control characters",
                    );
                    p.require(
                        smtp.hello_name.as_deref().is_none_or(is_hostname),
                        "notify.email.smtp.hello_name",
                        "must be a host name (letters, digits, '-' and '.')",
                    );
                    p.require_range(smtp.timeout, secs(1), mins(2), "notify.email.smtp.timeout");
                }
            }
        }
        for (name, path) in self.links.all() {
            p.require(
                path.starts_with('/')
                    && !path.starts_with("//")
                    && !path.contains(['?', '#', '\\'])
                    && !path.chars().any(|c| c.is_whitespace() || c.is_control()),
                &format!("notify.links.{name}"),
                "must be an absolute path without query, fragment or whitespace",
            );
        }
        let sms = &self.sms;
        if sms.provider == SmsProviderKind::Http {
            p.require(
                sms.http_url
                    .as_deref()
                    .is_some_and(|u| u.starts_with("https://") && url::Url::parse(u).is_ok()),
                "notify.sms.http_url",
                "an https URL is required for the http provider",
            );
            p.require(
                sms.http_api_key.is_some(),
                "notify.sms.http_api_key",
                "required for the http provider",
            );
            p.require(
                http::HeaderName::from_bytes(sms.http_auth_header.as_bytes()).is_ok(),
                "notify.sms.http_auth_header",
                "must be a valid HTTP header name",
            );
            p.require(
                sms.http_auth_scheme.len() <= 32
                    && sms
                        .http_auth_scheme
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "notify.sms.http_auth_scheme",
                "must be empty or an ASCII token of at most 32 characters",
            );
            p.require(
                is_valid_sms_body_template(&sms.http_body_template),
                "notify.sms.http_body_template",
                "must be a JSON object (at most 8 KiB) using {{to}} and {{text}} in string values",
            );
            p.require(
                sms.http_message_id_pointer
                    .as_deref()
                    .is_none_or(|ptr| ptr.starts_with('/') && ptr.len() <= 256),
                "notify.sms.http_message_id_pointer",
                "must be a JSON pointer starting with '/'",
            );
        }
        p.require(
            sms.sender_id
                .as_deref()
                .is_none_or(|s| !s.is_empty() && s.chars().count() <= 16 && is_header_safe(s)),
            "notify.sms.sender_id",
            "must be 1-16 characters without control characters",
        );
        p.require_range(sms.timeout, secs(1), mins(1), "notify.sms.timeout");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(config: &NotifyConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    fn smtp() -> SmtpConfig {
        SmtpConfig {
            host: "smtp.example.com".to_owned(),
            port: 587,
            tls: SmtpTls::Starttls,
            username: None,
            password: None,
            timeout: secs(10),
            extra_ca_file: None,
            hello_name: None,
        }
    }

    #[test]
    fn ntf_03_defaults_require_smtp_server() {
        let config = NotifyConfig::default();
        assert_eq!(
            problems(&config),
            vec!["notify.email.smtp: required when transport = \"smtp\""]
        );
        let mut config = NotifyConfig::default();
        config.email.smtp = Some(smtp());
        assert!(problems(&config).is_empty(), "{:?}", problems(&config));
    }

    #[test]
    fn ntf_03_header_injection_in_names_is_refused() {
        let mut config = NotifyConfig::default();
        config.email.smtp = Some(smtp());
        config.email.from_name = "Evil\r\nBcc: victim@example.com".to_owned();
        config.app_name = "App\u{202E}gnp.exe".to_owned();
        let found = problems(&config);
        assert!(
            found
                .iter()
                .any(|p| p.starts_with("notify.email.from_name"))
        );
        assert!(found.iter().any(|p| p.starts_with("notify.app_name")));
        let mut config = NotifyConfig::default();
        config.email.smtp = Some(SmtpConfig {
            hello_name: Some("bad host\r\n".to_owned()),
            ..smtp()
        });
        assert!(
            problems(&config)
                .iter()
                .any(|p| p.starts_with("notify.email.smtp.hello_name"))
        );
    }

    #[test]
    fn ntf_04_http_sms_provider_rules() {
        let mut config = NotifyConfig::default();
        config.email.smtp = Some(smtp());
        config.sms.provider = SmsProviderKind::Http;
        config.sms.http_url = Some("http://sms.example.com".to_owned());
        config.sms.http_body_template = r#"{"to":"{{to}}"}"#.to_owned();
        config.sms.http_auth_header = "bad header".to_owned();
        let found = problems(&config);
        for key in [
            "notify.sms.http_url",
            "notify.sms.http_api_key",
            "notify.sms.http_auth_header",
            "notify.sms.http_body_template",
        ] {
            assert!(found.iter().any(|p| p.starts_with(key)), "{key}: {found:?}");
        }
        config.sms.http_url = Some("https://sms.example.com/send".to_owned());
        config.sms.http_api_key = Some(SecretString::from("k".to_owned()));
        config.sms.http_auth_header = "x-api-key".to_owned();
        config.sms.http_auth_scheme = String::new();
        config.sms.http_body_template = SmsConfig::default().http_body_template;
        assert!(problems(&config).is_empty(), "{:?}", problems(&config));
    }

    #[test]
    fn ntf_02_link_paths_must_be_plain_absolute_paths() {
        let mut config = NotifyConfig::default();
        config.email.smtp = Some(smtp());
        config.links.magic_link = "//evil.example/x".to_owned();
        config.links.not_me = "/a b".to_owned();
        let found = problems(&config);
        assert!(
            found
                .iter()
                .any(|p| p.starts_with("notify.links.magic_link"))
        );
        assert!(found.iter().any(|p| p.starts_with("notify.links.not_me")));
    }
}
