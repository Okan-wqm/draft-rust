//! `[notify]` — e-mail and SMS delivery, templates, link paths (owner:
//! authn-notify). NTF-01 … NTF-04.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, mins, secs};
use crate::domain::EmailAddress;
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
            sender_id: None,
            timeout: secs(10),
        }
    }
}

/// `[notify]` section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    /// E-mail.
    pub email: EmailConfig,
    /// Template override directory (NTF-02). Default: built-in templates.
    pub template_dir: Option<PathBuf>,
    /// Link paths.
    pub links: LinkPaths,
    /// SMS.
    pub sms: SmsConfig,
}

impl NotifyConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        let e = &self.email;
        p.require(
            EmailAddress::parse(&e.from_address).is_ok(),
            "notify.email.from_address",
            "must be a valid e-mail address",
        );
        p.require(
            !e.from_name.contains(['\r', '\n', '<', '>', '"']),
            "notify.email.from_name",
            "must not contain line breaks, angle brackets or quotes",
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
                    p.require(
                        smtp.username.is_some() == smtp.password.is_some(),
                        "notify.email.smtp",
                        "username and password must be set together",
                    );
                    p.require_range(smtp.timeout, secs(1), mins(2), "notify.email.smtp.timeout");
                }
            }
        }
        for (name, path) in self.links.all() {
            p.require(
                path.starts_with('/')
                    && !path.starts_with("//")
                    && !path.contains(['?', '#', '\\']),
                &format!("notify.links.{name}"),
                "must be an absolute path without query or fragment",
            );
        }
        if self.sms.provider == SmsProviderKind::Http {
            p.require(
                self.sms
                    .http_url
                    .as_deref()
                    .is_some_and(|u| u.starts_with("https://")),
                "notify.sms.http_url",
                "an https URL is required for the http provider",
            );
            p.require(
                self.sms.http_api_key.is_some(),
                "notify.sms.http_api_key",
                "required for the http provider",
            );
        }
        p.require_range(self.sms.timeout, secs(1), mins(1), "notify.sms.timeout");
    }
}
