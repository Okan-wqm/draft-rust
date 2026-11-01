//! Template variables of every notification kind.
//!
//! Variables available to **every** e-mail template: `app_name`, `locale`,
//! `base_url`, `recipient_name` (sanitized or none), `sign_in_link`,
//! `reset_request_link`, `link` (token link or none), `code` (or none),
//! `expires_at` / `expires_in` (or none) and — in the text and HTML bodies —
//! `subject`. Kind-specific variables are listed in `README.md`.
//!
//! All untrusted strings pass through [`crate::sanitize`] here; tokens and
//! codes are format-checked so they cannot alter a URL or a message.

use std::collections::BTreeMap;

use authn_core::domain::{EmailAddress, FactorKind, Locale, PhoneNumber};
use authn_core::ports::{
    Notification, NotificationKind, Recipient, SmsNotification, SmsNotificationKind,
};
use authn_core::secret::SensitiveString;
use minijinja::Value;
use time::{Duration, OffsetDateTime};

use crate::error::RenderError;
use crate::format;
use crate::links::{LinkBuilder, LinkTarget};
use crate::sanitize::{self, MAX_DETAIL_CHARS, MAX_NAME_CHARS, MAX_ORG_NAME_CHARS};

/// Shortest accepted one-time code.
pub(crate) const MIN_CODE_LEN: usize = 6;
/// Longest accepted one-time code.
pub(crate) const MAX_CODE_LEN: usize = 10;

/// Template variables.
pub(crate) struct Rendered {
    pub(crate) values: BTreeMap<&'static str, Value>,
}

/// Whether `code` is a short decimal one-time code (6–10 ASCII digits).
pub(crate) fn is_valid_code(code: &str) -> bool {
    (MIN_CODE_LEN..=MAX_CODE_LEN).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit())
}

fn check_code(code: &SensitiveString) -> Result<String, RenderError> {
    let value = code.expose();
    if is_valid_code(value) {
        Ok(value.to_owned())
    } else {
        Err(RenderError::InvalidCode)
    }
}

fn detail(value: &str) -> Value {
    Value::from(sanitize::user_text(value, MAX_DETAIL_CHARS))
}

fn optional_detail(value: Option<&str>) -> Value {
    Value::from(sanitize::optional_user_text(value, MAX_DETAIL_CHARS))
}

/// The time after which delivering the notification is pointless (its
/// link or code has expired): the deliverer drops it instead of sending a
/// dead link.
#[must_use]
pub fn deliver_before(kind: &NotificationKind) -> Option<OffsetDateTime> {
    match kind {
        NotificationKind::EmailVerification { expires_at, .. }
        | NotificationKind::PasswordReset { expires_at, .. }
        | NotificationKind::EmailChangeVerification { expires_at, .. }
        | NotificationKind::MfaEmailCode { expires_at, .. }
        | NotificationKind::Invitation { expires_at, .. }
        | NotificationKind::MagicLink { expires_at, .. }
        | NotificationKind::LoginCode { expires_at, .. }
        | NotificationKind::OrgOwnershipTransfer { expires_at, .. } => Some(*expires_at),
        NotificationKind::EmailChanged {
            revert_expires_at, ..
        } => Some(*revert_expires_at),
        NotificationKind::AccountDeletionScheduled { scheduled_for, .. } => Some(*scheduled_for),
        // Security notices are delivered even late.
        NotificationKind::RegistrationAttempt
        | NotificationKind::PasswordChanged { .. }
        | NotificationKind::MfaFactorAdded { .. }
        | NotificationKind::MfaFactorRemoved { .. }
        | NotificationKind::MfaReset { .. }
        | NotificationKind::RecoveryCodeUsed { .. }
        | NotificationKind::NewDeviceLogin { .. }
        | NotificationKind::SuspiciousLoginBlocked { .. }
        | NotificationKind::AccountDeletionCancelled { .. }
        | NotificationKind::ImpersonationStarted { .. } => None,
    }
}

/// [`deliver_before`] for SMS.
pub(crate) fn sms_deliver_before(kind: &SmsNotificationKind) -> OffsetDateTime {
    match kind {
        SmsNotificationKind::MfaSmsCode { expires_at, .. }
        | SmsNotificationKind::PhoneVerification { expires_at, .. } => *expires_at,
    }
}

/// Builds the variables of an e-mail notification.
pub(crate) fn email_values(
    notification: &Notification,
    links: &LinkBuilder,
    app_name: &str,
    now: OffsetDateTime,
) -> Result<Rendered, RenderError> {
    let locale = notification.locale;
    let mut v: BTreeMap<&'static str, Value> = BTreeMap::new();
    v.insert("app_name", Value::from(app_name));
    v.insert("locale", Value::from(locale.as_str()));
    v.insert("base_url", Value::from(links.base_url().as_str()));
    v.insert(
        "recipient_name",
        Value::from(sanitize::optional_user_text(
            notification.recipient.display_name.as_deref(),
            MAX_NAME_CHARS,
        )),
    );
    v.insert("sign_in_link", Value::from(links.page(LinkTarget::SignIn)));
    v.insert(
        "reset_request_link",
        Value::from(links.page(LinkTarget::PasswordResetRequest)),
    );
    let at = |t: &OffsetDateTime| Value::from(format::datetime(*t, locale));

    let mut link: Option<SensitiveString> = None;
    let mut code: Option<String> = None;
    let mut expires: Option<OffsetDateTime> = None;
    match &notification.kind {
        NotificationKind::EmailVerification {
            token,
            code: c,
            expires_at,
        } => {
            link = Some(links.with_token(LinkTarget::EmailVerification, token)?);
            code = Some(check_code(c)?);
            expires = Some(*expires_at);
        }
        NotificationKind::RegistrationAttempt => {}
        NotificationKind::PasswordReset {
            token,
            code: c,
            expires_at,
        } => {
            link = Some(links.with_token(LinkTarget::PasswordReset, token)?);
            code = c.as_ref().map(check_code).transpose()?;
            expires = Some(*expires_at);
        }
        NotificationKind::PasswordChanged {
            at: when,
            ip_masked,
            device,
        } => {
            v.insert("at", at(when));
            v.insert("ip_masked", optional_detail(ip_masked.as_deref()));
            v.insert("device", optional_detail(device.as_deref()));
        }
        NotificationKind::EmailChangeVerification {
            token,
            code: c,
            expires_at,
        } => {
            link = Some(links.with_token(LinkTarget::EmailChangeVerification, token)?);
            code = Some(check_code(c)?);
            expires = Some(*expires_at);
        }
        NotificationKind::EmailChanged {
            new_email_masked,
            revert_token,
            revert_expires_at,
        } => {
            v.insert("new_email_masked", detail(new_email_masked));
            v.insert("revert_expires_at", at(revert_expires_at));
            link = Some(links.with_token(LinkTarget::EmailChangeRevert, revert_token)?);
            expires = Some(*revert_expires_at);
        }
        NotificationKind::MfaFactorAdded { factor, at: when }
        | NotificationKind::MfaFactorRemoved { factor, at: when } => {
            v.insert("factor", Value::from(format::factor(*factor, locale)));
            v.insert("at", at(when));
        }
        NotificationKind::MfaReset { at: when }
        | NotificationKind::AccountDeletionCancelled { at: when } => {
            v.insert("at", at(when));
        }
        NotificationKind::MfaEmailCode {
            code: c,
            expires_at,
        }
        | NotificationKind::LoginCode {
            code: c,
            expires_at,
        } => {
            code = Some(check_code(c)?);
            expires = Some(*expires_at);
        }
        NotificationKind::RecoveryCodeUsed {
            remaining,
            at: when,
        } => {
            v.insert("remaining", Value::from(*remaining));
            v.insert("low_on_codes", Value::from(*remaining <= 3));
            v.insert("at", at(when));
        }
        NotificationKind::NewDeviceLogin {
            device,
            approximate_location,
            ip_masked,
            at: when,
            not_me_token,
        } => {
            v.insert("device", detail(device));
            v.insert(
                "approximate_location",
                optional_detail(approximate_location.as_deref()),
            );
            v.insert("ip_masked", detail(ip_masked));
            v.insert("at", at(when));
            link = Some(links.with_token(LinkTarget::NotMe, not_me_token)?);
        }
        NotificationKind::SuspiciousLoginBlocked {
            device,
            ip_masked,
            at: when,
        } => {
            v.insert("device", detail(device));
            v.insert("ip_masked", detail(ip_masked));
            v.insert("at", at(when));
        }
        NotificationKind::AccountDeletionScheduled {
            scheduled_for,
            cancel_token,
        } => {
            v.insert("scheduled_for", at(scheduled_for));
            link = Some(links.with_token(LinkTarget::AccountDeletionCancel, cancel_token)?);
        }
        NotificationKind::Invitation {
            org_name,
            inviter_name,
            token,
            expires_at,
        } => {
            v.insert(
                "org_name",
                Value::from(sanitize::user_text(org_name, MAX_ORG_NAME_CHARS)),
            );
            v.insert(
                "inviter_name",
                Value::from(sanitize::optional_user_text(
                    inviter_name.as_deref(),
                    MAX_NAME_CHARS,
                )),
            );
            link = Some(links.with_token(LinkTarget::Invitation, token)?);
            expires = Some(*expires_at);
        }
        NotificationKind::MagicLink { token, expires_at } => {
            link = Some(links.with_token(LinkTarget::MagicLink, token)?);
            expires = Some(*expires_at);
        }
        NotificationKind::OrgOwnershipTransfer {
            org_name,
            token,
            expires_at,
        } => {
            v.insert(
                "org_name",
                Value::from(sanitize::user_text(org_name, MAX_ORG_NAME_CHARS)),
            );
            link = Some(links.with_token(LinkTarget::OrgOwnershipTransfer, token)?);
            expires = Some(*expires_at);
        }
        NotificationKind::ImpersonationStarted {
            at: when,
            expires_at,
        } => {
            v.insert("at", at(when));
            v.insert("ends_at", at(expires_at));
        }
    }
    v.insert(
        "link",
        Value::from(link.as_ref().map(|l| l.expose().to_owned())),
    );
    v.insert("code", Value::from(code));
    v.insert(
        "expires_at",
        Value::from(expires.map(|t| format::datetime(t, locale))),
    );
    v.insert(
        "expires_in",
        Value::from(expires.map(|t| format::remaining(now, t, locale))),
    );
    Ok(Rendered { values: v })
}

/// Builds the variables of an SMS: `app_name`, `code`, `expires_in`,
/// `expires_at`, `domain` (host of the public base URL, for origin-bound
/// one-time codes `@domain #code`).
pub(crate) fn sms_values(
    sms: &SmsNotification,
    domain: &str,
    app_name: &str,
    now: OffsetDateTime,
) -> Result<Rendered, RenderError> {
    let locale = sms.locale;
    let (code, expires_at) = match &sms.kind {
        SmsNotificationKind::MfaSmsCode { code, expires_at }
        | SmsNotificationKind::PhoneVerification { code, expires_at } => (code, *expires_at),
    };
    let mut v: BTreeMap<&'static str, Value> = BTreeMap::new();
    v.insert("app_name", Value::from(app_name));
    v.insert("locale", Value::from(locale.as_str()));
    v.insert("domain", Value::from(domain));
    v.insert("code", Value::from(check_code(code)?));
    v.insert(
        "expires_at",
        Value::from(format::datetime(expires_at, locale)),
    );
    v.insert(
        "expires_in",
        Value::from(format::remaining(now, expires_at, locale)),
    );
    Ok(Rendered { values: v })
}

/// The secrets a notification carries (for template validation).
pub(crate) struct SecretParts {
    pub(crate) tokens: Vec<SensitiveString>,
    pub(crate) codes: Vec<SensitiveString>,
}

/// Tokens and codes of a notification kind.
pub(crate) fn secret_parts(kind: &NotificationKind) -> SecretParts {
    let mut tokens = Vec::new();
    let mut codes = Vec::new();
    match kind {
        NotificationKind::EmailVerification { token, code, .. }
        | NotificationKind::EmailChangeVerification { token, code, .. } => {
            tokens.push(token.clone());
            codes.push(code.clone());
        }
        NotificationKind::PasswordReset { token, code, .. } => {
            tokens.push(token.clone());
            codes.extend(code.iter().cloned());
        }
        NotificationKind::EmailChanged { revert_token, .. } => tokens.push(revert_token.clone()),
        NotificationKind::NewDeviceLogin { not_me_token, .. } => tokens.push(not_me_token.clone()),
        NotificationKind::AccountDeletionScheduled { cancel_token, .. } => {
            tokens.push(cancel_token.clone());
        }
        NotificationKind::Invitation { token, .. }
        | NotificationKind::MagicLink { token, .. }
        | NotificationKind::OrgOwnershipTransfer { token, .. } => tokens.push(token.clone()),
        NotificationKind::MfaEmailCode { code, .. } | NotificationKind::LoginCode { code, .. } => {
            codes.push(code.clone());
        }
        NotificationKind::RegistrationAttempt
        | NotificationKind::PasswordChanged { .. }
        | NotificationKind::MfaFactorAdded { .. }
        | NotificationKind::MfaFactorRemoved { .. }
        | NotificationKind::MfaReset { .. }
        | NotificationKind::RecoveryCodeUsed { .. }
        | NotificationKind::SuspiciousLoginBlocked { .. }
        | NotificationKind::AccountDeletionCancelled { .. }
        | NotificationKind::ImpersonationStarted { .. } => {}
    }
    SecretParts { tokens, codes }
}

/// The code of an SMS kind.
pub(crate) fn sms_code(kind: &SmsNotificationKind) -> &SensitiveString {
    match kind {
        SmsNotificationKind::MfaSmsCode { code, .. }
        | SmsNotificationKind::PhoneVerification { code, .. } => code,
    }
}

const SAMPLE_TOKEN: &str = "SAMPLEtokenSAMPLEtokenSAMPLEtokenSAMPLE0123";
const SAMPLE_CODE: &str = "246810";

/// One sample notification per e-mail kind (template validation, tests).
#[allow(clippy::too_many_lines)] // one literal per notification kind
pub(crate) fn samples(locale: Locale, now: OffsetDateTime) -> Vec<Notification> {
    let token = || SensitiveString::new(SAMPLE_TOKEN);
    let code = || SensitiveString::new(SAMPLE_CODE);
    let soon = now + Duration::minutes(30);
    let kinds = vec![
        NotificationKind::EmailVerification {
            token: token(),
            code: code(),
            expires_at: now + Duration::hours(24),
        },
        NotificationKind::RegistrationAttempt,
        NotificationKind::PasswordReset {
            token: token(),
            code: Some(code()),
            expires_at: soon,
        },
        NotificationKind::PasswordChanged {
            at: now,
            ip_masked: Some("203.0.113.x".to_owned()),
            device: Some("Firefox on Linux".to_owned()),
        },
        NotificationKind::EmailChangeVerification {
            token: token(),
            code: code(),
            expires_at: soon,
        },
        NotificationKind::EmailChanged {
            new_email_masked: "n***@example.com".to_owned(),
            revert_token: token(),
            revert_expires_at: now + Duration::days(7),
        },
        NotificationKind::MfaFactorAdded {
            factor: FactorKind::Totp,
            at: now,
        },
        NotificationKind::MfaFactorRemoved {
            factor: FactorKind::Webauthn,
            at: now,
        },
        NotificationKind::MfaReset { at: now },
        NotificationKind::MfaEmailCode {
            code: code(),
            expires_at: now + Duration::minutes(10),
        },
        NotificationKind::RecoveryCodeUsed {
            remaining: 2,
            at: now,
        },
        NotificationKind::NewDeviceLogin {
            device: "Safari on iPhone".to_owned(),
            approximate_location: Some("Istanbul, TR".to_owned()),
            ip_masked: "198.51.100.x".to_owned(),
            at: now,
            not_me_token: token(),
        },
        NotificationKind::SuspiciousLoginBlocked {
            device: "Chrome on Windows".to_owned(),
            ip_masked: "192.0.2.x".to_owned(),
            at: now,
        },
        NotificationKind::AccountDeletionScheduled {
            scheduled_for: now + Duration::days(30),
            cancel_token: token(),
        },
        NotificationKind::AccountDeletionCancelled { at: now },
        NotificationKind::Invitation {
            org_name: "Example Org".to_owned(),
            inviter_name: Some("Grace Hopper".to_owned()),
            token: token(),
            expires_at: now + Duration::days(7),
        },
        NotificationKind::MagicLink {
            token: token(),
            expires_at: now + Duration::minutes(15),
        },
        NotificationKind::LoginCode {
            code: code(),
            expires_at: now + Duration::minutes(10),
        },
        NotificationKind::OrgOwnershipTransfer {
            org_name: "Example Org".to_owned(),
            token: token(),
            expires_at: now + Duration::days(7),
        },
        NotificationKind::ImpersonationStarted {
            at: now,
            expires_at: now + Duration::minutes(15),
        },
    ];
    let email = EmailAddress::parse("ada@example.com").ok();
    kinds
        .into_iter()
        .filter_map(|kind| {
            Some(Notification {
                recipient: Recipient {
                    email: email.clone()?,
                    user_id: None,
                    display_name: Some("Ada Lovelace".to_owned()),
                },
                locale,
                kind,
            })
        })
        .collect()
}

/// One sample per SMS kind.
pub(crate) fn sms_samples(locale: Locale, now: OffsetDateTime) -> Vec<SmsNotification> {
    let Ok(to) = PhoneNumber::parse("+905551112233") else {
        return Vec::new();
    };
    [
        SmsNotificationKind::MfaSmsCode {
            code: SensitiveString::new(SAMPLE_CODE),
            expires_at: now + Duration::minutes(10),
        },
        SmsNotificationKind::PhoneVerification {
            code: SensitiveString::new(SAMPLE_CODE),
            expires_at: now + Duration::minutes(10),
        },
    ]
    .into_iter()
    .map(|kind| SmsNotification {
        to: to.clone(),
        user_id: None,
        locale,
        kind,
    })
    .collect()
}
