//! User notifications (NTF-01, NTF-02, NTF-03). Owner of this file:
//! authn-notify.
//!
//! Semantics required from implementations:
//! * Delivery is asynchronous through the outbox (NTF-03): `notify*` only
//!   enqueues and never blocks the request on SMTP.
//! * Payload fields of type [`SensitiveString`] (tokens, codes) are stored
//!   sealed with envelope encryption (CRY-08) and wiped after delivery.
//! * Links are built **only** from the configured `public_base_url` and
//!   link paths (NTF-02, PWD-08); producers therefore pass raw tokens, never
//!   URLs, and never anything derived from the `Host` header.
//! * Templates exist in Turkish and English (HTML + text) and escape all
//!   user-provided values.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use time::OffsetDateTime;

use crate::domain::{EmailAddress, FactorKind, Locale, PhoneNumber};
use crate::error::{AuthError, codes};
use crate::id::UserId;
use crate::secret::SensitiveString;

/// Sends user notifications (e-mail; SMS through the same outbox).
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Enqueues a notification in its own transaction.
    async fn notify(&self, notification: Notification) -> Result<(), AuthError>;

    /// Enqueues a notification inside the caller's transaction; it is
    /// delivered only if that transaction commits.
    async fn notify_in_tx(
        &self,
        conn: &mut PgConnection,
        notification: Notification,
    ) -> Result<(), AuthError>;

    /// Enqueues an SMS (MFA-06, NTF-04) inside the caller's transaction;
    /// it is delivered asynchronously (retried) only if that transaction
    /// commits. The code is sealed at rest like e-mail secrets.
    ///
    /// SMS pumping protection (country allow-list, per-number / per-IP
    /// limits, global budget) stays the caller's job and must run *before*
    /// this call. Alternative: call an `SmsSender` directly for synchronous
    /// delivery.
    ///
    /// The default implementation (fakes, notifiers without SMS support)
    /// fails with `sms_unavailable`.
    async fn notify_sms_in_tx(
        &self,
        conn: &mut PgConnection,
        sms: SmsNotification,
    ) -> Result<(), AuthError> {
        let _ = (conn, sms);
        Err(AuthError::new(codes::notify::SMS_UNAVAILABLE)
            .with_context("this Notifier does not support SMS notifications"))
    }
}

/// An SMS notification (NTF-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmsNotification {
    /// Destination (E.164).
    pub to: PhoneNumber,
    /// The user, when the number belongs to an account.
    pub user_id: Option<UserId>,
    /// Template language.
    pub locale: Locale,
    /// What to send.
    pub kind: SmsNotificationKind,
}

/// Every SMS type with its template parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SmsNotificationKind {
    /// SMS one-time code used as a second factor (MFA-06).
    MfaSmsCode {
        /// Six-digit code.
        code: SensitiveString,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// Verification of a phone number before it becomes a factor (MFA-06).
    PhoneVerification {
        /// Six-digit code.
        code: SensitiveString,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
}

impl SmsNotificationKind {
    /// Stable template name (`mfa_sms_code`, `phone_verification`).
    #[must_use]
    pub const fn template_name(&self) -> &'static str {
        match self {
            Self::MfaSmsCode { .. } => "mfa_sms_code",
            Self::PhoneVerification { .. } => "phone_verification",
        }
    }
}

/// Addressee of a notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// Destination address.
    pub email: EmailAddress,
    /// The user, when the address belongs to an account.
    pub user_id: Option<UserId>,
    /// Display name used in the greeting (escaped by templates).
    pub display_name: Option<String>,
}

/// A notification to deliver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    /// Addressee.
    pub recipient: Recipient,
    /// Template language.
    pub locale: Locale,
    /// What to send.
    pub kind: NotificationKind,
}

/// Every notification type (NTF-01) with its template parameters.
///
/// Timestamps are absolute; templates render them in the user's time zone
/// when known. Masked values (`*_masked`) are already masked by the producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotificationKind {
    /// E-mail address verification: link token and 6-digit code (ACC-04).
    EmailVerification {
        /// Link token.
        token: SensitiveString,
        /// Six-digit code.
        code: SensitiveString,
        /// Expiry of the link.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// Someone tried to use the recipient's address for an account: a
    /// sign-up with an already registered address (ACC-02) or an e-mail
    /// change of another account to this address (ACC-07). The text covers
    /// both cases.
    RegistrationAttempt,
    /// Password reset link and optional mobile code (PWD-07, PWD-08).
    PasswordReset {
        /// Link token.
        token: SensitiveString,
        /// Optional six-digit code for mobile clients.
        code: Option<SensitiveString>,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// Password changed, added or removed (PWD-06, PWD-09, PWD-10, PWD-11).
    PasswordChanged {
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
        /// Masked IP of the request.
        ip_masked: Option<String>,
        /// Device description.
        device: Option<String>,
    },
    /// Verification sent to the *new* address on e-mail change (ACC-07).
    EmailChangeVerification {
        /// Link token.
        token: SensitiveString,
        /// Six-digit code.
        code: SensitiveString,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// Notice to the *old* address with a revert link (ACC-07).
    EmailChanged {
        /// Masked new address.
        new_email_masked: String,
        /// Revert link token.
        revert_token: SensitiveString,
        /// Revert link expiry.
        #[serde(with = "time::serde::rfc3339")]
        revert_expires_at: OffsetDateTime,
    },
    /// A second factor was added (MFA-07).
    MfaFactorAdded {
        /// Factor kind.
        factor: FactorKind,
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// A second factor was removed (MFA-07).
    MfaFactorRemoved {
        /// Factor kind.
        factor: FactorKind,
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// An admin reset the user's MFA (ADM-03).
    MfaReset {
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// E-mail OTP used as a second factor (MFA-05).
    MfaEmailCode {
        /// Six-digit code.
        code: SensitiveString,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// A recovery code was used (MFA-04).
    RecoveryCodeUsed {
        /// Remaining unused codes.
        remaining: u32,
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// Successful login from a new device (RSK-04) with a "not me" link.
    NewDeviceLogin {
        /// Device description.
        device: String,
        /// Approximate location, if a GeoIP provider is configured.
        approximate_location: Option<String>,
        /// Masked IP.
        ip_masked: String,
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
        /// "This wasn't me" token: revokes all sessions and forces a reset.
        not_me_token: SensitiveString,
    },
    /// High-risk login blocked (RSK-03).
    SuspiciousLoginBlocked {
        /// Device description.
        device: String,
        /// Masked IP.
        ip_masked: String,
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// Account deletion scheduled with a cancel link (ACC-09).
    AccountDeletionScheduled {
        /// When the deletion becomes final.
        #[serde(with = "time::serde::rfc3339")]
        scheduled_for: OffsetDateTime,
        /// Cancel link token.
        cancel_token: SensitiveString,
    },
    /// Account deletion cancelled (ACC-09).
    AccountDeletionCancelled {
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// Organization invitation (ORG-05).
    Invitation {
        /// Organization display name (escaped by templates).
        org_name: String,
        /// Inviter display name.
        inviter_name: Option<String>,
        /// Invitation token.
        token: SensitiveString,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// Passwordless magic link (SES-18).
    MagicLink {
        /// Link token.
        token: SensitiveString,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// Passwordless login code (SES-19).
    LoginCode {
        /// Six-digit code.
        code: SensitiveString,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// Organization ownership transfer request (ORG-11).
    OrgOwnershipTransfer {
        /// Organization display name.
        org_name: String,
        /// Acceptance token.
        token: SensitiveString,
        /// Expiry.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// A verified domain of an organization the recipient administers lost
    /// its verification (periodic re-verification, ORG-13, K-97): auto-join
    /// stopped until the TXT record is published and verified again.
    OrgDomainUnverified {
        /// Organization display name.
        org_name: String,
        /// The domain (normalized, punycode).
        domain: String,
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// An admin started impersonating the user (ADM-04).
    ImpersonationStarted {
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
        /// End of the impersonation.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
    /// An external sign-in provider was linked to the account (SOC-06):
    /// lets the owner notice a provider an attacker linked.
    IdentityLinked {
        /// Provider display name (`Google`, `Apple`, a generic provider's
        /// configured name). Escaped and length-capped by templates.
        provider: String,
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// An external sign-in provider was unlinked from the account (SOC-06).
    IdentityUnlinked {
        /// Provider display name (escaped and length-capped by templates).
        provider: String,
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// A passkey presented a signature counter that did not advance: the
    /// authenticator may have been cloned (PKY-05).
    PasskeyCloneSuspected {
        /// When it was detected.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
    /// An e-mail change was reverted from the previous address (ACC-07):
    /// every session was signed out and a password reset is required.
    EmailChangeReverted {
        /// When.
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
    },
}

impl NotificationKind {
    /// Stable template name (`email_verification`, `password_reset`…).
    #[must_use]
    pub const fn template_name(&self) -> &'static str {
        match self {
            Self::EmailVerification { .. } => "email_verification",
            Self::RegistrationAttempt => "registration_attempt",
            Self::PasswordReset { .. } => "password_reset",
            Self::PasswordChanged { .. } => "password_changed",
            Self::EmailChangeVerification { .. } => "email_change_verification",
            Self::EmailChanged { .. } => "email_changed",
            Self::MfaFactorAdded { .. } => "mfa_factor_added",
            Self::MfaFactorRemoved { .. } => "mfa_factor_removed",
            Self::MfaReset { .. } => "mfa_reset",
            Self::MfaEmailCode { .. } => "mfa_email_code",
            Self::RecoveryCodeUsed { .. } => "recovery_code_used",
            Self::NewDeviceLogin { .. } => "new_device_login",
            Self::SuspiciousLoginBlocked { .. } => "suspicious_login_blocked",
            Self::AccountDeletionScheduled { .. } => "account_deletion_scheduled",
            Self::AccountDeletionCancelled { .. } => "account_deletion_cancelled",
            Self::Invitation { .. } => "invitation",
            Self::MagicLink { .. } => "magic_link",
            Self::LoginCode { .. } => "login_code",
            Self::OrgOwnershipTransfer { .. } => "org_ownership_transfer",
            Self::OrgDomainUnverified { .. } => "org_domain_unverified",
            Self::ImpersonationStarted { .. } => "impersonation_started",
            Self::IdentityLinked { .. } => "identity_linked",
            Self::IdentityUnlinked { .. } => "identity_unlinked",
            Self::PasskeyCloneSuspected { .. } => "passkey_clone_suspected",
            Self::EmailChangeReverted { .. } => "email_change_reverted",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntf_01_secrets_are_redacted_in_debug_but_serializable_for_sealing() {
        let n = Notification {
            recipient: Recipient {
                email: EmailAddress::parse("alice@example.com").unwrap(),
                user_id: None,
                display_name: None,
            },
            locale: Locale::Tr,
            kind: NotificationKind::LoginCode {
                code: SensitiveString::new("123456"),
                expires_at: OffsetDateTime::UNIX_EPOCH,
            },
        };
        let debug = format!("{n:?}");
        assert!(!debug.contains("123456"));
        assert!(!debug.contains("alice@"));
        let json = serde_json::to_value(&n).unwrap();
        assert_eq!(json["kind"]["type"], "login_code");
        assert_eq!(json["kind"]["code"], "123456");
        let back: Notification = serde_json::from_value(json).unwrap();
        assert_eq!(back, n);
        assert_eq!(n.kind.template_name(), "login_code");
    }

    #[test]
    fn ntf_04_sms_notification_is_redacted_and_round_trips() {
        let sms = SmsNotification {
            to: PhoneNumber::parse("+905551112233").unwrap(),
            user_id: None,
            locale: Locale::En,
            kind: SmsNotificationKind::MfaSmsCode {
                code: SensitiveString::new("654321"),
                expires_at: OffsetDateTime::UNIX_EPOCH,
            },
        };
        let debug = format!("{sms:?}");
        assert!(!debug.contains("654321"));
        assert!(!debug.contains("5551112233"));
        let json = serde_json::to_value(&sms).unwrap();
        assert_eq!(json["kind"]["type"], "mfa_sms_code");
        let back: SmsNotification = serde_json::from_value(json).unwrap();
        assert_eq!(back, sms);
        assert_eq!(sms.kind.template_name(), "mfa_sms_code");
    }
}
