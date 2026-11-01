//! Public input / output types of [`AccountService`](crate::AccountService)
//! (also the JSON bodies of the HTTP API).

use std::fmt;

use authn_core::config::account::TermsDocument;
use authn_core::domain::{AccountStatus, Locale};
use authn_core::id::{OrgId, TermsVersionId, UserId};
use authn_core::ports::RequiredAction;
use authn_core::secret::SecretString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

/// A `(document, version)` pair the user accepted (ACC-11).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TermsAcceptance {
    /// Which document.
    pub document: TermsDocument,
    /// Accepted version label.
    pub version: String,
}

/// Registration input (ACC-01).
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignupInput {
    /// E-mail address (normalized per ACC-03).
    #[schema(value_type = String, format = Email)]
    pub email: String,
    /// Password (validated by the password policy, never logged).
    #[schema(value_type = String, format = Password)]
    pub password: SecretString,
    /// Optional display name (ACC-08 rules).
    pub display_name: Option<String>,
    /// Preferred language; defaults to the request language.
    pub locale: Option<Locale>,
    /// IANA time zone; defaults to `UTC`.
    pub time_zone: Option<String>,
    /// CAPTCHA response token when required (ACC-13).
    pub captcha: Option<String>,
    /// Accepted terms / privacy-policy versions (ACC-11).
    #[serde(default)]
    pub accepted_terms: Vec<TermsAcceptance>,
}

impl fmt::Debug for SignupInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignupInput")
            .field("email", &authn_core::redact::mask_email(&self.email))
            .field("password", &authn_core::secret::REDACTED)
            .field("locale", &self.locale)
            .field("accepted_terms", &self.accepted_terms)
            .finish_non_exhaustive()
    }
}

/// The user's profile (ACC-08).
#[derive(Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ProfileView {
    /// The user.
    pub user_id: UserId,
    /// Current e-mail address.
    pub email: Option<String>,
    /// Whether the address is verified.
    pub email_verified: bool,
    /// Account status.
    pub status: AccountStatus,
    /// Display name.
    pub display_name: Option<String>,
    /// Preferred language.
    pub locale: Locale,
    /// IANA time zone.
    pub time_zone: String,
}

impl fmt::Debug for ProfileView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileView")
            .field("user_id", &self.user_id)
            .field(
                "email",
                &self.email.as_deref().map(authn_core::redact::mask_email),
            )
            .field("email_verified", &self.email_verified)
            .field("status", &self.status)
            .field("locale", &self.locale)
            .finish_non_exhaustive()
    }
}

/// Partial profile update (ACC-08). Absent fields are unchanged;
/// `display_name: null` removes the display name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileUpdate {
    /// New display name, or `null` to remove it.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub display_name: Option<Option<String>>,
    /// New language.
    pub locale: Option<Locale>,
    /// New IANA time zone.
    pub time_zone: Option<String>,
}

/// Distinguishes "absent" (`None`) from "null" (`Some(None)`).
fn double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

/// State of a scheduled deletion (ACC-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DeletionView {
    /// `scheduled`.
    pub status: String,
    /// When the request was made.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub requested_at: OffsetDateTime,
    /// When the deletion becomes final.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub scheduled_for: OffsetDateTime,
}

/// A published document version (ACC-11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct TermsVersionView {
    /// Version id.
    pub id: TermsVersionId,
    /// Which document.
    pub document: TermsDocument,
    /// Version label.
    pub version: String,
    /// Where the text is published.
    pub url: Option<String>,
    /// Publication time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub published_at: OffsetDateTime,
    /// Users must accept it again at their next login.
    pub requires_reacceptance: bool,
}

/// A recorded acceptance (ACC-11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ConsentView {
    /// Which document.
    pub document: TermsDocument,
    /// Accepted version.
    pub version: String,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub accepted_at: OffsetDateTime,
}

/// What the login flow (authn-session) must do with an identified user
/// after a correct password (SES-01, SES-22; ACC-05, ACC-06, ACC-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginAssessment {
    /// Sign-in may continue; complete `required_actions` first (empty =
    /// none).
    Allowed {
        /// Required actions (`verify_email`, `accept_terms`).
        required_actions: Vec<RequiredAction>,
        /// Set while a deletion is scheduled (offer to cancel it).
        deletion_scheduled_for: Option<OffsetDateTime>,
    },
    /// Sign-in refused; answer with this error (revealed only after a
    /// correct password).
    Denied(DenialReason),
}

/// Why a login is refused by the account state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    /// E-mail not verified and `account.unverified_login = "block"`.
    EmailNotVerified,
    /// Temporarily locked until the given time.
    Locked {
        /// End of the lock.
        until: OffsetDateTime,
    },
    /// Suspended by an administrator.
    Suspended,
    /// Disabled or deleted.
    Disabled,
}

impl DenialReason {
    /// The error to answer with (`email_verification_required`,
    /// `account_locked` + `Retry-After`, `account_suspended`,
    /// `account_disabled`).
    #[must_use]
    pub fn into_error(self, now: OffsetDateTime) -> authn_core::AuthError {
        use authn_core::error::codes::account;
        match self {
            Self::EmailNotVerified => {
                authn_core::AuthError::new(account::EMAIL_VERIFICATION_REQUIRED)
            }
            Self::Locked { until } => {
                let wait = std::time::Duration::try_from(until - now)
                    .unwrap_or(std::time::Duration::from_secs(1))
                    .max(std::time::Duration::from_secs(1));
                authn_core::AuthError::new(account::ACCOUNT_LOCKED).with_retry_after(wait)
            }
            Self::Suspended => authn_core::AuthError::new(account::ACCOUNT_SUSPENDED),
            Self::Disabled => authn_core::AuthError::new(account::ACCOUNT_DISABLED),
        }
    }
}

/// Result of the deletion purge job (ACC-09).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Accounts deleted.
    pub purged: u64,
    /// Due deletions postponed because the user is the last owner of an
    /// organization.
    pub blocked: u64,
}

/// Result of an e-mail change revert (ACC-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct RevertOutcome {
    /// The password was invalidated; the user must reset it (via the
    /// restored address) before signing in with a password again.
    pub password_reset_required: bool,
}

/// Organizations blocking a deletion (envelope `details`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct LastOwnerDetails {
    /// Organizations in which the user is the only owner.
    pub organization_ids: Vec<OrgId>,
}
