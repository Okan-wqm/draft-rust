//! Public input / output types of [`crate::MfaService`]. Output types are
//! also the HTTP response bodies (no secrets except where documented).

use std::fmt;

use authn_core::domain::{AuthMethodRef, FactorKind};
use authn_core::id::{FactorId, TrustedDeviceId};
use authn_core::secret::SecretString;
use serde::{Serialize, Serializer};
use time::OffsetDateTime;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::device_token::TrustedDeviceToken;
use crate::totp::TotpProvisioning;

/// Enrollment state of a factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FactorState {
    /// Enrollment started; confirm it with a code.
    Pending,
    /// Usable as a second factor.
    Active,
}

/// A factor as shown to its owner (MFA-10). Never contains a secret; phone
/// numbers and addresses are masked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct FactorSummary {
    /// Factor id.
    pub id: FactorId,
    /// Kind (`totp`, `email`, `sms`).
    pub kind: FactorKind,
    /// Pending or active.
    pub status: FactorState,
    /// User-chosen label.
    pub label: Option<String>,
    /// Masked phone number (SMS factor).
    pub phone_number: Option<String>,
    /// Masked e-mail address (e-mail factor; the account address).
    pub email: Option<String>,
    /// Weak factor that organization policies may forbid (SMS, MFA-06).
    pub weak: bool,
    /// Phishing-resistant factor (never for TOTP / OTP factors).
    pub phishing_resistant: bool,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Confirmation time (active factors).
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub confirmed_at: Option<OffsetDateTime>,
    /// Last successful use.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_used_at: Option<OffsetDateTime>,
    /// Temporarily locked after failed attempts until (MFA-03).
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub locked_until: Option<OffsetDateTime>,
}

/// Recovery code counters (MFA-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct RecoveryCodesStatus {
    /// Unused codes.
    pub remaining: u32,
    /// Codes in the current batch.
    pub total: u32,
    /// When the current batch was generated.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub generated_at: Option<OffsetDateTime>,
}

/// The user's MFA state (MFA-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MfaStatus {
    /// At least one active second factor exists.
    pub enabled: bool,
    /// Pending and active factors (passkeys are listed by authn-webauthn).
    pub factors: Vec<FactorSummary>,
    /// Recovery codes.
    pub recovery_codes: RecoveryCodesStatus,
    /// Active trusted devices (MFA-09).
    pub trusted_devices: u32,
}

/// A started TOTP enrollment (MFA-01). Contains the shared secret: shown
/// exactly once.
pub struct TotpEnrollment {
    /// The pending factor.
    pub factor: FactorSummary,
    /// Secret, `otpauth://` URI and QR code.
    pub provisioning: TotpProvisioning,
    /// The pending factor is discarded after this time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrollment")
            .field("factor", &self.factor)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Channel of a one-time code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeChannel {
    /// E-mail (MFA-05).
    Email,
    /// SMS (MFA-06).
    Sms,
}

/// A one-time code was sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CodeDelivery {
    /// The factor the code belongs to.
    pub factor_id: FactorId,
    /// Channel.
    pub channel: CodeChannel,
    /// Masked destination (`a***@example.com`, `+90*******233`).
    pub destination: String,
    /// Code expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
}

/// Freshly generated recovery codes (MFA-04). Shown exactly once; redacted
/// in `Debug`, zeroized on drop.
#[derive(Clone, ToSchema)]
pub struct GeneratedRecoveryCodes {
    /// Codes in display form (`XXXXX-XXXXX`).
    #[schema(value_type = Vec<String>)]
    pub codes: Vec<Zeroizing<String>>,
    /// Generation time.
    #[schema(value_type = String, format = DateTime)]
    pub generated_at: OffsetDateTime,
}

impl fmt::Debug for GeneratedRecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedRecoveryCodes")
            .field("count", &self.codes.len())
            .field("generated_at", &self.generated_at)
            .finish_non_exhaustive()
    }
}

impl Serialize for GeneratedRecoveryCodes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let codes: Vec<&str> = self.codes.iter().map(|c| c.as_str()).collect();
        let generated_at = self
            .generated_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        let mut s = serializer.serialize_struct("GeneratedRecoveryCodes", 2)?;
        s.serialize_field("codes", &codes)?;
        s.serialize_field("generated_at", &generated_at)?;
        s.end()
    }
}

/// A confirmed (now active) factor.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConfirmedFactor {
    /// The factor.
    pub factor: FactorSummary,
    /// Recovery codes generated with the user's first factor (MFA-04);
    /// `None` when the user already had codes.
    pub recovery_codes: Option<GeneratedRecoveryCodes>,
}

/// Proof of a second factor submitted at login or step-up.
#[derive(Debug, Clone)]
pub enum FactorProof {
    /// TOTP code (MFA-01, MFA-02); optionally for one specific factor.
    Totp {
        /// The code.
        code: SecretString,
        /// Restrict the check to this factor.
        factor_id: Option<FactorId>,
    },
    /// A recovery code (MFA-04).
    RecoveryCode {
        /// The code.
        code: SecretString,
    },
    /// E-mail OTP (MFA-05).
    EmailOtp {
        /// The code.
        code: SecretString,
    },
    /// SMS OTP (MFA-06).
    SmsOtp {
        /// The code.
        code: SecretString,
    },
}

impl FactorProof {
    /// The factor kind the proof is for.
    #[must_use]
    pub const fn kind(&self) -> FactorKind {
        match self {
            Self::Totp { .. } => FactorKind::Totp,
            Self::RecoveryCode { .. } => FactorKind::RecoveryCode,
            Self::EmailOtp { .. } => FactorKind::Email,
            Self::SmsOtp { .. } => FactorKind::Sms,
        }
    }
}

/// A successful second-factor verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFactor {
    /// The factor kind.
    pub kind: FactorKind,
    /// The factor row (`None` for recovery codes).
    pub factor_id: Option<FactorId>,
    /// RFC 8176 method references of this factor (see [`crate::amr`]).
    pub amr: Vec<AuthMethodRef>,
    /// Unused recovery codes left after a recovery-code verification.
    pub recovery_codes_remaining: Option<u32>,
}

/// Where to send a login / step-up code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpChannel {
    /// The user's active e-mail factor.
    Email,
    /// An active SMS factor (the most recently used one when `None`).
    Sms {
        /// The factor.
        factor_id: Option<FactorId>,
    },
}

/// A newly trusted device (MFA-09). The token is a bearer secret: set it as
/// the `__Host-authn_trusted_device` cookie (web) or return it to native
/// clients for the `x-trusted-device` header.
#[derive(Debug, Clone)]
pub struct IssuedTrustedDevice {
    /// The device record.
    pub device_id: TrustedDeviceId,
    /// The signed token.
    pub token: TrustedDeviceToken,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// A trusted device as shown to its owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct TrustedDeviceSummary {
    /// Id.
    pub id: TrustedDeviceId,
    /// Device description (from the user agent).
    pub name: Option<String>,
    /// Masked IP of the request that trusted the device.
    pub ip: Option<String>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Expiry.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// Last use.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_used_at: Option<OffsetDateTime>,
}

/// What an admin MFA reset removed (ADM-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MfaResetSummary {
    /// Factors deleted.
    pub factors: u64,
    /// Recovery codes deleted.
    pub recovery_codes: u64,
    /// Trusted devices revoked.
    pub trusted_devices: u64,
}

/// Rows removed by [`crate::MfaService::purge_expired`] (OPS-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PurgeReport {
    /// Abandoned pending enrollments.
    pub pending_factors: u64,
    /// Expired or revoked trusted devices.
    pub trusted_devices: u64,
}
