//! Public input / output types of [`super::WebauthnService`].

use std::fmt;
use std::str::FromStr;

use authn_core::domain::UnknownVariant;
use authn_core::id::CredentialId;
#[cfg(feature = "passkey")]
use authn_core::{
    domain::AuthMethodRef,
    id::{CeremonyId, ChallengeId, SessionId, UserId},
    secret::SensitiveString,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// What a stored passkey may be used for (PKY-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyUsage {
    /// Passwordless (primary) login **and** second factor: user
    /// verification was performed at registration.
    Both,
    /// Second factor only: registered without user verification (e.g. a
    /// security key without PIN). Never accepted for passwordless login or
    /// step-up.
    SecondFactor,
    /// Passwordless login only (reserved; not produced by this version).
    Passwordless,
}

impl PasskeyUsage {
    /// The stored representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::SecondFactor => "second_factor",
            Self::Passwordless => "passwordless",
        }
    }

    /// Whether the passkey may be used for passwordless login and step-up.
    #[must_use]
    pub const fn allows_passwordless(self) -> bool {
        matches!(self, Self::Both | Self::Passwordless)
    }

    /// Whether the passkey may be used as a second factor.
    #[must_use]
    pub const fn allows_second_factor(self) -> bool {
        matches!(self, Self::Both | Self::SecondFactor)
    }
}

impl fmt::Display for PasskeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PasskeyUsage {
    type Err = UnknownVariant;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "both" => Ok(Self::Both),
            "second_factor" => Ok(Self::SecondFactor),
            "passwordless" => Ok(Self::Passwordless),
            _ => Err(UnknownVariant {
                kind: "PasskeyUsage",
            }),
        }
    }
}

/// Why a passkey authentication ceremony is run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationPurpose {
    /// Passwordless, username-less login (discoverable credential, SES-20).
    Login,
    /// Second factor of a login challenge (SES-02).
    SecondFactor,
    /// Re-authentication of an existing session (SES-13).
    StepUp,
}

/// A passkey as shown to its owner (PKY-04). Contains no key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PasskeySummary {
    /// Passkey id (not the authenticator credential id).
    pub id: CredentialId,
    /// User-chosen name.
    pub name: String,
    /// Registration time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Last successful use.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_used_at: Option<OffsetDateTime>,
    /// What the passkey may be used for.
    pub usage: PasskeyUsage,
    /// User verification (PIN / biometrics) was performed at registration.
    pub user_verified: bool,
    /// The passkey may be synced / backed up (multi-device credential).
    pub backup_eligible: bool,
    /// The passkey is currently synced / backed up.
    pub backup_state: bool,
    /// Client-reported discoverability (`credProps.rk`); `null` = unknown.
    /// UX hint only.
    pub discoverable: Option<bool>,
    /// Authenticator model, only when proven by verified attestation
    /// (PKY-08).
    #[schema(value_type = Option<String>, format = Uuid)]
    pub aaguid: Option<Uuid>,
    /// Transport hints reported at registration (`usb`, `nfc`, `internal`,
    /// `hybrid`…).
    pub transports: Vec<String>,
    /// Attestation statement format at registration (`none`, `packed`…).
    pub attestation_format: Option<String>,
    /// Set when a signature-counter regression suggested a cloned
    /// authenticator (PKY-05); the user should remove this passkey.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub clone_suspected_at: Option<OffsetDateTime>,
}

/// The kind of passkey the user wants to register (PKY-02).
#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationIntent {
    /// A passkey for passwordless login (and second factor): discoverable
    /// credential preferred, user verification required.
    #[default]
    Passwordless,
    /// A second factor only (security key): user verification preferred.
    SecondFactor,
}

/// Body of `POST /v1/me/passkeys/registration/options`.
#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrationOptionsRequest {
    /// Name shown in the passkey list (1–64 characters). Default
    /// `Passkey` / `Security key`.
    pub name: Option<String>,
    /// Kind of passkey. Default `passwordless`.
    pub usage: Option<RegistrationIntent>,
}

/// A started registration ceremony.
#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegistrationStart {
    /// Ceremony id; send it back with the authenticator response.
    pub ceremony_id: CeremonyId,
    /// The ceremony must be finished before this time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// `CredentialCreationOptions` for `navigator.credentials.create()` /
    /// the platform passkey APIs: `{"publicKey": {...}}` (binary fields are
    /// base64url).
    #[schema(value_type = Object)]
    pub options: serde_json::Value,
}

/// Body of `POST /v1/me/passkeys/registration/verify`.
#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrationVerifyRequest {
    /// The ceremony id from the options response.
    pub ceremony_id: CeremonyId,
    /// The `PublicKeyCredential` returned by `navigator.credentials.create()`
    /// (JSON, binary fields base64url).
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
    /// Optional name overriding the one given with the options.
    pub name: Option<String>,
}

/// A started registration ceremony bound to a pending login challenge
/// (K-112: passkey enrollment inside the login, SES-22).
#[cfg(feature = "passkey")]
#[derive(Debug, Clone)]
pub struct ChallengeRegistrationStart {
    /// Ceremony id.
    pub ceremony_id: CeremonyId,
    /// 256-bit client binding secret (PKY-01). authn-session hands it to
    /// the client in an `HttpOnly` cookie (web) or the response body
    /// (native) and passes it back to
    /// [`super::WebauthnService::verify_challenge_registration`]. Only its
    /// SHA-256 is stored.
    pub binding_token: SensitiveString,
    /// `CredentialCreationOptions` for `navigator.credentials.create()`:
    /// `{"publicKey": {...}}` (binary fields base64url).
    pub options: serde_json::Value,
    /// The ceremony must be finished before this time.
    pub expires_at: OffsetDateTime,
}

/// Who / what an authentication ceremony is for, and what it is bound to
/// (PKY-01: the same value must be presented when finishing).
#[cfg(feature = "passkey")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationTarget {
    /// Passwordless, username-less login with a discoverable credential
    /// (SES-20). `conditional_ui` requests conditional mediation (passkey
    /// autofill). User verification is required.
    Discoverable {
        /// Ask the browser for conditional mediation.
        conditional_ui: bool,
    },
    /// Second factor of a pending login challenge (SES-02). User
    /// verification is preferred (required for passkeys registered with
    /// it).
    SecondFactor {
        /// The user who passed the first factor.
        user_id: UserId,
        /// The login challenge (`auth_challenges.id`).
        challenge_id: ChallengeId,
    },
    /// Step-up of an existing session (SES-13). User verification is
    /// required.
    StepUp {
        /// The session owner.
        user_id: UserId,
        /// The session being elevated.
        session_id: SessionId,
    },
}

#[cfg(feature = "passkey")]
impl AuthenticationTarget {
    /// The purpose of the ceremony.
    #[must_use]
    pub const fn purpose(&self) -> AuthenticationPurpose {
        match self {
            Self::Discoverable { .. } => AuthenticationPurpose::Login,
            Self::SecondFactor { .. } => AuthenticationPurpose::SecondFactor,
            Self::StepUp { .. } => AuthenticationPurpose::StepUp,
        }
    }
}

/// A started authentication ceremony.
#[cfg(feature = "passkey")]
#[derive(Debug, Clone)]
pub struct AuthenticationStart {
    /// Ceremony id.
    pub ceremony_id: CeremonyId,
    /// 256-bit client binding secret (PKY-01). authn-session hands it to
    /// the client in an `HttpOnly` cookie (web) or the response body
    /// (native) and passes it back to
    /// [`super::WebauthnService::finish_authentication`]. Only its SHA-256
    /// is stored.
    pub binding_token: SensitiveString,
    /// `CredentialRequestOptions` for `navigator.credentials.get()`:
    /// `{"publicKey": {...}, "mediation"?: "conditional"}`.
    pub options: serde_json::Value,
    /// The ceremony must be finished before this time.
    pub expires_at: OffsetDateTime,
}

/// Input of [`super::WebauthnService::finish_authentication`].
#[cfg(feature = "passkey")]
#[derive(Debug, Clone)]
pub struct AuthenticationFinish {
    /// Ceremony id from [`AuthenticationStart`].
    pub ceremony_id: CeremonyId,
    /// Binding token from [`AuthenticationStart`].
    pub binding_token: SensitiveString,
    /// The same target the ceremony was started for (for `Discoverable`
    /// the `conditional_ui` flag is ignored).
    pub target: AuthenticationTarget,
    /// The `PublicKeyCredential` returned by `navigator.credentials.get()`.
    pub credential: serde_json::Value,
}

/// A verified passkey assertion (PKY-02, PKY-05).
#[cfg(feature = "passkey")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPasskey {
    /// The authenticated user.
    pub user_id: UserId,
    /// The passkey used.
    pub credential_id: CredentialId,
    /// Why the ceremony ran.
    pub purpose: AuthenticationPurpose,
    /// User verification (PIN / biometrics) was performed. Always `true`
    /// for `Login` and `StepUp`.
    pub user_verified: bool,
    /// The passkey is a multi-device (syncable) credential.
    pub backup_eligible: bool,
    /// The passkey is currently backed up / synced.
    pub backup_state: bool,
    /// RFC 8176 method references proven by this assertion: `swk` (synced
    /// passkey) or `hwk` (device-bound key), `user` (presence) and `mfa`
    /// when user verification was performed (possession + inherence /
    /// knowledge, SES-21).
    pub amr: Vec<AuthMethodRef>,
}
