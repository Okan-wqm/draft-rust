//! Error codes owned by `authn-mfa` (MFA-*).
//!
//! Only the `authn-mfa` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! Wrong or expired codes use the common `invalid_code`; exhausted attempt
//! limits use the common `too_many_attempts` (with `Retry-After`); send
//! limits use the common `rate_limited`; unknown or foreign factor ids use
//! the common `not_found` (ORG-10 style, nothing about other users leaks).

use http::StatusCode;

use crate::error::ErrorCode;

/// The requested second factor is not offered: disabled in the
/// configuration, no SMS provider / allowed country configured (MFA-06), or
/// forbidden by the applicable policy (MFA-08).
pub const MFA_FACTOR_NOT_AVAILABLE: ErrorCode = ErrorCode::new(
    "mfa_factor_not_available",
    StatusCode::FORBIDDEN,
    "This verification method is not available.",
    "Bu doğrulama yöntemi kullanılamıyor.",
);

/// The user already has an active factor of this kind that cannot be
/// enrolled twice (e-mail OTP) or the same phone number (MFA-06, MFA-07).
pub const MFA_FACTOR_ALREADY_ENROLLED: ErrorCode = ErrorCode::new(
    "mfa_factor_already_enrolled",
    StatusCode::CONFLICT,
    "This verification method is already set up.",
    "Bu doğrulama yöntemi zaten kurulu.",
);

/// The per-user factor limit (`mfa.max_factors_per_user`) is reached.
pub const MFA_FACTOR_LIMIT_REACHED: ErrorCode = ErrorCode::new(
    "mfa_factor_limit_reached",
    StatusCode::CONFLICT,
    "The maximum number of verification methods is reached. Remove one first.",
    "En fazla doğrulama yöntemi sayısına ulaşıldı. Önce birini kaldırın.",
);

/// Removing the factor would leave no usable second factor while MFA is
/// required for the account (MFA-07).
pub const MFA_LAST_FACTOR_REQUIRED: ErrorCode = ErrorCode::new(
    "mfa_last_factor_required",
    StatusCode::CONFLICT,
    "Two-step verification is required for this account; add another method before removing this one.",
    "Bu hesap için iki adımlı doğrulama zorunlu; bu yöntemi kaldırmadan önce başka bir yöntem ekleyin.",
);

/// The phone number is not in E.164 format (MFA-06).
pub const MFA_INVALID_PHONE_NUMBER: ErrorCode = ErrorCode::new(
    "mfa_invalid_phone_number",
    StatusCode::UNPROCESSABLE_ENTITY,
    "Enter the phone number in international format, e.g. +905551112233.",
    "Telefon numarasını uluslararası biçimde girin, ör. +905551112233.",
);

/// The phone number's country is not on the SMS allow-list (MFA-06).
pub const MFA_PHONE_COUNTRY_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "mfa_phone_country_not_allowed",
    StatusCode::UNPROCESSABLE_ENTITY,
    "SMS verification is not available for phone numbers of this country.",
    "Bu ülkeye ait telefon numaraları için SMS doğrulaması kullanılamıyor.",
);

/// The factor is not pending confirmation (already active, or the pending
/// enrollment expired and was discarded).
pub const MFA_ENROLLMENT_NOT_PENDING: ErrorCode = ErrorCode::new(
    "mfa_enrollment_not_pending",
    StatusCode::CONFLICT,
    "There is no pending setup for this verification method. Start the setup again.",
    "Bu doğrulama yöntemi için bekleyen bir kurulum yok. Kurulumu yeniden başlatın.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    MFA_FACTOR_NOT_AVAILABLE,
    MFA_FACTOR_ALREADY_ENROLLED,
    MFA_FACTOR_LIMIT_REACHED,
    MFA_LAST_FACTOR_REQUIRED,
    MFA_INVALID_PHONE_NUMBER,
    MFA_PHONE_COUNTRY_NOT_ALLOWED,
    MFA_ENROLLMENT_NOT_PENDING,
];
