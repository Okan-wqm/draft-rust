//! Error codes owned by `authn-webauthn` (PKY-*).
//!
//! Only the `authn-webauthn` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! Unknown or foreign passkey ids use the common `not_found` (nothing about
//! other users leaks); missing step-up uses the common `step_up_required`;
//! ceremony start limits use the common `rate_limited`. Removing the last
//! second factor of an account that must keep MFA uses
//! `mfa_last_factor_required` (authn-mfa) so clients see one code for one
//! rule.

use http::StatusCode;

use crate::error::ErrorCode;

/// The ceremony (challenge) is unknown, expired, already used, or belongs
/// to another user / session / login challenge (PKY-01). The variants are
/// deliberately indistinguishable.
pub const PASSKEY_CEREMONY_INVALID: ErrorCode = ErrorCode::new(
    "passkey_ceremony_invalid",
    StatusCode::BAD_REQUEST,
    "The passkey request has expired or is no longer valid. Please try again.",
    "Passkey isteğinin süresi doldu veya artık geçerli değil. Lütfen tekrar deneyin.",
);

/// The authenticator's registration response did not verify (wrong origin,
/// challenge, signature, missing user verification…).
pub const PASSKEY_REGISTRATION_FAILED: ErrorCode = ErrorCode::new(
    "passkey_registration_failed",
    StatusCode::BAD_REQUEST,
    "The passkey could not be registered. Please try again.",
    "Passkey kaydedilemedi. Lütfen tekrar deneyin.",
);

/// The assertion did not verify, or the passkey is unknown, not usable for
/// this purpose or suspected to be cloned. Deliberately generic.
pub const PASSKEY_AUTHENTICATION_FAILED: ErrorCode = ErrorCode::new(
    "passkey_authentication_failed",
    StatusCode::UNAUTHORIZED,
    "Passkey verification failed.",
    "Passkey doğrulaması başarısız oldu.",
);

/// This authenticator credential is already registered.
pub const PASSKEY_ALREADY_REGISTERED: ErrorCode = ErrorCode::new(
    "passkey_already_registered",
    StatusCode::CONFLICT,
    "This passkey is already registered.",
    "Bu passkey zaten kayıtlı.",
);

/// The per-user passkey limit (`webauthn.max_credentials_per_user`) is
/// reached.
pub const PASSKEY_LIMIT_REACHED: ErrorCode = ErrorCode::new(
    "passkey_limit_reached",
    StatusCode::CONFLICT,
    "The maximum number of passkeys is reached. Remove one first.",
    "En fazla passkey sayısına ulaşıldı. Önce birini kaldırın.",
);

/// Removing the passkey would leave the account without any way to log in
/// (PKY-04).
pub const PASSKEY_LAST_LOGIN_METHOD: ErrorCode = ErrorCode::new(
    "passkey_last_login_method",
    StatusCode::CONFLICT,
    "This is your last way to sign in. Add a password or another passkey before removing it.",
    "Bu, giriş yapmanın son yolu. Kaldırmadan önce bir şifre veya başka bir passkey ekleyin.",
);

/// The authenticator model is not allowed by the organization policy, or
/// its attestation could not be verified (PKY-08).
pub const PASSKEY_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "passkey_not_allowed",
    StatusCode::FORBIDDEN,
    "This security key or passkey provider is not allowed by your organization.",
    "Bu güvenlik anahtarı veya passkey sağlayıcısına kuruluşunuz izin vermiyor.",
);

/// The (already authenticated) user has no passkey usable for the requested
/// second-factor or step-up ceremony.
pub const PASSKEY_NOT_AVAILABLE: ErrorCode = ErrorCode::new(
    "passkey_not_available",
    StatusCode::BAD_REQUEST,
    "No passkey is available for this account.",
    "Bu hesap için kullanılabilir bir passkey yok.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    PASSKEY_CEREMONY_INVALID,
    PASSKEY_REGISTRATION_FAILED,
    PASSKEY_AUTHENTICATION_FAILED,
    PASSKEY_ALREADY_REGISTERED,
    PASSKEY_LIMIT_REACHED,
    PASSKEY_LAST_LOGIN_METHOD,
    PASSKEY_NOT_ALLOWED,
    PASSKEY_NOT_AVAILABLE,
];
