//! Error codes owned by `authn-password` (PWD-*).
//!
//! Only the `authn-password` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! None of these codes is used on an unauthenticated path where it could
//! reveal whether an account exists: the reset flow (PWD-07 … PWD-09)
//! answers unknown accounts, unusable tokens and wrong codes with the
//! common `invalid_or_expired_token` / `invalid_code` codes only.

use http::StatusCode;

use crate::error::ErrorCode;

/// The candidate password violates the policy (PWD-01, PWD-03, PWD-04). The
/// envelope `details` carry the violations and localized feedback; they only
/// describe the submitted password, never the account.
pub const PASSWORD_POLICY_VIOLATION: ErrorCode = ErrorCode::new(
    "password_policy_violation",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The password does not meet the requirements.",
    "Şifre gereksinimleri karşılamıyor.",
);

/// The breached-password service is unreachable and the deployment is
/// configured to fail closed (PWD-03). Rendered with `Retry-After`.
pub const PASSWORD_BREACH_CHECK_UNAVAILABLE: ErrorCode = ErrorCode::new(
    "password_breach_check_unavailable",
    StatusCode::SERVICE_UNAVAILABLE,
    "The password cannot be checked right now. Please try again later.",
    "Şifre şu anda kontrol edilemiyor. Lütfen daha sonra tekrar deneyin.",
);

/// Password change: the current password is wrong (PWD-06).
pub const CURRENT_PASSWORD_INCORRECT: ErrorCode = ErrorCode::new(
    "current_password_incorrect",
    StatusCode::FORBIDDEN,
    "The current password is incorrect.",
    "Mevcut şifre hatalı.",
);

/// Password change: the new password equals the current one (PWD-06).
pub const PASSWORD_UNCHANGED: ErrorCode = ErrorCode::new(
    "password_unchanged",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The new password must be different from the current password.",
    "Yeni şifre mevcut şifreden farklı olmalıdır.",
);

/// Adding a password to an account that already has one (PWD-10).
pub const PASSWORD_ALREADY_SET: ErrorCode = ErrorCode::new(
    "password_already_set",
    StatusCode::CONFLICT,
    "This account already has a password. Change it instead.",
    "Bu hesabın zaten bir şifresi var. Bunun yerine şifreyi değiştirin.",
);

/// Changing or removing the password of a passwordless account (PWD-06,
/// PWD-11, PWD-12).
pub const PASSWORD_NOT_SET: ErrorCode = ErrorCode::new(
    "password_not_set",
    StatusCode::CONFLICT,
    "This account does not have a password.",
    "Bu hesabın bir şifresi yok.",
);

/// Removing the password would leave the account without another strong
/// sign-in method (PWD-11).
pub const PASSWORD_REMOVAL_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "password_removal_not_allowed",
    StatusCode::CONFLICT,
    "The password cannot be removed until another sign-in method such as a passkey is set up.",
    "Passkey gibi başka bir giriş yöntemi eklenmeden şifre kaldırılamaz.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    PASSWORD_POLICY_VIOLATION,
    PASSWORD_BREACH_CHECK_UNAVAILABLE,
    CURRENT_PASSWORD_INCORRECT,
    PASSWORD_UNCHANGED,
    PASSWORD_ALREADY_SET,
    PASSWORD_NOT_SET,
    PASSWORD_REMOVAL_NOT_ALLOWED,
];
