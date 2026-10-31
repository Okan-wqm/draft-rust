//! Error codes owned by `authn-session` (SES-*).
//!
//! Only the `authn-session` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.

use http::StatusCode;

use crate::error::ErrorCode;

/// The single, uniform login failure (SES-01): unknown user, wrong password,
/// wrong passwordless code… all render exactly this code and status.
pub const INVALID_CREDENTIALS: ErrorCode = ErrorCode::new(
    "invalid_credentials",
    StatusCode::UNAUTHORIZED,
    "The credentials are incorrect.",
    "Giriş bilgileri hatalı.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[INVALID_CREDENTIALS];
