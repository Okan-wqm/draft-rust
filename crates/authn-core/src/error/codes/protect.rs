//! Error codes owned by `authn-protect` (PRT-*, RSK-*).
//!
//! Only the `authn-protect` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! None of these codes may reveal whether an account exists: the CAPTCHA and
//! soft-lock decisions are keyed on the *submitted identifier*, so existing
//! and unknown accounts receive exactly the same codes (PRT-03, SES-01).

use http::StatusCode;

use crate::error::ErrorCode;

/// A CAPTCHA must be solved before the action is attempted (PRT-05). The
/// envelope `details` carry the challenge (`type`, `site_key` or the
/// proof-of-work puzzle) — never anything account specific.
pub const CAPTCHA_REQUIRED: ErrorCode = ErrorCode::new(
    "captcha_required",
    StatusCode::FORBIDDEN,
    "Please complete the verification challenge to continue.",
    "Devam etmek için doğrulama adımını tamamlayın.",
);

/// The CAPTCHA response was wrong, expired or already used (PRT-05).
pub const CAPTCHA_FAILED: ErrorCode = ErrorCode::new(
    "captcha_failed",
    StatusCode::FORBIDDEN,
    "The verification challenge failed. Please try again.",
    "Doğrulama adımı başarısız oldu. Lütfen tekrar deneyin.",
);

/// Password sign-in from an unrecognised device is temporarily blocked after
/// too many failures (soft lock, PRT-03). Rendered with `Retry-After`.
/// Passkeys, trusted devices and password reset keep working.
pub const LOGIN_TEMPORARILY_BLOCKED: ErrorCode = ErrorCode::new(
    "login_temporarily_blocked",
    StatusCode::TOO_MANY_REQUESTS,
    "Too many failed sign-in attempts from this device. Try again later, sign in with a passkey or a trusted device, or reset your password.",
    "Bu cihazdan çok fazla başarısız giriş denemesi yapıldı. Daha sonra tekrar deneyin, passkey veya güvenilir bir cihazla giriş yapın ya da şifrenizi sıfırlayın.",
);

/// A high-risk sign-in was blocked (RSK-03). Only returned *after* the
/// credentials were verified (SES-01), so it reveals nothing to an attacker
/// who does not know the password.
pub const SUSPICIOUS_LOGIN_BLOCKED: ErrorCode = ErrorCode::new(
    "suspicious_login_blocked",
    StatusCode::FORBIDDEN,
    "This sign-in looked suspicious and was blocked. We have notified the account owner.",
    "Bu giriş şüpheli görüldüğü için engellendi. Hesap sahibine bildirim gönderildi.",
);

/// The `Host` / `:authority` of the request is not one of the configured
/// hosts (PRT-09).
pub const HOST_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "host_not_allowed",
    StatusCode::MISDIRECTED_REQUEST,
    "This host is not served here.",
    "Bu ana makine burada sunulmuyor.",
);

/// A CORS preflight from an origin outside the allow-list (PRT-08).
pub const CORS_ORIGIN_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "cors_origin_not_allowed",
    StatusCode::FORBIDDEN,
    "Cross-origin requests from this origin are not allowed.",
    "Bu kaynaktan gelen çapraz kaynak isteklerine izin verilmiyor.",
);

/// A `return_to` / `redirect_uri` value is not on the allow-list and is not
/// a safe relative path (PRT-10).
pub const INVALID_REDIRECT: ErrorCode = ErrorCode::new(
    "invalid_redirect",
    StatusCode::BAD_REQUEST,
    "The redirect target is not allowed.",
    "Yönlendirme adresine izin verilmiyor.",
);

/// A user-supplied outbound URL (webhook…) is not allowed: not `https`,
/// carries credentials, or resolves to a private / loopback / link-local /
/// metadata address (PRT-12).
pub const OUTBOUND_DESTINATION_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "outbound_destination_not_allowed",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The destination URL is not allowed. Use a public https URL.",
    "Hedef adrese izin verilmiyor. Herkese açık bir https adresi kullanın.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    CAPTCHA_REQUIRED,
    CAPTCHA_FAILED,
    LOGIN_TEMPORARILY_BLOCKED,
    SUSPICIOUS_LOGIN_BLOCKED,
    HOST_NOT_ALLOWED,
    CORS_ORIGIN_NOT_ALLOWED,
    INVALID_REDIRECT,
    OUTBOUND_DESTINATION_NOT_ALLOWED,
];
