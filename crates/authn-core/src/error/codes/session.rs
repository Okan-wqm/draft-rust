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

/// A state-changing cookie request failed the CSRF checks (SES-04): wrong
/// or missing `Origin` / `Sec-Fetch-Site`, or a missing / wrong
/// `X-CSRF-Token`. The variants are deliberately indistinguishable.
pub const CSRF_FAILED: ErrorCode = ErrorCode::new(
    "csrf_failed",
    StatusCode::FORBIDDEN,
    "The request could not be verified. Reload the page and try again.",
    "İstek doğrulanamadı. Sayfayı yenileyip tekrar deneyin.",
);

/// A refresh token is unknown, expired, revoked or was already used
/// (SES-05). Uniform for every cause, reuse included.
pub const INVALID_REFRESH_TOKEN: ErrorCode = ErrorCode::new(
    "invalid_refresh_token",
    StatusCode::UNAUTHORIZED,
    "The session has ended. Please sign in again.",
    "Oturum sona erdi. Lütfen yeniden giriş yapın.",
);

/// Step-up re-authentication failed (SES-13): wrong password, wrong code or
/// failed passkey assertion.
pub const REAUTHENTICATION_FAILED: ErrorCode = ErrorCode::new(
    "reauthentication_failed",
    StatusCode::UNAUTHORIZED,
    "Your identity could not be confirmed.",
    "Kimliğiniz doğrulanamadı.",
);

/// The step-up method is not allowed for this session (organization policy,
/// impersonation, factor not enrolled).
pub const STEP_UP_METHOD_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "step_up_method_not_allowed",
    StatusCode::FORBIDDEN,
    "This verification method cannot be used here.",
    "Bu doğrulama yöntemi burada kullanılamaz.",
);

/// A pending login challenge (SES-02, SES-22) is unknown, expired, used,
/// exhausted or bound to another client. Uniform for every cause.
pub const CHALLENGE_INVALID: ErrorCode = ErrorCode::new(
    "challenge_invalid",
    StatusCode::UNAUTHORIZED,
    "The sign-in request has expired. Please start again.",
    "Giriş isteğinin süresi doldu. Lütfen baştan başlayın.",
);

/// The organization does not allow the primary login method of the
/// session (SES-17, ORG-07): sign in again with an allowed method.
pub const LOGIN_METHOD_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "login_method_not_allowed",
    StatusCode::FORBIDDEN,
    "This organization does not allow the sign-in method you used. Sign in again with an allowed method.",
    "Bu organizasyon kullandığınız giriş yöntemine izin vermiyor. İzin verilen bir yöntemle yeniden giriş yapın.",
);

/// The impersonation target is not eligible (ADM-04: admins, break-glass
/// accounts, inactive accounts, oneself).
pub const IMPERSONATION_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "impersonation_not_allowed",
    StatusCode::FORBIDDEN,
    "This account cannot be impersonated.",
    "Bu hesabın yerine geçilemez.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    INVALID_CREDENTIALS,
    CSRF_FAILED,
    INVALID_REFRESH_TOKEN,
    REAUTHENTICATION_FAILED,
    STEP_UP_METHOD_NOT_ALLOWED,
    CHALLENGE_INVALID,
    LOGIN_METHOD_NOT_ALLOWED,
    IMPERSONATION_NOT_ALLOWED,
];
