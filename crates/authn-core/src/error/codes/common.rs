//! Cross-cutting error codes (owned by the architect / `authn-core`).
//!
//! Any crate may *use* these codes. Only `authn-core` edits this file; module
//! specific codes live in the module's own file next to this one.

use http::StatusCode;

use crate::error::ErrorCode;

/// Unexpected server-side failure. Details are logged with the request id,
/// never rendered.
pub const INTERNAL_ERROR: ErrorCode = ErrorCode::new(
    "internal_error",
    StatusCode::INTERNAL_SERVER_ERROR,
    "An unexpected error occurred. Please try again later.",
    "Beklenmeyen bir hata oluştu. Lütfen daha sonra tekrar deneyin.",
);

/// Syntactically malformed request (bad JSON, bad path parameter…).
pub const BAD_REQUEST: ErrorCode = ErrorCode::new(
    "bad_request",
    StatusCode::BAD_REQUEST,
    "The request is malformed.",
    "İstek hatalı biçimlendirilmiş.",
);

/// Well-formed request whose field values are invalid.
pub const VALIDATION_FAILED: ErrorCode = ErrorCode::new(
    "validation_failed",
    StatusCode::UNPROCESSABLE_ENTITY,
    "One or more fields are invalid.",
    "Bir veya daha fazla alan geçersiz.",
);

/// No (valid) credentials were presented.
pub const UNAUTHENTICATED: ErrorCode = ErrorCode::new(
    "unauthenticated",
    StatusCode::UNAUTHORIZED,
    "Authentication is required.",
    "Kimlik doğrulaması gerekiyor.",
);

/// Authenticated but not allowed.
pub const FORBIDDEN: ErrorCode = ErrorCode::new(
    "forbidden",
    StatusCode::FORBIDDEN,
    "You are not allowed to perform this action.",
    "Bu işlemi yapma yetkiniz yok.",
);

/// Unknown resource — also used for resources of *other* tenants (ORG-10).
pub const NOT_FOUND: ErrorCode = ErrorCode::new(
    "not_found",
    StatusCode::NOT_FOUND,
    "The requested resource was not found.",
    "İstenen kaynak bulunamadı.",
);

/// Unsupported HTTP method on an existing route.
pub const METHOD_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "method_not_allowed",
    StatusCode::METHOD_NOT_ALLOWED,
    "This method is not allowed for the resource.",
    "Bu kaynak için bu yöntem desteklenmiyor.",
);

/// State conflict. Never use it where it would reveal that an account exists
/// (ACC-02, PWD-07): those flows must answer exactly like the success case.
pub const CONFLICT: ErrorCode = ErrorCode::new(
    "conflict",
    StatusCode::CONFLICT,
    "The request conflicts with the current state of the resource.",
    "İstek, kaynağın mevcut durumuyla çakışıyor.",
);

/// Request body above the configured limit (PRT-11).
pub const PAYLOAD_TOO_LARGE: ErrorCode = ErrorCode::new(
    "payload_too_large",
    StatusCode::PAYLOAD_TOO_LARGE,
    "The request body is too large.",
    "İstek gövdesi çok büyük.",
);

/// Wrong or missing `Content-Type`.
pub const UNSUPPORTED_MEDIA_TYPE: ErrorCode = ErrorCode::new(
    "unsupported_media_type",
    StatusCode::UNSUPPORTED_MEDIA_TYPE,
    "The request content type is not supported.",
    "İstek içerik türü desteklenmiyor.",
);

/// Request did not finish within the configured timeout (PRT-11).
pub const REQUEST_TIMEOUT: ErrorCode = ErrorCode::new(
    "request_timeout",
    StatusCode::REQUEST_TIMEOUT,
    "The request took too long to complete.",
    "İstek zaman aşımına uğradı.",
);

/// Rate limit exceeded; rendered with `Retry-After` (PRT-04).
pub const RATE_LIMITED: ErrorCode = ErrorCode::new(
    "rate_limited",
    StatusCode::TOO_MANY_REQUESTS,
    "Too many requests. Please try again later.",
    "Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin.",
);

/// Too many wrong codes for one challenge / token (CRY-07, MFA-03).
pub const TOO_MANY_ATTEMPTS: ErrorCode = ErrorCode::new(
    "too_many_attempts",
    StatusCode::TOO_MANY_REQUESTS,
    "Too many attempts. Please request a new code or try again later.",
    "Çok fazla deneme yapıldı. Yeni bir kod isteyin veya daha sonra tekrar deneyin.",
);

/// A dependency (database, provider) is unavailable.
pub const SERVICE_UNAVAILABLE: ErrorCode = ErrorCode::new(
    "service_unavailable",
    StatusCode::SERVICE_UNAVAILABLE,
    "The service is temporarily unavailable. Please try again later.",
    "Hizmet geçici olarak kullanılamıyor. Lütfen daha sonra tekrar deneyin.",
);

/// The operation is sensitive and needs a recent re-authentication (SES-13).
pub const STEP_UP_REQUIRED: ErrorCode = ErrorCode::new(
    "step_up_required",
    StatusCode::UNAUTHORIZED,
    "Please confirm your identity again to continue.",
    "Devam etmek için kimliğinizi yeniden doğrulayın.",
);

/// A one-time link token is unknown, used, revoked or expired. The variants
/// are deliberately indistinguishable (CRY-06, ARC-06).
pub const INVALID_OR_EXPIRED_TOKEN: ErrorCode = ErrorCode::new(
    "invalid_or_expired_token",
    StatusCode::BAD_REQUEST,
    "The link is invalid or has expired.",
    "Bağlantı geçersiz veya süresi dolmuş.",
);

/// A short code (OTP) is wrong, used or expired (CRY-07).
pub const INVALID_CODE: ErrorCode = ErrorCode::new(
    "invalid_code",
    StatusCode::BAD_REQUEST,
    "The code is invalid or has expired.",
    "Kod geçersiz veya süresi dolmuş.",
);

/// Every code declared in this file.
pub const ALL: &[ErrorCode] = &[
    INTERNAL_ERROR,
    BAD_REQUEST,
    VALIDATION_FAILED,
    UNAUTHENTICATED,
    FORBIDDEN,
    NOT_FOUND,
    METHOD_NOT_ALLOWED,
    CONFLICT,
    PAYLOAD_TOO_LARGE,
    UNSUPPORTED_MEDIA_TYPE,
    REQUEST_TIMEOUT,
    RATE_LIMITED,
    TOO_MANY_ATTEMPTS,
    SERVICE_UNAVAILABLE,
    STEP_UP_REQUIRED,
    INVALID_OR_EXPIRED_TOKEN,
    INVALID_CODE,
];

/// Generic code for an HTTP status produced outside our handlers (router
/// fallbacks, tower layers). Used by the envelope middleware so that *every*
/// error response carries the standard envelope.
#[must_use]
pub fn for_status(status: StatusCode) -> ErrorCode {
    match status {
        StatusCode::UNAUTHORIZED => UNAUTHENTICATED,
        StatusCode::FORBIDDEN => FORBIDDEN,
        StatusCode::NOT_FOUND => NOT_FOUND,
        StatusCode::METHOD_NOT_ALLOWED => METHOD_NOT_ALLOWED,
        StatusCode::CONFLICT => CONFLICT,
        StatusCode::PAYLOAD_TOO_LARGE => PAYLOAD_TOO_LARGE,
        StatusCode::UNSUPPORTED_MEDIA_TYPE => UNSUPPORTED_MEDIA_TYPE,
        StatusCode::REQUEST_TIMEOUT => REQUEST_TIMEOUT,
        StatusCode::UNPROCESSABLE_ENTITY => VALIDATION_FAILED,
        StatusCode::TOO_MANY_REQUESTS => RATE_LIMITED,
        StatusCode::SERVICE_UNAVAILABLE => SERVICE_UNAVAILABLE,
        s if s.is_client_error() => BAD_REQUEST,
        _ => INTERNAL_ERROR,
    }
}
