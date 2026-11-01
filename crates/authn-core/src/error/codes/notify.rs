//! Error codes owned by `authn-notify` (NTF-*).
//!
//! Only the `authn-notify` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! Delivery errors are mostly seen by the outbox worker, not by clients:
//! transports report *temporary* failures with the common
//! `service_unavailable` code (retried with backoff) and *permanent*
//! rejections with [`DELIVERY_REJECTED`] (dead-lettered at once). A client
//! only sees them when a module calls an `SmsSender` synchronously (MFA-06).

use http::StatusCode;

use crate::error::ErrorCode;

/// The provider permanently refused the message (SMTP 5xx, invalid
/// recipient, SMS provider 4xx). Retrying cannot succeed.
pub const DELIVERY_REJECTED: ErrorCode = ErrorCode::new(
    "delivery_rejected",
    StatusCode::BAD_GATEWAY,
    "The message could not be delivered. Please check the address or number and try again.",
    "İleti teslim edilemedi. Lütfen adresi veya numarayı kontrol edip tekrar deneyin.",
);

/// No SMS provider is configured (ARC-11 `sms` behaves as disabled). Modules
/// must check `SmsSender::is_configured` and not offer SMS at all.
pub const SMS_UNAVAILABLE: ErrorCode = ErrorCode::new(
    "sms_unavailable",
    StatusCode::SERVICE_UNAVAILABLE,
    "SMS delivery is not available.",
    "SMS gönderimi kullanılamıyor.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[DELIVERY_REJECTED, SMS_UNAVAILABLE];
