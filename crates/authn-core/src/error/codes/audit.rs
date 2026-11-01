//! Error codes owned by `authn-audit` (AUD-*).
//!
//! Only the `authn-audit` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.

use http::StatusCode;

use crate::error::ErrorCode;

/// The webhook URL is not acceptable (AUD-07, PRT-12): not `https`, carries
/// credentials, points at a local / private destination or is malformed.
pub const WEBHOOK_URL_INVALID: ErrorCode = ErrorCode::new(
    "webhook_url_invalid",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The webhook URL must be a public https:// URL without credentials.",
    "Webhook adresi, kimlik bilgisi içermeyen ve herkese açık bir https:// adresi olmalıdır.",
);

/// The organization already has the configured maximum number of webhook
/// endpoints.
pub const WEBHOOK_ENDPOINT_LIMIT_REACHED: ErrorCode = ErrorCode::new(
    "webhook_endpoint_limit_reached",
    StatusCode::CONFLICT,
    "The maximum number of webhook endpoints for this organization has been reached.",
    "Bu organizasyon için izin verilen en fazla webhook uç noktası sayısına ulaşıldı.",
);

/// A manual redelivery was requested while the delivery is still scheduled.
pub const WEBHOOK_DELIVERY_IN_PROGRESS: ErrorCode = ErrorCode::new(
    "webhook_delivery_in_progress",
    StatusCode::CONFLICT,
    "This delivery is still scheduled; wait until it has finished.",
    "Bu teslimat hâlâ planlanmış durumda; tamamlanmasını bekleyin.",
);

/// The webhook endpoint is disabled; enable it before redelivering.
pub const WEBHOOK_ENDPOINT_DISABLED: ErrorCode = ErrorCode::new(
    "webhook_endpoint_disabled",
    StatusCode::CONFLICT,
    "The webhook endpoint is disabled. Enable it first.",
    "Webhook uç noktası devre dışı. Önce etkinleştirin.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    WEBHOOK_URL_INVALID,
    WEBHOOK_ENDPOINT_LIMIT_REACHED,
    WEBHOOK_DELIVERY_IN_PROGRESS,
    WEBHOOK_ENDPOINT_DISABLED,
];
