//! HTTP-level shared primitives.
//!
//! * [`context`] — [`RequestContext`] (request id, client IP behind trusted
//!   proxies, user agent, device id, locale), its middleware and extractor,
//!   and localisation of error envelopes.
//! * [`client_ip`] — PRT-06 client IP resolution.
//! * [`extract`] — `Json` / `Query` / `Path` extractors whose rejections are
//!   rendered as standard error envelopes.

pub mod client_ip;
pub mod context;
pub mod extract;

pub use client_ip::{ClientIpHeader, resolve_client_ip};
pub use context::{
    DEVICE_ID_COOKIE, DEVICE_ID_HEADER, REQUEST_ID_HEADER, RequestContext, RequestContextConfig,
    request_context_middleware,
};
pub use extract::{Json, Path, Query};

use crate::error::{AuthError, codes};

/// Router fallback: unknown routes answer with the standard `not_found`
/// envelope instead of an empty 404.
pub async fn not_found_fallback() -> AuthError {
    AuthError::new(codes::common::NOT_FOUND)
}
