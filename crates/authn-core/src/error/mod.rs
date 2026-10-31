//! Error model (ARC-08).
//!
//! * [`ErrorCode`] — a constant registry entry: stable snake_case `code`, HTTP
//!   status and Turkish/English messages. Codes are grouped per module under
//!   [`codes`]; each module owns exactly one file there so that parallel work
//!   never touches a shared file.
//! * [`AuthError`] — the error type returned by every handler and service. It
//!   renders the envelope
//!   `{"error":{"code":"…","message":"…","request_id":"…"}}`.
//!   Internal details (`source`, `context`) are logged, never rendered.
//!
//! The message language is chosen by the request-context middleware
//! ([`crate::http::context`]): a [`crate::domain::Locale`] response extension
//! set by the handler (user preference) wins over `Accept-Language`, which
//! wins over the configured default.

mod auth_error;
mod code;
pub mod codes;

pub(crate) use auth_error::render_envelope;
pub use auth_error::{AuthError, ErrorBody, ErrorEnvelope, RenderedError};
pub use code::ErrorCode;
