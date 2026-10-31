//! # authn-core
//!
//! Shared contracts of the `rust-authentication` workspace. Every other crate
//! depends on this one; it depends on no other `authn-*` crate.
//!
//! * [`id`] — UUIDv7 typed identifiers (ARC-05).
//! * [`error`] — the stable error model and the JSON error envelope (ARC-08).
//! * [`config`] — typed configuration with documented defaults and fail-fast
//!   validation, one file per module (ARC-07).
//! * [`ports`] — object-safe async traits behind which every side effect lives
//!   (ARC-02). Implementations live in the owning module crates; fakes live in
//!   `authn-testkit`.
//! * [`domain`] — shared domain primitives (e-mail address, locale, principal,
//!   account status, authentication method references, pagination).
//! * [`http`] — request context (request id, client IP behind trusted proxies,
//!   locale, device id), error-envelope localisation middleware and rejection-
//!   mapping extractors.
//! * [`secret`] / [`redact`] — helpers that keep secrets and personal data out
//!   of logs and `Debug` output.
//! * [`tls`] — installs the single rustls crypto provider (`ring`).
//!
//! The ownership rules for each file are documented in
//! `docs/architecture/contracts.md`.

#[macro_use]
mod macros;

pub mod config;
pub mod domain;
pub mod error;
pub mod http;
pub mod id;
pub mod ports;
pub mod redact;
pub mod secret;
pub mod tls;

pub use error::{AuthError, ErrorCode};

/// Convenience result alias used across the workspace.
pub type AuthResult<T> = Result<T, AuthError>;
