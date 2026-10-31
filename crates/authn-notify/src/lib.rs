//! # authn-notify
//!
//! Notification rendering (TR/EN, HTML + text, minijinja), e-mail transports (SMTP with mandatory TLS, log, test) and SMS senders.
//!
//! Owned requirements: NTF-01… NTF-04.
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring this crate's service via `FromRef<S>` — reference
//!   implementation: `authn_server::routes::example`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from this crate's file in
//!   `authn_core::error::codes`.
