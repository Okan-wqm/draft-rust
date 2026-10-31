//! # authn-session
//!
//! The login pipeline, web sessions with CSRF protection, native access/refresh tokens with rotation and reuse detection, JWKS, introspection, step-up, organization switching and passwordless login.
//!
//! Owned requirements: SES-01… SES-22, DOC-05.
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring this crate's service via `FromRef<S>` — reference
//!   implementation: `authn_server::routes::example`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from this crate's file in
//!   `authn_core::error::codes`.
