//! # authn-password
//!
//! Password policy (NIST 800-63B), NFKC normalization, HIBP k-anonymity breach check, zxcvbn strength estimation, password change/add/remove and the reset flow.
//!
//! Owned requirements: PWD-01… PWD-12.
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring this crate's service via `FromRef<S>` — reference
//!   implementation: `authn_server::routes::example`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from this crate's file in
//!   `authn_core::error::codes`.
