//! # authn-admin
//!
//! Platform admin API under /v1/admin: user management, impersonation, break-glass, emergency operations and audit queries.
//!
//! Owned requirements: ADM-01… ADM-08.
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring this crate's service via `FromRef<S>` — reference
//!   implementation: `authn_server::routes::example`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from this crate's file in
//!   `authn_core::error::codes`.
