//! # authn-protect
//!
//! Abuse protection and web security: rate limiting (memory/PostgreSQL/Redis), CAPTCHA (Turnstile, hCaptcha, proof-of-work), soft lock, risk evaluation, security headers, CORS, host and redirect validation, SSRF-safe outbound HTTP.
//!
//! Owned requirements: PRT-01… PRT-05, PRT-07… PRT-10, PRT-12, RSK-01… RSK-04, DOC-03.
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring this crate's service via `FromRef<S>` — reference
//!   implementation: `authn_server::routes::example`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from this crate's file in
//!   `authn_core::error::codes`.
