//! # authn-protect
//!
//! Abuse protection and web security for `rust-authentication`.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`rate_limit`] | PRT-01, PRT-02, PRT-04 | GCRA `RateLimiter` backends (memory, PostgreSQL, Redis) and the per-IP HTTP middleware |
//! | [`keys`] | PRT-02, RSK-02 | Keyed hashing of rate-limit keys and device ids (no personal data at rest) |
//! | [`captcha`] | PRT-05 | Turnstile, hCaptcha, proof-of-work verifiers and the policy gate [`CaptchaService`] |
//! | [`login`] | PRT-02, PRT-03, PRT-04 | Per-IP / per-identifier login limits, CAPTCHA escalation and the soft lock ([`LoginProtection`]) |
//! | [`risk`] | RSK-01 … RSK-05 | [`DefaultRiskEvaluator`], RSK-03 policy mapping, new-device and blocked-login alerts ([`RiskAlerts`]), MaxMind DB GeoIP ([`MmdbGeoIp`]) |
//! | [`routes`] | PRT-05 | `GET /v1/captcha/challenge` ([`router`], [`ProtectApi`]) |
//! | [`web`] | PRT-07, PRT-08, PRT-09, PRT-10 | Security headers, strict CORS, `Host` validation middleware and the `return_to` validator |
//! | [`outbound`] | PRT-12 | SSRF-safe `HttpClient` (vetted, pinned DNS; https only; no redirects; timeouts; size cap) |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring this crate's service via `FromRef<S>`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::protect`.

#![forbid(unsafe_code)]

mod audit;
pub mod captcha;
pub mod keys;
pub mod login;
pub mod outbound;
pub mod rate_limit;
pub mod risk;
pub mod routes;
pub mod web;

pub use captcha::CaptchaService;
pub use keys::KeyHasher;
pub use login::{LoginAttempt, LoginProtection};
pub use risk::{DefaultRiskEvaluator, MmdbGeoIp, NotMeTokenIssuer, RiskAlerts, RiskResponse};
pub use routes::{ProtectApi, router};
pub use web::{CorsPolicy, HostValidation, RedirectTarget, RedirectValidator, SecurityHeaders};
