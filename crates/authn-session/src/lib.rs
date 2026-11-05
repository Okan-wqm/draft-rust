//! # authn-session
//!
//! The session core of `rust-authentication`: web sessions with CSRF
//! protection, native access/refresh tokens with rotation and reuse
//! detection, JWKS, introspection, step-up, organization switching,
//! impersonation sessions and the authentication middleware. The login
//! flows (`src/login/`, SES-01/02/18–22) build on the API documented here
//! and in `README.md`.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`service`] | SES-03 … SES-17 | [`SessionService`] — establish, authenticate, refresh, revoke, step-up, org switch, introspection, challenges, impersonation |
//! | [`middleware`] | SES-03, SES-04, SES-05, ADM-04 | [`authenticate`] — cookie / bearer / API key → `Principal`, CSRF, read-only impersonation |
//! | [`routes`] | SES-04 … SES-17 | [`router`], [`SessionApi`] |
//! | [`csrf`] | SES-04 | origin check, synchronizer and login-CSRF tokens |
//! | [`cookies`] | SES-03, SES-07 | `__Host-` cookies |
//! | [`response`] | SES-03, SES-05 | rendering credentials and challenges |
//! | [`claims`] | SES-08 | access-token claims (RFC 9068, RFC 8693 `act`) |
//! | [`model`] | — | session records, credentials, the current session |
//! | [`settings`] | ARC-07 | [`SessionSettings`] from `[session]` |
//! | [`export`] | ACC-10 | [`SessionDataExporter`] |
//! | [`metrics`] | OPS-04 | metric names |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`SessionService`] via `FromRef<S>`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::session` and `codes::common`.

#![forbid(unsafe_code)]

pub mod claims;
pub mod cookies;
pub mod csrf;
pub mod export;
mod keys;
pub mod login;
pub mod metrics;
pub mod middleware;
pub mod model;
pub mod response;
pub mod routes;
pub mod service;
pub mod settings;
mod store;

pub use claims::AccessTokenClaims;
pub use csrf::{CSRF_HEADER, CsrfProtector, LoginCsrfVerified};
pub use export::SessionDataExporter;
pub use keys::SIGNING_KEYS_CHANNEL;
pub use login::routes::LoginApi;
pub use middleware::{IMPERSONATION_SESSION_HEADER, authenticate};
pub use model::{CurrentSession, DeviceInfo, EstablishedSession, IssuedCredentials, SessionRecord};
pub use routes::{SessionApi, router};
pub use service::{
    Authenticated, ChallengeKind, ChallengeProgress, ChallengeState, ClientChannel,
    EstablishSession, IntrospectionResponse, IssuedChallenge, MeResponse, NewChallenge, OrgSwitch,
    PgSessionRevoker, PurgeReport, RefreshedTokens, SessionService, SessionServiceDeps,
    SessionSummary, StepUpProof, VerifiedAccessToken, VerifiedOrg, is_session_active_in,
};
pub use settings::{SessionSettings, SessionShape};
