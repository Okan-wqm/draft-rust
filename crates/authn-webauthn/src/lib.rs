//! # authn-webauthn
//!
//! Passkeys / WebAuthn for `rust-authentication`: registration and
//! authentication ceremonies (verified exclusively by `webauthn-rs`, cargo
//! feature `passkey`), credential management and the mobile association
//! files.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`service`] | PKY-01 … PKY-05, PKY-08 | [`WebauthnService`] — ceremonies, management, the authentication API used by authn-session |
//! | [`routes`] | PKY-01, PKY-04, ARC-03 | [`router`], [`WebauthnApi`] — `/v1/me/passkeys/...` |
//! | [`well_known`] | PKY-07 | [`WellKnownDocuments`], [`well_known_router`] — `/.well-known/apple-app-site-association`, `/.well-known/assetlinks.json`, `/.well-known/webauthn` |
//! | `rp` (feature `passkey`) | PKY-06 | the relying-party (`webauthn-rs`) instance built from `[webauthn]` |
//! | [`policy`] | PKY-08 | [`PasskeyPolicy`] — organization AAGUID allow-list (input struct) |
//! | [`hooks`] | PKY-04, contracts §2 | [`AccountMethodsSource`], [`PasskeyPolicySource`] — implemented by authn-server |
//! | [`name`] | PKY-04 | passkey display-name validation |
//! | [`export`] | ACC-10 | [`PasskeyDataExporter`] — the `passkeys` section of the data export |
//! | [`metrics`] | OPS-04 | metric names |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`WebauthnService`] via `FromRef<S>`; the well-known
//!   documents have their own router requiring [`WellKnownDocuments`].
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::webauthn` and `codes::common`.
//! * WebAuthn verification is never hand-rolled: every signature, origin,
//!   challenge, RP id, user-verification, counter and attestation check is
//!   done by `webauthn-rs`. This crate adds server-side ceremony state,
//!   binding, single use, persistence, policy and auditing around it.

#![forbid(unsafe_code)]

pub mod export;
pub mod hooks;
pub mod metrics;
pub mod name;
pub mod policy;
pub mod routes;
#[cfg(feature = "passkey")]
mod rp;
pub mod service;
pub mod well_known;

mod store;

pub use export::PasskeyDataExporter;
pub use hooks::{
    AccountMethodsSource, MfaFacts, PasskeyPolicySource, PasswordOnlyMethods,
    UnrestrictedPolicySource,
};
pub use policy::PasskeyPolicy;
pub use routes::{WebauthnApi, router};
#[cfg(feature = "passkey")]
pub use service::{
    AuthenticatedPasskey, AuthenticationFinish, AuthenticationStart, AuthenticationTarget,
    ChallengeRegistrationStart, RegistrationIntent, RegistrationOptionsRequest, RegistrationStart,
    RegistrationVerifyRequest, VerifiedEnrollment,
};
pub use service::{
    AuthenticationPurpose, PasskeyRemovalReason, PasskeySummary, PasskeyUsage, WebauthnService,
    WebauthnServiceDeps, WebauthnServiceSettings,
};
pub use well_known::{WellKnownDocuments, well_known_router};
