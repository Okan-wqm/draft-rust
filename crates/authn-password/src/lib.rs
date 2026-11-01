//! # authn-password
//!
//! Password management for `rust-authentication`: policy (NIST SP 800-63B
//! rev. 4), NFKC normalization, HIBP k-anonymity breach check, zxcvbn
//! strength estimation with TR/EN feedback, password change / add / remove,
//! the enumeration-safe reset flow and login-time verification with
//! transparent hash upgrades.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`policy`] | PWD-01, PWD-02, PWD-04 | [`PasswordPolicy`] — the [`PasswordValidator`](authn_core::ports::PasswordValidator) port |
//! | [`breach`] | PWD-03 | [`HibpBreachChecker`] — the [`BreachedPasswordChecker`](authn_core::ports::BreachedPasswordChecker) port (HIBP range API + offline list) |
//! | [`service`] | PWD-05 … PWD-12, CRY-03/04/05 integration | [`PasswordService`] |
//! | [`routes`] | ARC-03, ARC-09 | [`router`], [`PasswordApi`] |
//! | [`hooks`] | contracts §2 | [`LoginMethodInventory`], [`ProfileLookup`] — implemented by `authn-server` |
//! | [`extract`] | PWD-05 | [`SecretJson`] — body extractor that never echoes content |
//! | [`metrics`] | OPS-04 | metric names |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`PasswordService`] via `FromRef<S>`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::password` and `codes::common`.

#![forbid(unsafe_code)]

pub mod breach;
pub mod extract;
pub mod hooks;
pub mod metrics;
pub mod policy;
pub mod routes;
pub mod service;

pub use breach::{HibpBreachChecker, OfflineBreachList};
pub use extract::SecretJson;
pub use hooks::{
    LoginMethodInventory, NoOtherLoginMethods, NoProfiles, ProfileHints, ProfileLookup,
    is_strong_login_method,
};
pub use policy::{PasswordPolicy, PolicySettings};
pub use routes::{PasswordApi, router};
pub use service::{
    LoginPasswordOutcome, PasswordService, PasswordServiceDeps, PasswordServiceSettings, ResetProof,
};
