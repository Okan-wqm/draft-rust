//! # authn-account
//!
//! Registration, e-mail verification, account lifecycle state machine,
//! profile, e-mail change, deletion, data export (aggregating
//! `DataExporter`s) and consent records.
//!
//! Owned requirements: ACC-01 … ACC-13, DOC-07.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`service`] | ACC-01 … ACC-11, ACC-13 | [`AccountService`] — every use case |
//! | [`lifecycle`] | ACC-06 | the single status transition function |
//! | [`profile`] | ACC-03, ACC-08 | display-name confusable checks, IANA time zones |
//! | [`disposable`] | ACC-12 | disposable e-mail domain block list |
//! | [`export`] | ACC-10 | the `account` export section |
//! | [`hooks`] | ACC-09 | [`OrganizationOwnership`] — implemented by `authn-server` |
//! | [`routes`] | ARC-03, ARC-09 | [`router`], [`AccountApi`] |
//! | [`model`] | — | input / output types |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`AccountService`] via `FromRef<S>`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::account` and `codes::common`.

#![forbid(unsafe_code)]

mod background;
pub mod disposable;
pub mod export;
pub mod extract;
pub mod hooks;
pub mod lifecycle;
pub mod model;
pub mod profile;
mod repo;
pub mod routes;
pub mod service;
mod tx;

use authn_store::TokenPurpose;

pub use disposable::DisposableDomains;
pub use export::AccountDataExporter;
pub use extract::SecretJson;
pub use hooks::{NoOrganizations, OrganizationOwnership};
pub use lifecycle::{
    StatusChange, StatusTransition, TransitionError, check_transition, resting_status,
};
pub use model::{
    ConsentView, DeletionView, DenialReason, LoginAssessment, ProfileUpdate, ProfileView,
    PurgeReport, RevertOutcome, SignupInput, TermsAcceptance, TermsVersionView,
};
pub use routes::{AccountApi, router};
pub use service::{
    AccountService, AccountServiceDeps, AccountServiceSettings, VerificationProof, actions,
};

/// `one_time_tokens.purpose` values owned by this crate (contracts §5).
pub const ACCOUNT_TOKEN_PURPOSES: &[TokenPurpose] = &[
    TokenPurpose::EmailVerification,
    TokenPurpose::EmailVerificationCode,
    TokenPurpose::EmailChange,
    TokenPurpose::EmailChangeCode,
    TokenPurpose::EmailChangeRevert,
    TokenPurpose::AccountDeletionCancel,
];

/// Tokens delivered to (or proving control of) the account's e-mail
/// address, of every module. They are revoked when the address changes or a
/// change is reverted (ACC-07): a password-reset or magic link sent to the
/// previous address must not survive the change.
pub const ADDRESS_BOUND_PURPOSES: &[TokenPurpose] = &[
    TokenPurpose::EmailVerification,
    TokenPurpose::EmailVerificationCode,
    TokenPurpose::EmailChange,
    TokenPurpose::EmailChangeCode,
    TokenPurpose::AccountDeletionCancel,
    TokenPurpose::PasswordReset,
    TokenPurpose::PasswordResetCode,
    TokenPurpose::MagicLink,
    TokenPurpose::LoginCode,
    TokenPurpose::NotMe,
    TokenPurpose::MfaEmailOtp,
];
