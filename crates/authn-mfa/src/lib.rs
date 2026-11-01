//! # authn-mfa
//!
//! Second factors for `rust-authentication`: TOTP, recovery codes, e-mail
//! OTP, SMS OTP (feature `sms`), MFA policy evaluation and trusted devices.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`policy`] | MFA-08 | [`evaluate`] — pure policy function over [`MfaPolicyInput`] |
//! | [`service`] | MFA-01 … MFA-07, MFA-09, MFA-10 | [`MfaService`] — enrollment, verification, management |
//! | [`routes`] | MFA-07, MFA-10, ARC-03 | [`router`], [`MfaApi`] — `/v1/me/mfa/...` |
//! | [`recovery`] | MFA-04 | 50-bit recovery codes, keyed hashes |
//! | [`totp`] | MFA-01 | `otpauth://` URI and QR (SVG) |
//! | [`phone`] | MFA-06 | strict E.164 and the country allow-list |
//! | [`device_token`] | MFA-09 | signed trusted-device tokens |
//! | [`amr`] | SES-08 | RFC 8176 method references of factors |
//! | [`hooks`] | contracts §2 | [`MfaPolicySource`] — implemented by `authn-server` |
//! | [`export`] | ACC-10 | [`MfaDataExporter`] — the `mfa` section of the data export |
//! | [`metrics`] | OPS-04 | metric names |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`MfaService`] via `FromRef<S>`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::mfa` and `codes::common`.
//! * The login challenge itself (`auth_challenges`) belongs to
//!   authn-session, which calls [`MfaService::verify_factor`] /
//!   [`MfaService::send_code`] / [`MfaService::evaluate_for_user`].

#![forbid(unsafe_code)]

pub mod amr;
pub mod device_token;
pub mod export;
pub mod extract;
pub mod hooks;
pub mod metrics;
pub mod phone;
pub mod policy;
pub mod recovery;
pub mod routes;
pub mod service;
pub mod totp;

mod store;

pub use device_token::{DeviceTokenSigner, TrustedDeviceToken};
pub use export::MfaDataExporter;
pub use hooks::{MfaPolicySource, StaticMfaPolicySource};
pub use policy::{MfaPolicyInput, MfaRequirement, OrgMfaPolicy, evaluate};
pub use routes::{MfaApi, TRUSTED_DEVICE_COOKIE, TRUSTED_DEVICE_HEADER, router};
pub use service::{
    CodeChannel, CodeDelivery, ConfirmedFactor, FactorProof, FactorState, FactorSummary,
    GeneratedRecoveryCodes, IssuedTrustedDevice, MfaResetSummary, MfaService, MfaServiceDeps,
    MfaServiceSettings, MfaStatus, OtpChannel, PurgeReport, RecoveryCodesStatus, TotpEnrollment,
    TrustedDeviceSummary, VerifiedFactor,
};
