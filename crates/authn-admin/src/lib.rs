//! # authn-admin
//!
//! Platform admin API under `/v1/admin`: user management, impersonation,
//! break-glass accounts, emergency operations and audit queries.
//!
//! | Module | Requirements | What |
//! |--------|--------------|------|
//! | [`guard`] | ADM-01 | [`AdminCaller`] extractor: platform admin (re-read from the database), passkey MFA session, step-up ≤ 10 min, IP allow-list, never under impersonation |
//! | [`service`] | ADM-02 … ADM-04, ADM-06 … ADM-08 | [`AdminService`]: search/details, per-user actions, impersonation, emergency operations, audit query/export/verification |
//! | [`routes`] | ADM-01 … ADM-07 | [`router`], [`AdminApi`] |
//! | [`break_glass`] | ADM-05 | [`create_break_glass_admin`] for the CLI `create-admin` |
//! | [`reason`] | ADM-08 | [`Justification`]: mandatory, bounded, printable |
//! | [`hooks`] | ADM-06 | [`SigningKeyCache`]: implemented by authn-server with authn-session |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`AdminService`] via `FromRef<S>`.
//! * authn-admin does not depend on authn-session: sessions are revoked via
//!   the `SessionRevoker` port and impersonation sessions are issued via the
//!   `SessionIssuer` port.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::admin` and `codes::common`.

#![forbid(unsafe_code)]

pub mod break_glass;
pub mod guard;
pub mod hooks;
pub mod metrics;
pub mod reason;
pub mod routes;
pub mod service;
pub mod settings;

mod store;

pub use break_glass::{BreakGlassAdmin, create_break_glass_admin};
pub use guard::{AdminCaller, Denial, authorize, is_phishing_resistant_mfa};
pub use hooks::{NoSigningKeyCache, SigningKeyCache};
pub use reason::Justification;
pub use routes::{AdminApi, router};
pub use service::{
    ActionOutcome, AdminAuditEvent, AdminAuditFilter, AdminService, AdminServiceDeps,
    AdminUserDetail, AdminUserSummary, AuditExport, BulkResetOutcome, ChainVerification,
    EmergencyOutcome, ForcedReset, ImpersonationOptions, KeyRotationOutcome, PasswordState,
    UserSearch, UserStatusFilter, VerifiedAnchor,
};
pub use settings::AdminSettings;
