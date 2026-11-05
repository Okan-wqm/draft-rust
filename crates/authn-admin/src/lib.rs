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
//! | [`operations`] | ADM-05, K-07 | Offline incident response for the CLI (`suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions`) |
//! | [`service`] (`AdminActionsDataExporter`) | ACC-10, K-39 | Justifications in the subject's data export, legal restriction |
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
pub mod operations;
pub mod reason;
pub mod routes;
pub mod service;
pub mod settings;

mod store;

pub use break_glass::{
    BREAK_GLASS_PASSWORD_TTL, BreakGlassAdmin, BreakGlassEnrollmentLink, create_break_glass_admin,
    create_break_glass_admin_with_passkey_link,
};
pub use guard::{AdminCaller, Denial, authorize, is_phishing_resistant_mfa};
pub use hooks::{NoSigningKeyCache, SigningKeyCache};
pub use operations::{OfflineOperator, OfflineTarget};
pub use reason::Justification;
pub use routes::{AdminApi, router};
#[cfg(feature = "passkey")]
pub use routes::{AdminEnrollmentApi, enrollment_router};
pub use service::{
    ActionOutcome, AdminActionsDataExporter, AdminAuditEvent, AdminAuditFilter, AdminService,
    AdminServiceDeps, AdminUserDetail, AdminUserSummary, ApprovalView, AuditExport,
    BulkResetOutcome, ChainVerification, CriticalOperation, EmergencyOutcome, ForcedReset,
    ImpersonationOptions, KeyRotationOutcome, PasswordState, RESTRICTION_MAX_PERIOD, UserSearch,
    UserStatusFilter, VerifiedAnchor,
};
pub use settings::AdminSettings;
