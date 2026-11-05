//! # authn-audit
//!
//! Tamper-evident audit log with hash chain and pseudonymised personal data,
//! the transactional outbox worker and signed webhooks (Standard Webhooks).
//!
//! Owned requirements: AUD-01 … AUD-07.
//!
//! | Module | Requirement | What |
//! |--------|-------------|------|
//! | [`sink`] | AUD-01, AUD-02, AUD-03, AUD-05 | [`PgAuditSink`] — the `AuditSink` port: sanitization, pseudonyms, hash-chained append |
//! | [`chain`], [`canonical`] | AUD-02 | Record layout, canonical JSON, `HMAC-SHA-256(K_v, prev_hash ‖ canonical_json(event))` (legacy rows: `SHA-256(…)`) |
//! | [`keys`] | AUD-02, K-77 | [`ChainKeys`] — versioned chain keys from the key ring |
//! | [`sanitize`] | AUD-03 | Structural "no secrets, no personal data" enforcement |
//! | [`verify`] | AUD-02 | Full / from-anchor chain verification |
//! | [`retention`] | AUD-05 | Retention purge through the checkpointed escape hatch |
//! | [`holds`] | AUD-04, K-62 | Events withheld from the subject's own view for a limited time |
//! | [`query`], [`api`] | AUD-04, AUD-07 | Own security events, organization audit log, webhook endpoints (HTTP) |
//! | [`policy`] | AUD-04, AUD-07, ORG-10 | [`AuditAccessPolicy`] — authorization delegated to the server |
//! | [`outbox`] | AUD-06 | [`OutboxEventPublisher`], [`OutboxWorker`], [`OutboxHandler`] registry |
//! | [`webhooks`] | AUD-07 | Endpoint management, fan-out, signed SSRF-safe delivery |
//! | [`service`] | ARC-03 | [`AuditService`] (state of [`router`]) and background-job entry points |
//!
//! Conventions (see `README.md` and `docs/architecture/contracts.md`):
//! * HTTP handlers are exposed as `pub fn router<S>() -> axum::Router<S>`
//!   requiring [`AuditService`] via `FromRef<S>`.
//! * Side effects go through the ports of `authn_core::ports`; tests use the
//!   fakes of `authn-testkit`.
//! * Errors are `authn_core::AuthError` with codes from
//!   `authn_core::error::codes::audit`.

#![forbid(unsafe_code)]

pub mod api;
pub mod canonical;
pub mod chain;
pub mod holds;
pub mod keys;
pub mod outbox;
pub mod policy;
pub mod query;
pub mod retention;
pub mod sanitize;
pub mod service;
pub mod sink;
pub mod verify;
pub mod webhooks;

pub use api::{AuditApi, router};
pub use holds::hide_from_subject_in_tx;
pub use outbox::{
    HandlerError, NewOutboxMessage, OutboxEventPublisher, OutboxHandler, OutboxHandlers,
    OutboxMessage, OutboxRepository, OutboxWorker,
};
pub use policy::{AccessDecision, AuditAccessPolicy, AuditPermission, DenyAllAuditAccess};
pub use query::{AuditEventDetail, AuditEventFilter, list_events};
pub use service::{AuditService, AuditServiceParts, MaintenanceReport};

pub use keys::ChainKeys;
pub use retention::{PurgeReport, create_checkpoint, purge_before, purge_expired};
pub use sink::{AppendedEvent, ChainKeyActivation, PgAuditSink};
pub use verify::{
    ChainAnchor, ChainBreak, ChainProblem, ChainReport, verify_chain, verify_chain_from,
};
