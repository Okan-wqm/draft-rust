//! # authn-store
//!
//! Shared persistence infrastructure:
//!
//! * [`pool`] — `PgPool` construction from [`DatabaseConfig`](authn_core::config::database::DatabaseConfig).
//! * [`migrate`] — the embedded migrations of `/migrations` and a readiness
//!   check (OPS-05, OPS-10).
//! * [`tx`] — transaction helpers (ARC-06).
//! * [`error`] — classification of database errors (unique violation →
//!   domain conflict, serialization failure → retryable…).
//! * [`users`] — the base repository for the shared `users` and
//!   `password_credentials` tables.
//! * [`one_time_tokens`] — the generic one-time token / code repository
//!   (ARC-06, CRY-06, CRY-07; owner: authn-crypto agent).
//! * [`signing_keys`] — JWT signing-key lifecycle (CRY-10; owner:
//!   authn-crypto agent).
//!
//! All queries are runtime-checked (`sqlx::query_as` + `FromRow`); the
//! compile-time `query!` macros are not used anywhere in the workspace.

pub mod error;
pub mod migrate;
pub mod one_time_tokens;
pub mod pool;
pub mod signing_keys;
pub mod tx;
pub mod users;

pub use error::StoreError;
pub use migrate::{MIGRATION_RANGES, MIGRATOR, MigrationStatus, migration_status, run_migrations};
pub use one_time_tokens::{
    CodeVerification, NewOneTimeToken, OneTimeTokenRecord, OneTimeTokenRepository, TokenKind,
    TokenPurpose, TokenSubject,
};
pub use pool::{connect, connect_lazy};
pub use signing_keys::{SigningKeyError, SigningKeyRecord, SigningKeyRepository};
pub use tx::{PgTx, begin, begin_serializable, commit, with_tx};
pub use users::{
    NewPasswordHash, NewUser, PasswordCredentialRecord, UserClaim, UserRecord, UserRepository,
};
