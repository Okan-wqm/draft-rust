//! Repositories of the tables owned by authn-mfa (contracts §5):
//! `mfa_factors`, `recovery_codes`, `mfa_user_settings`, `trusted_devices`.
//! Crate-private: other modules use [`crate::MfaService`].
//!
//! All SQL is static text with bind parameters (runtime `sqlx::query_as`).

pub(crate) mod factors;
pub(crate) mod recovery;
pub(crate) mod settings;
pub(crate) mod trusted;
