//! Repositories of the tables owned by this crate (contracts §5):
//! `webauthn_user_handles`, `webauthn_credentials`, `webauthn_ceremonies`.
//!
//! Reads take any executor; writes take `&mut PgConnection` so they always
//! run in a transaction chosen by the service (ARC-06). All SQL is static
//! with bound parameters.

// Without the `passkey` feature only management and cleanup are compiled;
// the ceremony helpers stay in place for the feature build.
#![cfg_attr(not(feature = "passkey"), allow(dead_code))]

pub(crate) mod ceremonies;
pub(crate) mod credentials;
pub(crate) mod handles;

use authn_core::error::{AuthError, codes};
use authn_store::StoreError;

/// Maps a store error, turning the listed foreign-key violations (a
/// session / challenge / user that vanished concurrently) into
/// `unauthenticated` instead of an internal error.
pub(crate) fn map_binding_error(err: StoreError) -> AuthError {
    match err {
        StoreError::ForeignKeyViolation { .. } => {
            AuthError::new(codes::common::UNAUTHENTICATED).with_source(err)
        }
        other => AuthError::from(other),
    }
}
