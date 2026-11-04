//! Extension points implemented outside this crate (contracts §2: wave-A
//! modules never depend on each other).
//!
//! | Trait | Implemented by | Used for |
//! |-------|----------------|----------|
//! | [`OrganizationOwnership`] | `authn-server` over `authn-org` | ACC-09: the last owner of an organization cannot delete the account |
//! | [`AccountErasureHook`] | other modules (e.g. authn-oidc-client's Apple token revocation), registered by `authn-server` with [`crate::AccountService::register_erasure_hook`] | ACC-09: work that must happen in the erasure transaction before the cascade deletes the module's rows |

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::{OrgId, UserId};
use sqlx::PgConnection;

/// Answers "in which organizations is this user the only owner?" (ACC-09,
/// ORG-02).
///
/// The server implements it with `authn-org`. It is called inside the
/// account transaction that holds the user's row lock, on the given
/// connection, both when the deletion is requested and again when it is
/// carried out (another owner may have left during the grace period).
#[async_trait]
pub trait OrganizationOwnership: Send + Sync {
    /// Organizations in which `user` is the only active owner.
    async fn sole_owner_organizations(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<OrgId>, AuthError>;
}

/// [`OrganizationOwnership`] for deployments (and tests) without
/// organizations: nobody owns anything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOrganizations;

#[async_trait]
impl OrganizationOwnership for NoOrganizations {
    async fn sole_owner_organizations(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<Vec<OrgId>, AuthError> {
        Ok(Vec::new())
    }
}

/// Work another module must do **inside the erasure transaction**, right
/// before the `users` row (and with it, by `ON DELETE CASCADE`, the
/// module's own rows) is deleted (ACC-09). Example: authn-oidc-client
/// queues the revocation of a stored Sign in with Apple refresh token
/// (Apple requires token revocation on in-app account deletion, K-35).
///
/// Rules: use **only the given connection** (the caller holds the user row
/// lock; a second pool connection could neither see the transaction's
/// state nor avoid deadlocks), do no network I/O (queue it and do it from
/// a background job), and treat soft failures (e.g. a token that cannot
/// be decrypted) yourself — return an error only when the transaction is
/// unusable (database errors), because an error rolls the erasure back
/// (it is retried on the next run of the purge job).
#[async_trait]
pub trait AccountErasureHook: Send + Sync {
    /// Runs before `user` is erased. Audit events written here are
    /// pseudonymised with the user's other events.
    async fn before_erasure_in_tx(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<(), AuthError>;
}
