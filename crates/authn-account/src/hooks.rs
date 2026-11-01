//! Extension points implemented outside this crate (contracts §2: wave-A
//! modules never depend on each other).
//!
//! | Trait | Implemented by | Used for |
//! |-------|----------------|----------|
//! | [`OrganizationOwnership`] | `authn-server` over `authn-org` | ACC-09: the last owner of an organization cannot delete the account |

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
