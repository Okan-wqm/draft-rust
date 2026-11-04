//! Facts this crate needs from other modules (contracts §2 / §4: wave-B
//! crates never depend on each other, and some data belongs to wave-A
//! modules whose APIs do not expose it yet). authn-server implements these
//! traits; the defaults are safe for tests and minimal deployments.
//!
//! Rule for implementations (contracts §4): read **only through the given
//! connection** — the caller holds the `users` row lock
//! (`UserRepository::lock_for_update`) and a second pool connection could
//! neither see uncommitted state nor avoid deadlocks — and produce no side
//! effects.

use async_trait::async_trait;
use authn_core::domain::{EmailAddress, LoginMethod};
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_store::UserRepository;
use sqlx::PgConnection;

/// Login methods of an account **besides linked social identities**
/// (SOC-06: the last way to sign in cannot be unlinked).
///
/// Called inside the unlink transaction after the user row was locked, so
/// "unlink the last identity", "remove the password" (authn-password,
/// PWD-11) and "delete the last passkey" (authn-webauthn, PKY-04) serialize
/// on the same row and can never all succeed concurrently.
///
/// Server implementation: `Password` if `UserRepository::find_password(conn,
/// user)` is set; `Passkey` if `WebauthnService::passkey_count_in(conn, user,
/// true) > 0`; `MagicLink` / `EmailCode` only if the deployment allows them
/// as a primary login for this user.
#[async_trait]
pub trait LoginMethodInventory: Send + Sync {
    /// Other login methods of `user`; empty = linked identities are the only
    /// way in. Must not report [`LoginMethod::Social`] (identities are
    /// counted by this crate).
    async fn other_login_methods(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError>;
}

/// [`LoginMethodInventory`] that only knows passwords (read through
/// authn-store). Safe default: passkeys and passwordless logins are not
/// seen, so it can only *refuse* an unlink, never strand an account.
#[derive(Debug, Clone, Copy, Default)]
pub struct PasswordOnlyInventory;

#[async_trait]
impl LoginMethodInventory for PasswordOnlyInventory {
    async fn other_login_methods(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError> {
        Ok(UserRepository::find_password(&mut *conn, user)
            .await?
            .map(|_| vec![LoginMethod::Password])
            .unwrap_or_default())
    }
}

/// Addresses that must not get a new account (SOC-05 with ACC-07): after an
/// e-mail change the old address stays reserved for its previous owner for
/// the revert period (`email_reservations`, owned by authn-account).
///
/// Server implementation: authn-account's reservation lookup on the given
/// connection (requested in `contract-change-requests.md`, authn-oidc-client
/// section — authn-account does not expose it yet).
#[async_trait]
pub trait AddressReservations: Send + Sync {
    /// Whether `email` is reserved for an existing account.
    async fn is_reserved(
        &self,
        conn: &mut PgConnection,
        email: &EmailAddress,
    ) -> Result<bool, AuthError>;

    /// Whether reservations are actually looked up. `false` only for
    /// [`NoReservations`]; the service logs a start-up warning then.
    fn enforced(&self) -> bool {
        true
    }
}

/// [`AddressReservations`] without reservations (tests, deployments without
/// e-mail change). **Production must use the authn-account adapter**: with
/// this one, a social sign-up during an e-mail change's revert period can
/// take the old address and make the revert impossible (ACC-07). The
/// service warns at start-up when it is wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReservations;

#[async_trait]
impl AddressReservations for NoReservations {
    async fn is_reserved(
        &self,
        _conn: &mut PgConnection,
        _email: &EmailAddress,
    ) -> Result<bool, AuthError> {
        Ok(false)
    }

    fn enforced(&self) -> bool {
        false
    }
}
