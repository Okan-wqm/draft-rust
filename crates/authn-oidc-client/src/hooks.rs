//! Facts this crate needs from other modules (contracts §2 / §4: wave-B
//! crates never depend on each other, and some data belongs to wave-A
//! modules whose APIs do not expose it). authn-server implements these
//! traits.
//!
//! Address reservations (ACC-07) are **not** a hook (K-02): the service
//! reads them through authn-account itself
//! (`AccountService::provision_verified_user_in_tx`, under the address
//! lock), so no deployment can wire a fail-open stand-in.
//!
//! Rule for implementations (contracts §4): read **only through the given
//! connection** — the caller holds the `users` row lock
//! (`UserRepository::lock_for_update`) and a second pool connection could
//! neither see uncommitted state nor avoid deadlocks — and produce no side
//! effects.

use async_trait::async_trait;
use authn_core::domain::LoginMethod;
use authn_core::error::AuthError;
use authn_core::id::{SessionId, UserId};
use authn_store::UserRepository;
use sqlx::PgConnection;
use time::OffsetDateTime;

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

/// Whether the session that started a **link** flow is still valid
/// (K-03, SOC-06, SES-13): the browser callback carries no session cookie
/// (Apple's cross-site `form_post`), so the flow stores the session id at
/// start and the callback asks this hook — inside the link transaction,
/// after the user row is locked — before attaching the identity.
///
/// Server implementation: authn-session on the given connection — `true`
/// only when the session exists, belongs to `user`, is not revoked and has
/// neither idle- nor absolute-expired at `now` (impersonation sessions:
/// `false`; they cannot link). There is **no default implementation**:
/// a permissive one would silently reopen the window this closes.
#[async_trait]
pub trait SessionLiveness: Send + Sync {
    /// Whether `session` is an active session of `user` at `now`.
    async fn is_active(
        &self,
        conn: &mut PgConnection,
        session: SessionId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError>;
}
