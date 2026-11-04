//! Passkey management (PKY-04): list, rename, delete.

use authn_core::domain::{LoginMethod, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{CredentialId, UserId};
use authn_core::ports::{Actor, SecurityEventKind};
use authn_store::UserRepository;
use sqlx::PgConnection;

use super::{PasskeySummary, WebauthnService, summary};
use crate::metrics;
use crate::name::normalize_name;
use crate::store::{ceremonies, credentials};

impl WebauthnService {
    /// The caller's passkeys, oldest first (PKY-04). Readable under
    /// read-only impersonation; contains no key material.
    pub async fn list_passkeys(
        &self,
        principal: &Principal,
    ) -> Result<Vec<PasskeySummary>, AuthError> {
        let user = Self::reading_user(principal)?;
        let rows = credentials::list_for_user(self.pool(), user).await?;
        Ok(rows.iter().map(summary).collect())
    }

    /// Renames one of the caller's passkeys. Unknown ids and other users'
    /// passkeys answer `not_found` alike.
    pub async fn rename_passkey(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        id: CredentialId,
        name: &str,
    ) -> Result<PasskeySummary, AuthError> {
        principal.require_writable()?;
        let user = principal.require_user()?;
        let name = normalize_name(name)?;
        let mut tx = self.begin().await?;
        let row = credentials::rename(&mut tx, id, user, &name)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        // The (user-chosen) name never goes into the audit log (AUD-03).
        let event = self
            .event(
                SecurityEventKind::PasskeyRenamed,
                ctx,
                user,
                Some(principal),
            )
            .with_resource("passkey", row.id);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(summary(&row))
    }

    /// Deletes one of the caller's passkeys (PKY-04). Requires step-up
    /// (SES-13). Refused when it would leave the account without any way to
    /// sign in (`passkey_last_login_method`) or without a second factor
    /// while MFA is mandatory (`mfa_last_factor_required`). The user row is
    /// locked for the whole decision, which serializes it with password
    /// removal and identity unlinking.
    pub async fn delete_passkey(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        id: CredentialId,
    ) -> Result<(), AuthError> {
        principal.require_writable()?;
        let user = principal.require_user()?;
        self.require_step_up(principal)?;

        let mut tx = self.begin().await?;
        let account = UserRepository::lock_for_update(&mut tx, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let all = credentials::list_for_user(&mut *tx, user).await?;
        let Some(target) = all.iter().find(|row| row.id == id) else {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        };
        let remaining: Vec<_> = all.iter().filter(|row| row.id != id).collect();

        let remaining_login_capable = remaining
            .iter()
            .any(|row| row.usage().allows_passwordless());
        if target.usage().allows_passwordless() && !remaining_login_capable {
            let others = self
                .deps()
                .account_methods
                .other_login_methods(&mut tx, user)
                .await?;
            if !others.iter().any(|m| *m != LoginMethod::Passkey) {
                return Err(AuthError::new(codes::webauthn::PASSKEY_LAST_LOGIN_METHOD));
            }
        }
        if remaining.is_empty() {
            let mfa = self.deps().account_methods.mfa_facts(&mut tx, user).await?;
            if mfa.mfa_required && mfa.other_factor_count == 0 {
                return Err(AuthError::new(codes::mfa::MFA_LAST_FACTOR_REQUIRED));
            }
        }

        if !credentials::delete(&mut tx, id, user).await? {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        }
        self.notify_factor_change(&mut tx, ctx, &account, false)
            .await?;
        let event = self
            .event(
                SecurityEventKind::PasskeyRemoved,
                ctx,
                user,
                Some(principal),
            )
            .with_resource("passkey", id)
            .with_meta("remaining", remaining.len());
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        metrics::passkey_removed();
        tracing::info!(user = %user, passkey = %id, "passkey removed");
        Ok(())
    }

    /// Removes **every** passkey of `user` in the caller's transaction
    /// (`conn`) and returns how many were removed (ADM-03, PKY-04).
    ///
    /// For administrative recovery (the admin "reset MFA" action, used
    /// together with a password reset): an attacker's passkey must not
    /// survive the reset, and a user who lost the device must not stay
    /// locked out by a passkey registered as second factor. Therefore —
    /// unlike [`WebauthnService::delete_passkey`] — no step-up and **no
    /// last-login-method rule** apply: authorization is the caller's job.
    /// The user row is locked (`FOR UPDATE`), which serializes the removal
    /// with registrations and other credential changes.
    ///
    /// Effects, all in `conn` (nothing happens unless the caller commits):
    /// one `passkey.removed` audit event per passkey with `Actor::System`
    /// and `reason = admin_reset` metadata (the real actor is in the
    /// caller's own `admin.*` event), and one `mfa_factor_removed`
    /// (`webauthn`) notification when at least one passkey was removed.
    /// Every open ceremony of the user is burned in the same transaction
    /// (also when no passkey existed): an authentication ceremony could not
    /// complete anyway (its credential is gone), but a **registration**
    /// started before the removal would otherwise re-enrol a passkey right
    /// after it (whoever still holds a bearer credential of the account,
    /// e.g. while `access_token_session_check = false`). Unknown users
    /// answer `not_found`.
    pub async fn remove_all_passkeys_in_tx(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<u32, AuthError> {
        let account = UserRepository::lock_for_update(conn, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        ceremonies::cancel_open_for_user(conn, user, self.now()).await?;
        let removed = credentials::delete_all_for_user(conn, user).await?;
        if removed.is_empty() {
            return Ok(0);
        }
        for id in &removed {
            let event = self
                .event(SecurityEventKind::PasskeyRemoved, ctx, user, None)
                .with_actor(Actor::System)
                .with_resource("passkey", *id)
                .with_meta("reason", "admin_reset")
                .with_meta("remaining", 0_u32);
            self.deps().audit.record_in_tx(&mut *conn, event).await?;
            metrics::passkey_removed();
        }
        self.notify_factor_change(conn, ctx, &account, false)
            .await?;
        tracing::info!(user = %user, count = removed.len(), "all passkeys removed (admin reset)");
        Ok(u32::try_from(removed.len()).unwrap_or(u32::MAX))
    }
}
