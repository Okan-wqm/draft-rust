//! Self-service password management (PWD-06, PWD-10, PWD-11) and the
//! `must_change_password` flag (PWD-12).

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{SessionId, UserId};
use authn_core::ports::{Actor, RateLimitKey, RevocationReason, RevokeOptions, SecurityEventKind};
use authn_core::secret::SecretString;
use authn_crypto::password::PasswordHashRecord;
use authn_store::{
    NewPasswordHash, OneTimeTokenRepository, PasswordCredentialRecord, TokenPurpose, UserRecord,
    UserRepository, begin, commit,
};
use sqlx::PgConnection;
use time::OffsetDateTime;

use super::{PasswordService, actions, stored_hash};
use crate::hooks::is_strong_login_method;
use crate::metrics;

const RESET_PURPOSES: &[TokenPurpose] =
    &[TokenPurpose::PasswordReset, TokenPurpose::PasswordResetCode];

impl PasswordService {
    /// Changes the caller's password (PWD-06).
    ///
    /// Proof of identity: the current password (`current = Some`, rate
    /// limited per user) **or** a recent authentication within
    /// `session.step_up_max_age` (`current = None`). The new password must
    /// satisfy the policy and differ from the current one. In one
    /// transaction the password is replaced, pending reset tokens are
    /// revoked, every *other* session is revoked (the current one stays),
    /// the user is notified and the change audited.
    ///
    /// Impersonated principals and API keys are refused (`forbidden`).
    pub async fn change_password(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        current: Option<&SecretString>,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        let user_id = Self::self_service_user(principal)?;
        let user = self.load_user(user_id).await?;
        let credential = UserRepository::find_password(self.pool(), user_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::password::PASSWORD_NOT_SET))?;
        match current {
            Some(current) => {
                self.limit(
                    &RateLimitKey::user(actions::CHANGE, user_id),
                    self.config().change_attempts_per_user,
                )
                .await?;
                let outcome = self
                    .deps()
                    .hasher
                    .verify(current, Some(&stored_hash(&credential)))
                    .await?;
                if !outcome.is_valid() {
                    let event = self
                        .event(SecurityEventKind::PasswordChanged, ctx)
                        .with_actor(Actor::User(user_id))
                        .with_subject(user_id)
                        .failed("wrong_current_password");
                    if let Err(err) = self.deps().audit.record(event).await {
                        tracing::warn!(error = %err, "audit of failed password change failed");
                    }
                    return Err(AuthError::new(codes::password::CURRENT_PASSWORD_INCORRECT));
                }
            }
            None => principal
                .require_recent_authentication(self.now(), self.inner.settings.step_up_max_age)?,
        }
        let keep = principal.session_id();
        self.replace_password(ctx, &user, &credential, keep, new_password, false)
            .await
    }

    /// Sets a new password for a user whose `must_change_password` flag is
    /// set (PWD-12), as the SES-22 required action. authn-session calls this
    /// only after the user proved the *old* password in the login flow;
    /// `keep_session` (if any) survives, every other session is revoked.
    /// Fails with `forbidden` when the flag is not set, so it can never
    /// bypass the proof required by [`Self::change_password`].
    pub async fn apply_required_password_change(
        &self,
        ctx: &RequestContext,
        user_id: UserId,
        keep_session: Option<SessionId>,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        let user = self.load_user(user_id).await?;
        let credential = UserRepository::find_password(self.pool(), user_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::password::PASSWORD_NOT_SET))?;
        if !credential.must_change {
            return Err(AuthError::new(codes::common::FORBIDDEN));
        }
        self.replace_password(ctx, &user, &credential, keep_session, new_password, true)
            .await
    }

    /// Policy, "must differ", hash and the change transaction shared by
    /// [`Self::change_password`] and [`Self::apply_required_password_change`].
    async fn replace_password(
        &self,
        ctx: &RequestContext,
        user: &UserRecord,
        credential: &PasswordCredentialRecord,
        keep_session: Option<SessionId>,
        new_password: &SecretString,
        require_flag: bool,
    ) -> Result<(), AuthError> {
        let hints = self.profile(user.id).await;
        let context = Self::password_context(user, &hints, ctx.locale);
        self.inner.policy.enforce(new_password, &context).await?;
        let same = self
            .deps()
            .hasher
            .verify(new_password, Some(&stored_hash(credential)))
            .await?;
        if same.is_valid() {
            return Err(AuthError::new(codes::password::PASSWORD_UNCHANGED));
        }
        let new_hash = self.deps().hasher.hash(new_password).await?;
        let now = self.now();

        let mut tx = begin(self.pool()).await?;
        let user = self.lock_user(&mut tx, user.id).await?;
        // Compare-and-set: the hash verified above must still be current.
        let current = UserRepository::find_password(&mut *tx, user.id).await?;
        let unchanged = current.as_ref().is_some_and(|c| {
            c.password_hash == credential.password_hash && (!require_flag || c.must_change)
        });
        if !unchanged {
            return Err(AuthError::new(codes::common::CONFLICT)
                .with_context("password changed concurrently"));
        }
        self.store_password(&mut tx, user.id, &new_hash, now)
            .await?;
        OneTimeTokenRepository::revoke_for_user(&mut tx, user.id, RESET_PURPOSES, now).await?;
        let revoked = match keep_session {
            Some(keep) => {
                self.deps()
                    .sessions
                    .revoke_all_except(
                        &mut tx,
                        user.id,
                        keep,
                        RevocationReason::PasswordChanged,
                        RevokeOptions::default(),
                    )
                    .await?
            }
            None => {
                self.deps()
                    .sessions
                    .revoke_all_for_user(
                        &mut tx,
                        user.id,
                        RevocationReason::PasswordChanged,
                        RevokeOptions::default(),
                    )
                    .await?
            }
        };
        self.notify_password_changed(&mut tx, ctx, &user, &hints, now)
            .await?;
        let event = self
            .event(SecurityEventKind::PasswordChanged, ctx)
            .with_actor(Actor::User(user.id))
            .with_subject(user.id)
            .with_meta("sessions_revoked", revoked)
            .with_meta("required_change", require_flag);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        commit(tx).await?;
        metrics::password_updated("changed");
        Ok(())
    }

    /// Adds a password to a passwordless account (PWD-10). Requires a recent
    /// authentication (step-up, SES-13); fails with `password_already_set`
    /// when the account already has one.
    pub async fn add_password(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        let user_id = Self::self_service_user(principal)?;
        principal.require_recent_authentication(self.now(), self.inner.settings.step_up_max_age)?;
        let user = self.load_user(user_id).await?;
        if UserRepository::find_password(self.pool(), user_id)
            .await?
            .is_some()
        {
            return Err(AuthError::new(codes::password::PASSWORD_ALREADY_SET));
        }
        let hints = self.profile(user_id).await;
        let context = Self::password_context(&user, &hints, ctx.locale);
        self.inner.policy.enforce(new_password, &context).await?;
        let new_hash = self.deps().hasher.hash(new_password).await?;
        let now = self.now();

        let mut tx = begin(self.pool()).await?;
        let user = self.lock_user(&mut tx, user_id).await?;
        if UserRepository::find_password(&mut *tx, user_id)
            .await?
            .is_some()
        {
            return Err(AuthError::new(codes::password::PASSWORD_ALREADY_SET));
        }
        self.store_password(&mut tx, user_id, &new_hash, now)
            .await?;
        self.notify_password_changed(&mut tx, ctx, &user, &hints, now)
            .await?;
        let event = self
            .event(SecurityEventKind::PasswordAdded, ctx)
            .with_actor(Actor::User(user_id))
            .with_subject(user_id);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        commit(tx).await?;
        metrics::password_updated("added");
        Ok(())
    }

    /// Removes the caller's password (PWD-11). Requires step-up and at least
    /// one other *strong* sign-in method (passkey or linked identity, see
    /// [`is_strong_login_method`]), checked inside the transaction with the
    /// user row locked. Pending reset tokens are revoked with it.
    pub async fn remove_password(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
    ) -> Result<(), AuthError> {
        let user_id = Self::self_service_user(principal)?;
        principal.require_recent_authentication(self.now(), self.inner.settings.step_up_max_age)?;
        let hints = self.profile(user_id).await;
        let now = self.now();

        let mut tx = begin(self.pool()).await?;
        let user = self.lock_user(&mut tx, user_id).await?;
        if UserRepository::find_password(&mut *tx, user_id)
            .await?
            .is_none()
        {
            return Err(AuthError::new(codes::password::PASSWORD_NOT_SET));
        }
        let methods = self
            .deps()
            .login_methods
            .other_login_methods(&mut tx, user_id)
            .await?;
        let strong: Vec<&str> = methods
            .iter()
            .filter(|m| is_strong_login_method(**m))
            .map(|m| m.as_str())
            .collect();
        if strong.is_empty() {
            drop(tx);
            let event = self
                .event(SecurityEventKind::PasswordRemoved, ctx)
                .with_actor(Actor::User(user_id))
                .with_subject(user_id)
                .failed("no_other_strong_method");
            if let Err(err) = self.deps().audit.record(event).await {
                tracing::warn!(error = %err, "audit of refused password removal failed");
            }
            return Err(AuthError::new(
                codes::password::PASSWORD_REMOVAL_NOT_ALLOWED,
            ));
        }
        UserRepository::delete_password(&mut tx, user_id).await?;
        OneTimeTokenRepository::revoke_for_user(&mut tx, user_id, RESET_PURPOSES, now).await?;
        self.notify_password_changed(&mut tx, ctx, &user, &hints, now)
            .await?;
        let event = self
            .event(SecurityEventKind::PasswordRemoved, ctx)
            .with_actor(Actor::User(user_id))
            .with_subject(user_id)
            .with_meta("remaining_methods", strong);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        commit(tx).await?;
        metrics::password_updated("removed");
        Ok(())
    }

    /// Sets or clears `must_change_password` (PWD-12) for `user`; used by
    /// authn-admin (ADM-03, ADM-06), which authorizes the actor and records
    /// its own `admin.action` event with the justification. Fails with
    /// `not_found` for an unknown user and `password_not_set` for an account
    /// without a password.
    pub async fn set_must_change_password(
        &self,
        ctx: &RequestContext,
        actor: Actor,
        user_id: UserId,
        must_change: bool,
    ) -> Result<(), AuthError> {
        let mut tx = begin(self.pool()).await?;
        UserRepository::lock_for_update(&mut tx, user_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if !UserRepository::set_must_change_password(&mut tx, user_id, must_change).await? {
            return Err(AuthError::new(codes::password::PASSWORD_NOT_SET));
        }
        let event = self
            .event(SecurityEventKind::PasswordChangeRequiredSet, ctx)
            .with_actor(actor)
            .with_subject(user_id)
            .with_meta("must_change_password", must_change);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        commit(tx).await
    }

    // --- helpers ------------------------------------------------------------

    async fn load_user(&self, user: UserId) -> Result<UserRecord, AuthError> {
        UserRepository::find_by_id(self.pool(), user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))
    }

    async fn lock_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<UserRecord, AuthError> {
        UserRepository::lock_for_update(conn, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))
    }

    async fn store_password(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        hash: &PasswordHashRecord,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        UserRepository::set_password(
            conn,
            user,
            &NewPasswordHash {
                password_hash: &hash.hash,
                algorithm: hash.algorithm.as_str(),
                pepper_version: hash.pepper_version,
            },
            false,
            now,
        )
        .await?;
        Ok(())
    }
}
