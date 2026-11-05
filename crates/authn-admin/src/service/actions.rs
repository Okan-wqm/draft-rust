//! Per-user admin actions (ADM-03), each in one transaction with its audit
//! event and justification (ADM-08).
//!
//! | Action | Effect | Targets |
//! |--------|--------|---------|
//! | suspend | `→ suspended` (authn-account state machine), every session and trusted device revoked | anyone but self and break-glass accounts |
//! | unsuspend | `suspended →` `active` (verified) / `pending_verification` | regular users |
//! | unlock | `locked → active`, login soft lock and failure counters cleared | anyone but self |
//! | revoke sessions | every session (and impersonation started by the user) and trusted device revoked | anyone but self and break-glass accounts |
//! | force password reset | the password is replaced by an unusable random one (`must_change` set), sessions and trusted devices revoked, a reset link is e-mailed | regular users |
//! | must change password | `must_change_password` set / cleared (PWD-12) | regular users |
//! | MFA reset | factors, recovery codes, trusted devices removed; the user is notified (authn-mfa); sessions revoked | regular users |
//! | mark e-mail verified | `MailboxProof::Administrator` (ADR 0002: unproven password removed, sessions revoked) | regular users |
//!
//! "Regular users" excludes platform admins and break-glass accounts: an
//! admin console session must not be able to take over another admin.
//! Break-glass accounts cannot be suspended or have their sessions revoked
//! either: a single compromised admin must not be able to disable the
//! recovery path of last resort (the break-glass account can in turn
//! suspend the compromised admin). Those cases are handled offline (CLI).
//!
//! Module events emitted by the delegated APIs (e.g.
//! `account.status_changed`) are attributed to `Actor::System`; the real
//! actor is recorded by this crate's `admin.action` event in the same
//! transaction, so staff identities stay hidden from user-facing views.

use authn_account::StatusChange;
use authn_account::lifecycle::resting_status;
use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{EventId, UserId};
use authn_core::ports::{Actor, RevocationReason, RevokeOptions, SecurityEventKind};
use authn_core::secret::SecretString;
use authn_crypto::token::OpaqueToken;
use authn_store::{NewPasswordHash, UserRepository};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{AdminService, CriticalOperation, TargetPolicy, meta};
use crate::guard::AdminCaller;
use crate::reason::Justification;

const ALL_DEVICES: RevokeOptions = RevokeOptions {
    also_trusted_devices: true,
};

/// Result of a per-user admin action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ActionOutcome {
    /// Action code (as audited).
    pub action: String,
    /// Target account.
    pub user_id: UserId,
    /// Whether anything changed (`false`: already in the requested state).
    pub changed: bool,
    /// Sessions revoked by the action.
    pub sessions_revoked: u64,
    /// The audit event recording the action.
    pub event_id: EventId,
}

/// Result of a forced password reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ForcedReset {
    /// The action.
    #[serde(flatten)]
    pub outcome: ActionOutcome,
    /// Whether a reset e-mail was queued (it is rate limited like any
    /// reset request).
    pub reset_email_queued: bool,
}

/// Marks an action on another platform admin as high priority (K-08).
fn with_admin_target(
    mut metadata: serde_json::Map<String, Value>,
    admin_target: bool,
    four_eyes: serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    metadata.extend(four_eyes);
    if admin_target {
        metadata.insert("target_is_admin".to_owned(), Value::from(true));
        metadata.insert("priority".to_owned(), Value::from("high"));
    }
    metadata
}

fn outcome(
    action: &str,
    user: UserId,
    changed: bool,
    sessions: u64,
    event: EventId,
) -> ActionOutcome {
    ActionOutcome {
        action: action.to_owned(),
        user_id: user,
        changed,
        sessions_revoked: sessions,
        event_id: event,
    }
}

impl AdminService {
    /// Suspends an account and revokes its sessions and trusted devices
    /// (ADM-03).
    pub async fn suspend_user(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        self.suspend_user_approved(caller, ctx, user, reason, None)
            .await
    }

    /// [`Self::suspend_user`] with a four-eyes approval (K-66): required when
    /// the target is another platform admin and `admin.four_eyes` is on.
    pub async fn suspend_user_approved(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
        approval: Option<Uuid>,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "suspend_user";
        let operation = CriticalOperation::SuspendAdmin(user);
        self.four_eyes_precheck_target(caller, ctx, &operation, approval)
            .await?;
        let (mut tx, target, admin_target) = self
            .begin_on_target(caller, ctx, user, TargetPolicy::NotBreakGlass, ACTION)
            .await?;
        let four_eyes = match self
            .four_eyes_on_admin_target(&mut tx, caller, ctx, admin_target, &operation, approval)
            .await?
        {
            Ok(four_eyes) => four_eyes,
            Err(refusal) => {
                tx.rollback().await?;
                return Err(self
                    .refuse_four_eyes(caller, ctx, &operation, refusal, approval)
                    .await);
            }
        };
        let transition = self
            .deps()
            .accounts
            .change_status_in_tx(
                &mut tx,
                ctx,
                user,
                &StatusChange::new(AccountStatus::Suspended, "admin_suspension", Actor::System),
            )
            .await?;
        let revoked = self
            .deps()
            .sessions
            .revoke_all_for_user(
                &mut tx,
                user,
                RevocationReason::AccountSuspended,
                ALL_DEVICES,
            )
            .await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(user),
                Some(reason),
                with_admin_target(
                    meta([
                        ("from", Value::from(target.status.as_str())),
                        ("to", Value::from(transition.to.as_str())),
                        ("sessions_revoked", Value::from(revoked)),
                    ]),
                    admin_target,
                    four_eyes,
                ),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(outcome(ACTION, user, true, revoked, event))
    }

    /// Lifts a suspension (ADM-03): back to `active`, or to
    /// `pending_verification` when the address was never verified.
    pub async fn unsuspend_user(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "unsuspend_user";
        let mut tx = self.begin().await?;
        let target = self
            .lock_target(&mut tx, caller, user, TargetPolicy::RegularUsersOnly)
            .await?;
        if target.status != AccountStatus::Suspended {
            return Err(
                AuthError::new(codes::account::ACCOUNT_STATUS_TRANSITION_NOT_ALLOWED)
                    .with_context("account is not suspended"),
            );
        }
        let to = resting_status(target.is_email_verified());
        self.deps()
            .accounts
            .change_status_in_tx(
                &mut tx,
                ctx,
                user,
                &StatusChange::new(to, "admin_unsuspension", Actor::System),
            )
            .await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(user),
                Some(reason),
                meta([
                    ("from", Value::from(target.status.as_str())),
                    ("to", Value::from(to.as_str())),
                ]),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(outcome(ACTION, user, true, 0, event))
    }

    /// Unlocks an account (ADM-03): ends a temporary `locked` status and
    /// clears the login soft lock and failure counters (PRT-03). The
    /// database change and audit event commit first; the soft lock is
    /// cleared right after (idempotent, retry on failure).
    pub async fn unlock_user(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        self.unlock_user_approved(caller, ctx, user, reason, None)
            .await
    }

    /// [`Self::unlock_user`] with a four-eyes approval (K-66): required when
    /// the target is another platform admin and `admin.four_eyes` is on.
    pub async fn unlock_user_approved(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
        approval: Option<Uuid>,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "unlock_user";
        let operation = CriticalOperation::UnlockAdmin(user);
        self.four_eyes_precheck_target(caller, ctx, &operation, approval)
            .await?;
        // Read before the transaction: never wait for a second pooled
        // connection while holding one.
        let soft_locked = self.deps().protection.locked_until(user).await?.is_some();
        let (mut tx, target, admin_target) = self
            .begin_on_target(caller, ctx, user, TargetPolicy::NotSelf, ACTION)
            .await?;
        let four_eyes = match self
            .four_eyes_on_admin_target(&mut tx, caller, ctx, admin_target, &operation, approval)
            .await?
        {
            Ok(four_eyes) => four_eyes,
            Err(refusal) => {
                tx.rollback().await?;
                return Err(self
                    .refuse_four_eyes(caller, ctx, &operation, refusal, approval)
                    .await);
            }
        };
        let status_unlocked = target.status == AccountStatus::Locked;
        if status_unlocked {
            self.deps()
                .accounts
                .change_status_in_tx(
                    &mut tx,
                    ctx,
                    user,
                    &StatusChange::new(AccountStatus::Active, "admin_unlock", Actor::System),
                )
                .await?;
        }
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(user),
                Some(reason),
                with_admin_target(
                    meta([
                        ("account_unlocked", Value::from(status_unlocked)),
                        ("soft_lock_cleared", Value::from(soft_locked)),
                    ]),
                    admin_target,
                    four_eyes,
                ),
            )
            .await?;
        authn_store::commit(tx).await?;
        if let Some(identifier) = target.email_normalized.as_deref() {
            self.deps().protection.unlock(user, identifier).await?;
        }
        Ok(outcome(
            ACTION,
            user,
            status_unlocked || soft_locked,
            0,
            event,
        ))
    }

    /// Revokes every session (and trusted device) of an account (ADM-03).
    /// Impersonation sessions the account started as an admin end too.
    pub async fn revoke_user_sessions(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        self.revoke_user_sessions_approved(caller, ctx, user, reason, None)
            .await
    }

    /// [`Self::revoke_user_sessions`] with a four-eyes approval (K-66): required when
    /// the target is another platform admin and `admin.four_eyes` is on.
    pub async fn revoke_user_sessions_approved(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
        approval: Option<Uuid>,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "revoke_user_sessions";
        let operation = CriticalOperation::RevokeAdminSessions(user);
        self.four_eyes_precheck_target(caller, ctx, &operation, approval)
            .await?;
        let (mut tx, _target, admin_target) = self
            .begin_on_target(caller, ctx, user, TargetPolicy::NotBreakGlass, ACTION)
            .await?;
        let four_eyes = match self
            .four_eyes_on_admin_target(&mut tx, caller, ctx, admin_target, &operation, approval)
            .await?
        {
            Ok(four_eyes) => four_eyes,
            Err(refusal) => {
                tx.rollback().await?;
                return Err(self
                    .refuse_four_eyes(caller, ctx, &operation, refusal, approval)
                    .await);
            }
        };
        let revoked = self
            .deps()
            .sessions
            .revoke_all_for_user(&mut tx, user, RevocationReason::AdminAction, ALL_DEVICES)
            .await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(user),
                Some(reason),
                with_admin_target(
                    meta([("sessions_revoked", Value::from(revoked))]),
                    admin_target,
                    four_eyes,
                ),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(outcome(ACTION, user, revoked > 0, revoked, event))
    }

    /// Forces a password reset (ADM-03): the current password stops
    /// working at once (replaced by the hash of a random, discarded
    /// 256-bit secret, `must_change` set), every session and trusted device
    /// is revoked, and — when `send_email` — a reset link is sent to the
    /// account address through the normal reset flow (PWD-07). Accounts
    /// without a password answer `password_not_set`.
    pub async fn force_password_reset(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
        send_email: bool,
    ) -> Result<ForcedReset, AuthError> {
        const ACTION: &str = "force_password_reset";
        // Hash before opening the transaction (Argon2 is slow; ARC-12).
        let unusable = OpaqueToken::generate().map_err(AuthError::from)?;
        let hash = self
            .deps()
            .hasher
            .hash(&SecretString::from(unusable.expose().to_owned()))
            .await
            .map_err(AuthError::from)?;
        drop(unusable);
        let mut tx = self.begin().await?;
        let target = self
            .lock_target(&mut tx, caller, user, TargetPolicy::RegularUsersOnly)
            .await?;
        if UserRepository::find_password(&mut *tx, user)
            .await?
            .is_none()
        {
            return Err(AuthError::new(codes::password::PASSWORD_NOT_SET));
        }
        UserRepository::set_password(
            &mut tx,
            user,
            &NewPasswordHash {
                password_hash: &hash.hash,
                algorithm: hash.algorithm.as_str(),
                pepper_version: hash.pepper_version,
            },
            true,
            self.now(),
        )
        .await?;
        let revoked = self
            .deps()
            .sessions
            .revoke_all_for_user(&mut tx, user, RevocationReason::AdminAction, ALL_DEVICES)
            .await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(user),
                Some(reason),
                meta([
                    ("sessions_revoked", Value::from(revoked)),
                    ("reset_link_requested", Value::from(send_email)),
                ]),
            )
            .await?;
        authn_store::commit(tx).await?;
        let mut queued = false;
        if send_email
            && let Some(email) = target
                .email
                .as_deref()
                .and_then(|e| EmailAddress::parse(e).ok())
        {
            match self.deps().passwords.request_reset(ctx, &email).await {
                Ok(()) => queued = true,
                Err(err) => tracing::warn!(
                    code = err.code().code(),
                    "forced password reset: reset e-mail not queued"
                ),
            }
        }
        Ok(ForcedReset {
            outcome: outcome(ACTION, user, true, revoked, event),
            reset_email_queued: queued,
        })
    }

    /// Sets or clears `must_change_password` (ADM-03, PWD-12). Accounts
    /// without a password answer `password_not_set`.
    pub async fn set_must_change_password(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        must_change: bool,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "set_must_change_password";
        let mut tx = self.begin().await?;
        self.lock_target(&mut tx, caller, user, TargetPolicy::RegularUsersOnly)
            .await?;
        let before = UserRepository::find_password(&mut *tx, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::password::PASSWORD_NOT_SET))?;
        UserRepository::set_must_change_password(&mut tx, user, must_change).await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(user),
                Some(reason),
                meta([("must_change", Value::from(must_change))]),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(outcome(
            ACTION,
            user,
            before.must_change != must_change,
            0,
            event,
        ))
    }

    /// Resets the account's MFA (ADM-03): every factor, recovery code,
    /// trusted device **and passkey** is removed, the user is notified
    /// (authn-mfa queues the `mfa_reset` notification and authn-webauthn the
    /// passkey removal notice in this transaction) and every session is
    /// revoked — all in one transaction. Removing every passkey closes two
    /// holes (K-01): an attacker-enrolled passkey would otherwise keep
    /// allowing passwordless sign-in after the reset, and a user who lost
    /// the device holding a second-factor passkey would stay locked out.
    pub async fn reset_user_mfa(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "reset_mfa";
        let mut tx = self.begin().await?;
        self.lock_target(&mut tx, caller, user, TargetPolicy::RegularUsersOnly)
            .await?;
        let summary = self
            .deps()
            .mfa
            .reset_user_mfa_in_tx(&mut tx, ctx, user)
            .await?;
        let passkeys = self
            .deps()
            .webauthn
            .remove_all_passkeys_in_tx(&mut tx, ctx, user)
            .await?;
        let revoked = self
            .deps()
            .sessions
            .revoke_all_for_user(&mut tx, user, RevocationReason::MfaChanged, ALL_DEVICES)
            .await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(user),
                Some(reason),
                meta([
                    ("factors_removed", Value::from(summary.factors)),
                    (
                        "recovery_codes_removed",
                        Value::from(summary.recovery_codes),
                    ),
                    (
                        "trusted_devices_revoked",
                        Value::from(summary.trusted_devices),
                    ),
                    ("passkeys_removed", Value::from(passkeys)),
                    ("sessions_revoked", Value::from(revoked)),
                ]),
            )
            .await?;
        authn_store::commit(tx).await?;
        let changed = summary.factors
            + summary.recovery_codes
            + summary.trusted_devices
            + u64::from(passkeys)
            > 0;
        Ok(outcome(ACTION, user, changed, revoked, event))
    }

    /// Marks the address verified on the admin's word (ADM-03,
    /// `MailboxProof::Administrator`). For an unverified account authn-account
    /// discards pending registrations, removes the never-proven password and
    /// revokes every session (ADR 0002); an already verified account is
    /// left unchanged (`changed: false`, still audited).
    pub async fn mark_email_verified(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "mark_email_verified";
        let mut tx = self.begin().await?;
        self.lock_target(&mut tx, caller, user, TargetPolicy::RegularUsersOnly)
            .await?;
        let changed = self
            .deps()
            .accounts
            .confirm_mailbox_control_in_tx(
                &mut tx,
                Some(ctx),
                user,
                authn_account::MailboxProof::Administrator {
                    admin: caller.user_id(),
                },
            )
            .await?;
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                ACTION,
                Some(user),
                Some(reason),
                meta([("changed", Value::from(changed))]),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(outcome(ACTION, user, changed, 0, event))
    }
}
