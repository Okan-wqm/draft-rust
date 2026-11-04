//! Offline incident response for the CLI (ADM-05, ADM-06, K-07).
//!
//! The admin API deliberately cannot suspend a break-glass account, cannot
//! lift the suspension of an admin and cannot act on the caller's own
//! account (`crate::service` target rules): a single compromised console
//! session must not disable the recovery path. The operator of the
//! deployment does those things **offline**, through the CLI commands
//! `suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions` and
//! `create-admin --passkey-link` for an existing break-glass account, which
//! call the functions below.
//!
//! * Only platform admins (break-glass or not) can be targeted
//!   (`admin_target_not_allowed` otherwise; regular users are handled in
//!   the console).
//! * A justification is mandatory ([`Justification`], ADM-08) and an
//!   operator label (who ran the command, e.g. the OS user) is recorded.
//! * Each command is one transaction: the change, the session revocation
//!   (impersonations started by the admin end too), a **high-priority**
//!   `admin.action` event with `Actor::System`, `surface: cli`, the
//!   operator label and `priority: high`, and the justification
//!   (`admin_action_reasons`, no acting admin) commit or roll back
//!   together.
//! * The request context is [`RequestContext::system`] (loopback address,
//!   no user agent): nothing of the operator's machine is recorded.

use authn_account::StatusChange;
use authn_account::lifecycle::resting_status;
use authn_core::domain::{AccountStatus, EmailAddress, Locale};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{EventId, UserId};
use authn_core::ports::{Actor, RevocationReason, RevokeOptions, SecurityEvent, SecurityEventKind};
use authn_store::{UserRecord, UserRepository};
use sqlx::PgConnection;

use crate::reason::Justification;
use crate::service::{ActionOutcome, AdminService};
use crate::store;

/// Who ran an offline command: a short label (OS user, ticket handle),
/// 1–64 characters of `[A-Za-z0-9._@-]`. Recorded in the audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineOperator(String);

impl OfflineOperator {
    /// Validates an operator label (`validation_failed` otherwise).
    pub fn parse(label: &str) -> Result<Self, AuthError> {
        let label = label.trim();
        let valid = (1..=64).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'));
        if valid {
            Ok(Self(label.to_owned()))
        } else {
            Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_details(serde_json::json!({ "field": "operator" })))
        }
    }

    /// The label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The admin account an offline command acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineTarget {
    /// By user id.
    Id(UserId),
    /// By e-mail address.
    Email(String),
}

impl OfflineTarget {
    /// A user id when `value` parses as one, otherwise an e-mail address.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        value
            .trim()
            .parse::<UserId>()
            .map_or_else(|_| Self::Email(value.trim().to_owned()), Self::Id)
    }
}

const ALL_DEVICES: RevokeOptions = RevokeOptions {
    also_trusted_devices: true,
};

impl AdminService {
    async fn resolve_offline_target(&self, target: &OfflineTarget) -> Result<UserId, AuthError> {
        let record = match target {
            OfflineTarget::Id(id) => UserRepository::find_by_id(self.pool(), *id).await?,
            OfflineTarget::Email(email) => {
                let email = EmailAddress::parse(email).map_err(|_| {
                    AuthError::new(codes::common::VALIDATION_FAILED)
                        .with_details(serde_json::json!({ "field": "target" }))
                })?;
                UserRepository::find_by_email(self.pool(), &email).await?
            }
        };
        record
            .map(|r| r.id)
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
    }

    /// Locks a platform admin account for an offline command.
    async fn lock_offline_target(
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<UserRecord, AuthError> {
        let record = UserRepository::lock_for_update(conn, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if !record.is_platform_admin {
            return Err(AuthError::new(codes::admin::TARGET_NOT_ALLOWED)
                .with_context("offline commands act on platform admins only"));
        }
        Ok(record)
    }

    /// The high-priority staff event of an offline command + its
    /// justification, in the command's transaction.
    #[allow(clippy::too_many_arguments)]
    async fn record_offline(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        operator: &OfflineOperator,
        action: &'static str,
        target: &UserRecord,
        reason: &Justification,
        metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Result<EventId, AuthError> {
        let now = self.now();
        let mut event = SecurityEvent::new(SecurityEventKind::AdminAction, now)
            .with_context(ctx)
            .with_actor(Actor::System)
            .with_subject(target.id)
            .with_meta("action", action)
            .with_meta("surface", "cli")
            .with_meta("operator", operator.as_str())
            .with_meta("priority", "high")
            .with_meta("target_is_break_glass", target.is_break_glass)
            .with_meta("reason_recorded", true);
        for (key, value) in metadata {
            event.metadata.insert(key, value);
        }
        let id = event.id;
        self.deps().audit.record_in_tx(&mut *conn, event).await?;
        store::insert_reason(
            conn,
            id,
            None,
            Some(target.id),
            action,
            reason.as_str(),
            now,
        )
        .await?;
        crate::metrics::action(action);
        tracing::warn!(
            target_user = %target.id,
            operator = operator.as_str(),
            action,
            event = %id,
            "offline admin command (high priority)"
        );
        Ok(id)
    }

    /// `suspend-admin`: suspends a platform admin (break-glass accounts
    /// included) and revokes every session, impersonation and trusted
    /// device of the account (K-07).
    pub async fn suspend_admin_offline(
        &self,
        operator: &OfflineOperator,
        target: &OfflineTarget,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "offline_suspend_admin";
        let user = self.resolve_offline_target(target).await?;
        let ctx = RequestContext::system(Locale::default());
        let mut tx = self.begin().await?;
        let record = Self::lock_offline_target(&mut tx, user).await?;
        let changed = record.status != AccountStatus::Suspended;
        if changed {
            self.deps()
                .accounts
                .change_status_in_tx(
                    &mut tx,
                    &ctx,
                    user,
                    &StatusChange::new(AccountStatus::Suspended, "admin_suspension", Actor::System),
                )
                .await?;
        }
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
            .record_offline(
                &mut tx,
                &ctx,
                operator,
                ACTION,
                &record,
                reason,
                super_meta(&[
                    ("from", record.status.as_str().into()),
                    ("sessions_revoked", revoked.into()),
                ]),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(offline_outcome(ACTION, user, changed, revoked, event))
    }

    /// `unsuspend-admin`: lifts the suspension of a platform admin (back
    /// to `active`, or `pending_verification` for an unverified address).
    pub async fn unsuspend_admin_offline(
        &self,
        operator: &OfflineOperator,
        target: &OfflineTarget,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "offline_unsuspend_admin";
        let user = self.resolve_offline_target(target).await?;
        let ctx = RequestContext::system(Locale::default());
        let mut tx = self.begin().await?;
        let record = Self::lock_offline_target(&mut tx, user).await?;
        if record.status != AccountStatus::Suspended {
            return Err(
                AuthError::new(codes::account::ACCOUNT_STATUS_TRANSITION_NOT_ALLOWED)
                    .with_context("account is not suspended"),
            );
        }
        let to = resting_status(record.is_email_verified());
        self.deps()
            .accounts
            .change_status_in_tx(
                &mut tx,
                &ctx,
                user,
                &StatusChange::new(to, "admin_unsuspension", Actor::System),
            )
            .await?;
        let event = self
            .record_offline(
                &mut tx,
                &ctx,
                operator,
                ACTION,
                &record,
                reason,
                super_meta(&[("to", to.as_str().into())]),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(offline_outcome(ACTION, user, true, 0, event))
    }

    /// `revoke-admin-sessions`: revokes every session (and the
    /// impersonations it started, and trusted devices) of a platform admin,
    /// break-glass accounts included, without suspending it (K-07).
    pub async fn revoke_admin_sessions_offline(
        &self,
        operator: &OfflineOperator,
        target: &OfflineTarget,
        reason: &Justification,
    ) -> Result<ActionOutcome, AuthError> {
        const ACTION: &str = "offline_revoke_admin_sessions";
        let user = self.resolve_offline_target(target).await?;
        let ctx = RequestContext::system(Locale::default());
        let mut tx = self.begin().await?;
        let record = Self::lock_offline_target(&mut tx, user).await?;
        let revoked = self
            .deps()
            .sessions
            .revoke_all_for_user(&mut tx, user, RevocationReason::AdminAction, ALL_DEVICES)
            .await?;
        let event = self
            .record_offline(
                &mut tx,
                &ctx,
                operator,
                ACTION,
                &record,
                reason,
                super_meta(&[("sessions_revoked", revoked.into())]),
            )
            .await?;
        authn_store::commit(tx).await?;
        Ok(offline_outcome(ACTION, user, revoked > 0, revoked, event))
    }
}

impl AdminService {
    /// `create-admin --passkey-link` for an **existing** break-glass
    /// account (lost or compromised passkey, K-07 / K-11): issues a new
    /// single-use enrollment link (`ttl` 1 second – 24 hours) and ends the
    /// account's previous open links, in one audited transaction (the
    /// operator label and justification are recorded). The token is
    /// returned once.
    ///
    /// The link **replaces** the account's credentials: in the same
    /// transaction the password, every passkey, every MFA factor (with
    /// recovery codes and trusted devices) and every session are removed,
    /// so a compromised credential cannot come back when the account is
    /// unsuspended. Works on a suspended account (the link itself can only
    /// be used once the account is active again: `suspend-admin` →
    /// new link → `unsuspend-admin` → enroll).
    pub async fn issue_break_glass_enrollment_link_offline(
        &self,
        operator: &OfflineOperator,
        target: &OfflineTarget,
        reason: &Justification,
        ttl: std::time::Duration,
    ) -> Result<crate::BreakGlassEnrollmentLink, AuthError> {
        const ACTION: &str = "offline_issue_enrollment_link";
        if ttl.is_zero() || ttl > crate::settings::ENROLLMENT_LINK_HARD_CAP {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_details(serde_json::json!({ "field": "ttl" })));
        }
        let user = self.resolve_offline_target(target).await?;
        let token = authn_crypto::token::OpaqueToken::generate().map_err(AuthError::from)?;
        let ctx = RequestContext::system(Locale::default());
        let now = self.now();
        let expires_at = now + ttl;
        let mut tx = self.begin().await?;
        let record = Self::lock_offline_target(&mut tx, user).await?;
        if !record.is_break_glass {
            return Err(AuthError::new(codes::admin::TARGET_NOT_ALLOWED)
                .with_context("enrollment links are for break-glass accounts only"));
        }
        let replaced = store::expire_enrollments_of(&mut tx, user, now).await?;
        // The new link *replaces* every credential of the account (lost or
        // compromised passkey): otherwise an attacker's passkey, password
        // or second factor would work again as soon as the account is
        // unsuspended. Sessions and trusted devices end too.
        let mfa = self
            .deps()
            .mfa
            .reset_user_mfa_in_tx(&mut tx, &ctx, user)
            .await?;
        let passkeys = self
            .deps()
            .webauthn
            .remove_all_passkeys_in_tx(&mut tx, &ctx, user)
            .await?;
        let password_removed = UserRepository::delete_password(&mut tx, user).await?;
        let revoked = self
            .deps()
            .sessions
            .revoke_all_for_user(&mut tx, user, RevocationReason::AdminAction, ALL_DEVICES)
            .await?;
        store::insert_enrollment(
            &mut tx,
            uuid::Uuid::now_v7(),
            user,
            token.hash().as_bytes(),
            now,
            expires_at,
        )
        .await?;
        self.record_offline(
            &mut tx,
            &ctx,
            operator,
            ACTION,
            &record,
            reason,
            super_meta(&[
                ("links_replaced", replaced.into()),
                ("link_expires_unix", expires_at.unix_timestamp().into()),
                ("passkeys_removed", passkeys.into()),
                ("password_removed", password_removed.into()),
                ("factors_removed", mfa.factors.into()),
                ("sessions_revoked", revoked.into()),
            ]),
        )
        .await?;
        authn_store::commit(tx).await?;
        Ok(crate::BreakGlassEnrollmentLink {
            user_id: user,
            token: token.into_sensitive(),
            expires_at,
        })
    }
}

fn super_meta(entries: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn offline_outcome(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adm_05_k07_operator_labels_are_bounded_and_printable() {
        assert_eq!(
            OfflineOperator::parse(" ops.oncall@host-1 ")
                .unwrap()
                .as_str(),
            "ops.oncall@host-1"
        );
        for bad in ["", "a b", "x\ny", "é", &"a".repeat(65)] {
            assert!(OfflineOperator::parse(bad).is_err(), "{bad:?}");
        }
        let id = UserId::generate();
        assert_eq!(OfflineTarget::parse(&id.to_string()), OfflineTarget::Id(id));
        assert_eq!(
            OfflineTarget::parse("root@example.com"),
            OfflineTarget::Email("root@example.com".into())
        );
    }
}
