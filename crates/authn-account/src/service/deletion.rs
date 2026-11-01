//! Account deletion (ACC-09).
//!
//! * **Request** (`DELETE /v1/me`, session + step-up): refused with
//!   `account_deletion_blocked_last_owner` while the user is the only owner
//!   of an organization ([`OrganizationOwnership`](crate::OrganizationOwnership)).
//!   Otherwise the account moves to `pending_deletion` (ACC-06, audited),
//!   an `account_deletions` row records the schedule and the status to
//!   restore, and a cancel link (`account_deletion_cancel`, valid for the
//!   grace period) is e-mailed. Repeating the request is idempotent.
//! * **Cancel**: with the session (`POST /v1/me/deletion/cancel`) or with
//!   the e-mailed link (`POST /v1/account/deletion/cancel`). The account
//!   returns to its previous status — never to `active` without a verified
//!   address.
//! * **Purge** ([`AccountService::purge_due_deletions`], scheduled by the
//!   server): after the grace period, per account and in its own
//!   transaction (`FOR UPDATE SKIP LOCKED`, multi-instance safe): last-owner
//!   check again (another owner may have left meanwhile — the deletion is
//!   then postponed and audited), transition to `deleted`, `user.deleted`
//!   event, `account.deleted` audit, audit pseudonymisation
//!   (`AuditSink::pseudonymize_subject`, AUD-05) and finally the `users`
//!   row is deleted: `ON DELETE CASCADE` removes every module's personal
//!   data (profile, credentials, sessions, factors, passkeys, identities,
//!   memberships, tokens, consents, reservations…).

use authn_core::domain::{AccountStatus, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, DomainEvent, DomainEventKind, Notification, NotificationKind, RateLimitKey,
    SecurityEventKind,
};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::token::OpaqueToken;
use authn_store::{OneTimeTokenRepository, TokenPurpose, UserRepository};
use time::OffsetDateTime;

use super::verification::invalid_token;
use super::{AccountService, LinkSpec, actions, after};
use crate::lifecycle::{StatusChange, apply_transition, lock_user, resting_status};
use crate::model::{DeletionView, LastOwnerDetails, PurgeReport};
use crate::repo::{DeletionRecord, DeletionRepository};
use crate::tx::AccountTx;

/// Shortest validity of a cancel link (grace period 0 still gets one).
const MIN_CANCEL_LINK_TTL: std::time::Duration = std::time::Duration::from_secs(60);

impl From<DeletionRecord> for DeletionView {
    fn from(record: DeletionRecord) -> Self {
        Self {
            status: record.status,
            requested_at: record.requested_at,
            scheduled_for: record.scheduled_for,
        }
    }
}

impl AccountService {
    /// ACC-09: schedules the deletion of the signed-in user's account.
    pub async fn request_deletion(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
    ) -> Result<DeletionView, AuthError> {
        let user_id = Self::self_service_user(principal)?;
        self.require_step_up(principal)?;
        let now = self.now();
        let mut tx = self.begin().await?;
        let user = lock_user(&mut tx, user_id)
            .await
            .map_err(|_| AuthError::new(codes::common::UNAUTHENTICATED))?;
        if user.status == AccountStatus::PendingDeletion
            && let Some(existing) = DeletionRepository::find_scheduled(tx.conn(), user.id).await?
        {
            return Ok(existing.into());
        }
        let blocking = self
            .deps()
            .ownership
            .sole_owner_organizations(tx.conn(), user.id)
            .await?;
        if !blocking.is_empty() {
            return Err(
                AuthError::new(codes::account::ACCOUNT_DELETION_BLOCKED_LAST_OWNER).with_details(
                    serde_json::to_value(LastOwnerDetails {
                        organization_ids: blocking,
                    })
                    .unwrap_or_default(),
                ),
            );
        }
        apply_transition(
            &mut tx,
            &user,
            &StatusChange::new(
                AccountStatus::PendingDeletion,
                "user_requested_deletion",
                Actor::User(user.id),
            ),
            user.email_verified_at.is_some(),
            now,
            Some(ctx),
        )
        .await?;
        let scheduled_for = after(now, self.config().deletion_grace_period)?;
        let record =
            DeletionRepository::schedule(tx.conn(), user.id, now, scheduled_for, user.status)
                .await?;
        let link_expires_at = scheduled_for.max(after(now, MIN_CANCEL_LINK_TTL)?);
        let cancel_token = self
            .issue_link(
                tx.conn(),
                LinkSpec {
                    purpose: TokenPurpose::AccountDeletionCancel,
                    user: user.id,
                    target: None,
                    expires_at: link_expires_at,
                    invalidate_previous: true,
                },
                Some(ctx.client_ip),
            )
            .await?;
        if let Some((recipient, locale)) = self.recipient(tx.conn(), &user, ctx.locale).await? {
            self.deps()
                .notifier
                .notify_in_tx(
                    tx.conn(),
                    Notification {
                        recipient,
                        locale,
                        kind: NotificationKind::AccountDeletionScheduled {
                            scheduled_for,
                            cancel_token: cancel_token.into_sensitive(),
                        },
                    },
                )
                .await?;
        }
        self.publish_status(&mut tx, user.id, AccountStatus::PendingDeletion)
            .await?;
        tx.audit(
            self.event(SecurityEventKind::AccountDeletionScheduled, ctx)
                .with_actor(Actor::User(user.id))
                .with_subject(user.id)
                .with_meta("scheduled_for", scheduled_for.unix_timestamp()),
        );
        tx.commit().await?;
        Ok(record.into())
    }

    /// The scheduled deletion of the signed-in user, if any.
    pub async fn deletion_status(
        &self,
        principal: &Principal,
    ) -> Result<Option<DeletionView>, AuthError> {
        let user = principal.require_user()?;
        Ok(DeletionRepository::find_scheduled(self.pool(), user)
            .await?
            .map(DeletionView::from))
    }

    /// ACC-09: cancels the signed-in user's scheduled deletion.
    pub async fn cancel_deletion(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let user_id = Self::self_service_user(principal)?;
        let mut tx = self.begin().await?;
        self.cancel_deletion_in_tx(
            &mut tx,
            user_id,
            Actor::User(user_id),
            ctx,
            "user_cancelled",
        )
        .await?;
        tx.commit().await
    }

    /// ACC-09: cancels a scheduled deletion with the e-mailed link.
    pub async fn cancel_deletion_with_link(
        &self,
        ctx: &RequestContext,
        token: &SecretString,
    ) -> Result<(), AuthError> {
        self.limit(
            &RateLimitKey::ip(actions::LINK_ACTION_IP, ctx.client_ip),
            self.config().link_actions_per_ip,
        )
        .await?;
        let token = OpaqueToken::parse(token.expose_secret()).map_err(|_| invalid_token())?;
        let mut tx = self.begin().await?;
        let Some(user_id) = OneTimeTokenRepository::consume_link(
            tx.conn(),
            TokenPurpose::AccountDeletionCancel,
            &token.hash(),
            self.now(),
        )
        .await?
        .and_then(|r| r.user_id) else {
            return Err(invalid_token());
        };
        self.cancel_deletion_in_tx(&mut tx, user_id, Actor::Anonymous, ctx, "link_cancelled")
            .await
            .map_err(|err| {
                if err.code() == codes::account::ACCOUNT_DELETION_NOT_SCHEDULED {
                    invalid_token()
                } else {
                    err
                }
            })?;
        tx.commit().await
    }

    /// Cancels the scheduled deletion of `user` inside `tx`.
    pub(super) async fn cancel_deletion_in_tx(
        &self,
        tx: &mut AccountTx,
        user_id: UserId,
        actor: Actor,
        ctx: &RequestContext,
        reason: &'static str,
    ) -> Result<(), AuthError> {
        let now = self.now();
        let user = lock_user(tx, user_id).await?;
        if user.status != AccountStatus::PendingDeletion {
            return Err(AuthError::new(
                codes::account::ACCOUNT_DELETION_NOT_SCHEDULED,
            ));
        }
        let record = DeletionRepository::cancel(tx.conn(), user.id, now).await?;
        let verified = user.email_verified_at.is_some();
        let target = match record.as_ref().and_then(|r| r.previous_status) {
            Some(AccountStatus::Suspended) => AccountStatus::Suspended,
            Some(AccountStatus::Disabled) => AccountStatus::Disabled,
            _ => resting_status(verified),
        };
        apply_transition(
            tx,
            &user,
            &StatusChange::new(target, reason, actor),
            verified,
            now,
            Some(ctx),
        )
        .await?;
        OneTimeTokenRepository::revoke_for_user(
            tx.conn(),
            user.id,
            &[TokenPurpose::AccountDeletionCancel],
            now,
        )
        .await?;
        if let Some((recipient, locale)) = self.recipient(tx.conn(), &user, ctx.locale).await? {
            self.deps()
                .notifier
                .notify_in_tx(
                    tx.conn(),
                    Notification {
                        recipient,
                        locale,
                        kind: NotificationKind::AccountDeletionCancelled { at: now },
                    },
                )
                .await?;
        }
        self.publish_status(tx, user.id, target).await?;
        tx.audit(
            self.event(SecurityEventKind::AccountDeletionCancelled, ctx)
                .with_actor(actor)
                .with_subject(user.id)
                .with_meta("reason", reason),
        );
        Ok(())
    }

    async fn publish_status(
        &self,
        tx: &mut AccountTx,
        user: UserId,
        status: AccountStatus,
    ) -> Result<(), AuthError> {
        self.deps()
            .events
            .publish(
                tx.conn(),
                DomainEvent {
                    user_id: Some(user),
                    ..DomainEvent::new(
                        DomainEventKind::UserUpdated,
                        self.now(),
                        serde_json::json!({ "user_id": user, "status": status }),
                    )
                },
            )
            .await
    }

    /// ACC-09 purge job: deletes up to `max` accounts whose grace period
    /// ended. Schedule it periodically (OPS-06); safe to run on several
    /// instances concurrently.
    pub async fn purge_due_deletions(&self, max: u32) -> Result<PurgeReport, AuthError> {
        let mut report = PurgeReport::default();
        let mut blocked_ids = Vec::new();
        for _ in 0..max {
            let now = self.now();
            let mut tx = self.begin().await?;
            let Some(due) = DeletionRepository::claim_due(tx.conn(), now, &blocked_ids).await?
            else {
                break;
            };
            let Some(user) = UserRepository::lock_for_update(tx.conn(), due.user_id).await? else {
                // The row disappeared some other way: close the request.
                DeletionRepository::complete(tx.conn(), due.id, now).await?;
                tx.commit().await?;
                continue;
            };
            if user.status != AccountStatus::PendingDeletion {
                // Inconsistent legacy data (status changed outside the
                // state machine): never delete an account that is not
                // pending deletion; close the stale schedule instead.
                tracing::warn!(user_id = %user.id, status = user.status.as_str(), "stale deletion schedule cancelled: account not pending deletion");
                DeletionRepository::cancel(tx.conn(), user.id, now).await?;
                tx.commit().await?;
                continue;
            }
            let blocking = self
                .deps()
                .ownership
                .sole_owner_organizations(tx.conn(), user.id)
                .await?;
            if !blocking.is_empty() {
                blocked_ids.push(due.id.as_uuid());
                report.blocked += 1;
                drop(tx);
                let event =
                    authn_core::ports::SecurityEvent::new(SecurityEventKind::AccountDeleted, now)
                        .with_actor(Actor::System)
                        .with_subject(user.id)
                        .failed("last_owner")
                        .with_meta("organizations", blocking.len());
                if let Err(err) = self.deps().audit.record(event).await {
                    tracing::warn!(error = %err, "postponed deletion could not be audited");
                }
                continue;
            }
            self.erase_account(tx, &user, due.id, "grace_period_elapsed", now)
                .await?;
            report.purged += 1;
        }
        Ok(report)
    }

    /// Final step of a deletion: audited transition, events,
    /// pseudonymisation and the cascading delete of the user row.
    pub(super) async fn erase_account(
        &self,
        mut tx: AccountTx,
        user: &authn_store::UserRecord,
        deletion: authn_core::id::DeletionRequestId,
        reason: &'static str,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        apply_transition(
            &mut tx,
            user,
            &StatusChange::new(AccountStatus::Deleted, reason, Actor::System),
            user.email_verified_at.is_some(),
            now,
            None,
        )
        .await?;
        DeletionRepository::complete(tx.conn(), deletion, now).await?;
        self.finish_erasure(tx, user.id, reason, now).await
    }

    /// Records the deletion, pseudonymises the audit trail (AUD-05) and
    /// deletes the user row (cascade), then commits.
    pub(super) async fn finish_erasure(
        &self,
        mut tx: AccountTx,
        user: UserId,
        reason: &'static str,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        self.deps()
            .events
            .publish(
                tx.conn(),
                DomainEvent {
                    user_id: Some(user),
                    ..DomainEvent::new(
                        DomainEventKind::UserDeleted,
                        now,
                        serde_json::json!({ "user_id": user }),
                    )
                },
            )
            .await?;
        tx.audit(
            authn_core::ports::SecurityEvent::new(SecurityEventKind::AccountDeleted, now)
                .with_actor(Actor::System)
                .with_subject(user)
                .with_meta("reason", reason),
        );
        // Order: record the events (they get the pseudonym), unlink the
        // pseudonym and erase audit PII, then delete the row.
        tx.flush_audit().await?;
        self.deps()
            .audit
            .pseudonymize_subject(tx.conn(), user)
            .await?;
        if !UserRepository::delete(tx.conn(), user).await? {
            return Err(AuthError::internal("user row vanished during erasure"));
        }
        tx.commit().await?;
        metrics::counter!("authn_account_deletions_total", "reason" => reason).increment(1);
        tracing::info!(user_id = %user, reason, "account erased");
        Ok(())
    }
}
