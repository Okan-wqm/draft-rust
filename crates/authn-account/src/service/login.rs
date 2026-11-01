//! What the login flow must do with an account (ACC-05, ACC-06, ACC-11),
//! and the ACC-06 status API for other modules.

use authn_core::config::account::UnverifiedLoginPolicy;
use authn_core::domain::AccountStatus;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::RequiredAction;
use authn_store::{UserRecord, UserRepository};
use sqlx::PgConnection;

use super::AccountService;
use crate::lifecycle::{
    StatusChange, StatusTransition, apply_transition, lock_user, transition_event, write_transition,
};
use crate::model::{DenialReason, LoginAssessment};
use crate::repo::DeletionRepository;

impl AccountService {
    /// ACC-05 / ACC-06 / ACC-11: evaluates an identified user for sign-in.
    /// authn-session calls it **after** the password (or other primary
    /// factor) was verified (SES-01: the account state is revealed only
    /// then):
    ///
    /// * `deleted` / `disabled` → denied (`account_disabled`);
    /// * `suspended` → denied (`account_suspended`);
    /// * `locked` → denied until `locked_until` (`account_locked` +
    ///   `Retry-After`); an expired lock counts as active;
    /// * unverified address → denied (`email_verification_required`) with
    ///   `account.unverified_login = "block"`, otherwise allowed with the
    ///   `verify_email` required action;
    /// * terms to (re-)accept → `accept_terms` required action;
    /// * `pending_deletion` → allowed (the user may cancel the deletion).
    pub async fn assess_login(&self, user: &UserRecord) -> Result<LoginAssessment, AuthError> {
        let now = self.now();
        match user.status {
            AccountStatus::Deleted | AccountStatus::Disabled => {
                return Ok(LoginAssessment::Denied(DenialReason::Disabled));
            }
            AccountStatus::Suspended => {
                return Ok(LoginAssessment::Denied(DenialReason::Suspended));
            }
            AccountStatus::Locked => match user.locked_until {
                Some(until) if until > now => {
                    return Ok(LoginAssessment::Denied(DenialReason::Locked { until }));
                }
                _ => {}
            },
            AccountStatus::Active
            | AccountStatus::PendingVerification
            | AccountStatus::PendingDeletion => {}
        }
        let mut required_actions = Vec::new();
        if !user.is_email_verified() {
            match self.config().unverified_login {
                UnverifiedLoginPolicy::Block => {
                    return Ok(LoginAssessment::Denied(DenialReason::EmailNotVerified));
                }
                UnverifiedLoginPolicy::Limited => {
                    required_actions.push(RequiredAction::VerifyEmail);
                }
            }
        }
        if !self.terms_requirements(user.id).await?.is_empty() {
            required_actions.push(RequiredAction::AcceptTerms);
        }
        let deletion_scheduled_for = if user.status == AccountStatus::PendingDeletion {
            DeletionRepository::find_scheduled(self.pool(), user.id)
                .await?
                .map(|d| d.scheduled_for)
        } else {
            None
        };
        Ok(LoginAssessment::Allowed {
            required_actions,
            deletion_scheduled_for,
        })
    }

    /// [`Self::assess_login`] by user id (`None` for unknown users).
    pub async fn assess_login_by_id(
        &self,
        user: UserId,
    ) -> Result<Option<LoginAssessment>, AuthError> {
        match UserRepository::find_by_id(self.pool(), user).await? {
            Some(record) => Ok(Some(self.assess_login(&record).await?)),
            None => Ok(None),
        }
    }

    /// ACC-06: changes a user's status through the state machine in its own
    /// transaction (admin suspend / unsuspend / disable / lock / unlock…).
    /// Illegal transitions fail with `account_status_transition_not_allowed`;
    /// every transition is audited. Session revocation for blocking statuses
    /// is the caller's job (use [`Self::change_status_in_tx`] to do both
    /// atomically).
    ///
    /// `pending_deletion` and `deleted` cannot be set here: they are entered
    /// only through the deletion flow ([`Self::request_deletion`], which
    /// records the schedule and the cancel link, and the purge jobs, which
    /// erase the row). A bare status write would leave an account that is
    /// never purged, or a `deleted` row that still holds personal data
    /// (ACC-09).
    pub async fn change_status(
        &self,
        ctx: &RequestContext,
        user: UserId,
        change: &StatusChange,
    ) -> Result<StatusTransition, AuthError> {
        ensure_settable(change)?;
        let mut tx = self.begin().await?;
        let record = lock_user(&mut tx, user).await?;
        let verified = record.email_verified_at.is_some();
        let transition =
            apply_transition(&mut tx, &record, change, verified, self.now(), Some(ctx)).await?;
        tx.commit().await?;
        Ok(transition)
    }

    /// ACC-06: like [`Self::change_status`] (same restrictions) but inside
    /// the caller's transaction (the row is locked with `FOR UPDATE`); the
    /// audit event is recorded with `AuditSink::record_in_tx` before
    /// returning.
    pub async fn change_status_in_tx(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
        change: &StatusChange,
    ) -> Result<StatusTransition, AuthError> {
        ensure_settable(change)?;
        let now = self.now();
        let record = UserRepository::lock_for_update(&mut *conn, user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let verified = record.email_verified_at.is_some();
        let transition = write_transition(&mut *conn, &record, change, verified, now).await?;
        let event = transition_event(&record, change, now, Some(ctx));
        self.deps().audit.record_in_tx(conn, event).await?;
        Ok(transition)
    }
}

/// Statuses with side effects of their own (schedule, erasure) are not
/// settable through the generic status API.
fn ensure_settable(change: &StatusChange) -> Result<(), AuthError> {
    match change.to {
        AccountStatus::PendingDeletion | AccountStatus::Deleted => Err(AuthError::new(
            codes::account::ACCOUNT_STATUS_TRANSITION_NOT_ALLOWED,
        )
        .with_context("deletion statuses are entered only through the deletion flow")),
        _ => Ok(()),
    }
}
