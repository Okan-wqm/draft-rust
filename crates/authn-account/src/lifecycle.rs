//! Account status state machine (ACC-06).
//!
//! [`check_transition`] is the **single** definition of which status
//! changes are legal. Every status write of this crate (and of wave-B
//! callers through [`AccountService::change_status`](crate::AccountService::change_status))
//! goes through one internal function (`apply_transition`), which row-locks the user, consults
//! [`check_transition`], performs a compare-and-set update
//! (`UserRepository::update_status`) and emits an
//! `account.status_changed` audit event with `from` / `to` / `reason`.
//!
//! | from \ to | pending_verification | active | locked | suspended | disabled | pending_deletion | deleted |
//! |-----------|---|---|---|---|---|---|---|
//! | pending_verification | – | ✓¹ | – | ✓ | ✓ | ✓ | ✓ |
//! | active | – | – | ✓ | ✓ | ✓ | ✓ | – |
//! | locked | – | ✓¹ | – | ✓ | ✓ | – | – |
//! | suspended | ✓² | ✓¹ | – | – | ✓ | ✓ | – |
//! | disabled | ✓² | ✓¹ | – | ✓ | – | ✓ | – |
//! | pending_deletion | ✓² | ✓¹ | – | ✓ | ✓ | – | ✓ |
//! | deleted | – | – | – | – | – | – | – |
//!
//! ¹ only when the e-mail address is verified — invariant: *an `active`
//! account always has a verified address*, so unsuspending, unlocking or
//! cancelling a deletion can never skip e-mail verification.
//! ² only when the address is **not** verified (the account returns to
//! verification instead of becoming active).
//!
//! Further rules: `locked` is entered only from `active` (a temporary lock
//! must not hide the verification state) and requires a future
//! `locked_until`; `deleted` is terminal and reached only from
//! `pending_verification` (purge of never-verified accounts, ACC-05) and
//! `pending_deletion` (end of the grace period, ACC-09); a no-op transition
//! (`x → x`) is rejected. `pending_deletion` and `deleted` are entered only
//! by the deletion flow and the purge jobs of this crate (schedule, cancel
//! link, erasure); the generic status API for other modules
//! ([`AccountService::change_status`](crate::AccountService::change_status))
//! refuses them.

use std::fmt;

use authn_core::domain::AccountStatus;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{Actor, SecurityEvent, SecurityEventKind};
use authn_store::{UserRecord, UserRepository};
use sqlx::PgConnection;
use time::OffsetDateTime;

use crate::tx::AccountTx;

/// Why a transition is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// `from == to`.
    Unchanged,
    /// `from` is terminal (`deleted`).
    Terminal,
    /// The pair is not in the transition table.
    NotAllowed,
    /// `→ active` needs a verified e-mail address.
    EmailNotVerified,
    /// `→ pending_verification` with an already verified address.
    EmailAlreadyVerified,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unchanged => "status unchanged",
            Self::Terminal => "status is terminal",
            Self::NotAllowed => "transition not allowed",
            Self::EmailNotVerified => "active requires a verified e-mail address",
            Self::EmailAlreadyVerified => "verified accounts cannot return to verification",
        })
    }
}

impl std::error::Error for TransitionError {}

impl From<TransitionError> for AuthError {
    fn from(err: TransitionError) -> Self {
        AuthError::new(codes::account::ACCOUNT_STATUS_TRANSITION_NOT_ALLOWED)
            .with_context(err.to_string())
    }
}

/// The single source of truth for legal status changes (see the module
/// table). `email_verified` is the verification state *after* the
/// operation (e.g. `true` when verifying the address in the same
/// transaction).
pub fn check_transition(
    from: AccountStatus,
    to: AccountStatus,
    email_verified: bool,
) -> Result<(), TransitionError> {
    use AccountStatus::{
        Active, Deleted, Disabled, Locked, PendingDeletion, PendingVerification, Suspended,
    };
    if from == to {
        return Err(TransitionError::Unchanged);
    }
    if from.is_terminal() {
        return Err(TransitionError::Terminal);
    }
    let allowed = match from {
        PendingVerification => matches!(
            to,
            Active | Suspended | Disabled | PendingDeletion | Deleted
        ),
        Active => matches!(to, Locked | Suspended | Disabled | PendingDeletion),
        Locked => matches!(to, Active | Suspended | Disabled),
        Suspended => matches!(
            to,
            PendingVerification | Active | Disabled | PendingDeletion
        ),
        Disabled => matches!(
            to,
            PendingVerification | Active | Suspended | PendingDeletion
        ),
        PendingDeletion => matches!(
            to,
            PendingVerification | Active | Suspended | Disabled | Deleted
        ),
        Deleted => false,
    };
    if !allowed {
        return Err(TransitionError::NotAllowed);
    }
    match to {
        Active if !email_verified => Err(TransitionError::EmailNotVerified),
        PendingVerification if email_verified => Err(TransitionError::EmailAlreadyVerified),
        _ => Ok(()),
    }
}

/// The status an account returns to when a suspension, a deactivation or
/// a scheduled deletion ends: `active` with a verified address, otherwise
/// `pending_verification`.
#[must_use]
pub fn resting_status(email_verified: bool) -> AccountStatus {
    if email_verified {
        AccountStatus::Active
    } else {
        AccountStatus::PendingVerification
    }
}

/// A requested status change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusChange {
    /// Target status.
    pub to: AccountStatus,
    /// Stable snake_case reason code (`email_verified`, `admin_suspension`…);
    /// stored in `users.status_reason` and audited. Never free text.
    pub reason: &'static str,
    /// End of the lock; required for (and only for) `locked`.
    pub locked_until: Option<OffsetDateTime>,
    /// Who causes the change (audited).
    pub actor: Actor,
}

impl StatusChange {
    /// A change to `to` for `reason` by `actor`.
    #[must_use]
    pub fn new(to: AccountStatus, reason: &'static str, actor: Actor) -> Self {
        Self {
            to,
            reason,
            locked_until: None,
            actor,
        }
    }
}

/// A performed transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusTransition {
    /// The user.
    pub user_id: UserId,
    /// Previous status.
    pub from: AccountStatus,
    /// New status.
    pub to: AccountStatus,
}

/// Whether `reason` is a valid stored reason code (`users_status_reason_check`).
fn is_reason_code(reason: &str) -> bool {
    let mut bytes = reason.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && reason.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Validates `change` against the state machine and writes it with a
/// compare-and-set on the already row-locked `user` (no audit).
pub(crate) async fn write_transition(
    conn: &mut PgConnection,
    user: &UserRecord,
    change: &StatusChange,
    email_verified: bool,
    now: OffsetDateTime,
) -> Result<StatusTransition, AuthError> {
    check_transition(user.status, change.to, email_verified)?;
    if !is_reason_code(change.reason) {
        return Err(AuthError::internal("invalid status reason code"));
    }
    match (change.to, change.locked_until) {
        (AccountStatus::Locked, Some(until)) if until > now => {}
        (AccountStatus::Locked, _) => {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_context("locked requires a future locked_until"));
        }
        (_, Some(_)) => {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_context("locked_until is only valid for locked"));
        }
        (_, None) => {}
    }
    let changed = UserRepository::update_status(
        &mut *conn,
        user.id,
        user.status,
        change.to,
        Some(change.reason),
        change.locked_until,
        now,
    )
    .await?;
    if !changed {
        // The caller holds the row lock, so this only happens on a bug.
        return Err(AuthError::new(codes::common::CONFLICT)
            .with_context("concurrent account status change"));
    }
    if user.status == AccountStatus::PendingDeletion && change.to != AccountStatus::Deleted {
        // Leaving `pending_deletion` other than by erasure ends the schedule
        // (e.g. an administrator suspends the account during the grace
        // period): the purge job must never delete it afterwards.
        crate::repo::DeletionRepository::cancel(&mut *conn, user.id, now).await?;
    }
    tracing::info!(
        user_id = %user.id,
        from = user.status.as_str(),
        to = change.to.as_str(),
        reason = change.reason,
        "account status changed"
    );
    Ok(StatusTransition {
        user_id: user.id,
        from: user.status,
        to: change.to,
    })
}

/// Whether the request's client IP / user agent may be attached to an
/// event about a user performed by `actor` (K-14). The audit sink stores an
/// event's client data under the acting user's pseudonym when the actor is
/// a user, otherwise under the **subject's**: for `Actor::System` (platform
/// staff through authn-admin, jobs), service accounts and API keys the
/// caller's network would become the subject's personal data and appear
/// (masked) in the subject's own event list, so it is not attached.
pub(crate) fn keeps_client_context(actor: Actor) -> bool {
    match actor {
        Actor::User(_) | Actor::Anonymous => true,
        Actor::System | Actor::ServiceAccount(_) | Actor::ApiKey(_) => false,
    }
}

/// The `account.status_changed` audit event of a transition.
pub(crate) fn transition_event(
    user: &UserRecord,
    change: &StatusChange,
    now: OffsetDateTime,
    ctx: Option<&RequestContext>,
) -> SecurityEvent {
    let mut event = SecurityEvent::new(SecurityEventKind::AccountStatusChanged, now);
    if let Some(ctx) = ctx {
        if keeps_client_context(change.actor) {
            event = event.with_context(ctx);
        } else {
            // K-14 (ADM-08): a status change made by platform staff
            // (`Actor::System` from authn-admin), a service account or an
            // API key lands in the user's own event list; the caller's IP /
            // user agent would be shown there (masked) and stored as the
            // user's personal data. Only the request id is
            // kept, for correlation with the caller's own `admin.*` event.
            event.request_id = Some(ctx.request_id);
        }
    }
    event
        .with_actor(change.actor)
        .with_subject(user.id)
        .with_resource("user", user.id)
        .with_meta("from", user.status.as_str())
        .with_meta("to", change.to.as_str())
        .with_meta("reason", change.reason)
}

/// Applies `change` to an already row-locked `user` inside `tx` (ACC-06):
/// validates it with [`check_transition`], writes it with a compare-and-set
/// and queues the `account.status_changed` audit event (recorded when `tx`
/// commits). `email_verified` overrides the stored verification state when
/// the caller verifies the address in the same transaction.
pub(crate) async fn apply_transition(
    tx: &mut AccountTx,
    user: &UserRecord,
    change: &StatusChange,
    email_verified: bool,
    now: OffsetDateTime,
    ctx: Option<&RequestContext>,
) -> Result<StatusTransition, AuthError> {
    let transition = write_transition(tx.conn(), user, change, email_verified, now).await?;
    tx.audit(transition_event(user, change, now, ctx));
    Ok(transition)
}

/// Locks the user row (`FOR UPDATE`) in `tx`; `not_found` when it does not
/// exist.
pub(crate) async fn lock_user(tx: &mut AccountTx, user: UserId) -> Result<UserRecord, AuthError> {
    UserRepository::lock_for_update(tx.conn(), user)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use AccountStatus::{
        Active, Deleted, Disabled, Locked, PendingDeletion, PendingVerification, Suspended,
    };

    /// The expected table, written out independently of the implementation.
    fn expected(from: AccountStatus, to: AccountStatus, verified: bool) -> bool {
        let pair_allowed = matches!(
            (from, to),
            (
                PendingVerification,
                Active | Suspended | Disabled | PendingDeletion | Deleted
            ) | (Active, Locked | Suspended | Disabled | PendingDeletion)
                | (Locked, Active | Suspended | Disabled)
                | (
                    Suspended,
                    PendingVerification | Active | Disabled | PendingDeletion
                )
                | (
                    Disabled,
                    PendingVerification | Active | Suspended | PendingDeletion
                )
                | (
                    PendingDeletion,
                    PendingVerification | Active | Suspended | Disabled | Deleted
                )
        );
        pair_allowed && !(to == Active && !verified) && !(to == PendingVerification && verified)
    }

    #[test]
    fn acc_06_transition_table_is_exhaustively_enforced() {
        let mut allowed = 0;
        for &from in AccountStatus::ALL {
            for &to in AccountStatus::ALL {
                for verified in [false, true] {
                    let result = check_transition(from, to, verified);
                    assert_eq!(
                        result.is_ok(),
                        expected(from, to, verified),
                        "{from} -> {to} (verified: {verified}): {result:?}"
                    );
                    if result.is_ok() {
                        allowed += 1;
                    }
                }
            }
        }
        // 7 × 7 × 2 combinations were checked; this pins the table size.
        assert_eq!(allowed, 42);
    }

    #[test]
    fn acc_06_forbidden_transitions_report_the_reason() {
        assert_eq!(
            check_transition(Active, Active, true),
            Err(TransitionError::Unchanged)
        );
        assert_eq!(
            check_transition(Deleted, Active, true),
            Err(TransitionError::Terminal)
        );
        assert_eq!(
            check_transition(PendingVerification, Locked, false),
            Err(TransitionError::NotAllowed)
        );
        assert_eq!(
            check_transition(Active, Deleted, true),
            Err(TransitionError::NotAllowed)
        );
        assert_eq!(
            check_transition(Suspended, Active, false),
            Err(TransitionError::EmailNotVerified)
        );
        assert_eq!(
            check_transition(PendingDeletion, PendingVerification, true),
            Err(TransitionError::EmailAlreadyVerified)
        );
        let err = AuthError::from(TransitionError::NotAllowed);
        assert_eq!(
            err.code(),
            codes::account::ACCOUNT_STATUS_TRANSITION_NOT_ALLOWED
        );
    }

    #[test]
    fn acc_06_deleted_is_reachable_only_from_purge_states() {
        for &from in AccountStatus::ALL {
            let ok = check_transition(from, Deleted, false).is_ok()
                || check_transition(from, Deleted, true).is_ok();
            assert_eq!(
                ok,
                matches!(from, PendingVerification | PendingDeletion),
                "{from}"
            );
        }
    }

    #[test]
    fn acc_06_resting_status_respects_verification() {
        assert_eq!(resting_status(true), Active);
        assert_eq!(resting_status(false), PendingVerification);
    }

    #[test]
    fn acc_06_reason_codes_are_validated() {
        assert!(is_reason_code("email_verified"));
        assert!(is_reason_code("a1"));
        assert!(!is_reason_code(""));
        assert!(!is_reason_code("Admin"));
        assert!(!is_reason_code("1abc"));
        assert!(!is_reason_code("has space"));
        assert!(!is_reason_code(&"a".repeat(65)));
    }

    fn status() -> impl Strategy<Value = AccountStatus> {
        prop::sample::select(AccountStatus::ALL.to_vec())
    }

    proptest! {
        /// TST-03: random walks through the machine keep the invariants:
        /// `active` implies a verified address, `deleted` is absorbing.
        #[test]
        fn acc_06_random_walks_preserve_invariants(
            steps in prop::collection::vec((status(), any::<bool>()), 1..64)
        ) {
            let mut current = PendingVerification;
            let mut verified = false;
            for (to, verify_now) in steps {
                let verified_after = verified || verify_now;
                if check_transition(current, to, verified_after).is_ok() {
                    prop_assert!(current != Deleted);
                    current = to;
                    verified = verified_after;
                }
                if current == Active {
                    prop_assert!(verified);
                }
                if current == PendingVerification {
                    prop_assert!(!verified);
                }
            }
        }
    }
}
