//! Four-eyes approval of critical admin operations (K-66).
//!
//! **Critical operations**: the emergency operations (ADM-06: revoke every
//! session, emergency signing key rotation, bulk forced password change)
//! and the actions on **another platform admin** (ADM-03: suspend, unlock,
//! revoke sessions — the only ones the API allows on admins). K-08 limits
//! the damage of one compromised admin console session; four-eyes prevents
//! it: such an operation needs a second platform admin.
//!
//! Flow (`admin.four_eyes`, default on in production and staging):
//!
//! 1. The requester asks for an approval (`POST /v1/admin/approvals`) with
//!    the exact operation and parameters and a justification. The request
//!    is stored with `params_hash` = SHA-256 of the canonical parameters
//!    and expires after `admin.four_eyes_approval_ttl` (default 30 min).
//!    Audited (`admin.approval_requested`). At most 3 pending and 10
//!    requests per hour per requester (`429 rate_limited`, audited): no
//!    approval fatigue by flooding the other admins with prompts.
//! 2. A **different** platform admin — who passes the same ADM-01 guard
//!    (passkey session with `mfa`, step-up within `step_up_max_age`, IP
//!    allow-list) and is not the target of the operation — approves or
//!    denies it with a justification. Audited (`admin.approval_decided`).
//!    Decisions are final.
//!
//!    The request and decision events of an action on another admin name
//!    that admin as subject; until the request expires they are hidden
//!    from the target's own event list (`authn_audit::holds`) and their
//!    justifications from its data export — a compromised admin gets no
//!    warning of its containment. Afterwards both are visible.
//! 3. The requester runs the operation with `approval_id`. Inside the
//!    operation's transaction one conditional `UPDATE` consumes the
//!    approval: same requester, same operation, same target, same
//!    parameter hash, approved, unexpired, unused, approver still an
//!    active platform admin. Single use: a replay, a changed parameter, an
//!    expired or denied approval all answer `403 admin_approval_invalid`;
//!    no approval answers `403 admin_approval_required`. Refusals are
//!    audited as high-priority failed `admin.action` events. The
//!    operation's own event carries `four_eyes = approved` and the
//!    approval id.
//!
//! **Exceptions** (each recorded as a high-priority
//! `admin.four_eyes_bypassed` event in the operation's transaction, and in
//! the operation's metadata):
//!
//! * `break_glass` — a break-glass account (ADM-05) is the recovery path of
//!   last resort, used precisely when the other admins are compromised or
//!   unreachable; it is never blocked by four-eyes. Every break-glass use
//!   is already a high-priority `admin.break_glass_used` event, and
//!   break-glass accounts are created and managed offline only.
//! * `no_second_admin` — no other active, non-break-glass platform admin
//!   exists at all: requiring an impossible approval would only push
//!   operators to share accounts. The **target counts** as another admin
//!   (audit finding): with two admins, neither can suspend, unlock or
//!   revoke the other alone — that needs a third admin's approval, the
//!   break-glass account or the CLI. So an attacker cannot manufacture this
//!   state through the API: removing an active admin is always a
//!   four-eyes operation while that admin exists, and creating or
//!   demoting admins is CLI-only.

use authn_core::domain::AccountStatus;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{Actor, SecurityEvent, SecurityEventKind};
use authn_store::UserRepository;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::PgConnection;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::ToSchema;
use uuid::Uuid;

use super::limits::{Limit, MAX_APPROVALS_PER_HOUR, MAX_PENDING_APPROVALS};
use super::{AdminService, TargetPolicy, check_target, meta};
use crate::guard::AdminCaller;
use crate::reason::Justification;
use crate::store;

/// A critical operation with its exact parameters (K-66).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriticalOperation {
    /// ADM-06 revoke every session.
    RevokeAllSessions {
        /// Whether the caller's own session is revoked too.
        include_own_session: bool,
    },
    /// ADM-06 emergency signing key rotation.
    RotateSigningKey,
    /// ADM-06 bulk forced password change.
    ForcePasswordChange {
        /// Passwords changed before this instant.
        changed_before: OffsetDateTime,
        /// Whether sessions are revoked too.
        revoke_sessions: bool,
    },
    /// ADM-03 suspend another platform admin.
    SuspendAdmin(UserId),
    /// ADM-03 unlock another platform admin.
    UnlockAdmin(UserId),
    /// ADM-03 revoke the sessions of another platform admin.
    RevokeAdminSessions(UserId),
}

impl CriticalOperation {
    /// The operation's action code (as audited).
    #[must_use]
    pub fn action(&self) -> &'static str {
        match self {
            Self::RevokeAllSessions { .. } => "revoke_all_sessions",
            Self::RotateSigningKey => "rotate_signing_key",
            Self::ForcePasswordChange { .. } => "force_password_change_before",
            Self::SuspendAdmin(_) => "suspend_user",
            Self::UnlockAdmin(_) => "unlock_user",
            Self::RevokeAdminSessions(_) => "revoke_user_sessions",
        }
    }

    /// The account the operation targets, if any.
    #[must_use]
    pub fn target(&self) -> Option<UserId> {
        match self {
            Self::SuspendAdmin(u) | Self::UnlockAdmin(u) | Self::RevokeAdminSessions(u) => Some(*u),
            _ => None,
        }
    }

    /// The parameters as shown to the approver.
    fn params(&self) -> Map<String, Value> {
        match self {
            Self::RevokeAllSessions {
                include_own_session,
            } => meta([("include_own_session", Value::from(*include_own_session))]),
            Self::ForcePasswordChange {
                changed_before,
                revoke_sessions,
            } => meta([
                (
                    "changed_before",
                    Value::from(utc(*changed_before).format(&Rfc3339).unwrap_or_default()),
                ),
                ("revoke_sessions", Value::from(*revoke_sessions)),
            ]),
            Self::RotateSigningKey
            | Self::SuspendAdmin(_)
            | Self::UnlockAdmin(_)
            | Self::RevokeAdminSessions(_) => Map::new(),
        }
    }

    /// SHA-256 of the canonical form: version, action, target and every
    /// parameter in a fixed order (instants as UTC nanoseconds, so
    /// equivalent spellings of one instant hash alike).
    #[must_use]
    pub fn params_hash(&self) -> [u8; 32] {
        let target = self
            .target()
            .map_or_else(|| "-".to_owned(), |u| u.to_string());
        let params = match self {
            Self::RevokeAllSessions {
                include_own_session,
            } => format!("include_own_session={include_own_session}"),
            Self::ForcePasswordChange {
                changed_before,
                revoke_sessions,
            } => format!(
                "changed_before={};revoke_sessions={revoke_sessions}",
                changed_before.unix_timestamp_nanos()
            ),
            Self::RotateSigningKey
            | Self::SuspendAdmin(_)
            | Self::UnlockAdmin(_)
            | Self::RevokeAdminSessions(_) => String::new(),
        };
        authn_crypto::sha256(
            format!(
                "authn-admin/four-eyes/v1\n{}\n{target}\n{params}",
                self.action()
            )
            .as_bytes(),
        )
    }
}

fn utc(at: OffsetDateTime) -> OffsetDateTime {
    at.to_offset(time::UtcOffset::UTC)
}

/// A four-eyes approval request as shown to admins (K-66).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApprovalView {
    /// Approval id (pass it as `approval_id` when running the operation).
    #[schema(value_type = String)]
    pub id: Uuid,
    /// The operation's action code.
    pub action: String,
    /// The target account, for actions on another admin.
    pub target_user_id: Option<UserId>,
    /// The operation's parameters.
    #[schema(value_type = Object)]
    pub params: Value,
    /// The requesting admin (the only one who may use the approval).
    pub requested_by: UserId,
    /// The requester's justification.
    pub reason: Option<String>,
    /// When it was requested.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// When it expires (unused).
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub expires_at: OffsetDateTime,
    /// `pending`, `approved`, `denied`, `expired` or `used`.
    pub status: String,
    /// The deciding admin.
    pub decided_by: Option<UserId>,
}

/// Why an operation was refused by four-eyes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FourEyesRefusal {
    /// No approval was given although one is needed.
    Required,
    /// The given approval cannot be used for this operation.
    Invalid,
}

impl FourEyesRefusal {
    fn reason(self) -> &'static str {
        match self {
            Self::Required => "four_eyes_approval_required",
            Self::Invalid => "four_eyes_approval_invalid",
        }
    }

    fn error(self) -> AuthError {
        match self {
            Self::Required => AuthError::new(codes::admin::APPROVAL_REQUIRED),
            Self::Invalid => AuthError::new(codes::admin::APPROVAL_INVALID),
        }
    }
}

/// Outcome of the four-eyes check inside an operation's transaction:
/// metadata for the operation's audit event, or a refusal.
pub(crate) type FourEyes = Result<Map<String, Value>, FourEyesRefusal>;

impl AdminService {
    /// Requests the approval of `operation` by a second platform admin
    /// (K-66). The target (if any) must exist and be another account that
    /// the operation may target.
    pub async fn request_approval(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        operation: CriticalOperation,
        reason: &Justification,
    ) -> Result<ApprovalView, AuthError> {
        if let Some(target) = operation.target() {
            let record = UserRepository::find_by_id(self.pool(), target)
                .await?
                .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
            let policy = match operation {
                CriticalOperation::UnlockAdmin(_) => TargetPolicy::NotSelf,
                _ => TargetPolicy::NotBreakGlass,
            };
            check_target(caller, &record, policy)?;
        }
        let now = self.now();
        let expires_at = now + self.settings().four_eyes_approval_ttl;
        let id = Uuid::now_v7();
        let params = Value::Object(operation.params());
        let mut tx = self.begin().await?;
        // Approval fatigue: cap the prompts one admin can raise.
        let (pending, recent) = store::lock_and_count_requests(
            &mut tx,
            caller.user_id(),
            now,
            now - time::Duration::hours(1),
        )
        .await?;
        let exceeded = if pending >= MAX_PENDING_APPROVALS {
            Some(Limit::ApprovalsPendingPerAdmin)
        } else if recent >= MAX_APPROVALS_PER_HOUR {
            Some(Limit::ApprovalsPerHourPerAdmin)
        } else {
            None
        };
        if let Some(limit) = exceeded {
            tx.rollback().await?;
            let wait = self.settings().four_eyes_approval_ttl;
            return Err(self
                .throttled(caller, ctx, "approval_requested", limit, wait)
                .await);
        }
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminApprovalRequested,
                "approval_requested",
                operation.target(),
                Some(reason),
                meta([
                    ("approval_id", Value::from(id.to_string())),
                    ("requested_action", Value::from(operation.action())),
                    (
                        "expires_at",
                        Value::from(expires_at.format(&Rfc3339).unwrap_or_default()),
                    ),
                    ("priority", Value::from("high")),
                ]),
            )
            .await?;
        if operation.target().is_some() {
            // No tip-off: the target admin does not see a pending request
            // in its own list (the export leaves the justification out
            // as long, `store::reasons_about`).
            authn_audit::hide_from_subject_in_tx(&mut tx, event, expires_at, now).await?;
        }
        store::insert_approval(
            &mut tx,
            &store::NewApproval {
                id,
                action: operation.action(),
                params: &params,
                params_hash: &operation.params_hash(),
                target: operation.target(),
                requested_by: caller.user_id(),
                request_event: event,
                created_at: now,
                expires_at,
            },
        )
        .await?;
        authn_store::commit(tx).await?;
        tracing::warn!(
            admin = %caller.user_id(),
            approval = %id,
            action = operation.action(),
            "four-eyes approval requested"
        );
        self.approval(id).await
    }

    /// Approves (`approve`) or denies a pending request of **another**
    /// admin (K-66), with a justification. The deciding admin passed the
    /// ADM-01 guard (the [`AdminCaller`]) and must not be the requester
    /// (`admin_self_approval_not_allowed`) nor the operation's target
    /// (`admin_target_not_allowed`). Decided or expired requests answer
    /// `admin_approval_invalid`; unknown ones `404`.
    pub async fn decide_approval(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        id: Uuid,
        approve: bool,
        reason: &Justification,
    ) -> Result<ApprovalView, AuthError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let row = store::lock_approval(&mut tx, id)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let refusal = if row.requested_by == caller.user_id() {
            Some((
                "four_eyes_self_approval",
                AuthError::new(codes::admin::SELF_APPROVAL_NOT_ALLOWED),
            ))
        } else if row.target_user_id == Some(caller.user_id()) {
            Some((
                "four_eyes_target_approval",
                AuthError::new(codes::admin::TARGET_NOT_ALLOWED)
                    .with_context("the target of an operation cannot decide on it"),
            ))
        } else if row.decision.is_some() || row.expires_at <= now {
            Some((
                "four_eyes_approval_not_pending",
                AuthError::new(codes::admin::APPROVAL_INVALID),
            ))
        } else {
            None
        };
        if let Some((why, error)) = refusal {
            tx.rollback().await?;
            self.audit_four_eyes_refusal(caller, ctx, "approval_decided", why, Some(id))
                .await;
            return Err(error);
        }
        let decision = if approve { "approved" } else { "denied" };
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminApprovalDecided,
                "approval_decided",
                row.target_user_id,
                Some(reason),
                meta([
                    ("approval_id", Value::from(id.to_string())),
                    ("requested_action", Value::from(row.action.clone())),
                    ("decision", Value::from(decision)),
                    ("priority", Value::from("high")),
                ]),
            )
            .await?;
        if row.target_user_id.is_some() {
            // Hidden from the target as long as the request (no tip-off).
            authn_audit::hide_from_subject_in_tx(&mut tx, event, row.expires_at, now).await?;
        }
        store::decide_approval(&mut tx, id, decision, caller.user_id(), event, now).await?;
        authn_store::commit(tx).await?;
        tracing::warn!(
            admin = %caller.user_id(),
            approval = %id,
            decision,
            "four-eyes approval decided"
        );
        self.approval(id).await
    }

    /// Recent approval requests (pending first, newest first; K-66).
    pub async fn list_approvals(
        &self,
        _caller: &AdminCaller,
    ) -> Result<Vec<ApprovalView>, AuthError> {
        let now = self.now();
        let rows = store::recent_approvals(self.pool(), now - time::Duration::days(7), 100).await?;
        Ok(rows.into_iter().map(|r| r.into_view(now)).collect())
    }

    async fn approval(&self, id: Uuid) -> Result<ApprovalView, AuthError> {
        let now = self.now();
        store::approval(self.pool(), id)
            .await?
            .map(|r| r.into_view(now))
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
    }

    /// The four-eyes rule for `operation`, inside the operation's
    /// transaction (K-66): consumes `approval` (single use) or applies an
    /// exception (recorded as `admin.four_eyes_bypassed` in the same
    /// transaction). `Ok(Err(_))`: refused — the caller rolls back and
    /// answers with [`Self::refuse_four_eyes`].
    pub(crate) async fn four_eyes_in_tx(
        &self,
        conn: &mut PgConnection,
        caller: &AdminCaller,
        ctx: &RequestContext,
        operation: &CriticalOperation,
        approval: Option<Uuid>,
    ) -> Result<FourEyes, AuthError> {
        if !self.settings().four_eyes {
            return Ok(Ok(Map::new()));
        }
        let now = self.now();
        if let Some(id) = approval {
            let approver = store::consume_approval(
                &mut *conn,
                &store::ApprovalUse {
                    id,
                    requested_by: caller.user_id(),
                    action: operation.action(),
                    params_hash: &operation.params_hash(),
                    target: operation.target(),
                    now,
                },
            )
            .await?;
            let approver_ok = match approver {
                Some(approver) => UserRepository::find_by_id(&mut *conn, approver)
                    .await?
                    .is_some_and(|u| u.is_platform_admin && u.status == AccountStatus::Active),
                None => false,
            };
            if !approver_ok {
                return Ok(Err(FourEyesRefusal::Invalid));
            }
            return Ok(Ok(meta([
                ("four_eyes", Value::from("approved")),
                ("approval_id", Value::from(id.to_string())),
            ])));
        }
        let exception = if caller.is_break_glass() {
            Some("break_glass")
        } else if !self.second_admin_exists(&mut *conn, caller).await? {
            Some("no_second_admin")
        } else {
            None
        };
        let Some(exception) = exception else {
            return Ok(Err(FourEyesRefusal::Required));
        };
        tracing::warn!(
            admin = %caller.user_id(),
            action = operation.action(),
            exception,
            "critical admin operation without four-eyes approval (high priority)"
        );
        let mut event = SecurityEvent::new(SecurityEventKind::AdminFourEyesBypassed, now)
            .with_context(ctx)
            .with_actor(Actor::User(caller.user_id()))
            .with_meta("action", operation.action())
            .with_meta("exception", exception)
            .with_meta("priority", "high");
        if let Some(target) = operation.target() {
            event = event.with_subject(target);
        }
        self.deps().audit.record_in_tx(&mut *conn, event).await?;
        crate::metrics::four_eyes_bypassed(exception);
        Ok(Ok(meta([
            ("four_eyes", Value::from("bypassed")),
            ("four_eyes_exception", Value::from(exception)),
            ("priority", Value::from("high")),
        ])))
    }

    /// Read-only four-eyes check **before** any rate-limit budget is
    /// spent (K-66 with K-08): an operation without a usable approval is
    /// refused here, so a compromised admin cannot burn the shared
    /// emergency cool-down or the global admin-target budget with
    /// unapproved (or forged) attempts and block the real incident
    /// response. The authoritative, single-use consumption happens later in
    /// the operation's transaction ([`Self::four_eyes_in_tx`]).
    pub(crate) async fn four_eyes_precheck(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        operation: &CriticalOperation,
        approval: Option<Uuid>,
    ) -> Result<(), AuthError> {
        if !self.settings().four_eyes || caller.is_break_glass() {
            return Ok(());
        }
        let refusal = match approval {
            Some(id) => {
                let usable = store::approval_usable(
                    self.pool(),
                    &store::ApprovalUse {
                        id,
                        requested_by: caller.user_id(),
                        action: operation.action(),
                        params_hash: &operation.params_hash(),
                        target: operation.target(),
                        now: self.now(),
                    },
                )
                .await?;
                (!usable).then_some(FourEyesRefusal::Invalid)
            }
            None => {
                let mut conn = self.pool().acquire().await?;
                let second = self.second_admin_exists(&mut conn, caller).await?;
                second.then_some(FourEyesRefusal::Required)
            }
        };
        match refusal {
            None => Ok(()),
            Some(refusal) => Err(self
                .refuse_four_eyes(caller, ctx, operation, refusal, approval)
                .await),
        }
    }

    /// [`Self::four_eyes_precheck`] for an ADM-03 action on `target`: only
    /// relevant when the target is (currently) another platform admin; the
    /// locked row decides again inside the transaction.
    pub(crate) async fn four_eyes_precheck_target(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        operation: &CriticalOperation,
        approval: Option<Uuid>,
    ) -> Result<(), AuthError> {
        let Some(target) = operation.target() else {
            return Ok(());
        };
        let is_admin = UserRepository::find_by_id(self.pool(), target)
            .await?
            .is_some_and(|u| u.is_platform_admin && u.id != caller.user_id());
        if is_admin {
            self.four_eyes_precheck(caller, ctx, operation, approval)
                .await?;
        }
        Ok(())
    }

    /// [`Self::four_eyes_in_tx`] for an ADM-03 action: only an action whose
    /// (locked) target is another platform admin is critical.
    pub(crate) async fn four_eyes_on_admin_target(
        &self,
        conn: &mut PgConnection,
        caller: &AdminCaller,
        ctx: &RequestContext,
        admin_target: bool,
        operation: &CriticalOperation,
        approval: Option<Uuid>,
    ) -> Result<FourEyes, AuthError> {
        if !admin_target {
            return Ok(Ok(Map::new()));
        }
        self.four_eyes_in_tx(conn, caller, ctx, operation, approval)
            .await
    }

    /// Records a refused critical operation (high priority, no open
    /// transaction) and returns the error to answer with.
    pub(crate) async fn refuse_four_eyes(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        operation: &CriticalOperation,
        refusal: FourEyesRefusal,
        approval: Option<Uuid>,
    ) -> AuthError {
        self.audit_four_eyes_refusal(caller, ctx, operation.action(), refusal.reason(), approval)
            .await;
        refusal.error()
    }

    async fn audit_four_eyes_refusal(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        action: &str,
        why: &'static str,
        approval: Option<Uuid>,
    ) {
        crate::metrics::four_eyes_refused(why);
        tracing::warn!(
            admin = %caller.user_id(),
            action,
            reason = why,
            "critical admin operation refused by four-eyes (high priority)"
        );
        let mut event = SecurityEvent::new(SecurityEventKind::AdminAction, self.now())
            .with_context(ctx)
            .with_actor(Actor::User(caller.user_id()))
            .with_meta("action", action.to_owned())
            .with_meta("priority", "high")
            .failed(why);
        if let Some(id) = approval {
            event = event.with_meta("approval_id", id.to_string());
        }
        if let Err(err) = self.deps().audit.record(event).await {
            tracing::error!(
                code = err.code().code(),
                "could not audit a four-eyes refusal"
            );
        }
    }

    /// Whether another active, non-break-glass platform admin exists
    /// besides the caller — **the target included** (K-66 audit). The
    /// single-admin exception applies only when no such admin exists at
    /// all. When the only other admin is the target, the operation still
    /// needs an approval (which only a third admin could give): otherwise
    /// one compromised admin of two could suspend the other through the
    /// exception and then run every critical operation alone. That case is
    /// for the break-glass account (never blocked) or the CLI. One exact
    /// `EXISTS` over every admin (no page of the newest few that
    /// break-glass accounts could fill).
    async fn second_admin_exists(
        &self,
        conn: &mut PgConnection,
        caller: &AdminCaller,
    ) -> Result<bool, AuthError> {
        Ok(store::other_active_admin_exists(conn, caller.user_id()).await?)
    }

    /// [`Self::four_eyes_in_tx`] in a transaction of its own, for an
    /// operation that spans several transactions (the bulk password
    /// change): the approval is consumed before the first batch.
    pub(crate) async fn four_eyes_standalone(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        operation: &CriticalOperation,
        approval: Option<Uuid>,
    ) -> Result<Map<String, Value>, AuthError> {
        let mut tx = self.begin().await?;
        match self
            .four_eyes_in_tx(&mut tx, caller, ctx, operation, approval)
            .await?
        {
            Ok(metadata) => {
                authn_store::commit(tx).await?;
                Ok(metadata)
            }
            Err(refusal) => {
                tx.rollback().await?;
                Err(self
                    .refuse_four_eyes(caller, ctx, operation, refusal, approval)
                    .await)
            }
        }
    }
}
