//! Staff roles through the API (K-93, ADM-09, ADM-10).
//!
//! * `GET /v1/admin/staff` (`staff:read`) lists the staff accounts with
//!   their roles.
//! * `POST /v1/admin/staff/{user_id}/role` (`staff:manage`, i.e.
//!   `platform_admin`) changes the role of **another**, non-break-glass
//!   staff account. The API still never makes a regular account staff nor
//!   removes staff rights (CLI `grant-admin` / `revoke-admin`, K-76): a
//!   compromised console session and a persuaded approver cannot mint new
//!   staff.
//!
//! A role change is a critical operation (`change_staff_role`, K-66):
//! with `admin.four_eyes` on, it needs the approval of a **different**
//! staff member who holds `staff:manage` as well (another
//! `platform_admin`), for the exact target and role. It takes the
//! admin-target budget (K-08), runs in one transaction that also revokes
//! every session and trusted device of the target (the person signs in
//! again; permissions are read from the database on every request anyway,
//! so a demotion applies to the very next request even without that) and
//! records a high-priority `admin.action` (`staff_role_changed`) with the
//! previous and the new role and the justification.

use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{EventId, UserId};
use authn_core::ports::{RevocationReason, RevokeOptions, SecurityEventKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::approvals::CriticalOperation;
use super::{AdminService, TargetPolicy, meta};
use crate::guard::AdminCaller;
use crate::reason::Justification;
use crate::roles::{AdminPermission, StaffRole};
use crate::store;

/// Most staff accounts listed.
const STAFF_LIST_LIMIT: i64 = 1000;

/// A staff account (K-93).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StaffMember {
    /// The account.
    pub user_id: UserId,
    /// Its address.
    pub email: Option<String>,
    /// Account status.
    pub status: String,
    /// Break-glass account (always `platform_admin`; managed by the CLI).
    pub is_break_glass: bool,
    /// The role; `null`: staff flag without a role (no admin permission).
    pub role: Option<StaffRole>,
    /// When the role was last set.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub role_updated_at: Option<OffsetDateTime>,
}

/// Result of a staff role change (K-93).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StaffRoleChange {
    /// The staff member.
    pub user_id: UserId,
    /// The role before the change (`null`: none).
    pub previous_role: Option<StaffRole>,
    /// The new role.
    pub role: StaffRole,
    /// Sessions of the staff member revoked by the change.
    pub sessions_revoked: u64,
    /// The audit event recording the change.
    pub event_id: EventId,
}

const ALL_DEVICES: RevokeOptions = RevokeOptions {
    also_trusted_devices: true,
};

impl AdminService {
    /// Every staff account with its role (`staff:read`).
    pub async fn list_staff(&self, caller: &AdminCaller) -> Result<Vec<StaffMember>, AuthError> {
        caller.require(AdminPermission::StaffRead)?;
        let rows = store::list_staff(self.pool(), STAFF_LIST_LIMIT).await?;
        Ok(rows
            .into_iter()
            .map(|row| StaffMember {
                role: row.role(),
                user_id: row.user_id,
                email: row.email,
                status: row.status,
                is_break_glass: row.is_break_glass,
                role_updated_at: row.role_updated_at,
            })
            .collect())
    }

    /// Changes the role of another, non-break-glass staff member
    /// (`staff:manage`, four-eyes `change_staff_role`; module docs).
    /// `conflict` when the member already has `role`;
    /// `admin_target_not_allowed` for the caller's own account, a
    /// break-glass account or a regular account.
    pub async fn change_staff_role(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        user: UserId,
        role: StaffRole,
        reason: &Justification,
        approval: Option<Uuid>,
    ) -> Result<StaffRoleChange, AuthError> {
        const ACTION: &str = "change_staff_role";
        caller.require(AdminPermission::StaffManage)?;
        let operation = CriticalOperation::ChangeStaffRole { target: user, role };
        self.four_eyes_precheck_target(caller, ctx, &operation, approval)
            .await?;
        let (mut tx, target, staff_target) = self
            .begin_on_target(caller, ctx, user, TargetPolicy::NotBreakGlass, ACTION)
            .await?;
        if !staff_target {
            tx.rollback().await?;
            return Err(AuthError::new(codes::admin::TARGET_NOT_ALLOWED)
                .with_context("roles are changed on staff accounts only"));
        }
        // Both role rows locked in one statement (in user id order, so two
        // staff members changing each other's role cannot deadlock), and
        // the caller's own authority re-checked under the lock: of two
        // concurrent mutual demotions (four-eyes off) only one runs.
        let roles = store::lock_staff_roles(&mut tx, &[caller.user_id(), user]).await?;
        let own = roles
            .iter()
            .find(|(id, _)| *id == caller.user_id())
            .map(|(_, r)| *r);
        if !own.is_some_and(|r| r.grants(AdminPermission::StaffManage)) {
            tx.rollback().await?;
            return Err(AdminPermission::StaffManage.denied());
        }
        let previous = roles.iter().find(|(id, _)| *id == user).map(|(_, r)| *r);
        if previous == Some(role) {
            tx.rollback().await?;
            return Err(AuthError::new(codes::common::CONFLICT)
                .with_context("the staff member already has this role"));
        }
        let four_eyes = match self
            .four_eyes_in_tx(&mut tx, caller, ctx, &operation, approval)
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
        let now = self.now();
        store::set_staff_role(&mut tx, user, role, now).await?;
        let revoked = self
            .deps()
            .sessions
            .revoke_all_for_user(&mut tx, user, RevocationReason::AdminAction, ALL_DEVICES)
            .await?;
        let mut metadata = meta([
            (
                "previous_role",
                previous.map_or(Value::Null, |r| Value::from(r.as_str())),
            ),
            ("role", Value::from(role.as_str())),
            ("sessions_revoked", Value::from(revoked)),
            ("target_status", Value::from(target.status.as_str())),
            ("admin_target", Value::from(true)),
            ("priority", Value::from("high")),
        ]);
        metadata.extend(four_eyes);
        let event = self
            .record_action(
                &mut tx,
                ctx,
                caller,
                SecurityEventKind::AdminAction,
                "staff_role_changed",
                Some(user),
                Some(reason),
                metadata,
            )
            .await?;
        authn_store::commit(tx).await?;
        tracing::warn!(
            admin = %caller.user_id(),
            target_user = %user,
            role = role.as_str(),
            "staff role changed (high priority)"
        );
        Ok(StaffRoleChange {
            user_id: user,
            previous_role: previous,
            role,
            sessions_revoked: revoked,
            event_id: event,
        })
    }
}
