//! Memberships (ORG-02) with last-owner protection and the escalation
//! guard (ORG-04).
//!
//! Rules enforced for every change of another member: the actor must hold
//! every permission of the target's *current* role (nobody manages a more
//! privileged member) and of the *new* role, and only owners act on owners
//! or grant `owner` (step-up required for granting `owner`). A change that
//! removes the last active owner is refused (`org_last_owner`; the database
//! re-checks at commit). Removal, suspension and downgrades revoke the
//! member's sessions in the organization (`SessionRevoker`) and revoke the
//! pending invitations the member sent; removal also deletes the member's
//! personal API keys there (foreign-key cascade).

use authn_core::domain::{Page, PageRequest, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{MembershipId, OrgId, RoleId, UserId};
use authn_core::ports::{DomainEventKind, RevocationReason, SecurityEventKind};
use authn_store::UserRepository;
use serde::Deserialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::roles::load_role;
use super::{OrgService, cursor_of, fetch_limit, page_after, require_session_user};
use crate::authz::{self, Authorization};
use crate::model::{Member, MemberPage, MemberStatus, RoleRef};
use crate::permission::{OWNER_ROLE_ID, Permission, PermissionSet, is_owner_role};

/// Body of `PATCH /v1/orgs/{org_id}/members/{member_id}`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateMember {
    /// New role (built-in or a custom role of this organization).
    pub role_id: Option<RoleId>,
    /// New status (`active` / `suspended`).
    pub status: Option<MemberStatus>,
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    id: MembershipId,
    user_id: UserId,
    status: MemberStatus,
    invited_by: Option<UserId>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    role_id: RoleId,
    role_key: String,
    role_name: String,
}

/// A membership row locked for a change.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct LockedMember {
    pub id: MembershipId,
    pub user_id: UserId,
    pub status: MemberStatus,
    pub role_id: RoleId,
    pub permissions: Vec<String>,
    pub created_at: OffsetDateTime,
}

impl LockedMember {
    pub(crate) fn permission_set(&self) -> PermissionSet {
        PermissionSet::from_db(&self.permissions)
    }

    pub(crate) fn is_active_owner(&self) -> bool {
        self.status == MemberStatus::Active && is_owner_role(self.role_id)
    }
}

macro_rules! member_select {
    () => {
        "SELECT m.id, m.user_id, m.status, m.invited_by, m.created_at, m.updated_at, \
         r.id AS role_id, r.key AS role_key, r.name AS role_name \
         FROM memberships m JOIN roles r ON r.id = m.role_id "
    };
}

impl OrgService {
    /// Lists members (`members:read`), oldest first.
    pub async fn list_members(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        page: &PageRequest,
    ) -> Result<MemberPage, AuthError> {
        self.authorize(ctx, principal, Permission::MembersRead, org)
            .await?;
        let (after_at, after_id) = page_after(page)?;
        let sql = concat!(
            member_select!(),
            "WHERE m.org_id = $1 AND ($2::timestamptz IS NULL OR (m.created_at, m.id) > ($2, $3)) \
             ORDER BY m.created_at, m.id LIMIT $4"
        );
        let rows = sqlx::query_as::<_, MemberRow>(sql)
            .bind(org)
            .bind(after_at)
            .bind(after_id)
            .bind(fetch_limit(page))
            .fetch_all(self.pool())
            .await?;
        let page = Page::from_overfetch(rows, page.limit(), |r| {
            cursor_of(r.created_at, r.id.as_uuid())
        });
        let mut items = Vec::with_capacity(page.items.len());
        for row in page.items {
            items.push(self.member_from_row(row).await?);
        }
        Ok(MemberPage {
            items,
            next_cursor: page.next_cursor,
        })
    }

    /// Reads one member (`members:read`).
    pub async fn get_member(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        member: MembershipId,
    ) -> Result<Member, AuthError> {
        self.authorize(ctx, principal, Permission::MembersRead, org)
            .await?;
        self.load_member(org, member).await
    }

    /// Changes a member's role and / or status (`members:update`).
    pub async fn update_member(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        member: MembershipId,
        input: UpdateMember,
    ) -> Result<Member, AuthError> {
        if input.role_id.is_none() && input.status.is_none() {
            return Err(crate::validate::invalid("role_id"));
        }
        if input.role_id == Some(OWNER_ROLE_ID) {
            self.require_step_up(principal)?;
        }
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::MembersUpdate, org)
            .await?;
        let target = lock_member(&mut tx, org, member).await?;
        auth.ensure_can_grant(target.role_id, &target.permission_set())?;
        let is_self = auth.user_id() == Some(target.user_id);
        if is_self && input.status == Some(MemberStatus::Suspended) {
            return Err(AuthError::new(codes::common::CONFLICT)
                .with_context("members cannot suspend themselves"));
        }
        let new_role = match input.role_id {
            Some(role_id) if role_id != target.role_id => {
                let role = load_role(&mut tx, org, role_id)
                    .await?
                    .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
                auth.ensure_can_grant(role.id, &role.permission_set())?;
                Some(role)
            }
            _ => None,
        };
        let new_role_id = new_role.as_ref().map_or(target.role_id, |r| r.id);
        let new_status = input.status.unwrap_or(target.status);
        let stays_owner = is_owner_role(new_role_id) && new_status == MemberStatus::Active;
        if target.is_active_owner() && !stays_owner {
            ensure_other_owner(&mut tx, org, target.user_id).await?;
        }
        sqlx::query(
            "UPDATE memberships SET role_id = $3, status = $4 WHERE id = $1 AND org_id = $2",
        )
        .bind(member)
        .bind(org)
        .bind(new_role_id)
        .bind(new_status)
        .execute(&mut *tx)
        .await?;
        let downgraded = new_role
            .as_ref()
            .is_some_and(|r| !r.permission_set().is_superset(&target.permission_set()));
        let suspended =
            new_status == MemberStatus::Suspended && target.status == MemberStatus::Active;
        let mut sessions_revoked = 0;
        if downgraded || suspended {
            sessions_revoked = self
                .deps()
                .session_revoker
                .revoke_for_user_in_org(
                    &mut tx,
                    target.user_id,
                    org,
                    RevocationReason::MembershipRemoved,
                )
                .await?;
            revoke_invitations_sent_by(&mut tx, org, target.user_id, self.now()).await?;
        }
        if new_role.is_some() {
            self.publish(
                &mut tx,
                DomainEventKind::MemberRoleChanged,
                org,
                Some(target.user_id),
                serde_json::json!({
                    "org_id": org,
                    "user_id": target.user_id,
                    "role_id": new_role_id,
                }),
            )
            .await?;
        }
        let kind = if new_role.is_some() {
            SecurityEventKind::MemberRoleChanged
        } else {
            SecurityEventKind::MemberStatusChanged
        };
        let event = self
            .event(kind, ctx, principal, Some(org))
            .with_subject(target.user_id)
            .with_resource("membership", member)
            .with_meta("from_role", target.role_id.to_string())
            .with_meta("to_role", new_role_id.to_string())
            .with_meta("status", new_status.as_str())
            .with_meta("sessions_revoked", sessions_revoked);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        self.load_member(org, member).await
    }

    /// Removes a member (`members:remove`).
    pub async fn remove_member(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        member: MembershipId,
    ) -> Result<(), AuthError> {
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::MembersRemove, org)
            .await?;
        let target = lock_member(&mut tx, org, member).await?;
        auth.ensure_can_grant(target.role_id, &target.permission_set())?;
        self.delete_membership(&mut tx, ctx, principal, org, &target, "removed")
            .await?;
        authn_store::commit(tx).await
    }

    /// The caller leaves the organization. Needs no permission, only an
    /// active membership; the last owner cannot leave (ORG-02).
    pub async fn leave_organization(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<(), AuthError> {
        let user = require_session_user(principal)?;
        let mut tx = self.begin().await?;
        // Any active member may leave: authorize on the always-granted
        // membership itself (tenant isolation and status still apply).
        let auth = self
            .authorize_membership(&mut tx, ctx, principal, org)
            .await?;
        super::lock_org(&mut tx, org).await?;
        let _auth = self
            .authorize_membership(&mut tx, ctx, principal, org)
            .await?;
        let membership = match auth.subject {
            authz::AuthzSubject::Member { membership_id, .. } => membership_id,
            authz::AuthzSubject::ServiceAccount { .. } => {
                return Err(AuthError::new(codes::common::FORBIDDEN));
            }
        };
        let target = lock_member(&mut tx, org, membership).await?;
        if target.user_id != user {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        }
        self.delete_membership(&mut tx, ctx, principal, org, &target, "left")
            .await?;
        authn_store::commit(tx).await
    }

    /// Organizations in which `user` is the only active owner (ACC-09:
    /// account deletion must be refused until ownership is transferred).
    /// Runs on the caller's connection / transaction.
    pub async fn sole_owner_organizations(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<OrgId>, AuthError> {
        sole_owner_organizations(conn, user).await
    }

    async fn authorize_membership(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<Authorization, AuthError> {
        principal.require_writable()?;
        let facts = authz::load_facts(&mut *conn, principal, org).await?;
        authz::decide_membership(facts, principal, Some(ctx.client_ip), self.now())
    }

    async fn delete_membership(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        target: &LockedMember,
        reason: &'static str,
    ) -> Result<(), AuthError> {
        if target.is_active_owner() {
            ensure_other_owner(&mut *conn, org, target.user_id).await?;
        }
        sqlx::query("DELETE FROM memberships WHERE id = $1 AND org_id = $2")
            .bind(target.id)
            .bind(org)
            .execute(&mut *conn)
            .await?;
        // ORG-06: domain auto-join must not silently undo this.
        sqlx::query(
            "INSERT INTO org_auto_join_exclusions (org_id, user_id, reason, created_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (org_id, user_id) DO UPDATE SET reason = EXCLUDED.reason, \
             created_at = EXCLUDED.created_at",
        )
        .bind(org)
        .bind(target.user_id)
        .bind(reason)
        .bind(self.now())
        .execute(&mut *conn)
        .await?;
        revoke_invitations_sent_by(&mut *conn, org, target.user_id, self.now()).await?;
        let revoked = self
            .deps()
            .session_revoker
            .revoke_for_user_in_org(
                &mut *conn,
                target.user_id,
                org,
                RevocationReason::MembershipRemoved,
            )
            .await?;
        self.publish(
            &mut *conn,
            DomainEventKind::MemberRemoved,
            org,
            Some(target.user_id),
            serde_json::json!({ "org_id": org, "user_id": target.user_id }),
        )
        .await?;
        let event = self
            .event(SecurityEventKind::MemberRemoved, ctx, principal, Some(org))
            .with_subject(target.user_id)
            .with_resource("membership", target.id)
            .with_meta("reason", reason)
            .with_meta("sessions_revoked", revoked);
        self.audit_in_tx(conn, event).await
    }

    async fn load_member(&self, org: OrgId, member: MembershipId) -> Result<Member, AuthError> {
        let sql = concat!(member_select!(), "WHERE m.org_id = $1 AND m.id = $2");
        let row = sqlx::query_as::<_, MemberRow>(sql)
            .bind(org)
            .bind(member)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        self.member_from_row(row).await
    }

    async fn member_from_row(&self, row: MemberRow) -> Result<Member, AuthError> {
        let email = UserRepository::find_by_id(self.pool(), row.user_id)
            .await?
            .and_then(|u| u.email);
        Ok(Member {
            id: row.id,
            user_id: row.user_id,
            email,
            role: RoleRef {
                id: row.role_id,
                key: row.role_key,
                name: row.role_name,
            },
            status: row.status,
            invited_by: row.invited_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// Locks a membership of `org` (`404` for other organizations).
pub(crate) async fn lock_member(
    conn: &mut PgConnection,
    org: OrgId,
    member: MembershipId,
) -> Result<LockedMember, AuthError> {
    sqlx::query_as::<_, LockedMember>(
        "SELECT m.id, m.user_id, m.status, m.role_id, m.created_at, \
         ARRAY(SELECT rp.permission FROM role_permissions rp WHERE rp.role_id = m.role_id) \
         AS permissions \
         FROM memberships m WHERE m.org_id = $1 AND m.id = $2 FOR UPDATE",
    )
    .bind(org)
    .bind(member)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
}

/// Locks the membership of `user` in `org`, if any.
pub(crate) async fn lock_member_of_user(
    conn: &mut PgConnection,
    org: OrgId,
    user: UserId,
) -> Result<Option<LockedMember>, AuthError> {
    Ok(sqlx::query_as::<_, LockedMember>(
        "SELECT m.id, m.user_id, m.status, m.role_id, m.created_at, \
         ARRAY(SELECT rp.permission FROM role_permissions rp WHERE rp.role_id = m.role_id) \
         AS permissions \
         FROM memberships m WHERE m.org_id = $1 AND m.user_id = $2 FOR UPDATE",
    )
    .bind(org)
    .bind(user)
    .fetch_optional(conn)
    .await?)
}

/// Revokes the pending invitations a member sent (ORG-04): when the member
/// is removed, suspended or loses permissions, an invitation they issued
/// must not still grant a role they can no longer grant.
pub(crate) async fn revoke_invitations_sent_by(
    conn: &mut PgConnection,
    org: OrgId,
    user: UserId,
    now: OffsetDateTime,
) -> Result<u64, AuthError> {
    Ok(sqlx::query(
        "UPDATE invitations SET status = 'revoked', revoked_at = $3 \
         WHERE org_id = $1 AND invited_by = $2 AND status = 'pending'",
    )
    .bind(org)
    .bind(user)
    .bind(now)
    .execute(conn)
    .await?
    .rows_affected())
}

/// `org_last_owner` unless another active owner than `user` exists. Call
/// with the organization row locked.
pub(crate) async fn ensure_other_owner(
    conn: &mut PgConnection,
    org: OrgId,
    user: UserId,
) -> Result<(), AuthError> {
    let others: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memberships WHERE org_id = $1 AND role_id = $2 \
         AND status = 'active' AND user_id <> $3",
    )
    .bind(org)
    .bind(OWNER_ROLE_ID)
    .bind(user)
    .fetch_one(conn)
    .await?;
    if others > 0 {
        Ok(())
    } else {
        Err(AuthError::new(codes::org::ORG_LAST_OWNER))
    }
}

/// Organizations in which `user` is the only active owner (ACC-09, ORG-02).
pub async fn sole_owner_organizations(
    conn: &mut PgConnection,
    user: UserId,
) -> Result<Vec<OrgId>, AuthError> {
    Ok(sqlx::query_scalar(
        "SELECT m.org_id FROM memberships m \
         WHERE m.user_id = $1 AND m.role_id = $2 AND m.status = 'active' \
         AND NOT EXISTS (SELECT 1 FROM memberships o WHERE o.org_id = m.org_id \
                         AND o.role_id = $2 AND o.status = 'active' AND o.user_id <> $1) \
         ORDER BY m.org_id",
    )
    .bind(user)
    .bind(OWNER_ROLE_ID)
    .fetch_all(conn)
    .await?)
}
