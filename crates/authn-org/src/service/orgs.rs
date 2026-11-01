//! Organization lifecycle (ORG-01, ORG-12).

use authn_core::domain::{Page, PageRequest, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{MembershipId, OrgId, RoleId, UserId};
use authn_core::ports::{
    Actor, DomainEventKind, RateLimitKey, RevocationReason, SecurityEvent, SecurityEventKind,
};
use authn_store::{OneTimeTokenRepository, UserRepository};
use serde::Deserialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::{
    OrgService, actions, cursor_of, fetch_limit, on_unique, page_after, require_session_user,
};
use crate::model::{
    MemberStatus, MyOrganization, MyOrganizationPage, OrgStatus, Organization, RoleRef,
};
use crate::permission::{OWNER_ROLE_ID, Permission};
use crate::validate;

/// Column list of [`Organization`].
macro_rules! org_columns {
    () => {
        "id, slug, name, status, deletion_scheduled_for, created_at, updated_at"
    };
}

/// Name of the unique constraint on `organizations.slug`.
const SLUG_UNIQUE: &str = "organizations_slug_key";

/// Body of `POST /v1/orgs`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateOrganization {
    /// Display name (1–200 characters).
    pub name: String,
    /// URL-safe unique slug (`[a-z0-9-]`, 1–63 characters).
    pub slug: String,
}

/// Body of `PATCH /v1/orgs/{org_id}`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateOrganization {
    /// New display name.
    pub name: Option<String>,
    /// New slug.
    pub slug: Option<String>,
}

#[derive(sqlx::FromRow)]
struct MyOrgRow {
    id: OrgId,
    slug: String,
    name: String,
    status: OrgStatus,
    deletion_scheduled_for: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    membership_id: MembershipId,
    member_status: MemberStatus,
    member_created_at: OffsetDateTime,
    role_id: RoleId,
    role_key: String,
    role_name: String,
}

impl OrgService {
    /// Creates an organization; the caller becomes its `owner` (ORG-01).
    /// Requires a human session with a verified e-mail address (spam /
    /// invitation abuse) and is rate-limited per user.
    pub async fn create_organization(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        input: CreateOrganization,
    ) -> Result<Organization, AuthError> {
        let user = require_session_user(principal)?;
        principal.require_writable()?;
        let name = validate::display_text(&input.name, validate::MAX_ORG_NAME_CHARS, "name")?;
        let slug = validate::slug(&input.slug)?;
        self.rate_limit(
            RateLimitKey::user(actions::ORG_CREATE, user),
            self.config().creates_per_user,
        )
        .await?;
        let record = UserRepository::find_by_id(self.pool(), user)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))?;
        if !record.is_email_verified() {
            return Err(AuthError::new(codes::org::ORG_EMAIL_VERIFICATION_REQUIRED));
        }
        let now = self.now();
        let org_id = OrgId::generate();
        let mut tx = self.begin().await?;
        let sql = concat!(
            "INSERT INTO organizations (id, slug, name, status, created_by, created_at, updated_at) \
             VALUES ($1, $2, $3, 'active', $4, $5, $5) RETURNING ",
            org_columns!()
        );
        let org = sqlx::query_as::<_, Organization>(sql)
            .bind(org_id)
            .bind(&slug)
            .bind(&name)
            .bind(user)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| on_unique(e, SLUG_UNIQUE, codes::org::ORG_SLUG_TAKEN))?;
        let membership = MembershipId::generate();
        sqlx::query(
            "INSERT INTO memberships (id, org_id, user_id, role_id, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'active', $5, $5)",
        )
        .bind(membership)
        .bind(org_id)
        .bind(user)
        .bind(OWNER_ROLE_ID)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO org_policies (org_id, updated_by, created_at, updated_at) \
             VALUES ($1, $2, $3, $3)",
        )
        .bind(org_id)
        .bind(user)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        self.publish(
            &mut tx,
            DomainEventKind::OrganizationCreated,
            org_id,
            Some(user),
            serde_json::json!({ "org_id": org_id, "slug": org.slug }),
        )
        .await?;
        self.publish(
            &mut tx,
            DomainEventKind::MemberAdded,
            org_id,
            Some(user),
            serde_json::json!({ "org_id": org_id, "user_id": user, "role": "owner" }),
        )
        .await?;
        let event = self
            .event(SecurityEventKind::OrgCreated, ctx, principal, Some(org_id))
            .with_subject(user)
            .with_resource("organization", org_id);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        crate::metrics::org_created();
        Ok(org)
    }

    /// Reads an organization (`org:read`).
    pub async fn get_organization(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<Organization, AuthError> {
        self.authorize(ctx, principal, Permission::OrgRead, org)
            .await?;
        load_org(self.pool(), org).await
    }

    /// Renames the organization or changes its slug (`org:update`).
    pub async fn update_organization(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        input: UpdateOrganization,
    ) -> Result<Organization, AuthError> {
        let name = input
            .name
            .as_deref()
            .map(|n| validate::display_text(n, validate::MAX_ORG_NAME_CHARS, "name"))
            .transpose()?;
        let slug = input.slug.as_deref().map(validate::slug).transpose()?;
        if name.is_none() && slug.is_none() {
            return Err(validate::invalid("name"));
        }
        let (mut tx, _auth) = self
            .begin_write(ctx, principal, Permission::OrgUpdate, org)
            .await?;
        let sql = concat!(
            "UPDATE organizations SET name = COALESCE($2, name), slug = COALESCE($3, slug) \
             WHERE id = $1 RETURNING ",
            org_columns!()
        );
        let updated = sqlx::query_as::<_, Organization>(sql)
            .bind(org)
            .bind(name.as_deref())
            .bind(slug.as_deref())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| on_unique(e, SLUG_UNIQUE, codes::org::ORG_SLUG_TAKEN))?;
        self.publish(
            &mut tx,
            DomainEventKind::OrganizationUpdated,
            org,
            None,
            serde_json::json!({ "org_id": org, "slug": updated.slug }),
        )
        .await?;
        let event = self
            .event(SecurityEventKind::OrgUpdated, ctx, principal, Some(org))
            .with_resource("organization", org)
            .with_meta("name_changed", name.is_some())
            .with_meta("slug_changed", slug.is_some());
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(updated)
    }

    /// The caller's organizations (any membership status), oldest first.
    pub async fn list_my_organizations(
        &self,
        principal: &Principal,
        page: &PageRequest,
    ) -> Result<MyOrganizationPage, AuthError> {
        let user = require_session_user(principal)?;
        let (after_at, after_id) = page_after(page)?;
        let rows = sqlx::query_as::<_, MyOrgRow>(
            "SELECT o.id, o.slug, o.name, o.status, o.deletion_scheduled_for, o.created_at, \
             o.updated_at, m.id AS membership_id, m.status AS member_status, \
             m.created_at AS member_created_at, r.id AS role_id, r.key AS role_key, \
             r.name AS role_name \
             FROM memberships m JOIN organizations o ON o.id = m.org_id \
             JOIN roles r ON r.id = m.role_id \
             WHERE m.user_id = $1 \
             AND ($2::timestamptz IS NULL OR (m.created_at, m.id) > ($2, $3)) \
             ORDER BY m.created_at, m.id LIMIT $4",
        )
        .bind(user)
        .bind(after_at)
        .bind(after_id)
        .bind(fetch_limit(page))
        .fetch_all(self.pool())
        .await?;
        let page = Page::from_overfetch(rows, page.limit(), |r| {
            cursor_of(r.member_created_at, r.membership_id.as_uuid())
        });
        Ok(MyOrganizationPage {
            items: page
                .items
                .into_iter()
                .map(|r| MyOrganization {
                    organization: Organization {
                        id: r.id,
                        slug: r.slug,
                        name: r.name,
                        status: r.status,
                        deletion_scheduled_for: r.deletion_scheduled_for,
                        created_at: r.created_at,
                        updated_at: r.updated_at,
                    },
                    membership_id: r.membership_id,
                    role: RoleRef {
                        id: r.role_id,
                        key: r.role_key,
                        name: r.role_name,
                    },
                    member_status: r.member_status,
                })
                .collect(),
            next_cursor: page.next_cursor,
        })
    }

    /// Schedules the organization's deletion after the grace period
    /// (ORG-12): owner only, step-up. Pending invitations and ownership
    /// transfers are revoked and every session in the organization is
    /// revoked; API keys stop working immediately.
    pub async fn schedule_deletion(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<Organization, AuthError> {
        self.require_step_up(principal)?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::OrgDelete, org)
            .await?;
        auth.require_owner(Permission::OrgDelete)?;
        if auth.org_status != OrgStatus::Active {
            return Err(AuthError::new(codes::org::ORG_PENDING_DELETION));
        }
        let now = self.now();
        let scheduled_for = now + self.config().deletion_grace_period;
        let sql = concat!(
            "UPDATE organizations SET status = 'pending_deletion', deletion_scheduled_for = $2 \
             WHERE id = $1 RETURNING ",
            org_columns!()
        );
        let updated = sqlx::query_as::<_, Organization>(sql)
            .bind(org)
            .bind(scheduled_for)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE invitations SET status = 'revoked', revoked_at = $2 \
             WHERE org_id = $1 AND status = 'pending'",
        )
        .bind(org)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        OneTimeTokenRepository::revoke_group(&mut tx, org.as_uuid(), now).await?;
        let revoked = self
            .deps()
            .session_revoker
            .revoke_all_for_org(&mut tx, org, RevocationReason::OrgPolicyChanged)
            .await?;
        let event = self
            .event(
                SecurityEventKind::OrgDeletionScheduled,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("organization", org)
            .with_meta("scheduled_for", scheduled_for.unix_timestamp())
            .with_meta("sessions_revoked", revoked);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(updated)
    }

    /// Cancels a scheduled deletion (owner only, step-up).
    pub async fn cancel_deletion(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<Organization, AuthError> {
        self.require_step_up(principal)?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::OrgDelete, org)
            .await?;
        auth.require_owner(Permission::OrgDelete)?;
        if auth.org_status != OrgStatus::PendingDeletion {
            return Err(AuthError::new(codes::org::ORG_DELETION_NOT_SCHEDULED));
        }
        let sql = concat!(
            "UPDATE organizations SET status = 'active', deletion_scheduled_for = NULL \
             WHERE id = $1 AND status = 'pending_deletion' RETURNING ",
            org_columns!()
        );
        let updated = sqlx::query_as::<_, Organization>(sql)
            .bind(org)
            .fetch_one(&mut *tx)
            .await?;
        let event = self
            .event(
                SecurityEventKind::OrgDeletionCancelled,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("organization", org);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(updated)
    }

    /// Background job (OPS-06): permanently deletes up to `limit`
    /// organizations whose grace period ended. Safe with several instances
    /// (`FOR UPDATE SKIP LOCKED`, one organization per transaction). Every
    /// organization-scoped row is removed by `ON DELETE CASCADE`.
    pub async fn purge_due_deletions(&self, limit: u32) -> Result<u64, AuthError> {
        let mut purged = 0_u64;
        for _ in 0..limit {
            let now = self.now();
            let mut tx = self.begin().await?;
            let due: Option<OrgId> = sqlx::query_scalar(
                "SELECT id FROM organizations WHERE status = 'pending_deletion' \
                 AND deletion_scheduled_for <= $1 ORDER BY deletion_scheduled_for \
                 LIMIT 1 FOR UPDATE SKIP LOCKED",
            )
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(org) = due else {
                authn_store::commit(tx).await?;
                break;
            };
            self.deps()
                .session_revoker
                .revoke_all_for_org(&mut tx, org, RevocationReason::OrgPolicyChanged)
                .await?;
            OneTimeTokenRepository::revoke_group(&mut tx, org.as_uuid(), now).await?;
            self.publish(
                &mut tx,
                DomainEventKind::OrganizationDeleted,
                org,
                None,
                serde_json::json!({ "org_id": org }),
            )
            .await?;
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org)
                .execute(&mut *tx)
                .await?;
            let event = SecurityEvent::new(SecurityEventKind::OrgDeleted, now)
                .with_actor(Actor::System)
                .with_org(org)
                .with_resource("organization", org);
            self.audit_in_tx(&mut tx, event).await?;
            authn_store::commit(tx).await?;
            purged += 1;
        }
        Ok(purged)
    }

    /// Background job (OPS-06): marks pending invitations past their expiry
    /// as `expired`. Returns the number of rows changed.
    pub async fn expire_invitations(&self) -> Result<u64, AuthError> {
        let result = sqlx::query(
            "UPDATE invitations SET status = 'expired' WHERE status = 'pending' AND expires_at <= $1",
        )
        .bind(self.now())
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

/// Loads an organization by id (no authorization; callers authorize first).
pub(crate) async fn load_org<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    org: OrgId,
) -> Result<Organization, AuthError> {
    let sql = concat!(
        "SELECT ",
        org_columns!(),
        " FROM organizations WHERE id = $1"
    );
    sqlx::query_as::<_, Organization>(sql)
        .bind(org)
        .fetch_optional(executor)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
}

/// Inserts an active membership (invitation acceptance, auto-join).
pub(crate) async fn insert_membership(
    conn: &mut PgConnection,
    org: OrgId,
    user: UserId,
    role: RoleId,
    invited_by: Option<UserId>,
    now: OffsetDateTime,
) -> Result<MembershipId, AuthError> {
    let id = MembershipId::generate();
    sqlx::query(
        "INSERT INTO memberships (id, org_id, user_id, role_id, status, invited_by, created_at, \
         updated_at) VALUES ($1, $2, $3, $4, 'active', $5, $6, $6)",
    )
    .bind(id)
    .bind(org)
    .bind(user)
    .bind(role)
    .bind(invited_by)
    .bind(now)
    .execute(conn)
    .await
    .map_err(|e| {
        on_unique(
            e,
            "memberships_org_user_key",
            codes::org::ORG_ALREADY_MEMBER,
        )
    })?;
    Ok(id)
}
