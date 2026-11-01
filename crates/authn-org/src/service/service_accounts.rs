//! Service accounts (ORG-09): non-human identities of one organization that
//! authenticate only with API keys. They carry a role like members (never
//! `owner`), are subject to the same escalation guard (ORG-04), and their
//! keys stop working as soon as they are disabled or deleted (keys are
//! deleted with them by foreign-key cascade).

use authn_core::domain::{Page, PageRequest, Principal};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, RoleId, ServiceAccountId, UserId};
use authn_core::ports::SecurityEventKind;
use serde::Deserialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::roles::{RoleRow, load_role};
use super::{OrgService, cursor_of, fetch_limit, on_unique, page_after};
use crate::authz::Authorization;
use crate::model::{RoleRef, ServiceAccount, ServiceAccountPage, ServiceAccountStatus};
use crate::permission::{Permission, PermissionSet, is_owner_role};
use crate::validate;

/// Body of `POST /v1/orgs/{org_id}/service-accounts`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateServiceAccount {
    /// Name, unique in the organization (1–100 characters).
    pub name: String,
    /// Description (≤ 500 characters).
    pub description: Option<String>,
    /// Role (not `owner`).
    pub role_id: RoleId,
}

/// Body of `PATCH /v1/orgs/{org_id}/service-accounts/{service_account_id}`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateServiceAccount {
    /// New name.
    pub name: Option<String>,
    /// New description (empty string clears it).
    pub description: Option<String>,
    /// New role (not `owner`).
    pub role_id: Option<RoleId>,
    /// New status.
    pub status: Option<ServiceAccountStatus>,
}

#[derive(sqlx::FromRow)]
struct SaRow {
    id: ServiceAccountId,
    name: String,
    description: Option<String>,
    status: ServiceAccountStatus,
    created_by: Option<UserId>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    role_id: RoleId,
    role_key: String,
    role_name: String,
    permissions: Vec<String>,
}

impl SaRow {
    fn into_model(self) -> ServiceAccount {
        ServiceAccount {
            id: self.id,
            name: self.name,
            description: self.description,
            role: RoleRef {
                id: self.role_id,
                key: self.role_key,
                name: self.role_name,
            },
            status: self.status,
            created_by: self.created_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

macro_rules! sa_select {
    () => {
        "SELECT s.id, s.name, s.description, s.status, s.created_by, s.created_at, s.updated_at, \
         r.id AS role_id, r.key AS role_key, r.name AS role_name, \
         ARRAY(SELECT rp.permission FROM role_permissions rp WHERE rp.role_id = s.role_id) \
         AS permissions FROM service_accounts s JOIN roles r ON r.id = s.role_id "
    };
}

const NAME_UNIQUE: &str = "service_accounts_org_name_key";

impl OrgService {
    /// Lists service accounts (`service_accounts:read`), oldest first.
    pub async fn list_service_accounts(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        page: &PageRequest,
    ) -> Result<ServiceAccountPage, AuthError> {
        self.authorize(ctx, principal, Permission::ServiceAccountsRead, org)
            .await?;
        let (after_at, after_id) = page_after(page)?;
        let sql = concat!(
            sa_select!(),
            "WHERE s.org_id = $1 AND ($2::timestamptz IS NULL OR (s.created_at, s.id) > ($2, $3)) \
             ORDER BY s.created_at, s.id LIMIT $4"
        );
        let rows = sqlx::query_as::<_, SaRow>(sql)
            .bind(org)
            .bind(after_at)
            .bind(after_id)
            .bind(fetch_limit(page))
            .fetch_all(self.pool())
            .await?;
        let page = Page::from_overfetch(rows, page.limit(), |r| {
            cursor_of(r.created_at, r.id.as_uuid())
        });
        Ok(ServiceAccountPage {
            items: page.items.into_iter().map(SaRow::into_model).collect(),
            next_cursor: page.next_cursor,
        })
    }

    /// Reads a service account (`service_accounts:read`).
    pub async fn get_service_account(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        id: ServiceAccountId,
    ) -> Result<ServiceAccount, AuthError> {
        self.authorize(ctx, principal, Permission::ServiceAccountsRead, org)
            .await?;
        let mut conn = self.pool().acquire().await?;
        Ok(load_sa(&mut conn, org, id, false).await?.into_model())
    }

    /// Creates a service account (`service_accounts:manage`).
    pub async fn create_service_account(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        input: CreateServiceAccount,
    ) -> Result<ServiceAccount, AuthError> {
        let name = validate::display_text(&input.name, validate::MAX_RESOURCE_NAME_CHARS, "name")?;
        let description = validate::description(input.description.as_deref())?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::ServiceAccountsManage, org)
            .await?;
        let role = assignable_role(&mut tx, &auth, org, input.role_id).await?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM service_accounts WHERE org_id = $1")
                .bind(org)
                .fetch_one(&mut *tx)
                .await?;
        if count >= i64::from(self.config().limits.service_accounts) {
            return Err(AuthError::new(codes::org::ORG_LIMIT_REACHED));
        }
        let id = ServiceAccountId::generate();
        sqlx::query(
            "INSERT INTO service_accounts (id, org_id, name, description, role_id, status, \
             created_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $7)",
        )
        .bind(id)
        .bind(org)
        .bind(&name)
        .bind(description.as_deref())
        .bind(role.id)
        .bind(auth.user_id())
        .bind(self.now())
        .execute(&mut *tx)
        .await
        .map_err(|e| on_unique(e, NAME_UNIQUE, codes::org::SERVICE_ACCOUNT_NAME_TAKEN))?;
        let event = self
            .event(
                SecurityEventKind::ServiceAccountCreated,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("service_account", id)
            .with_meta("role", role.key.clone());
        self.audit_in_tx(&mut tx, event).await?;
        let created = load_sa(&mut tx, org, id, false).await?;
        authn_store::commit(tx).await?;
        Ok(created.into_model())
    }

    /// Changes a service account (`service_accounts:manage`).
    pub async fn update_service_account(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        id: ServiceAccountId,
        input: UpdateServiceAccount,
    ) -> Result<ServiceAccount, AuthError> {
        let name = input
            .name
            .as_deref()
            .map(|n| validate::display_text(n, validate::MAX_RESOURCE_NAME_CHARS, "name"))
            .transpose()?;
        let description = input
            .description
            .as_deref()
            .map(|d| validate::description(Some(d)))
            .transpose()?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::ServiceAccountsManage, org)
            .await?;
        let current = load_sa(&mut tx, org, id, true).await?;
        auth.ensure_can_grant(
            current.role_id,
            &PermissionSet::from_db(&current.permissions),
        )?;
        let role_id = match input.role_id {
            Some(role_id) if role_id != current.role_id => {
                Some(assignable_role(&mut tx, &auth, org, role_id).await?.id)
            }
            _ => None,
        };
        sqlx::query(
            "UPDATE service_accounts SET name = COALESCE($3, name), \
             description = CASE WHEN $4 THEN $5 ELSE description END, \
             role_id = COALESCE($6, role_id), status = COALESCE($7, status) \
             WHERE org_id = $1 AND id = $2",
        )
        .bind(org)
        .bind(id)
        .bind(name.as_deref())
        .bind(description.is_some())
        .bind(description.flatten())
        .bind(role_id)
        .bind(input.status)
        .execute(&mut *tx)
        .await
        .map_err(|e| on_unique(e, NAME_UNIQUE, codes::org::SERVICE_ACCOUNT_NAME_TAKEN))?;
        let mut event = self
            .event(
                SecurityEventKind::ServiceAccountUpdated,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("service_account", id);
        if let Some(role_id) = role_id {
            event = event.with_meta("role_id", role_id.to_string());
        }
        if let Some(status) = input.status {
            event = event.with_meta("status", status.as_str());
        }
        self.audit_in_tx(&mut tx, event).await?;
        let updated = load_sa(&mut tx, org, id, false).await?;
        authn_store::commit(tx).await?;
        Ok(updated.into_model())
    }

    /// Deletes a service account and its API keys
    /// (`service_accounts:manage`).
    pub async fn delete_service_account(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        id: ServiceAccountId,
    ) -> Result<(), AuthError> {
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::ServiceAccountsManage, org)
            .await?;
        let current = load_sa(&mut tx, org, id, true).await?;
        auth.ensure_can_grant(
            current.role_id,
            &PermissionSet::from_db(&current.permissions),
        )?;
        sqlx::query("DELETE FROM service_accounts WHERE org_id = $1 AND id = $2")
            .bind(org)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let event = self
            .event(
                SecurityEventKind::ServiceAccountDeleted,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("service_account", id);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await
    }
}

async fn load_sa(
    conn: &mut PgConnection,
    org: OrgId,
    id: ServiceAccountId,
    lock: bool,
) -> Result<SaRow, AuthError> {
    let row = if lock {
        sqlx::query_as::<_, SaRow>(concat!(
            sa_select!(),
            "WHERE s.org_id = $1 AND s.id = $2 FOR UPDATE OF s"
        ))
        .bind(org)
        .bind(id)
        .fetch_optional(conn)
        .await?
    } else {
        sqlx::query_as::<_, SaRow>(concat!(sa_select!(), "WHERE s.org_id = $1 AND s.id = $2"))
            .bind(org)
            .bind(id)
            .fetch_optional(conn)
            .await?
    };
    row.ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
}

/// A role the actor may give a service account: exists in this
/// organization (or is built-in), is not `owner`, and passes the
/// escalation guard.
async fn assignable_role(
    conn: &mut PgConnection,
    auth: &Authorization,
    org: OrgId,
    role: RoleId,
) -> Result<RoleRow, AuthError> {
    let role = load_role(conn, org, role)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
    if is_owner_role(role.id) {
        return Err(validate::invalid("role_id"));
    }
    auth.ensure_can_grant(role.id, &role.permission_set())?;
    Ok(role)
}
