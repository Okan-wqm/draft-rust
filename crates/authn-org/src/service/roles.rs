//! Roles (ORG-03) and the escalation guard on role definitions (ORG-04).
//!
//! Built-in roles are global, immutable and usable in every organization;
//! custom roles belong to exactly one organization (a role id of another
//! organization is `404`, and the database trigger `authn_check_role_tenant`
//! refuses cross-tenant assignments as a second line of defence). A custom
//! role may only contain catalog permissions the editor holds, never the
//! owner-only ones; editing or deleting a role requires holding all of its
//! current permissions too. Removing permissions from a role revokes the
//! organization sessions of every member holding it and the pending
//! invitations those members sent.

use std::collections::BTreeSet;

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, RoleId, UserId};
use authn_core::ports::{RevocationReason, SecurityEventKind};
use serde::Deserialize;
use sqlx::PgConnection;
use utoipa::ToSchema;

use super::members::revoke_invitations_sent_by;
use super::{OrgService, on_unique};
use crate::model::Role;
use crate::permission::{BuiltinRole, Permission, PermissionSet};
use crate::validate;

/// Body of `POST /v1/orgs/{org_id}/roles`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRole {
    /// Key, unique in the organization (`^[a-z][a-z0-9_]{0,62}$`, not a
    /// built-in key).
    pub key: String,
    /// Display name (1–100 characters).
    pub name: String,
    /// Description (≤ 500 characters).
    pub description: Option<String>,
    /// Catalog permissions (`resource:action`).
    pub permissions: Vec<String>,
}

/// Body of `PATCH /v1/orgs/{org_id}/roles/{role_id}`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateRole {
    /// New display name.
    pub name: Option<String>,
    /// New description (empty string clears it).
    pub description: Option<String>,
    /// New permission list (replaces the old one).
    pub permissions: Option<Vec<String>>,
}

/// A role row with its permissions.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct RoleRow {
    pub id: RoleId,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub is_builtin: bool,
    pub permissions: Vec<String>,
}

impl RoleRow {
    pub(crate) fn permission_set(&self) -> PermissionSet {
        PermissionSet::from_db(&self.permissions)
    }

    fn into_role(self) -> Role {
        let permissions = self.permission_set().iter().collect();
        Role {
            id: self.id,
            key: self.key,
            name: self.name,
            description: self.description,
            builtin: self.is_builtin,
            permissions,
        }
    }
}

macro_rules! role_select {
    () => {
        "SELECT r.id, r.key, r.name, r.description, r.is_builtin, \
         ARRAY(SELECT rp.permission FROM role_permissions rp WHERE rp.role_id = r.id \
               ORDER BY rp.permission) AS permissions FROM roles r "
    };
}

impl OrgService {
    /// Built-in and custom roles of the organization (`roles:read`).
    pub async fn list_roles(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<Vec<Role>, AuthError> {
        self.authorize(ctx, principal, Permission::RolesRead, org)
            .await?;
        let sql = concat!(
            role_select!(),
            "WHERE r.org_id = $1 OR r.org_id IS NULL ORDER BY r.is_builtin DESC, r.created_at, r.id"
        );
        let rows = sqlx::query_as::<_, RoleRow>(sql)
            .bind(org)
            .fetch_all(self.pool())
            .await?;
        Ok(rows.into_iter().map(RoleRow::into_role).collect())
    }

    /// Creates a custom role (`roles:manage`, ORG-04 escalation guard).
    pub async fn create_role(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        input: CreateRole,
    ) -> Result<Role, AuthError> {
        let key = role_key(&input.key)?;
        let name = validate::display_text(&input.name, validate::MAX_ROLE_NAME_CHARS, "name")?;
        let description = validate::description(input.description.as_deref())?;
        let permissions = parse_role_permissions(&input.permissions)?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::RolesManage, org)
            .await?;
        let role_id = RoleId::generate();
        auth.ensure_can_grant(role_id, &permissions)?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM roles WHERE org_id = $1")
            .bind(org)
            .fetch_one(&mut *tx)
            .await?;
        if count >= i64::from(self.config().limits.custom_roles) {
            return Err(AuthError::new(codes::org::ORG_LIMIT_REACHED));
        }
        let now = self.now();
        sqlx::query(
            "INSERT INTO roles (id, org_id, key, name, description, is_builtin, created_at, \
             updated_at) VALUES ($1, $2, $3, $4, $5, false, $6, $6)",
        )
        .bind(role_id)
        .bind(org)
        .bind(&key)
        .bind(&name)
        .bind(description.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| on_unique(e, "roles_org_key_idx", codes::org::ORG_ROLE_KEY_TAKEN))?;
        replace_permissions(&mut tx, role_id, &permissions).await?;
        let event = self
            .event(SecurityEventKind::RoleCreated, ctx, principal, Some(org))
            .with_resource("role", role_id)
            .with_meta("permissions", permissions.to_strings());
        self.audit_in_tx(&mut tx, event).await?;
        let role = load_role(&mut tx, org, role_id)
            .await?
            .ok_or_else(|| AuthError::internal("created role not found"))?;
        authn_store::commit(tx).await?;
        Ok(role.into_role())
    }

    /// Changes a custom role (`roles:manage`).
    pub async fn update_role(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        role_id: RoleId,
        input: UpdateRole,
    ) -> Result<Role, AuthError> {
        let name = input
            .name
            .as_deref()
            .map(|n| validate::display_text(n, validate::MAX_ROLE_NAME_CHARS, "name"))
            .transpose()?;
        let description = input
            .description
            .as_deref()
            .map(|d| validate::description(Some(d)))
            .transpose()?;
        let permissions = input
            .permissions
            .as_deref()
            .map(parse_role_permissions)
            .transpose()?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::RolesManage, org)
            .await?;
        let current = lock_custom_role(&mut tx, org, role_id).await?;
        auth.ensure_can_grant(role_id, &current.permission_set())?;
        if let Some(new) = &permissions {
            auth.ensure_can_grant(role_id, new)?;
        }
        sqlx::query(
            "UPDATE roles SET name = COALESCE($3, name), \
             description = CASE WHEN $4 THEN $5 ELSE description END \
             WHERE id = $1 AND org_id = $2",
        )
        .bind(role_id)
        .bind(org)
        .bind(name.as_deref())
        .bind(description.is_some())
        .bind(description.flatten())
        .execute(&mut *tx)
        .await?;
        let mut sessions_revoked = 0_u64;
        if let Some(new) = &permissions {
            replace_permissions(&mut tx, role_id, new).await?;
            if !new.is_superset(&current.permission_set()) {
                let holders: Vec<UserId> = sqlx::query_scalar(
                    "SELECT user_id FROM memberships WHERE org_id = $1 AND role_id = $2 \
                     AND status = 'active'",
                )
                .bind(org)
                .bind(role_id)
                .fetch_all(&mut *tx)
                .await?;
                let now = self.now();
                for user in holders {
                    sessions_revoked += self
                        .deps()
                        .session_revoker
                        .revoke_for_user_in_org(
                            &mut tx,
                            user,
                            org,
                            RevocationReason::MembershipRemoved,
                        )
                        .await?;
                    // Like a member downgrade (ORG-04): a pending invitation
                    // must not grant a role its sender can no longer grant.
                    revoke_invitations_sent_by(&mut tx, org, user, now).await?;
                }
            }
        }
        let mut event = self
            .event(SecurityEventKind::RoleUpdated, ctx, principal, Some(org))
            .with_resource("role", role_id)
            .with_meta("sessions_revoked", sessions_revoked);
        if let Some(new) = &permissions {
            event = event.with_meta("permissions", new.to_strings());
        }
        self.audit_in_tx(&mut tx, event).await?;
        let role = load_role(&mut tx, org, role_id)
            .await?
            .ok_or_else(|| AuthError::internal("updated role not found"))?;
        authn_store::commit(tx).await?;
        Ok(role.into_role())
    }

    /// Deletes an unused custom role (`roles:manage`). Finished invitations
    /// that referenced it are removed with it; pending invitations, members
    /// and service accounts block the deletion (`org_role_in_use`).
    pub async fn delete_role(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        role_id: RoleId,
    ) -> Result<(), AuthError> {
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::RolesManage, org)
            .await?;
        let current = lock_custom_role(&mut tx, org, role_id).await?;
        auth.ensure_can_grant(role_id, &current.permission_set())?;
        let in_use: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM memberships WHERE org_id = $1 AND role_id = $2) \
             OR EXISTS (SELECT 1 FROM service_accounts WHERE org_id = $1 AND role_id = $2) \
             OR EXISTS (SELECT 1 FROM invitations WHERE org_id = $1 AND role_id = $2 \
                        AND status = 'pending')",
        )
        .bind(org)
        .bind(role_id)
        .fetch_one(&mut *tx)
        .await?;
        if in_use {
            return Err(AuthError::new(codes::org::ORG_ROLE_IN_USE));
        }
        sqlx::query("DELETE FROM invitations WHERE org_id = $1 AND role_id = $2")
            .bind(org)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM roles WHERE id = $1 AND org_id = $2")
            .bind(role_id)
            .bind(org)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                let store = authn_store::StoreError::from(e);
                if matches!(store, authn_store::StoreError::ForeignKeyViolation { .. }) {
                    AuthError::new(codes::org::ORG_ROLE_IN_USE).with_source(store)
                } else {
                    AuthError::from(store)
                }
            })?;
        let event = self
            .event(SecurityEventKind::RoleDeleted, ctx, principal, Some(org))
            .with_resource("role", role_id);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await
    }
}

/// A built-in role or a custom role of `org` (tenant-filtered).
pub(crate) async fn load_role(
    conn: &mut PgConnection,
    org: OrgId,
    role: RoleId,
) -> Result<Option<RoleRow>, AuthError> {
    let sql = concat!(
        role_select!(),
        "WHERE r.id = $2 AND (r.org_id = $1 OR r.org_id IS NULL)"
    );
    Ok(sqlx::query_as::<_, RoleRow>(sql)
        .bind(org)
        .bind(role)
        .fetch_optional(conn)
        .await?)
}

/// Locks a custom role of `org`: `404` for unknown / foreign roles,
/// `org_builtin_role_immutable` for built-in roles.
async fn lock_custom_role(
    conn: &mut PgConnection,
    org: OrgId,
    role: RoleId,
) -> Result<RoleRow, AuthError> {
    let row = load_role(&mut *conn, org, role)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
    if row.is_builtin {
        return Err(AuthError::new(codes::org::ORG_BUILTIN_ROLE_IMMUTABLE));
    }
    sqlx::query("SELECT 1 FROM roles WHERE id = $1 AND org_id = $2 FOR UPDATE")
        .bind(role)
        .bind(org)
        .execute(conn)
        .await?;
    Ok(row)
}

async fn replace_permissions(
    conn: &mut PgConnection,
    role: RoleId,
    permissions: &PermissionSet,
) -> Result<(), AuthError> {
    sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
        .bind(role)
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) SELECT $1, unnest($2::text[])")
        .bind(role)
        .bind(permissions.to_strings())
        .execute(conn)
        .await?;
    Ok(())
}

/// Validates a custom role key.
fn role_key(input: &str) -> Result<String, AuthError> {
    let key = input.trim();
    let ok = (1..=63).contains(&key.len())
        && key.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !BuiltinRole::ALL.iter().any(|r| r.as_str() == key);
    if ok {
        Ok(key.to_owned())
    } else {
        Err(validate::invalid("key"))
    }
}

/// Parses role permissions: non-empty, catalog entries only, no
/// owner-only permission (ORG-04), duplicates removed.
pub(crate) fn parse_role_permissions(values: &[String]) -> Result<PermissionSet, AuthError> {
    if values.is_empty() || values.len() > 64 {
        return Err(validate::invalid("permissions"));
    }
    let mut set = BTreeSet::new();
    for value in values {
        let permission =
            Permission::from_catalog(value).ok_or_else(|| validate::invalid("permissions"))?;
        if permission.is_owner_only() {
            return Err(AuthError::new(codes::org::ORG_ROLE_ESCALATION)
                .with_context("owner-only permission on a custom role"));
        }
        set.insert(permission);
    }
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_03_role_keys() {
        assert_eq!(role_key("support_agent").unwrap(), "support_agent");
        for bad in [
            "",
            "Owner",
            "owner",
            "admin",
            "1abc",
            "a-b",
            &"a".repeat(64),
        ] {
            assert!(role_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn org_04_custom_roles_never_carry_owner_only_permissions() {
        let ok = parse_role_permissions(&["members:read".into(), "members:read".into()]).unwrap();
        assert_eq!(ok.len(), 1);
        let err = parse_role_permissions(&["org:delete".into()]).unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
        let err = parse_role_permissions(&["org:transfer_ownership".into()]).unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
        assert!(parse_role_permissions(&["members:everything".into()]).is_err());
        assert!(parse_role_permissions(&[]).is_err());
    }
}
