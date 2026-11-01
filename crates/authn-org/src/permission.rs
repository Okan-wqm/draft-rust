//! The permission catalog and the built-in roles (ORG-03, ORG-04).
//!
//! Permissions are `resource:action` strings. The catalog is closed: custom
//! roles and API key scopes may only contain catalog entries, so a typo can
//! never create a permission that nothing checks. Values read from the
//! database that are not in the catalog are ignored (default deny).
//!
//! The built-in roles and their permissions are seeded by migration
//! `0012_builtin_roles.sql` with fixed ids; [`BuiltinRole::permissions`]
//! mirrors that seed (a database test keeps both in sync). Authorization
//! itself always reads the database.

use std::collections::BTreeSet;

use authn_core::id::RoleId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

org_text_enum! {
    /// One permission of the catalog (ORG-03).
    pub enum Permission {
        /// Read the organization.
        OrgRead => "org:read",
        /// Rename the organization, change its slug.
        OrgUpdate => "org:update",
        /// Schedule / cancel the organization's deletion (owner only, ORG-12).
        OrgDelete => "org:delete",
        /// Transfer ownership (owner only, ORG-11).
        OrgTransferOwnership => "org:transfer_ownership",
        /// List members.
        MembersRead => "members:read",
        /// Invite members, manage invitations (ORG-05).
        MembersInvite => "members:invite",
        /// Change member roles, suspend / reactivate members.
        MembersUpdate => "members:update",
        /// Remove members.
        MembersRemove => "members:remove",
        /// List roles.
        RolesRead => "roles:read",
        /// Create, change and delete custom roles.
        RolesManage => "roles:manage",
        /// Read the security policy (ORG-07).
        PoliciesRead => "policies:read",
        /// Change the security policy (ORG-07).
        PoliciesManage => "policies:manage",
        /// List domains (ORG-06).
        DomainsRead => "domains:read",
        /// Add, verify and remove domains (ORG-06).
        DomainsManage => "domains:manage",
        /// List API keys (ORG-08).
        ApiKeysRead => "api_keys:read",
        /// Create, rotate and revoke API keys (ORG-08).
        ApiKeysManage => "api_keys:manage",
        /// List service accounts (ORG-09).
        ServiceAccountsRead => "service_accounts:read",
        /// Create, change and delete service accounts (ORG-09).
        ServiceAccountsManage => "service_accounts:manage",
        /// Read webhook endpoints (AUD-07, authn-audit).
        WebhooksRead => "webhooks:read",
        /// Manage webhook endpoints (AUD-07, authn-audit).
        WebhooksManage => "webhooks:manage",
        /// Read the organization audit log (AUD-04, authn-audit).
        AuditRead => "audit:read",
        /// Read billing data (host application).
        BillingRead => "billing:read",
        /// Manage billing (host application).
        BillingManage => "billing:manage",
    }
}

impl Permission {
    /// Read-only permissions (`*:read`). Every other permission changes
    /// state and is refused during read-only impersonation (ADM-04).
    #[must_use]
    pub fn is_read_only(self) -> bool {
        self.as_str().ends_with(":read")
    }

    /// Permissions that only the built-in `owner` role carries; they can
    /// never be put on a custom role or an API key (ORG-04, ORG-11, ORG-12).
    #[must_use]
    pub const fn is_owner_only(self) -> bool {
        matches!(self, Self::OrgDelete | Self::OrgTransferOwnership)
    }

    /// Parses a catalog entry; unknown strings are `None`.
    #[must_use]
    pub fn from_catalog(value: &str) -> Option<Self> {
        value.parse().ok()
    }
}

/// A set of permissions (ordered, deduplicated).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct PermissionSet(BTreeSet<Permission>);

impl PermissionSet {
    /// The empty set (default deny).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a set from database strings, ignoring values outside the
    /// catalog (they grant nothing).
    #[must_use]
    pub fn from_db<S: AsRef<str>>(values: &[S]) -> Self {
        Self(
            values
                .iter()
                .filter_map(|v| Permission::from_catalog(v.as_ref()))
                .collect(),
        )
    }

    /// Whether `permission` is in the set.
    #[must_use]
    pub fn contains(&self, permission: Permission) -> bool {
        self.0.contains(&permission)
    }

    /// Whether every permission of `other` is in this set.
    #[must_use]
    pub fn is_superset(&self, other: &Self) -> bool {
        self.0.is_superset(&other.0)
    }

    /// Permissions of `other` that are missing from this set.
    #[must_use]
    pub fn missing_from(&self, other: &Self) -> Vec<Permission> {
        other.0.difference(&self.0).copied().collect()
    }

    /// The intersection (API keys: role ∩ scopes).
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self(self.0.intersection(&other.0).copied().collect())
    }

    /// Iterates in catalog order.
    pub fn iter(&self) -> impl Iterator<Item = Permission> + '_ {
        self.0.iter().copied()
    }

    /// Number of permissions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The permissions as database strings.
    #[must_use]
    pub fn to_strings(&self) -> Vec<&'static str> {
        self.0.iter().map(|p| p.as_str()).collect()
    }
}

impl FromIterator<Permission> for PermissionSet {
    fn from_iter<I: IntoIterator<Item = Permission>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

org_text_enum! {
    /// The built-in roles (seeded in `0012_builtin_roles.sql`).
    pub enum BuiltinRole {
        /// Full control including deletion and ownership transfer.
        Owner => "owner",
        /// Manages members, roles, policies, keys and webhooks.
        Admin => "admin",
        /// Regular member.
        Member => "member",
        /// Billing.
        Billing => "billing",
        /// Read-only access.
        Viewer => "viewer",
    }
}

const OWNER_ROLE_UUID: u128 = 0x0190_0000_0000_7000_8000_0000_0000_0001;
const ADMIN_ROLE_UUID: u128 = 0x0190_0000_0000_7000_8000_0000_0000_0002;
const MEMBER_ROLE_UUID: u128 = 0x0190_0000_0000_7000_8000_0000_0000_0003;
const BILLING_ROLE_UUID: u128 = 0x0190_0000_0000_7000_8000_0000_0000_0004;
const VIEWER_ROLE_UUID: u128 = 0x0190_0000_0000_7000_8000_0000_0000_0005;

/// Id of the built-in `owner` role.
pub const OWNER_ROLE_ID: RoleId = RoleId::from_uuid(Uuid::from_u128(OWNER_ROLE_UUID));
/// Id of the built-in `admin` role.
pub const ADMIN_ROLE_ID: RoleId = RoleId::from_uuid(Uuid::from_u128(ADMIN_ROLE_UUID));
/// Id of the built-in `member` role.
pub const MEMBER_ROLE_ID: RoleId = RoleId::from_uuid(Uuid::from_u128(MEMBER_ROLE_UUID));
/// Id of the built-in `billing` role.
pub const BILLING_ROLE_ID: RoleId = RoleId::from_uuid(Uuid::from_u128(BILLING_ROLE_UUID));
/// Id of the built-in `viewer` role.
pub const VIEWER_ROLE_ID: RoleId = RoleId::from_uuid(Uuid::from_u128(VIEWER_ROLE_UUID));

impl BuiltinRole {
    /// The fixed role id.
    #[must_use]
    pub const fn id(self) -> RoleId {
        match self {
            Self::Owner => OWNER_ROLE_ID,
            Self::Admin => ADMIN_ROLE_ID,
            Self::Member => MEMBER_ROLE_ID,
            Self::Billing => BILLING_ROLE_ID,
            Self::Viewer => VIEWER_ROLE_ID,
        }
    }

    /// The built-in role with this id, if any.
    #[must_use]
    pub fn from_id(id: RoleId) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.id() == id)
    }

    /// The permissions seeded by `0012_builtin_roles.sql`.
    #[must_use]
    pub fn permissions(self) -> PermissionSet {
        use Permission as P;
        let list: &[Permission] = match self {
            Self::Owner => Permission::ALL,
            Self::Admin => &[
                P::OrgRead,
                P::OrgUpdate,
                P::MembersRead,
                P::MembersInvite,
                P::MembersUpdate,
                P::MembersRemove,
                P::RolesRead,
                P::RolesManage,
                P::PoliciesRead,
                P::PoliciesManage,
                P::DomainsRead,
                P::DomainsManage,
                P::ApiKeysRead,
                P::ApiKeysManage,
                P::ServiceAccountsRead,
                P::ServiceAccountsManage,
                P::WebhooksRead,
                P::WebhooksManage,
                P::AuditRead,
                P::BillingRead,
            ],
            Self::Member => &[P::OrgRead, P::MembersRead],
            Self::Billing => &[P::OrgRead, P::BillingRead, P::BillingManage],
            Self::Viewer => &[
                P::OrgRead,
                P::MembersRead,
                P::RolesRead,
                P::PoliciesRead,
                P::DomainsRead,
            ],
        };
        list.iter().copied().collect()
    }
}

/// Whether `role` is the built-in owner role.
#[must_use]
pub fn is_owner_role(role: RoleId) -> bool {
    role == OWNER_ROLE_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_03_catalog_entries_are_resource_action_strings() {
        for p in Permission::ALL {
            let (resource, action) = p.as_str().split_once(':').unwrap();
            for part in [resource, action] {
                assert!(!part.is_empty() && part.len() <= 32, "{p}");
                assert!(part.as_bytes()[0].is_ascii_lowercase(), "{p}");
                assert!(
                    part.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                    "{p}"
                );
            }
            assert_eq!(Permission::from_catalog(p.as_str()), Some(*p));
        }
        assert_eq!(Permission::from_catalog("org:read "), None);
        assert_eq!(Permission::from_catalog("ORG:READ"), None);
        assert_eq!(Permission::from_catalog("anything:goes"), None);
    }

    #[test]
    fn org_03_unknown_database_values_grant_nothing() {
        let set = PermissionSet::from_db(&["org:read", "root:everything", "", "org:delete\0"]);
        assert_eq!(set.to_strings(), vec!["org:read"]);
    }

    #[test]
    fn org_04_owner_only_permissions_are_exactly_delete_and_transfer() {
        let owner_only: Vec<_> = Permission::ALL
            .iter()
            .filter(|p| p.is_owner_only())
            .collect();
        assert_eq!(
            owner_only,
            vec![&Permission::OrgDelete, &Permission::OrgTransferOwnership]
        );
        for role in BuiltinRole::ALL {
            if *role != BuiltinRole::Owner {
                assert!(
                    role.permissions().iter().all(|p| !p.is_owner_only()),
                    "{role}"
                );
            }
        }
        assert!(
            BuiltinRole::Owner
                .permissions()
                .is_superset(&BuiltinRole::Admin.permissions())
        );
    }

    #[test]
    fn org_03_builtin_role_ids_round_trip() {
        for role in BuiltinRole::ALL {
            assert_eq!(BuiltinRole::from_id(role.id()), Some(*role));
        }
        assert_eq!(
            OWNER_ROLE_ID.to_string(),
            "01900000-0000-7000-8000-000000000001"
        );
        assert_eq!(BuiltinRole::from_id(RoleId::generate()), None);
        assert!(is_owner_role(OWNER_ROLE_ID));
    }

    #[test]
    fn org_03_set_algebra() {
        let admin = BuiltinRole::Admin.permissions();
        let viewer = BuiltinRole::Viewer.permissions();
        assert!(admin.is_superset(&viewer));
        assert!(!viewer.is_superset(&admin));
        assert!(
            viewer
                .missing_from(&admin)
                .contains(&Permission::MembersInvite)
        );
        assert_eq!(admin.intersection(&viewer), viewer);
        assert!(Permission::OrgRead.is_read_only());
        assert!(!Permission::OrgUpdate.is_read_only());
    }
}
