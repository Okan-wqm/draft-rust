//! Staff roles and admin permissions (K-93, ADM-09).
//!
//! `users.is_platform_admin` marks a **staff** account (admin console
//! access, phishing-resistant MFA everywhere). What the staff member may do
//! is decided by its [`StaffRole`] (`admin_staff_roles`, migration `2203`),
//! re-read from the database on every request together with the account:
//! a role change applies to the very next request, whatever the session or
//! token says. An account without a role row has no permission at all.
//!
//! The decision is the single table in [`StaffRole::grants`] (an exhaustive
//! `match`: a new permission does not compile until every role is decided)
//! and every admin route declares its permission in
//! [`crate::routes::ROUTE_PERMISSIONS`]. A route without an entry is refused
//! for everyone (no default allow).
//!
//! | Permission | `support_readonly` | `support` | `security` | `platform_admin` |
//! |------------|:-:|:-:|:-:|:-:|
//! | `users:read` | ✓ | ✓ | ✓ | ✓ |
//! | `users:unlock`, `users:revoke_sessions`, `users:reset_password` | | ✓ | ✓ | ✓ |
//! | `users:recover` (MFA reset, mark e-mail verified) | | ✓ | | ✓ |
//! | `users:impersonate` | | ✓ | | ✓ |
//! | `users:suspend` (suspend, unsuspend) | | | ✓ | ✓ |
//! | `staff:contain` (act on another staff member) | | | ✓ | ✓ |
//! | `approvals:read`, `approvals:request`, `approvals:decide` | | | ✓ | ✓ |
//! | `emergency:execute` | | | ✓ | ✓ |
//! | `audit:read`, `audit:export`, `audit:verify`, `audit:restrict` | | | ✓ | ✓ |
//! | `staff:read`, `oauth_clients:read` | | | ✓ | ✓ |
//! | `staff:manage`, `oauth_clients:manage` | | | | ✓ |

use std::fmt;
use std::str::FromStr;

use authn_core::error::{AuthError, codes};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The role of a staff account (K-93).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StaffRole {
    /// Reads accounts only (first-line support, auditors of support work).
    SupportReadonly,
    /// Account support: recovery (MFA reset, password reset, e-mail
    /// verification), unlock, session revocation, impersonation of regular
    /// users.
    Support,
    /// Security operations: suspension, containment of other staff,
    /// emergency operations, audit, four-eyes decisions. No account
    /// recovery and no impersonation (separation of duties: the team that
    /// investigates does not take over accounts).
    Security,
    /// Everything, including staff role changes. Break-glass accounts are
    /// always `platform_admin`.
    PlatformAdmin,
}

impl StaffRole {
    /// Every role, least privileged first.
    pub const ALL: [Self; 4] = [
        Self::SupportReadonly,
        Self::Support,
        Self::Security,
        Self::PlatformAdmin,
    ];

    /// Stable wire / database value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SupportReadonly => "support_readonly",
            Self::Support => "support",
            Self::Security => "security",
            Self::PlatformAdmin => "platform_admin",
        }
    }

    /// Whether the role holds `permission`. The whole decision table: an
    /// exhaustive `match` on the permission, so a new permission is a
    /// compile error until every role is decided.
    #[must_use]
    pub const fn grants(self, permission: AdminPermission) -> bool {
        use AdminPermission as P;
        let support_readonly = matches!(self, Self::SupportReadonly);
        let support = matches!(self, Self::Support);
        let security = matches!(self, Self::Security);
        let platform_admin = matches!(self, Self::PlatformAdmin);
        match permission {
            P::UsersRead => true,
            P::UsersUnlock | P::UsersRevokeSessions | P::UsersResetPassword => !support_readonly,
            P::UsersRecover | P::UsersImpersonate => support || platform_admin,
            P::UsersSuspend
            | P::StaffContain
            | P::ApprovalsRead
            | P::ApprovalsRequest
            | P::ApprovalsDecide
            | P::EmergencyExecute
            | P::AuditRead
            | P::AuditExport
            | P::AuditVerify
            | P::AuditRestrict
            | P::StaffRead
            | P::OAuthClientsRead => security || platform_admin,
            P::StaffManage | P::OAuthClientsManage => platform_admin,
        }
    }

    /// Whether the role holds every permission of `permissions`.
    #[must_use]
    pub fn grants_all(self, permissions: &[AdminPermission]) -> bool {
        permissions.iter().all(|p| self.grants(*p))
    }

    /// The roles holding every permission of `permissions`.
    #[must_use]
    pub fn holding(permissions: &[AdminPermission]) -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|r| r.grants_all(permissions))
            .collect()
    }
}

impl fmt::Display for StaffRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StaffRole {
    type Err = AuthError;

    /// Parses a wire value (`validation_failed` for anything else).
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|r| r.as_str() == value)
            .ok_or_else(|| {
                AuthError::new(codes::common::VALIDATION_FAILED)
                    .with_details(serde_json::json!({ "field": "role" }))
            })
    }
}

/// A permission of the admin API (K-93). Every admin route requires
/// exactly one ([`crate::routes::ROUTE_PERMISSIONS`]); service operations
/// check theirs again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminPermission {
    /// Search accounts and read their details (ADM-02).
    UsersRead,
    /// Unlock an account (ADM-03).
    UsersUnlock,
    /// Revoke an account's sessions (ADM-03).
    UsersRevokeSessions,
    /// Force a password reset / set `must_change_password` (ADM-03).
    UsersResetPassword,
    /// Reset MFA, mark the address verified (ADM-03; takeover-enabling).
    UsersRecover,
    /// Impersonate a regular user (ADM-04).
    UsersImpersonate,
    /// Suspend / unsuspend an account (ADM-03).
    UsersSuspend,
    /// Act (suspend, unlock, revoke sessions) on **another staff member**
    /// (ADM-03, K-66: also four-eyes).
    StaffContain,
    /// List four-eyes requests (K-66).
    ApprovalsRead,
    /// Request a four-eyes approval (K-66).
    ApprovalsRequest,
    /// Approve or deny another staff member's request (K-66): four-eyes
    /// authority, `security` and `platform_admin` only.
    ApprovalsDecide,
    /// Emergency operations (ADM-06).
    EmergencyExecute,
    /// Query platform audit events (ADM-07).
    AuditRead,
    /// Export audit events (ADM-07).
    AuditExport,
    /// Verify the audit chain (ADM-07, K-09).
    AuditVerify,
    /// Restrict a justification / extend a restriction (ADM-08, K-39, K-62).
    AuditRestrict,
    /// List staff accounts and their roles (K-93).
    StaffRead,
    /// Change the role of another staff member (K-93; four-eyes).
    StaffManage,
    /// Read OAuth client registrations (K-80, authn-oidc-provider).
    OAuthClientsRead,
    /// Create / change / delete OAuth client registrations (K-80).
    OAuthClientsManage,
}

impl AdminPermission {
    /// Every permission.
    pub const ALL: [Self; 20] = [
        Self::UsersRead,
        Self::UsersUnlock,
        Self::UsersRevokeSessions,
        Self::UsersResetPassword,
        Self::UsersRecover,
        Self::UsersImpersonate,
        Self::UsersSuspend,
        Self::StaffContain,
        Self::ApprovalsRead,
        Self::ApprovalsRequest,
        Self::ApprovalsDecide,
        Self::EmergencyExecute,
        Self::AuditRead,
        Self::AuditExport,
        Self::AuditVerify,
        Self::AuditRestrict,
        Self::StaffRead,
        Self::StaffManage,
        Self::OAuthClientsRead,
        Self::OAuthClientsManage,
    ];

    /// Stable name (audit metadata, logs, error details, documentation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsersRead => "users:read",
            Self::UsersUnlock => "users:unlock",
            Self::UsersRevokeSessions => "users:revoke_sessions",
            Self::UsersResetPassword => "users:reset_password",
            Self::UsersRecover => "users:recover",
            Self::UsersImpersonate => "users:impersonate",
            Self::UsersSuspend => "users:suspend",
            Self::StaffContain => "staff:contain",
            Self::ApprovalsRead => "approvals:read",
            Self::ApprovalsRequest => "approvals:request",
            Self::ApprovalsDecide => "approvals:decide",
            Self::EmergencyExecute => "emergency:execute",
            Self::AuditRead => "audit:read",
            Self::AuditExport => "audit:export",
            Self::AuditVerify => "audit:verify",
            Self::AuditRestrict => "audit:restrict",
            Self::StaffRead => "staff:read",
            Self::StaffManage => "staff:manage",
            Self::OAuthClientsRead => "oauth_clients:read",
            Self::OAuthClientsManage => "oauth_clients:manage",
        }
    }

    /// The `403 admin_permission_denied` error for this permission.
    #[must_use]
    pub fn denied(self) -> AuthError {
        AuthError::new(codes::admin::PERMISSION_DENIED)
            .with_details(serde_json::json!({ "permission": self.as_str() }))
    }
}

impl fmt::Display for AdminPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adm_09_roles_round_trip_and_unknown_roles_are_refused() {
        for role in StaffRole::ALL {
            assert_eq!(role.as_str().parse::<StaffRole>().unwrap(), role);
            assert_eq!(
                serde_json::to_value(role).unwrap(),
                serde_json::Value::from(role.as_str())
            );
        }
        for bad in ["", "admin", "PLATFORM_ADMIN", "platform_admin ", "owner"] {
            assert_eq!(
                bad.parse::<StaffRole>().unwrap_err().code(),
                codes::common::VALIDATION_FAILED
            );
        }
    }

    #[test]
    fn adm_09_roles_are_strictly_nested_except_the_separated_duties() {
        use AdminPermission as P;
        // support_readonly ⊂ support, support_readonly ⊂ security,
        // everything ⊂ platform_admin.
        for p in AdminPermission::ALL {
            if StaffRole::SupportReadonly.grants(p) {
                assert!(StaffRole::Support.grants(p) && StaffRole::Security.grants(p));
            }
            assert!(StaffRole::PlatformAdmin.grants(p), "{p}");
        }
        assert_eq!(
            AdminPermission::ALL
                .into_iter()
                .filter(|p| StaffRole::SupportReadonly.grants(*p))
                .collect::<Vec<_>>(),
            vec![P::UsersRead]
        );
        // Separation of duties: security neither recovers nor impersonates;
        // support neither suspends nor decides four-eyes requests.
        for p in [P::UsersRecover, P::UsersImpersonate] {
            assert!(!StaffRole::Security.grants(p));
            assert!(StaffRole::Support.grants(p));
        }
        for p in [
            P::UsersSuspend,
            P::StaffContain,
            P::ApprovalsDecide,
            P::ApprovalsRequest,
            P::EmergencyExecute,
            P::AuditRead,
        ] {
            assert!(!StaffRole::Support.grants(p));
            assert!(StaffRole::Security.grants(p));
        }
    }

    #[test]
    fn adm_10_four_eyes_authority_is_platform_admin_and_security_only() {
        assert_eq!(
            StaffRole::holding(&[AdminPermission::ApprovalsDecide]),
            vec![StaffRole::Security, StaffRole::PlatformAdmin]
        );
        assert_eq!(
            StaffRole::holding(&[AdminPermission::StaffManage]),
            vec![StaffRole::PlatformAdmin]
        );
        assert_eq!(
            StaffRole::holding(&[AdminPermission::UsersImpersonate]),
            vec![StaffRole::Support, StaffRole::PlatformAdmin]
        );
    }

    #[test]
    fn adm_09_permission_names_are_unique() {
        let mut names: Vec<_> = AdminPermission::ALL.iter().map(|p| p.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), AdminPermission::ALL.len());
    }
}
