//! Authorization of the organization-scoped endpoints (AUD-04, AUD-07,
//! ORG-10).
//!
//! `authn-audit` (wave A) cannot depend on `authn-org`, so authorization is
//! delegated through [`AuditAccessPolicy`]; `authn-server` implements it
//! with authn-org's RBAC (permissions `audit:read`, `webhooks:read`,
//! `webhooks:manage` — seeded in migration 0012). Default deny: anything
//! but [`AccessDecision::Allow`] is answered with `404 not_found`, exactly
//! like an unknown organization (no tenant enumeration).
//!
//! The client IP is passed along so that organization IP allow-lists
//! (ORG-07) are enforced on these endpoints too.

use std::net::IpAddr;

use async_trait::async_trait;
use authn_core::domain::{Principal, Subject};
use authn_core::error::{AuthError, codes};
use authn_core::id::{OrgId, UserId};
use authn_core::ports::Actor;

/// What the caller wants to do in an organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditPermission {
    /// Read the organization's audit log (`audit:read`).
    AuditRead,
    /// Read webhook endpoints and delivery history (`webhooks:read`).
    WebhooksRead,
    /// Create / change / delete webhook endpoints, rotate secrets, redeliver
    /// (`webhooks:manage`).
    WebhooksManage,
}

impl AuditPermission {
    /// The RBAC permission string (ORG-03).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditRead => "audit:read",
            Self::WebhooksRead => "webhooks:read",
            Self::WebhooksManage => "webhooks:manage",
        }
    }
}

/// Outcome of an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// The principal holds the permission in that organization.
    Allow,
    /// Anything else (not a member, other tenant, missing permission,
    /// unknown organization, suspended membership…).
    Deny,
}

/// Decides whether a principal may act on an organization's audit log or
/// webhooks. Implemented by `authn-server` with authn-org RBAC.
///
/// Requirements for implementations: default deny; service accounts / API
/// keys only ever for their own organization (and only with the matching
/// scope); a platform administrator is *not* implicitly allowed (admin
/// access goes through the admin API, ADM-07); the organization's IP
/// allow-list (ORG-07) is applied to `client_ip` (fail closed when it is
/// `None` and the organization has an allow-list).
#[async_trait]
pub trait AuditAccessPolicy: Send + Sync {
    /// Checks `permission` for `principal` in `org`, for a request from
    /// `client_ip` (PRT-06 resolved client address).
    async fn check(
        &self,
        principal: &Principal,
        org: OrgId,
        permission: AuditPermission,
        client_ip: Option<IpAddr>,
    ) -> Result<AccessDecision, AuthError>;
}

/// A policy that denies everything (safe default until the server wires
/// the RBAC implementation).
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllAuditAccess;

#[async_trait]
impl AuditAccessPolicy for DenyAllAuditAccess {
    async fn check(
        &self,
        _principal: &Principal,
        _org: OrgId,
        _permission: AuditPermission,
        _client_ip: Option<IpAddr>,
    ) -> Result<AccessDecision, AuthError> {
        Ok(AccessDecision::Deny)
    }
}

/// Runs the policy; denial (and a service account of another organization)
/// becomes `not_found` (ORG-10).
pub(crate) async fn authorize(
    policy: &dyn AuditAccessPolicy,
    principal: &Principal,
    org: OrgId,
    permission: AuditPermission,
    client_ip: Option<IpAddr>,
) -> Result<(), AuthError> {
    if let Subject::ServiceAccount { org_id, .. } = principal.subject
        && org_id != org
    {
        return Err(AuthError::new(codes::common::NOT_FOUND)
            .with_context("service account of another organization"));
    }
    match policy.check(principal, org, permission, client_ip).await? {
        AccessDecision::Allow => Ok(()),
        AccessDecision::Deny => {
            Err(AuthError::new(codes::common::NOT_FOUND)
                .with_context("audit access denied by policy"))
        }
    }
}

/// The audit actor of a principal and the impersonating admin, if any.
#[must_use]
pub fn actor_of(principal: &Principal) -> (Actor, Option<UserId>) {
    let actor = match principal.subject {
        Subject::User { user_id } => Actor::User(user_id),
        Subject::ServiceAccount {
            service_account_id, ..
        } => Actor::ServiceAccount(service_account_id),
    };
    (actor, principal.impersonation.map(|i| i.admin_user_id))
}
