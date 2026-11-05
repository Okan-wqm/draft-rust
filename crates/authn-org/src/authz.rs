//! Authorization (ORG-03, ORG-04, ORG-07, ORG-10, ARC-10).
//!
//! Every organization-scoped use case — in this crate and, through
//! [`crate::OrgService::authorize`], in others — runs one decision function,
//! `decide`, over facts loaded with a single tenant-filtered query.
//! Default deny, in this order:
//!
//! 1. **Tenant isolation:** no active membership (or a service account of
//!    another organization, or an API key bound to another organization)
//!    → `404 not_found`, exactly like an unknown organization; nothing
//!    about other tenants leaks.
//! 2. Read-only impersonation may only use `*:read` permissions.
//! 3. Organization status: `suspended` → `403 org_suspended`;
//!    `pending_deletion` → read permissions and `org:delete` (cancel) only.
//! 4. Organization policy (ORG-07): IP allow-list for every principal
//!    (fails closed without a client IP), MFA / phishing-resistant MFA, the
//!    allowed login methods and second factors (K-57) and the session
//!    lifetime cap for user sessions.
//! 5. Permission: the role's permissions, intersected with the API key's
//!    scopes for API-key principals; missing → `403 forbidden`.
//!
//! Platform administrators get no implicit access (ADM-07 has its own API).

use std::net::IpAddr;

use authn_core::domain::{AuthMethodRef, Principal, PrincipalCredential, Subject};
use authn_core::error::{AuthError, codes};
use authn_core::id::{MembershipId, OrgId, RoleId, ServiceAccountId, UserId};
use authn_core::ports::Actor;
use ipnet::IpNet;
use sqlx::PgExecutor;
use time::OffsetDateTime;
use uuid::Uuid;

use authn_core::domain::{FactorKind, LoginMethod};

use crate::model::{MemberStatus, OrgStatus, ServiceAccountStatus};
use crate::permission::{Permission, PermissionSet, is_owner_role};
use crate::policy::{OrgPolicy, PolicyViolation};

/// Who acts inside the organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzSubject {
    /// A member.
    Member {
        /// The user.
        user_id: UserId,
        /// The membership.
        membership_id: MembershipId,
    },
    /// A service account of the organization.
    ServiceAccount {
        /// The service account.
        service_account_id: ServiceAccountId,
    },
}

/// A successful authorization: who acts, with which rights, in which
/// organization. Use cases keep it for their escalation checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// The organization.
    pub org_id: OrgId,
    /// Its display name.
    pub org_name: String,
    /// Its status.
    pub org_status: OrgStatus,
    /// The acting member or service account.
    pub subject: AuthzSubject,
    /// The subject's role.
    pub role_id: RoleId,
    /// Whether that role is the built-in `owner` role.
    pub is_owner: bool,
    /// Effective permissions: the role's, intersected with API key scopes.
    pub permissions: PermissionSet,
    /// The organization policy.
    pub policy: OrgPolicy,
}

impl Authorization {
    /// The acting user, if a member acts.
    #[must_use]
    pub fn user_id(&self) -> Option<UserId> {
        match self.subject {
            AuthzSubject::Member { user_id, .. } => Some(user_id),
            AuthzSubject::ServiceAccount { .. } => None,
        }
    }

    /// The acting user or `forbidden` (service accounts cannot do this).
    pub fn require_user(&self) -> Result<UserId, AuthError> {
        self.user_id()
            .ok_or_else(|| AuthError::new(codes::common::FORBIDDEN).with_context("user required"))
    }

    /// Whether the subject holds `permission` (effective).
    #[must_use]
    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Owner-only operations (ORG-11, ORG-12): the built-in owner role and
    /// the permission.
    pub fn require_owner(&self, permission: Permission) -> Result<(), AuthError> {
        if self.is_owner && self.has(permission) && self.user_id().is_some() {
            Ok(())
        } else {
            Err(AuthError::new(codes::org::ORG_OWNER_REQUIRED))
        }
    }

    /// ORG-04: the subject may grant / manage a role with `role_permissions`
    /// only if it holds every one of them itself, and the `owner` role only
    /// if it is an owner.
    pub fn ensure_can_grant(
        &self,
        role_id: RoleId,
        role_permissions: &PermissionSet,
    ) -> Result<(), AuthError> {
        if is_owner_role(role_id) && !self.is_owner {
            return Err(AuthError::new(codes::org::ORG_ROLE_ESCALATION)
                .with_context("only owners grant or manage the owner role"));
        }
        if !self.permissions.is_superset(role_permissions) {
            return Err(AuthError::new(codes::org::ORG_ROLE_ESCALATION)
                .with_context("role has permissions the actor lacks"));
        }
        Ok(())
    }

    /// The audit actor.
    #[must_use]
    pub fn actor(&self) -> Actor {
        match self.subject {
            AuthzSubject::Member { user_id, .. } => Actor::User(user_id),
            AuthzSubject::ServiceAccount { service_account_id } => {
                Actor::ServiceAccount(service_account_id)
            }
        }
    }
}

/// Facts about a principal inside one organization (one query).
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct Facts {
    pub org_id: OrgId,
    pub org_name: String,
    pub org_status: OrgStatus,
    /// Membership id or service-account id.
    pub subject_id: Uuid,
    /// Membership or service-account status (text).
    pub subject_status: String,
    pub role_id: RoleId,
    pub permissions: Vec<String>,
    #[sqlx(flatten)]
    pub policy: PolicyRow,
}

/// The columns of `org_policies` (all nullable through the LEFT JOIN).
#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub(crate) struct PolicyRow {
    pub mfa_required: Option<bool>,
    pub phishing_resistant_mfa_required: Option<bool>,
    pub allowed_login_methods: Option<Vec<LoginMethod>>,
    pub allowed_mfa_factors: Option<Vec<FactorKind>>,
    pub max_session_lifetime_seconds: Option<i32>,
    pub ip_allowlist: Option<Vec<IpNet>>,
    pub trusted_devices_allowed: Option<bool>,
    pub allowed_aaguids: Option<Vec<Uuid>>,
}

impl PolicyRow {
    pub(crate) fn into_policy(self) -> OrgPolicy {
        let defaults = OrgPolicy::default();
        OrgPolicy {
            mfa_required: self.mfa_required.unwrap_or(defaults.mfa_required),
            phishing_resistant_mfa_required: self
                .phishing_resistant_mfa_required
                .unwrap_or(defaults.phishing_resistant_mfa_required),
            allowed_login_methods: self.allowed_login_methods,
            allowed_mfa_factors: self.allowed_mfa_factors,
            // A stored value outside u32 cannot exist (CHECK > 0); a
            // corrupt value restricts rather than relaxes.
            max_session_lifetime_seconds: self
                .max_session_lifetime_seconds
                .map(|s| u32::try_from(s).unwrap_or(crate::policy::MIN_SESSION_LIFETIME_SECONDS)),
            ip_allowlist: self.ip_allowlist,
            trusted_devices_allowed: self
                .trusted_devices_allowed
                .unwrap_or(defaults.trusted_devices_allowed),
            allowed_passkey_aaguids: self.allowed_aaguids,
        }
    }
}

/// Policy columns selected from `org_policies p`.
macro_rules! policy_columns {
    () => {
        "p.mfa_required, p.phishing_resistant_mfa_required, p.allowed_login_methods, \
         p.allowed_mfa_factors, p.max_session_lifetime_seconds, p.ip_allowlist, \
         p.trusted_devices_allowed, p.allowed_aaguids"
    };
}
pub(crate) use policy_columns;

/// Loads the facts of `principal` in `org`; `None` when the principal has
/// no membership / service account there (tenant isolation).
pub(crate) async fn load_facts<'e>(
    executor: impl PgExecutor<'e>,
    principal: &Principal,
    org: OrgId,
) -> Result<Option<Facts>, AuthError> {
    let row = match principal.subject {
        Subject::User { user_id } => {
            let sql = concat!(
                "SELECT o.id AS org_id, o.name AS org_name, o.status AS org_status, \
                 m.id AS subject_id, m.status AS subject_status, m.role_id, \
                 ARRAY(SELECT rp.permission FROM role_permissions rp WHERE rp.role_id = m.role_id) \
                 AS permissions, ",
                policy_columns!(),
                " FROM organizations o \
                 JOIN memberships m ON m.org_id = o.id AND m.user_id = $2 \
                 LEFT JOIN org_policies p ON p.org_id = o.id \
                 WHERE o.id = $1"
            );
            sqlx::query_as::<_, Facts>(sql)
                .bind(org)
                .bind(user_id)
                .fetch_optional(executor)
                .await?
        }
        Subject::ServiceAccount {
            service_account_id,
            org_id,
        } => {
            if org_id != org {
                return Ok(None);
            }
            let sql = concat!(
                "SELECT o.id AS org_id, o.name AS org_name, o.status AS org_status, \
                 sa.id AS subject_id, sa.status AS subject_status, sa.role_id, \
                 ARRAY(SELECT rp.permission FROM role_permissions rp WHERE rp.role_id = sa.role_id) \
                 AS permissions, ",
                policy_columns!(),
                " FROM organizations o \
                 JOIN service_accounts sa ON sa.org_id = o.id AND sa.id = $2 \
                 LEFT JOIN org_policies p ON p.org_id = o.id \
                 WHERE o.id = $1"
            );
            sqlx::query_as::<_, Facts>(sql)
                .bind(org)
                .bind(service_account_id)
                .fetch_optional(executor)
                .await?
        }
    };
    Ok(row)
}

fn not_found(context: &'static str) -> AuthError {
    AuthError::new(codes::common::NOT_FOUND).with_context(context)
}

/// The single authorization decision (pure; see the module docs).
pub(crate) fn decide(
    facts: Option<Facts>,
    principal: &Principal,
    permission: Permission,
    client_ip: Option<IpAddr>,
    now: OffsetDateTime,
) -> Result<Authorization, AuthError> {
    decide_access(
        facts,
        principal,
        Some(permission),
        !permission.is_read_only(),
        client_ip,
        now,
    )
}

/// [`decide`] for operations every active member may perform on their own
/// membership (leaving): all checks except the permission; treated as a
/// state change (read-only impersonation is refused).
pub(crate) fn decide_membership(
    facts: Option<Facts>,
    principal: &Principal,
    client_ip: Option<IpAddr>,
    now: OffsetDateTime,
) -> Result<Authorization, AuthError> {
    decide_access(facts, principal, None, true, client_ip, now)
}

/// [`decide`] without a permission and without a state change: "is this an
/// active member / service account of the organization that satisfies its
/// policy?" (organization switch, SES-17).
pub(crate) fn decide_member_check(
    facts: Option<Facts>,
    principal: &Principal,
    client_ip: Option<IpAddr>,
    now: OffsetDateTime,
) -> Result<Authorization, AuthError> {
    decide_access(facts, principal, None, false, client_ip, now)
}

fn decide_access(
    facts: Option<Facts>,
    principal: &Principal,
    permission: Option<Permission>,
    state_change: bool,
    client_ip: Option<IpAddr>,
    now: OffsetDateTime,
) -> Result<Authorization, AuthError> {
    let Some(facts) = facts else {
        return Err(not_found("no membership in organization"));
    };
    // 1. Tenant isolation and subject status.
    let subject = match principal.subject {
        Subject::User { user_id } => {
            if facts.subject_status != MemberStatus::Active.as_str() {
                return Err(not_found("membership not active"));
            }
            AuthzSubject::Member {
                user_id,
                membership_id: MembershipId::from_uuid(facts.subject_id),
            }
        }
        Subject::ServiceAccount {
            service_account_id,
            org_id,
        } => {
            if org_id != facts.org_id
                || service_account_id.as_uuid() != facts.subject_id
                || facts.subject_status != ServiceAccountStatus::Active.as_str()
            {
                return Err(not_found("service account not active in organization"));
            }
            AuthzSubject::ServiceAccount { service_account_id }
        }
    };
    let api_key = matches!(principal.credential, PrincipalCredential::ApiKey { .. });
    if (api_key || matches!(subject, AuthzSubject::ServiceAccount { .. }))
        && principal.active_org != Some(facts.org_id)
    {
        return Err(not_found("api key bound to another organization"));
    }
    // 2. Read-only impersonation.
    if state_change {
        principal.require_writable()?;
    }
    // 3. Organization status.
    match facts.org_status {
        OrgStatus::Active => {}
        OrgStatus::Suspended => return Err(AuthError::new(codes::org::ORG_SUSPENDED)),
        OrgStatus::PendingDeletion => {
            if let Some(permission) = permission
                && !(permission.is_read_only() || permission == Permission::OrgDelete)
            {
                return Err(AuthError::new(codes::org::ORG_PENDING_DELETION));
            }
        }
    }
    // 4. Organization policy.
    let policy = facts.policy.into_policy();
    if policy.ip_allowlist.is_some() && !client_ip.is_some_and(|ip| policy.allows_ip(ip)) {
        return Err(AuthError::new(codes::org::ORG_POLICY_IP_DENIED));
    }
    if !api_key && matches!(subject, AuthzSubject::Member { .. }) {
        match policy.check_session(&principal.amr, principal.auth_time, now) {
            Ok(()) => {}
            Err(PolicyViolation::MfaRequired | PolicyViolation::PhishingResistantRequired) => {
                return Err(AuthError::new(codes::org::ORG_POLICY_MFA_REQUIRED));
            }
            Err(PolicyViolation::SessionTooOld) => {
                return Err(AuthError::new(codes::common::STEP_UP_REQUIRED)
                    .with_context("organization session lifetime cap"));
            }
            Err(PolicyViolation::IpNotAllowed) => {
                return Err(AuthError::new(codes::org::ORG_POLICY_IP_DENIED));
            }
            Err(
                PolicyViolation::LoginMethodNotAllowed | PolicyViolation::SecondFactorNotAllowed,
            ) => {
                return Err(AuthError::internal("unexpected policy violation"));
            }
        }
        // K-57: how the session was established, on every request — not
        // only at a login that requested this organization or at the
        // organization switch (a personal-context session acting here).
        match policy.check_session_methods(
            principal.login_method,
            &principal.mfa_factors,
            &principal.amr,
            principal.is_impersonated(),
        ) {
            Ok(()) => {}
            Err(PolicyViolation::LoginMethodNotAllowed) => {
                return Err(AuthError::new(codes::session::LOGIN_METHOD_NOT_ALLOWED));
            }
            Err(_) => {
                return Err(AuthError::new(codes::org::ORG_POLICY_MFA_REQUIRED)
                    .with_context("the session's second factor is not allowed here"));
            }
        }
    }
    // 5. Permission.
    let role_permissions = PermissionSet::from_db(&facts.permissions);
    let permissions = if api_key || matches!(subject, AuthzSubject::ServiceAccount { .. }) {
        role_permissions.intersection(&PermissionSet::from_db(&principal.scopes))
    } else {
        role_permissions
    };
    if let Some(permission) = permission
        && !permissions.contains(permission)
    {
        return Err(AuthError::new(codes::common::FORBIDDEN)
            .with_context(format!("missing permission {permission}")));
    }
    Ok(Authorization {
        org_id: facts.org_id,
        org_name: facts.org_name,
        org_status: facts.org_status,
        subject,
        role_id: facts.role_id,
        is_owner: is_owner_role(facts.role_id),
        permissions,
        policy,
    })
}

/// Whether the session `amr` shows a phishing-resistant factor.
#[must_use]
pub fn is_phishing_resistant(amr: &[AuthMethodRef]) -> bool {
    amr.iter()
        .any(|a| matches!(a, AuthMethodRef::Hwk | AuthMethodRef::Swk))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use authn_core::domain::Impersonation;
    use authn_core::id::{ApiKeyId, SessionId};

    use super::*;
    use crate::permission::{ADMIN_ROLE_ID, BuiltinRole, OWNER_ROLE_ID, VIEWER_ROLE_ID};

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
    }

    fn facts(org: OrgId, role: BuiltinRole) -> Facts {
        Facts {
            org_id: org,
            org_name: "Acme".into(),
            org_status: OrgStatus::Active,
            subject_id: Uuid::now_v7(),
            subject_status: "active".into(),
            role_id: role.id(),
            permissions: role
                .permissions()
                .to_strings()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            policy: PolicyRow::default(),
        }
    }

    fn user(org: OrgId) -> Principal {
        Principal {
            subject: Subject::User {
                user_id: UserId::generate(),
            },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: Some(org),
            amr: vec![AuthMethodRef::Pwd],
            acr: None,
            auth_time: Some(now()),
            scopes: vec![],
            impersonation: None,
            is_platform_admin: false,
            login_method: None,
            mfa_factors: Vec::new(),
        }
    }

    fn ip() -> Option<IpAddr> {
        Some("203.0.113.10".parse().unwrap())
    }

    #[test]
    fn org_10_no_membership_is_not_found() {
        let org = OrgId::generate();
        let err = decide(None, &user(org), Permission::OrgRead, ip(), now()).unwrap_err();
        assert_eq!(err.code(), codes::common::NOT_FOUND);
        // Platform admins get nothing implicitly.
        let mut admin = user(org);
        admin.is_platform_admin = true;
        let err = decide(None, &admin, Permission::OrgRead, ip(), now()).unwrap_err();
        assert_eq!(err.code(), codes::common::NOT_FOUND);
    }

    #[test]
    fn org_02_suspended_members_are_treated_as_outsiders() {
        let org = OrgId::generate();
        let mut f = facts(org, BuiltinRole::Owner);
        f.subject_status = "suspended".into();
        let err = decide(Some(f), &user(org), Permission::OrgRead, ip(), now()).unwrap_err();
        assert_eq!(err.code(), codes::common::NOT_FOUND);
    }

    #[test]
    fn org_03_default_deny_and_role_permissions() {
        let org = OrgId::generate();
        let viewer = facts(org, BuiltinRole::Viewer);
        assert!(
            decide(
                Some(viewer.clone()),
                &user(org),
                Permission::MembersRead,
                ip(),
                now()
            )
            .is_ok()
        );
        let err = decide(
            Some(viewer),
            &user(org),
            Permission::MembersInvite,
            ip(),
            now(),
        )
        .unwrap_err();
        assert_eq!(err.code(), codes::common::FORBIDDEN);
        let mut empty = facts(org, BuiltinRole::Viewer);
        empty.permissions = vec!["root:all".into()];
        let err = decide(Some(empty), &user(org), Permission::OrgRead, ip(), now()).unwrap_err();
        assert_eq!(err.code(), codes::common::FORBIDDEN);
        let auth = decide(
            Some(facts(org, BuiltinRole::Owner)),
            &user(org),
            Permission::OrgDelete,
            ip(),
            now(),
        )
        .unwrap();
        assert!(auth.is_owner);
        assert!(auth.require_owner(Permission::OrgDelete).is_ok());
    }

    #[test]
    fn org_04_escalation_guard() {
        let org = OrgId::generate();
        let admin = decide(
            Some(facts(org, BuiltinRole::Admin)),
            &user(org),
            Permission::MembersUpdate,
            ip(),
            now(),
        )
        .unwrap();
        assert!(
            admin
                .ensure_can_grant(VIEWER_ROLE_ID, &BuiltinRole::Viewer.permissions())
                .is_ok()
        );
        assert!(
            admin
                .ensure_can_grant(ADMIN_ROLE_ID, &BuiltinRole::Admin.permissions())
                .is_ok()
        );
        let err = admin
            .ensure_can_grant(OWNER_ROLE_ID, &BuiltinRole::Owner.permissions())
            .unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
        let custom: PermissionSet = [Permission::BillingManage].into_iter().collect();
        let err = admin
            .ensure_can_grant(RoleId::generate(), &custom)
            .unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
        assert_eq!(
            admin
                .require_owner(Permission::OrgDelete)
                .unwrap_err()
                .code(),
            codes::org::ORG_OWNER_REQUIRED
        );
    }

    #[test]
    fn adm_04_read_only_impersonation_reads_only() {
        let org = OrgId::generate();
        let mut p = user(org);
        p.impersonation = Some(Impersonation {
            admin_user_id: UserId::generate(),
            read_only: true,
            expires_at: now(),
        });
        assert!(
            decide(
                Some(facts(org, BuiltinRole::Owner)),
                &p,
                Permission::OrgRead,
                ip(),
                now()
            )
            .is_ok()
        );
        let err = decide(
            Some(facts(org, BuiltinRole::Owner)),
            &p,
            Permission::OrgUpdate,
            ip(),
            now(),
        )
        .unwrap_err();
        assert_eq!(err.code(), codes::common::FORBIDDEN);
    }

    #[test]
    fn org_12_pending_deletion_allows_read_and_cancel_only() {
        let org = OrgId::generate();
        let mut f = facts(org, BuiltinRole::Owner);
        f.org_status = OrgStatus::PendingDeletion;
        assert!(
            decide(
                Some(f.clone()),
                &user(org),
                Permission::OrgRead,
                ip(),
                now()
            )
            .is_ok()
        );
        assert!(
            decide(
                Some(f.clone()),
                &user(org),
                Permission::OrgDelete,
                ip(),
                now()
            )
            .is_ok()
        );
        let err = decide(
            Some(f.clone()),
            &user(org),
            Permission::MembersInvite,
            ip(),
            now(),
        )
        .unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_PENDING_DELETION);
        f.org_status = OrgStatus::Suspended;
        let err = decide(Some(f), &user(org), Permission::OrgRead, ip(), now()).unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_SUSPENDED);
    }

    #[test]
    fn org_07_policy_is_enforced_per_request() {
        let org = OrgId::generate();
        let mut f = facts(org, BuiltinRole::Owner);
        f.policy.ip_allowlist = Some(vec!["10.0.0.0/8".parse().unwrap()]);
        let err = decide(
            Some(f.clone()),
            &user(org),
            Permission::OrgRead,
            ip(),
            now(),
        )
        .unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_POLICY_IP_DENIED);
        let err = decide(
            Some(f.clone()),
            &user(org),
            Permission::OrgRead,
            None,
            now(),
        )
        .unwrap_err();
        assert_eq!(
            err.code(),
            codes::org::ORG_POLICY_IP_DENIED,
            "fails closed without IP"
        );
        assert!(
            decide(
                Some(f),
                &user(org),
                Permission::OrgRead,
                Some("10.1.2.3".parse().unwrap()),
                now()
            )
            .is_ok()
        );

        let mut f = facts(org, BuiltinRole::Owner);
        f.policy.mfa_required = Some(true);
        let err = decide(
            Some(f.clone()),
            &user(org),
            Permission::OrgRead,
            ip(),
            now(),
        )
        .unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_POLICY_MFA_REQUIRED);
        let mut mfa = user(org);
        mfa.amr = vec![AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa];
        assert!(decide(Some(f.clone()), &mfa, Permission::OrgRead, ip(), now()).is_ok());
        f.policy.max_session_lifetime_seconds = Some(600);
        mfa.auth_time = Some(now() - Duration::from_secs(601));
        let err = decide(Some(f), &mfa, Permission::OrgRead, ip(), now()).unwrap_err();
        assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    }

    #[test]
    fn org_08_api_keys_are_limited_by_scopes_and_bound_to_their_org() {
        let org = OrgId::generate();
        let mut key = user(org);
        key.credential = PrincipalCredential::ApiKey {
            api_key_id: ApiKeyId::generate(),
        };
        key.amr = vec![];
        key.auth_time = None;
        key.scopes = vec!["members:read".into()];
        let f = facts(org, BuiltinRole::Owner);
        assert!(decide(Some(f.clone()), &key, Permission::MembersRead, ip(), now()).is_ok());
        let err = decide(
            Some(f.clone()),
            &key,
            Permission::MembersInvite,
            ip(),
            now(),
        )
        .unwrap_err();
        assert_eq!(err.code(), codes::common::FORBIDDEN);
        // MFA policies do not apply to API keys; IP allow-lists do.
        let mut mfa_policy = f.clone();
        mfa_policy.policy.mfa_required = Some(true);
        assert!(decide(Some(mfa_policy), &key, Permission::MembersRead, ip(), now()).is_ok());
        key.active_org = Some(OrgId::generate());
        let err = decide(Some(f), &key, Permission::MembersRead, ip(), now()).unwrap_err();
        assert_eq!(err.code(), codes::common::NOT_FOUND);
    }

    #[test]
    fn org_09_service_accounts_only_in_their_org() {
        let org = OrgId::generate();
        let sa = ServiceAccountId::generate();
        let mut f = facts(org, BuiltinRole::Admin);
        f.subject_id = sa.as_uuid();
        let mut p = user(org);
        p.subject = Subject::ServiceAccount {
            service_account_id: sa,
            org_id: org,
        };
        p.credential = PrincipalCredential::ApiKey {
            api_key_id: ApiKeyId::generate(),
        };
        p.scopes = vec!["members:read".into(), "org:delete".into()];
        let auth = decide(Some(f.clone()), &p, Permission::MembersRead, ip(), now()).unwrap();
        assert!(auth.user_id().is_none());
        assert!(auth.require_user().is_err());
        // Scopes never add to the role.
        assert!(decide(Some(f.clone()), &p, Permission::OrgDelete, ip(), now()).is_err());
        f.subject_status = "disabled".into();
        let err = decide(Some(f), &p, Permission::MembersRead, ip(), now()).unwrap_err();
        assert_eq!(err.code(), codes::common::NOT_FOUND);
    }
}
