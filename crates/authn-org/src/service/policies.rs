//! Organization security policy (ORG-07).
//!
//! Changing the policy needs `policies:manage` **and** step-up, is audited
//! (`org.policy_changed` with the old and new values) and refuses changes
//! that would lock the caller out (`org_policy_lockout`: the caller's IP
//! outside the new allow-list, the caller's session not meeting a new
//! MFA requirement, or — K-57 — its login method or second factor no
//! longer allowed). A tightening change revokes every session whose
//! active organization is this one, so everybody re-authenticates under the
//! new rules (authn-session enforces login methods and lifetimes at login /
//! organization switch; [`crate::OrgService::authorize`] enforces IP, MFA,
//! allowed login methods and second factors (K-57) and lifetime on every
//! organization request — so a member session that never activated the
//! organization, and therefore was not revoked here, is held to the new
//! rules as well).

use authn_core::domain::{Principal, PrincipalCredential};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, UserId};
use authn_core::ports::{RevocationReason, SecurityEventKind};
use sqlx::PgConnection;

use super::OrgService;
use crate::authz::{PolicyRow, policy_columns};
use crate::permission::Permission;
use crate::policy::{OrgPolicy, OrgPolicyInput, PolicyViolation};

impl OrgService {
    /// Reads the policy (`policies:read`).
    pub async fn get_policy(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<OrgPolicy, AuthError> {
        let auth = self
            .authorize(ctx, principal, Permission::PoliciesRead, org)
            .await?;
        Ok(auth.policy)
    }

    /// Replaces the policy (`policies:manage` + step-up).
    pub async fn update_policy(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        input: OrgPolicyInput,
    ) -> Result<OrgPolicy, AuthError> {
        self.require_step_up(principal)?;
        let policy = input.validate()?;
        let (mut tx, auth) = self
            .begin_write(ctx, principal, Permission::PoliciesManage, org)
            .await?;
        // Lock-out guard: the change must not shut out the caller.
        if !policy.allows_ip(ctx.client_ip) {
            return Err(AuthError::new(codes::org::ORG_POLICY_LOCKOUT)
                .with_details(serde_json::json!({ "reason": "ip_allowlist" })));
        }
        if !matches!(principal.credential, PrincipalCredential::ApiKey { .. }) {
            match policy.check_session(&principal.amr, principal.auth_time, self.now()) {
                Err(PolicyViolation::MfaRequired | PolicyViolation::PhishingResistantRequired) => {
                    return Err(AuthError::new(codes::org::ORG_POLICY_LOCKOUT)
                        .with_details(serde_json::json!({ "reason": "mfa" })));
                }
                Ok(())
                | Err(
                    PolicyViolation::SessionTooOld
                    | PolicyViolation::IpNotAllowed
                    | PolicyViolation::LoginMethodNotAllowed
                    | PolicyViolation::SecondFactorNotAllowed,
                ) => {}
            }
            // K-57: organization requests now check the session's login
            // method and second factor too; never shut out the caller.
            match policy.check_session_methods(
                principal.login_method,
                &principal.mfa_factors,
                &principal.amr,
                principal.is_impersonated(),
            ) {
                Ok(()) => {}
                Err(PolicyViolation::LoginMethodNotAllowed) => {
                    return Err(AuthError::new(codes::org::ORG_POLICY_LOCKOUT)
                        .with_details(serde_json::json!({ "reason": "login_method" })));
                }
                Err(_) => {
                    return Err(AuthError::new(codes::org::ORG_POLICY_LOCKOUT)
                        .with_details(serde_json::json!({ "reason": "mfa" })));
                }
            }
        }
        let previous = auth.policy.clone();
        sqlx::query(
            "INSERT INTO org_policies (org_id, mfa_required, phishing_resistant_mfa_required, \
             allowed_login_methods, allowed_mfa_factors, max_session_lifetime_seconds, \
             ip_allowlist, trusted_devices_allowed, allowed_aaguids, updated_by, created_at, \
             updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7::cidr[], $8, $9, $10, $11, $11) \
             ON CONFLICT (org_id) DO UPDATE SET mfa_required = EXCLUDED.mfa_required, \
             phishing_resistant_mfa_required = EXCLUDED.phishing_resistant_mfa_required, \
             allowed_login_methods = EXCLUDED.allowed_login_methods, \
             allowed_mfa_factors = EXCLUDED.allowed_mfa_factors, \
             max_session_lifetime_seconds = EXCLUDED.max_session_lifetime_seconds, \
             ip_allowlist = EXCLUDED.ip_allowlist, \
             trusted_devices_allowed = EXCLUDED.trusted_devices_allowed, \
             allowed_aaguids = EXCLUDED.allowed_aaguids, updated_by = EXCLUDED.updated_by",
        )
        .bind(org)
        .bind(policy.mfa_required)
        .bind(policy.phishing_resistant_mfa_required)
        .bind(policy.allowed_login_methods.as_deref())
        .bind(policy.allowed_mfa_factors.as_deref())
        .bind(
            policy
                .max_session_lifetime_seconds
                .map(i32::try_from)
                .transpose()
                .map_err(|_| crate::validate::invalid("max_session_lifetime_seconds"))?,
        )
        .bind(policy.ip_allowlist.as_deref())
        .bind(policy.trusted_devices_allowed)
        .bind(policy.allowed_passkey_aaguids.as_deref())
        .bind(auth.user_id())
        .bind(self.now())
        .execute(&mut *tx)
        .await?;
        let tightened = policy.tightens(&previous);
        let mut sessions_revoked = 0;
        if tightened {
            sessions_revoked = self
                .deps()
                .session_revoker
                .revoke_all_for_org(&mut tx, org, RevocationReason::OrgPolicyChanged)
                .await?;
        }
        let event = self
            .event(
                SecurityEventKind::OrgPolicyChanged,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("org_policy", org)
            .with_meta(
                "previous",
                serde_json::to_value(&previous).unwrap_or_default(),
            )
            .with_meta("policy", serde_json::to_value(&policy).unwrap_or_default())
            .with_meta("tightened", tightened)
            .with_meta("sessions_revoked", sessions_revoked);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(policy)
    }

    /// The policy of one organization, without authorization (for the
    /// server / authn-session at login and organization switch, SES-17).
    pub async fn policy(&self, org: OrgId) -> Result<OrgPolicy, AuthError> {
        policy_of(&mut *self.pool().acquire().await?, org).await
    }

    /// The policies of every organization in which `user` is an active
    /// member of an active organization (MFA-08 strictest combination,
    /// MFA-09 trusted devices). Runs on the caller's connection.
    pub async fn policies_for_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<(OrgId, OrgPolicy)>, AuthError> {
        policies_for_user(conn, user).await
    }
}

#[derive(sqlx::FromRow)]
struct UserPolicyRow {
    org_id: OrgId,
    #[sqlx(flatten)]
    policy: PolicyRow,
}

/// The policy of `org` (defaults when no row exists).
pub async fn policy_of(conn: &mut PgConnection, org: OrgId) -> Result<OrgPolicy, AuthError> {
    let sql = concat!(
        "SELECT ",
        policy_columns!(),
        " FROM organizations o LEFT JOIN org_policies p ON p.org_id = o.id WHERE o.id = $1"
    );
    let row = sqlx::query_as::<_, PolicyRow>(sql)
        .bind(org)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
    Ok(row.into_policy())
}

/// Policies of the user's active memberships in active organizations.
pub async fn policies_for_user(
    conn: &mut PgConnection,
    user: UserId,
) -> Result<Vec<(OrgId, OrgPolicy)>, AuthError> {
    let sql = concat!(
        "SELECT o.id AS org_id, ",
        policy_columns!(),
        " FROM memberships m JOIN organizations o ON o.id = m.org_id \
         LEFT JOIN org_policies p ON p.org_id = o.id \
         WHERE m.user_id = $1 AND m.status = 'active' AND o.status = 'active' ORDER BY o.id"
    );
    let rows = sqlx::query_as::<_, UserPolicyRow>(sql)
        .bind(user)
        .fetch_all(conn)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.org_id, r.policy.into_policy()))
        .collect())
}
