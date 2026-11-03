//! The hook traits the module crates declare and the server implements
//! (`docs/architecture/contracts.md` §15.1).
//!
//! Several hooks need a service that itself needs the hook (MFA ↔
//! passkeys). Those hooks hold a [`Late`] cell that is filled once every
//! service is built ([`crate::services::Services::build`]); a hook called
//! before that (impossible outside of start-up) answers with an internal
//! error rather than guessing.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use authn_account::{AccountService, OrganizationOwnership};
use authn_audit::{AccessDecision, AuditAccessPolicy, AuditPermission};
use authn_core::domain::{LoginMethod, Principal};
use authn_core::error::AuthError;
use authn_core::id::{OrgId, UserId};
use authn_mfa::{MfaPolicySource, MfaService, OrgMfaPolicy};
use authn_org::{OrgService, Permission};
use authn_password::{LoginMethodInventory, ProfileHints, ProfileLookup};
use authn_store::UserRepository;
use authn_webauthn::{
    AccountMethodsSource, MfaFacts, PasskeyPolicy, PasskeyPolicySource, WebauthnService,
};
use sqlx::PgConnection;

/// A service bound after construction (breaks the MFA ↔ passkey cycle).
pub struct Late<T>(OnceLock<T>);

impl<T> Default for Late<T> {
    fn default() -> Self {
        Self(OnceLock::new())
    }
}

impl<T> Late<T> {
    /// Binds the value (the first call wins).
    pub fn bind(&self, value: T) {
        let _ = self.0.set(value);
    }

    fn get(&self) -> Result<&T, AuthError> {
        self.0
            .get()
            .ok_or_else(|| AuthError::internal("hook used before the services were bound"))
    }
}

/// Whether the user has a linked external identity (authn-oidc-client's
/// `identities` table), read through `conn`.
async fn has_identity(conn: &mut PgConnection, user: UserId) -> Result<bool, AuthError> {
    Ok(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM identities WHERE user_id = $1)",
        )
        .bind(user)
        .fetch_one(&mut *conn)
        .await?,
    )
}

/// The organization MFA policies of every active membership, combined
/// (`OrgMfaPolicy::strictest`).
async fn strictest_org_mfa_policy(
    conn: &mut PgConnection,
    user: UserId,
) -> Result<Option<OrgMfaPolicy>, AuthError> {
    let policies = authn_org::policies_for_user(conn, user).await?;
    Ok(policies
        .iter()
        .map(|(_, p)| authn_session::service::org_mfa_policy(p))
        .reduce(|a, b| a.strictest(&b)))
}

/// `authn_password::LoginMethodInventory` (PWD-11): passkeys and linked
/// identities, read only through `conn`.
#[derive(Default)]
pub struct ServerLoginMethods {
    /// Passkey store.
    pub webauthn: Late<WebauthnService>,
}

#[async_trait]
impl LoginMethodInventory for ServerLoginMethods {
    async fn other_login_methods(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError> {
        let mut methods = Vec::new();
        if self
            .webauthn
            .get()?
            .passkey_count_in(&mut *conn, user, true)
            .await?
            > 0
        {
            methods.push(LoginMethod::Passkey);
        }
        if has_identity(conn, user).await? {
            methods.push(LoginMethod::Social);
        }
        Ok(methods)
    }
}

/// `authn_password::ProfileLookup` (PWD-04): the account profile.
#[derive(Default)]
pub struct ServerProfiles {
    /// Profiles.
    pub accounts: Late<AccountService>,
}

#[async_trait]
impl ProfileLookup for ServerProfiles {
    async fn profile(&self, user: UserId) -> Result<ProfileHints, AuthError> {
        let profile = self.accounts.get()?.profile_of(user).await?;
        Ok(ProfileHints {
            display_name: profile.as_ref().and_then(|p| p.display_name.clone()),
            locale: profile.map(|p| p.locale),
        })
    }
}

/// `authn_account::OrganizationOwnership` (ACC-09).
#[derive(Debug, Default, Clone, Copy)]
pub struct ServerOwnership;

#[async_trait]
impl OrganizationOwnership for ServerOwnership {
    async fn sole_owner_organizations(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<OrgId>, AuthError> {
        authn_org::sole_owner_organizations(conn, user).await
    }
}

/// `authn_mfa::MfaPolicySource` (MFA-07, MFA-08, MFA-09).
#[derive(Default)]
pub struct ServerMfaPolicy {
    /// Passkey store (second-factor count).
    pub webauthn: Late<WebauthnService>,
}

#[async_trait]
impl MfaPolicySource for ServerMfaPolicy {
    async fn org_policy_for_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Option<OrgMfaPolicy>, AuthError> {
        strictest_org_mfa_policy(conn, user).await
    }

    async fn webauthn_factor_count(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<u32, AuthError> {
        self.webauthn
            .get()?
            .passkey_count_in(conn, user, false)
            .await
    }
}

/// `authn_webauthn::AccountMethodsSource` (PKY-04, PWD-11, MFA-07).
#[derive(Default)]
pub struct ServerAccountMethods {
    /// MFA state.
    pub mfa: Late<MfaService>,
}

#[async_trait]
impl AccountMethodsSource for ServerAccountMethods {
    async fn other_login_methods(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError> {
        let mut methods = Vec::new();
        if UserRepository::find_password(&mut *conn, user)
            .await?
            .is_some()
        {
            methods.push(LoginMethod::Password);
        }
        if has_identity(conn, user).await? {
            methods.push(LoginMethod::Social);
        }
        Ok(methods)
    }

    async fn mfa_facts(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<MfaFacts, AuthError> {
        let org_policy = strictest_org_mfa_policy(&mut *conn, user).await?;
        let input = self
            .mfa
            .get()?
            .policy_input(user, org_policy, false)
            .await?;
        let other_factor_count = input
            .enrolled_factors
            .iter()
            .filter(|k| {
                !matches!(
                    k,
                    authn_core::domain::FactorKind::Webauthn
                        | authn_core::domain::FactorKind::RecoveryCode
                )
            })
            .count();
        Ok(MfaFacts {
            mfa_required: authn_mfa::policy::required_by_policy(&input) || input.user_opted_in,
            other_factor_count: u32::try_from(other_factor_count).unwrap_or(u32::MAX),
        })
    }
}

/// `authn_webauthn::PasskeyPolicySource` (PKY-08).
#[derive(Debug, Default, Clone, Copy)]
pub struct ServerPasskeyPolicy;

#[async_trait]
impl PasskeyPolicySource for ServerPasskeyPolicy {
    async fn policy_for_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        active_org: Option<OrgId>,
    ) -> Result<PasskeyPolicy, AuthError> {
        let policies = authn_org::policies_for_user(conn, user).await?;
        let of = |p: &authn_org::OrgPolicy| match &p.allowed_passkey_aaguids {
            Some(list) => PasskeyPolicy::allow_only(list.iter().copied()),
            None => PasskeyPolicy::unrestricted(),
        };
        Ok(match active_org {
            Some(org) => policies
                .iter()
                .find(|(id, _)| *id == org)
                .map_or_else(PasskeyPolicy::unrestricted, |(_, p)| of(p)),
            None => PasskeyPolicy::strictest(policies.iter().map(|(_, p)| of(p))),
        })
    }
}

/// `authn_audit::AuditAccessPolicy` (AUD-04, AUD-07, ORG-07): authn-org
/// RBAC, default deny.
pub struct ServerAuditAccess {
    /// RBAC.
    pub orgs: OrgService,
}

#[async_trait]
impl AuditAccessPolicy for ServerAuditAccess {
    async fn check(
        &self,
        principal: &Principal,
        org: OrgId,
        permission: AuditPermission,
        client_ip: Option<IpAddr>,
    ) -> Result<AccessDecision, AuthError> {
        let permission = match permission {
            AuditPermission::AuditRead => Permission::AuditRead,
            AuditPermission::WebhooksRead => Permission::WebhooksRead,
            AuditPermission::WebhooksManage => Permission::WebhooksManage,
        };
        match self
            .orgs
            .authorize_from(principal, permission, org, client_ip)
            .await
        {
            Ok(_) => Ok(AccessDecision::Allow),
            Err(err) if err.status().is_server_error() => Err(err),
            Err(_) => Ok(AccessDecision::Deny),
        }
    }
}

/// The late-bound hooks, kept together so [`crate::services`] can bind
/// them once.
#[derive(Default)]
pub struct LateHooks {
    /// PWD-11.
    pub login_methods: Arc<ServerLoginMethods>,
    /// PWD-04.
    pub profiles: Arc<ServerProfiles>,
    /// MFA-07/08/09.
    pub mfa_policy: Arc<ServerMfaPolicy>,
    /// PKY-04.
    pub account_methods: Arc<ServerAccountMethods>,
}
