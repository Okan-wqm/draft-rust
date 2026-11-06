//! The hook traits the module crates declare and the server implements
//! (`docs/architecture/contracts.md` §15.1).
//!
//! Several hooks need a service that itself needs the hook (MFA ↔
//! passkeys). Those hooks hold a [`Late`] cell that is filled once every
//! service is built ([`crate::services::Services::build`]); a hook called
//! before that (impossible outside of start-up) answers with an internal
//! error rather than guessing.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock, Weak};

use async_trait::async_trait;
use authn_account::{AccountService, OrganizationOwnership};
use authn_audit::{AccessDecision, AuditAccessPolicy, AuditPermission};
use authn_core::domain::{LoginMethod, Principal};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, SessionId, UserId};
use authn_mfa::{MfaPolicySource, MfaService, OrgMfaPolicy};
use authn_oidc_client::OidcClientService;
use authn_org::{OrgService, Permission};
use authn_password::{LoginMethodInventory, ProfileHints, ProfileLookup};
use authn_session::SessionService;
use authn_store::UserRepository;
use authn_webauthn::{
    AccountMethodsSource, MfaFacts, PasskeyPolicy, PasskeyPolicySource, WebauthnService,
};
use sqlx::PgConnection;
use time::OffsetDateTime;

/// A service bound after construction (breaks the MFA ↔ passkey cycle).
///
/// It holds only a **weak** reference: the strong one lives in
/// [`HookAnchors`], owned by [`crate::services::Services`]. A strong
/// reference here would close a reference cycle (passkeys → this hook →
/// MFA → its hook → passkeys; accounts → revert hook → social login →
/// accounts) and every service — with its database pool — would outlive
/// the last `Services` handle (leaked pools in tests; no clean shutdown).
pub struct Late<T>(OnceLock<Weak<T>>);

impl<T> Default for Late<T> {
    fn default() -> Self {
        Self(OnceLock::new())
    }
}

impl<T> Late<T> {
    /// Binds the value (the first call wins).
    pub fn bind(&self, value: &Arc<T>) {
        let _ = self.0.set(Arc::downgrade(value));
    }

    fn get(&self) -> Result<Arc<T>, AuthError> {
        self.0
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| AuthError::internal("hook used outside the services' lifetime"))
    }
}

/// The strong references the [`Late`] hooks point to; dropped with the
/// last [`crate::services::Services`] handle.
pub struct HookAnchors {
    /// Passkeys.
    pub webauthn: Arc<WebauthnService>,
    /// MFA.
    pub mfa: Arc<MfaService>,
    /// Accounts.
    pub accounts: Arc<AccountService>,
    /// Social login.
    pub oidc: Arc<OidcClientService>,
}

/// Whether the user has a linked external identity (authn-oidc-client),
/// read through `conn` (SOC-06: a linked identity is a
/// [`LoginMethod::Social`]).
async fn has_identity(conn: &mut PgConnection, user: UserId) -> Result<bool, AuthError> {
    Ok(OidcClientService::linked_identity_count_in(conn, user).await? > 0)
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
        // Resolve the late-bound service before touching the connection;
        // then read only through the removal's connection (K-69, contracts
        // §4): the caller holds the user row lock and a pooled connection,
        // so a second pooled connection could starve the pool, and its
        // reads would not belong to the caller's transaction.
        let mfa = self.mfa.get()?;
        let org_policy = strictest_org_mfa_policy(&mut *conn, user).await?;
        let input = mfa
            .policy_input_in(&mut *conn, user, org_policy, false)
            .await?;
        // Only factors the policy still permits count (MFA-07, as in
        // `MfaService::remove_factor`): under a phishing-resistant policy
        // (organization or platform admin) a TOTP / e-mail / SMS factor
        // does not satisfy MFA, and a kind the deployment switched off
        // cannot be used at all, so neither may stand in for the last
        // passkey.
        let permitted = authn_mfa::policy::permitted_factors(&input);
        let other_factor_count = input
            .enrolled_factors
            .iter()
            .filter(|k| permitted.contains(k))
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

/// `authn_oidc_client::LoginMethodInventory` (SOC-06): the account's
/// **strong** login methods besides linked identities, read only through
/// `conn` (the unlink transaction holds the user row lock).
///
/// Passwordless e-mail logins (magic link, e-mail code) are deliberately
/// not counted, exactly as in the password (PWD-11) and passkey (PKY-04)
/// adapters: they exist for every account with an address, so counting
/// them would make the "last login method" rule vacuous; the three rules
/// stay identical and can only refuse, never strand an account.
pub struct ServerOidcLoginMethods {
    /// Passkey store.
    pub webauthn: WebauthnService,
}

#[async_trait]
impl authn_oidc_client::LoginMethodInventory for ServerOidcLoginMethods {
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
        if self
            .webauthn
            .passkey_count_in(&mut *conn, user, true)
            .await?
            > 0
        {
            methods.push(LoginMethod::Passkey);
        }
        Ok(methods)
    }
}

/// `authn_oidc_client::SessionLiveness` (K-03): the session that started a
/// link flow must still be a live, non-impersonation session of the same
/// user — authn-session's check on the caller's connection.
#[derive(Debug, Default, Clone, Copy)]
pub struct ServerSessionLiveness;

#[async_trait]
impl authn_oidc_client::SessionLiveness for ServerSessionLiveness {
    async fn is_active(
        &self,
        conn: &mut PgConnection,
        session: SessionId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        authn_session::is_session_active_in(conn, session, user, now).await
    }
}

/// `authn_admin::SigningKeyCache` (ADM-06): an emergency rotation drops
/// this instance's cached signing keys at once; other serving instances
/// drop theirs when the `signing_keys` change notification arrives (K-58,
/// listener started by [`crate::jobs::spawn`]), at the latest after
/// `session.signing_key_cache_ttl` (5 s while the listener is
/// disconnected).
#[derive(Clone)]
pub struct ServerSigningKeyCache(pub SessionService);

impl authn_admin::SigningKeyCache for ServerSigningKeyCache {
    fn invalidate_signing_keys(&self) {
        self.0.invalidate_signing_keys();
    }
}

/// `authn_account::EmailChangeRevertHook` (ACC-07, K-20): reverting an
/// e-mail change means the account was taken over through its mailbox, so
/// every login method that could have been added meanwhile goes, in the
/// revert transaction (authn-account already revoked every session and
/// trusted device and made the password unusable): all passkeys, every
/// MFA factor and recovery code, and every linked social identity (their
/// provider tokens are queued for revocation). The owner signs in again
/// through the restored mailbox (password reset) and re-enrols.
pub struct ServerRevertHook {
    /// Passkeys.
    pub webauthn: WebauthnService,
    /// MFA factors, recovery codes, trusted devices.
    pub mfa: MfaService,
    /// Linked identities (weak: the social login service holds the
    /// account service, which holds this hook).
    pub oidc: Late<OidcClientService>,
}

#[async_trait]
impl authn_account::EmailChangeRevertHook for ServerRevertHook {
    async fn after_revert_in_tx(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
    ) -> Result<(), AuthError> {
        // Resolve the late-bound service first: outside the services'
        // lifetime the hook fails (and authn-account rolls the revert
        // back) before touching anything.
        let oidc = self.oidc.get()?;
        let passkeys = self
            .webauthn
            .remove_all_passkeys_in_tx(
                &mut *conn,
                ctx,
                user,
                authn_webauthn::PasskeyRemovalReason::EmailChangeReverted,
            )
            .await?;
        let mfa = self.mfa.reset_user_mfa_in_tx(&mut *conn, ctx, user).await?;
        let identities = oidc
            .remove_all_identities_in_tx(&mut *conn, ctx, user)
            .await?;
        tracing::info!(
            user = %user,
            passkeys,
            factors = mfa.factors,
            recovery_codes = mfa.recovery_codes,
            identities,
            "login methods removed after e-mail change revert"
        );
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A late-bound hook never answers without its service: unbound, or
    /// after the last `Services` handle (and with it the anchor) is gone,
    /// every use is an error — callers propagate it, so the security check
    /// behind the hook fails closed (no "no other login method" guess).
    #[test]
    fn ops_07_late_hooks_fail_closed_outside_the_services_lifetime() {
        let late: Late<u32> = Late::default();
        assert!(late.get().is_err(), "unbound");
        let anchor = Arc::new(7);
        late.bind(&anchor);
        assert_eq!(*late.get().unwrap(), 7);
        // The first binding wins.
        let other = Arc::new(8);
        late.bind(&other);
        assert_eq!(*late.get().unwrap(), 7);
        drop(anchor);
        let err = late.get().unwrap_err();
        assert!(err.status().is_server_error(), "{err}");
    }
}

/// `authn_oidc_provider::SessionLiveness` (OIDP-12): a provider grant lives
/// only as long as the browser session it was authorized in — sign-out,
/// "sign out everywhere", password reset, suspension, deletion and admin
/// revocation end every grant of that session.
#[cfg(feature = "oidc-provider")]
#[async_trait]
impl authn_oidc_provider::SessionLiveness for ServerSessionLiveness {
    async fn is_active(
        &self,
        conn: &mut PgConnection,
        session: SessionId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        authn_session::is_session_active_in(conn, session, user, now).await
    }
}

/// `authn_oidc_provider::ClientAdminAuthorizer` (OIDP-01): the staff-role
/// check of authn-admin (K-93): `oauth_clients:read` (security, platform
/// admin) and `oauth_clients:manage` (platform admin), on top of the full
/// ADM-01 guard (passkey MFA, recent authentication, IP allow-list, no
/// impersonation).
#[cfg(feature = "oidc-provider")]
#[derive(Clone)]
pub struct ServerClientAdmin(pub authn_admin::AdminService);

#[cfg(feature = "oidc-provider")]
#[async_trait]
impl authn_oidc_provider::ClientAdminAuthorizer for ServerClientAdmin {
    async fn authorize(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        access: authn_oidc_provider::ClientAdminAccess,
    ) -> Result<(), AuthError> {
        let permission = match access {
            authn_oidc_provider::ClientAdminAccess::Read => {
                authn_admin::AdminPermission::OAuthClientsRead
            }
            authn_oidc_provider::ClientAdminAccess::Manage => {
                authn_admin::AdminPermission::OAuthClientsManage
            }
        };
        self.0
            .authorize_permission(principal, ctx, permission)
            .await
            .map(|_| ())
    }
}
