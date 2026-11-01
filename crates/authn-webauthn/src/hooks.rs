//! Facts this crate needs from other modules (contracts §2: wave-A crates
//! never depend on each other). authn-server implements these traits with
//! the owning modules' APIs; simple implementations are provided for tests
//! and minimal deployments.

use std::fmt;

use async_trait::async_trait;
use authn_core::domain::LoginMethod;
use authn_core::error::AuthError;
use authn_core::id::{OrgId, UserId};
use authn_store::UserRepository;
use sqlx::PgConnection;

use crate::policy::PasskeyPolicy;

/// MFA facts relevant when a passkey (a second factor too) is removed
/// (MFA-07: the last factor of an account that must keep MFA cannot be
/// removed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MfaFacts {
    /// MFA is mandatory for the user (user choice, organization policy or
    /// admin role, MFA-08).
    pub mfa_required: bool,
    /// Active second factors other than passkeys (TOTP, e-mail, SMS,
    /// recovery codes count only if the deployment treats them as a factor
    /// on their own).
    pub other_factor_count: u32,
}

/// What else the account can use to sign in / as a second factor. Used by
/// passkey removal (PKY-04).
///
/// Both methods are called inside the removal transaction **after** the
/// user row was locked with `UserRepository::lock_for_update`, and must
/// read through the given connection: password removal (authn-password,
/// PWD-11) and identity unlinking (authn-oidc-client, SOC-06) lock the same
/// row, so "remove the last passkey" and "remove the password" can never
/// both succeed concurrently.
#[async_trait]
pub trait AccountMethodsSource: Send + Sync {
    /// Login methods the user has **besides passkeys**: `Password` if a
    /// password is set, `Social` for linked identities, `MagicLink` /
    /// `EmailCode` only if the deployment allows them as a primary login
    /// for this user. An empty list means passkeys are the only way in.
    async fn other_login_methods(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError>;

    /// MFA requirement and remaining non-passkey factors. The default says
    /// "MFA not required" — implementations backed by authn-mfa / authn-org
    /// override it.
    async fn mfa_facts(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<MfaFacts, AuthError> {
        let _ = (conn, user);
        Ok(MfaFacts::default())
    }
}

/// [`AccountMethodsSource`] that only knows about passwords (read from
/// `password_credentials` through authn-store). Safe default: social
/// identities are ignored, so it can only *block* removals, never allow a
/// removal that strands the account.
#[derive(Debug, Clone, Copy, Default)]
pub struct PasswordOnlyMethods;

#[async_trait]
impl AccountMethodsSource for PasswordOnlyMethods {
    async fn other_login_methods(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Vec<LoginMethod>, AuthError> {
        let password = UserRepository::find_password(&mut *conn, user).await?;
        Ok(password
            .map(|_| vec![LoginMethod::Password])
            .unwrap_or_default())
    }
}

/// Organization passkey policy of a user (PKY-08), implemented by the
/// server from authn-org policies (e.g. the strictest policy of the user's
/// active memberships, or the active organization's policy).
#[async_trait]
pub trait PasskeyPolicySource: Send + Sync {
    /// The policy applying to `user`; `active_org` is the principal's active
    /// organization (SES-17), if any. Reads through `conn`.
    ///
    /// Called with `active_org = None` for every authentication ceremony
    /// (login has no active organization yet): implementations should then
    /// return the policy that applies whatever organization the user later
    /// switches to, e.g. [`PasskeyPolicy::strictest`] over the user's active
    /// memberships.
    async fn policy_for_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        active_org: Option<OrgId>,
    ) -> Result<PasskeyPolicy, AuthError>;
}

/// [`PasskeyPolicySource`] without restrictions (attestation `none`).
#[derive(Clone, Copy, Default)]
pub struct UnrestrictedPolicySource;

impl fmt::Debug for UnrestrictedPolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnrestrictedPolicySource")
    }
}

#[async_trait]
impl PasskeyPolicySource for UnrestrictedPolicySource {
    async fn policy_for_user(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
        _active_org: Option<OrgId>,
    ) -> Result<PasskeyPolicy, AuthError> {
        Ok(PasskeyPolicy::unrestricted())
    }
}
