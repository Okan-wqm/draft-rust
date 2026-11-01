//! Data this crate needs from other modules, behind a small trait that
//! `authn-server` implements (contracts §2: wave-A crates never depend on
//! each other).
//!
//! | Method | Data | Owner of the data |
//! |--------|------|-------------------|
//! | [`MfaPolicySource::org_policy_for_user`] | MFA facts of the user's organization policies (ORG-07) | authn-org (`org_policies`, `memberships`) |
//! | [`MfaPolicySource::webauthn_factor_count`] | passkeys usable as a second factor (PKY-02) | authn-webauthn (`webauthn_credentials`) |
//!
//! The platform-admin flag is read from `users` through `authn-store`;
//! the user's own factors and preference are this crate's tables.

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use sqlx::PgConnection;

use crate::policy::OrgMfaPolicy;

/// Supplies policy facts owned by other modules.
///
/// Both methods are called through `conn`, mostly inside authn-mfa
/// transactions that hold the user's MFA settings row lock (and, for factor
/// removal, the `users` row lock); [`MfaPolicySource::org_policy_for_user`]
/// is also called on a plain connection by
/// [`crate::MfaService::is_trusted_device`]. Implementations must read
/// through `conn` and must not open another transaction on the same rows.
#[async_trait]
pub trait MfaPolicySource: Send + Sync {
    /// The MFA policy that applies to `user` outside of a specific login
    /// context: the strictest combination ([`OrgMfaPolicy::strictest`]) over
    /// the organizations the user is an active member of; `None` when the
    /// user belongs to no organization. Used for the "last factor" rule
    /// (MFA-07) and for trusted devices (MFA-09: when any organization of
    /// the user sets `trusted_devices_allowed = false`, no device is
    /// trusted or honoured, whatever the login context).
    async fn org_policy_for_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<Option<OrgMfaPolicy>, AuthError>;

    /// Number of the user's passkeys that can serve as a second factor.
    async fn webauthn_factor_count(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<u32, AuthError>;
}

/// A fixed answer for every user: tests and single-tenant deployments
/// without organizations or passkeys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticMfaPolicySource {
    /// Returned by [`MfaPolicySource::org_policy_for_user`].
    pub org_policy: Option<OrgMfaPolicy>,
    /// Returned by [`MfaPolicySource::webauthn_factor_count`].
    pub webauthn_factors: u32,
}

#[async_trait]
impl MfaPolicySource for StaticMfaPolicySource {
    async fn org_policy_for_user(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<Option<OrgMfaPolicy>, AuthError> {
        Ok(self.org_policy.clone())
    }

    async fn webauthn_factor_count(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<u32, AuthError> {
        Ok(self.webauthn_factors)
    }
}
