//! Session revocation (SES-15). Owner of this file: authn-session.
//!
//! Used by password change/reset (PWD-06, PWD-09), e-mail change revert
//! (ACC-07), MFA changes, membership removal, admin and emergency actions.
//! All methods run inside the caller's transaction and revoke web sessions
//! *and* their refresh-token families. Revoked sessions must be rejected on
//! the very next request (no stale cache). Every side effect requested
//! through [`RevokeOptions`] happens on the same connection, so it commits or
//! rolls back together with the caller's change (ARC-06).

use async_trait::async_trait;
use sqlx::PgConnection;

use crate::error::AuthError;
use crate::id::{OrgId, SessionId, UserId};

/// Revokes sessions.
#[async_trait]
pub trait SessionRevoker: Send + Sync {
    /// Revokes one session. Returns whether it was active.
    async fn revoke_session(
        &self,
        conn: &mut PgConnection,
        session: SessionId,
        reason: RevocationReason,
    ) -> Result<bool, AuthError>;

    /// Revokes every session of a user. Returns the number revoked.
    async fn revoke_all_for_user(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        reason: RevocationReason,
        options: RevokeOptions,
    ) -> Result<u64, AuthError>;

    /// Revokes every session of a user except `keep` (PWD-06).
    async fn revoke_all_except(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        keep: SessionId,
        reason: RevocationReason,
        options: RevokeOptions,
    ) -> Result<u64, AuthError>;

    /// Revokes the user's sessions whose active organization is `org`
    /// (membership removed / suspended).
    async fn revoke_for_user_in_org(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        org: OrgId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError>;

    /// Revokes every session whose active organization is `org` (policy
    /// tightened, organization deleted).
    async fn revoke_all_for_org(
        &self,
        conn: &mut PgConnection,
        org: OrgId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError>;

    /// Emergency: revokes every session of every user (ADM-06).
    async fn revoke_everything(
        &self,
        conn: &mut PgConnection,
        reason: RevocationReason,
    ) -> Result<u64, AuthError>;

    /// Emergency: revokes every session of every user **except** `keep`
    /// (ADM-06, K-10: the calling admin's own session survives "revoke all
    /// sessions" unless they ask otherwise). Impersonation sessions started
    /// from `keep` are revoked like any other session.
    ///
    /// The default implementation refuses: a revoker that cannot keep a
    /// session must not silently revoke it (or anything else). Wrappers
    /// (e.g. authn-account's `AccountAwareSessionRevoker`) must forward it
    /// with the same side effects as [`SessionRevoker::revoke_everything`].
    async fn revoke_everything_except(
        &self,
        conn: &mut PgConnection,
        keep: SessionId,
        reason: RevocationReason,
    ) -> Result<u64, AuthError> {
        let _ = (conn, keep, reason);
        Err(AuthError::internal(
            "revoke_everything_except is not supported by this session revoker",
        ))
    }
}

/// Extra effects of a bulk revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RevokeOptions {
    /// Also revoke the user's trusted devices (MFA-09: password reset, MFA
    /// change, "sign out everywhere"; PWD-09).
    ///
    /// Applied on the **same connection, inside the caller's transaction**
    /// (the implementation calls authn-mfa's
    /// `revoke_trusted_devices_in_tx(conn, user, reason)`): if the caller
    /// rolls back, sessions and trusted devices both stay; if it commits,
    /// both are gone. An implementation must never revoke them in a
    /// separate transaction or ignore the flag.
    pub also_trusted_devices: bool,
}

text_enum! {
    /// Why sessions were revoked (stored in `sessions.revoked_reason`).
    pub enum RevocationReason {
        /// User logged out (SES-12).
        Logout => "logout",
        /// User revoked a session from the session list (SES-11).
        UserRequest => "user_request",
        /// Password changed (PWD-06).
        PasswordChanged => "password_changed",
        /// Password reset completed (PWD-09).
        PasswordReset => "password_reset",
        /// E-mail change reverted (ACC-07).
        EmailChangeReverted => "email_change_reverted",
        /// "This wasn't me" from a new-device notice (RSK-04).
        NotMe => "not_me",
        /// MFA factors changed.
        MfaChanged => "mfa_changed",
        /// Refresh token replay detected (SES-05).
        RefreshTokenReuse => "refresh_token_reuse",
        /// Account suspended / disabled / locked by an admin.
        AccountSuspended => "account_suspended",
        /// Account deleted.
        AccountDeleted => "account_deleted",
        /// Membership removed or suspended.
        MembershipRemoved => "membership_removed",
        /// Role or permissions of a membership changed (demotion, a
        /// permission removed from a custom role, previous owner demoted
        /// by an ownership transfer; ORG-02, ORG-04, SES-03).
        MembershipChanged => "membership_changed",
        /// Organization policy changed or organization deleted.
        OrgPolicyChanged => "org_policy_changed",
        /// Admin action (ADM-03).
        AdminAction => "admin_action",
        /// Emergency mass revocation (ADM-06).
        Emergency => "emergency",
        /// Concurrent session limit reached (SES-14).
        ConcurrentLimit => "concurrent_limit",
        /// Session expired (cleanup job).
        Expired => "expired",
        /// Impersonation ended.
        ImpersonationEnded => "impersonation_ended",
    }
}
