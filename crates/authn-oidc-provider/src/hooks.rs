//! Hook traits implemented by authn-server (contracts §4 "module hooks").
//!
//! The provider sits on the wave-B layer and may not depend on
//! authn-session or authn-admin; what it needs from them comes through
//! these traits.

use async_trait::async_trait;
use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{SessionId, UserId};
use sqlx::PgConnection;
use time::OffsetDateTime;

/// Whether the user session that created a grant is still live (OIDP-12).
///
/// Every provider grant is bound to the session the user authorized it
/// with: when that session ends — sign-out, "sign out everywhere",
/// password reset, suspension, deletion, admin or emergency revocation,
/// expiry — the grant's refresh tokens stop working and introspection /
/// `userinfo` answer inactive at once. The server implements it with
/// `authn_session::is_session_active_in`, which also checks that the user
/// may still sign in.
#[async_trait]
pub trait SessionLiveness: Send + Sync {
    /// Whether `session` is a live, non-impersonation session of `user`,
    /// read **only** through `conn` (the caller's transaction).
    async fn is_active(
        &self,
        conn: &mut PgConnection,
        session: SessionId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError>;
}

/// Liveness that always answers "ended": the fail-closed default until the
/// server installs its adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLiveSessions;

#[async_trait]
impl SessionLiveness for NoLiveSessions {
    async fn is_active(
        &self,
        _conn: &mut PgConnection,
        _session: SessionId,
        _user: UserId,
        _now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        Ok(false)
    }
}

/// What a client-registry operation needs (OIDP-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAdminAccess {
    /// List and read registrations.
    Read,
    /// Create, change, rotate secrets, delete.
    Manage,
}

/// Authorizes the staff operations of the client registry (OIDP-01). The
/// server implements it with authn-admin's staff-role check
/// (`AdminService::authorize_permission`, `oauth_clients:read` /
/// `oauth_clients:manage`: platform admin, passkey MFA, recent
/// authentication, IP allow-list, no impersonation).
#[async_trait]
pub trait ClientAdminAuthorizer: Send + Sync {
    /// `Ok` when `principal` may perform `access`.
    async fn authorize(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        access: ClientAdminAccess,
    ) -> Result<(), AuthError>;
}

/// Refuses every registry operation (the fail-closed default).
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyClientAdmin;

#[async_trait]
impl ClientAdminAuthorizer for DenyClientAdmin {
    async fn authorize(
        &self,
        _principal: &Principal,
        _ctx: &RequestContext,
        _access: ClientAdminAccess,
    ) -> Result<(), AuthError> {
        Err(AuthError::new(codes::common::FORBIDDEN).with_context("no client admin authorizer"))
    }
}
