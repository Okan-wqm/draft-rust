//! [`OrgService`]: every organization use case.
//!
//! | Module | Requirements | Use cases |
//! |--------|--------------|-----------|
//! | [`orgs`] | ORG-01, ORG-12 | create, read, update, list own, schedule / cancel deletion, purge |
//! | [`members`] | ORG-02, ORG-04 | list, change role / status, remove, leave, sole-owner query |
//! | [`roles`] | ORG-03, ORG-04 | list, create / change / delete custom roles |
//! | [`invitations`] | ORG-05 | invite, list, resend, revoke, preview, accept |
//! | [`domains`] | ORG-06 | add, verify (DNS TXT), auto-join, remove |
//! | [`policies`] | ORG-07 | read, replace (audited, lock-out guard) |
//! | [`api_keys`] | ORG-08 | create, list, read, revoke, rotate, authenticate |
//! | [`service_accounts`] | ORG-09 | create, list, read, change, delete |
//! | [`transfer`] | ORG-11 | request, cancel, accept ownership transfer |
//!
//! Concurrency (ARC-06): every state change of an organization runs in one
//! transaction that first authorizes the caller, then takes the row lock of
//! the organization (`SELECT … FOR UPDATE`) and authorizes **again** on a
//! fresh snapshot. All writes of one organization are therefore serialized:
//! "last owner" checks, resource limits and escalation checks cannot be
//! raced (TOCTOU), and an actor whose role was just reduced cannot finish a
//! change with the old role. The lock is only taken for callers that are
//! members, so outsiders cannot block a tenant.

pub mod api_keys;
pub mod domains;
pub mod invitations;
pub mod members;
pub mod orgs;
pub mod policies;
pub mod reverify;
pub mod roles;
pub mod service_accounts;
pub mod transfer;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use authn_core::config::AppConfig;
use authn_core::config::org::OrgConfig;
use authn_core::domain::{Cursor, PageRequest, Principal, Subject};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, UserId};
use authn_core::ports::{
    Actor, AuditSink, Clock, DnsTxtResolver, DomainEvent, DomainEventKind, EventPublisher,
    Notifier, RateLimitKey, RateLimitPolicy, RateLimiter, SecurityEvent, SecurityEventKind,
    SessionRevoker,
};
use authn_store::PgTx;
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use crate::authz::{self, Authorization};
use crate::permission::Permission;

/// Rate-limit action names (`RateLimitKey::action`).
pub mod actions {
    /// Organization creation per user.
    pub const ORG_CREATE: &str = "org_create";
    /// Invitation e-mails per organization.
    pub const INVITATION_SEND: &str = "org_invitation_send";
    /// Resend cooldown per invitation.
    pub const INVITATION_RESEND: &str = "org_invitation_resend";
    /// Invitation e-mails per organization and recipient address.
    pub const INVITATION_RECIPIENT: &str = "org_invitation_recipient";
    /// Invitation preview / accept and transfer accept per user.
    pub const TOKEN_ATTEMPT: &str = "org_token_attempt";
    /// DNS verification checks per organization.
    pub const DOMAIN_CHECK: &str = "org_domain_check";
    /// Ownership transfer requests per organization.
    pub const OWNERSHIP_TRANSFER: &str = "org_ownership_transfer";
    /// Failed API key authentications per client IP.
    pub const API_KEY_AUTH_FAILURE: &str = "api_key_auth_failure";
}

/// Upper bound on waiting for an organization's row lock.
const LOCK_TIMEOUT_SQL: &str = "SET LOCAL lock_timeout = '5s'";

/// Ports and infrastructure the service needs.
#[derive(Clone)]
pub struct OrgServiceDeps {
    /// Database pool.
    pub pool: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Security audit (authn-audit).
    pub audit: Arc<dyn AuditSink>,
    /// Domain events / webhooks through the outbox (authn-audit).
    pub events: Arc<dyn EventPublisher>,
    /// Invitation and ownership-transfer e-mails (authn-notify).
    pub notifier: Arc<dyn Notifier>,
    /// Rate limiter (authn-protect).
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// Session revocation on membership removal / downgrade, policy
    /// tightening and organization deletion (authn-session).
    pub session_revoker: Arc<dyn SessionRevoker>,
    /// DNS TXT lookups (ORG-06): [`crate::dns::HickoryDnsTxtResolver`] in
    /// production.
    pub dns: Arc<dyn DnsTxtResolver>,
}

/// Settings of the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgServiceSettings {
    /// `[org]`.
    pub org: OrgConfig,
    /// Step-up window for sensitive operations (`session.step_up_max_age`,
    /// SES-13): API key creation / rotation, policy changes, ownership
    /// transfer, organization deletion, granting `owner`.
    pub step_up_max_age: Duration,
}

impl OrgServiceSettings {
    /// Settings from the application configuration.
    #[must_use]
    pub fn from_app_config(config: &AppConfig) -> Self {
        Self {
            org: config.org.clone(),
            step_up_max_age: config.session.step_up_max_age,
        }
    }
}

/// The organization service. Cheap to clone; handlers obtain it through
/// `FromRef` (see [`crate::router`]).
#[derive(Clone)]
pub struct OrgService {
    inner: Arc<Inner>,
}

struct Inner {
    deps: OrgServiceDeps,
    settings: OrgServiceSettings,
}

impl std::fmt::Debug for OrgService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrgService")
            .field("settings", &self.inner.settings)
            .finish_non_exhaustive()
    }
}

impl OrgService {
    /// Builds the service.
    #[must_use]
    pub fn new(deps: OrgServiceDeps, settings: OrgServiceSettings) -> Self {
        Self {
            inner: Arc::new(Inner { deps, settings }),
        }
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &OrgServiceSettings {
        &self.inner.settings
    }

    /// The `[org]` configuration.
    #[must_use]
    pub fn config(&self) -> &OrgConfig {
        &self.inner.settings.org
    }

    /// The database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.inner.deps.pool
    }

    pub(crate) fn deps(&self) -> &OrgServiceDeps {
        &self.inner.deps
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.inner.deps.clock.now()
    }

    // --- authorization ------------------------------------------------------

    /// **The** authorization entry point (ORG-03): default deny, tenant
    /// isolation (`404` for other organizations), organization status,
    /// policy (IP allow-list, MFA, session lifetime) and permission. Used by
    /// every handler of this crate; other modules (via the server) call it
    /// for their organization-scoped endpoints.
    pub async fn authorize(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        permission: Permission,
        org: OrgId,
    ) -> Result<Authorization, AuthError> {
        self.authorize_from(principal, permission, org, Some(ctx.client_ip))
            .await
    }

    /// [`Self::authorize`] for callers without a request context. Without a
    /// client IP an organization with an IP allow-list denies (fails
    /// closed).
    pub async fn authorize_from(
        &self,
        principal: &Principal,
        permission: Permission,
        org: OrgId,
        client_ip: Option<IpAddr>,
    ) -> Result<Authorization, AuthError> {
        let facts = authz::load_facts(self.pool(), principal, org).await?;
        authz::decide(facts, principal, permission, client_ip, self.now())
    }

    /// Checks that `principal` is an active member (or service account) of
    /// `org` and satisfies its policy, without requiring a permission — for
    /// authn-session's organization switch (SES-17). The returned
    /// [`Authorization`] carries the role, effective permissions and the
    /// policy (login methods, session lifetime cap) to apply.
    pub async fn check_membership(
        &self,
        principal: &Principal,
        org: OrgId,
        client_ip: Option<IpAddr>,
    ) -> Result<Authorization, AuthError> {
        let facts = authz::load_facts(self.pool(), principal, org).await?;
        authz::decide_member_check(facts, principal, client_ip, self.now())
    }

    /// [`Self::authorize`] inside the caller's transaction (no lock).
    pub async fn authorize_in(
        &self,
        conn: &mut PgConnection,
        principal: &Principal,
        permission: Permission,
        org: OrgId,
        client_ip: Option<IpAddr>,
    ) -> Result<Authorization, AuthError> {
        let facts = authz::load_facts(&mut *conn, principal, org).await?;
        authz::decide(facts, principal, permission, client_ip, self.now())
    }

    /// Begins a write transaction on an organization: authorize, lock the
    /// organization row, authorize again on a fresh snapshot (see the
    /// module docs).
    pub(crate) async fn begin_write(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        permission: Permission,
        org: OrgId,
    ) -> Result<(PgTx, Authorization), AuthError> {
        let mut tx = self.begin().await?;
        self.authorize_in(&mut tx, principal, permission, org, Some(ctx.client_ip))
            .await?;
        lock_org(&mut tx, org).await?;
        let auth = self
            .authorize_in(&mut tx, principal, permission, org, Some(ctx.client_ip))
            .await?;
        Ok((tx, auth))
    }

    pub(crate) async fn begin(&self) -> Result<PgTx, AuthError> {
        let mut tx = authn_store::begin(self.pool()).await?;
        sqlx::query(LOCK_TIMEOUT_SQL).execute(&mut *tx).await?;
        Ok(tx)
    }

    /// Step-up guard (SES-13).
    pub(crate) fn require_step_up(&self, principal: &Principal) -> Result<(), AuthError> {
        principal.require_recent_authentication(self.now(), self.settings().step_up_max_age)
    }

    /// Consumes one unit of a rate limit (PRT-04: `429` + `Retry-After`).
    pub(crate) async fn rate_limit(
        &self,
        key: RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<(), AuthError> {
        self.inner
            .deps
            .rate_limiter
            .check(&key, policy, 1)
            .await?
            .into_result()
            .map(|_| ())
    }

    // --- audit / events -----------------------------------------------------

    /// A security event pre-filled with actor, impersonator, request
    /// context and organization.
    pub(crate) fn event(
        &self,
        kind: SecurityEventKind,
        ctx: &RequestContext,
        principal: &Principal,
        org: Option<OrgId>,
    ) -> SecurityEvent {
        let (actor, impersonator) = actor_of(principal);
        let mut event = SecurityEvent::new(kind, self.now())
            .with_context(ctx)
            .with_actor(actor);
        event.impersonator = impersonator;
        if let Some(org) = org {
            event = event.with_org(org);
        }
        event
    }

    /// Records a security event as the last step of the caller's
    /// transaction (AUD-01).
    pub(crate) async fn audit_in_tx(
        &self,
        conn: &mut PgConnection,
        event: SecurityEvent,
    ) -> Result<(), AuthError> {
        self.inner.deps.audit.record_in_tx(conn, event).await
    }

    /// Publishes a domain event (webhooks) in the caller's transaction.
    pub(crate) async fn publish(
        &self,
        conn: &mut PgConnection,
        kind: DomainEventKind,
        org: OrgId,
        user: Option<UserId>,
        data: serde_json::Value,
    ) -> Result<(), AuthError> {
        let mut event = DomainEvent::new(kind, self.now(), data);
        event.org_id = Some(org);
        event.user_id = user;
        self.inner.deps.events.publish(conn, event).await
    }
}

/// Takes the row lock of an organization (serializes its writes).
pub(crate) async fn lock_org(conn: &mut PgConnection, org: OrgId) -> Result<(), AuthError> {
    let found: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(org)
            .fetch_optional(conn)
            .await?;
    found
        .map(|_| ())
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
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

/// The acting human user or `forbidden` (service accounts, API keys of
/// service accounts).
pub(crate) fn require_user(principal: &Principal) -> Result<UserId, AuthError> {
    principal.require_user()
}

/// A human session principal: not an API key (account-level operations
/// such as creating organizations or accepting invitations must not be
/// possible with an organization API key).
pub(crate) fn require_session_user(principal: &Principal) -> Result<UserId, AuthError> {
    if matches!(
        principal.credential,
        authn_core::domain::PrincipalCredential::ApiKey { .. }
    ) {
        return Err(AuthError::new(codes::common::FORBIDDEN).with_context("api key not allowed"));
    }
    require_user(principal)
}

/// Keyset pagination helper: the decoded cursor as `(created_at, id)`.
pub(crate) fn page_after(
    page: &PageRequest,
) -> Result<(Option<OffsetDateTime>, uuid::Uuid), AuthError> {
    match page.cursor()? {
        None => Ok((None, uuid::Uuid::nil())),
        Some(cursor) => {
            let at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(cursor.sort_key) * 1000)
                .map_err(|_| AuthError::new(codes::common::VALIDATION_FAILED))?;
            Ok((Some(at), cursor.id))
        }
    }
}

/// Cursor of a row ordered by `(created_at, id)`.
pub(crate) fn cursor_of(created_at: OffsetDateTime, id: uuid::Uuid) -> Cursor {
    let micros = created_at.unix_timestamp_nanos() / 1000;
    Cursor {
        sort_key: i64::try_from(micros).unwrap_or(i64::MAX),
        id,
    }
}

/// `limit + 1` for over-fetching.
pub(crate) fn fetch_limit(page: &PageRequest) -> i64 {
    i64::from(page.limit()) + 1
}

/// Maps a database error, turning a unique violation of `constraint` into
/// `code` (never used where it would reveal account existence).
pub(crate) fn on_unique(
    err: sqlx::Error,
    constraint: &str,
    code: authn_core::ErrorCode,
) -> AuthError {
    let store = authn_store::StoreError::from(err);
    if store.is_unique_violation(constraint) {
        AuthError::new(code).with_source(store)
    } else {
        AuthError::from(store)
    }
}
