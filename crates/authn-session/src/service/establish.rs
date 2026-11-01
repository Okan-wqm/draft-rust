//! Creating sessions and (re-)issuing their credentials (SES-03, SES-05,
//! SES-06, SES-07, SES-14).

use std::time::Duration;

use authn_core::domain::{AuthMethodRef, ClientKind, LoginMethod};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, RefreshTokenId, SessionId, UserId};
use authn_core::ports::{DomainEvent, DomainEventKind, RevocationReason};
use authn_core::secret::SensitiveString;
use authn_crypto::token::OpaqueToken;
use authn_org::OrgPolicy;
use sqlx::PgConnection;
use time::OffsetDateTime;

use super::{SessionService, after, remaining};
use crate::csrf::LoginCsrfVerified;
use crate::metrics;
use crate::model::{DeviceInfo, EstablishedSession, IssuedCredentials, SessionRecord};
use crate::settings::SessionShape;
use crate::store::refresh::{self, NewRefreshToken};
use crate::store::sessions::{self, NewSession, Target};

/// Largest number of `amr` values stored (`sessions_amr_check`).
const MAX_AMR: usize = 16;

/// How the client receives its credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientChannel {
    /// Browser: `__Host-authn_session` cookie + CSRF token. Requires the
    /// proof that the login request passed the login-CSRF checks
    /// ([`SessionService::verify_login_csrf`]).
    Web(LoginCsrfVerified),
    /// Native app: access + refresh token in the response body.
    Native,
}

impl ClientChannel {
    /// The client kind.
    #[must_use]
    pub const fn kind(self) -> ClientKind {
        match self {
            Self::Web(_) => ClientKind::Web,
            Self::Native => ClientKind::Native,
        }
    }
}

/// An organization the user may activate at login: an active membership
/// in an active organization whose IP allow-list and allowed login methods
/// admit this login. Obtained only from
/// [`SessionService::verify_login_org`] and bound to the user it was
/// verified for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOrg {
    user_id: UserId,
    org_id: OrgId,
    policy: OrgPolicy,
}

impl VerifiedOrg {
    /// The organization.
    #[must_use]
    pub fn org_id(&self) -> OrgId {
        self.org_id
    }

    /// Its policy (ORG-07).
    #[must_use]
    pub fn policy(&self) -> &OrgPolicy {
        &self.policy
    }

    /// The user the membership was verified for; [`SessionService::establish`]
    /// refuses it for anyone else.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        self.user_id
    }
}

/// Input of [`SessionService::establish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishSession {
    /// The authenticated user (every factor and required action done).
    pub user_id: UserId,
    /// Primary login method.
    pub method: LoginMethod,
    /// Every method proven during this login (RFC 8176); at least one.
    pub amr: Vec<AuthMethodRef>,
    /// Authentication context class, if any.
    pub acr: Option<String>,
    /// Time of authentication (normally now; never in the future).
    pub auth_time: OffsetDateTime,
    /// Web (with login-CSRF proof) or native.
    pub client: ClientChannel,
    /// "Remember me" (persistent cookie, longer lifetime; web only).
    pub remember_me: bool,
    /// "This is not my device" (SES-07; wins over `remember_me`).
    pub shared_device: bool,
    /// Organization to activate (SES-17).
    pub org: Option<VerifiedOrg>,
    /// Device facts (normally [`DeviceInfo::from_context`]).
    pub device: DeviceInfo,
}

/// Normalizes an `amr` list: deduplicated, order kept, at most 16 values.
pub(crate) fn normalize_amr(amr: &[AuthMethodRef]) -> Result<Vec<AuthMethodRef>, AuthError> {
    let mut out = Vec::with_capacity(amr.len());
    for a in amr {
        if !out.contains(a) {
            out.push(*a);
        }
    }
    if out.is_empty() || out.len() > MAX_AMR {
        return Err(AuthError::internal(
            "a session needs 1-16 authentication methods",
        ));
    }
    Ok(out)
}

/// The absolute expiry of a session: the configured lifetime, capped by the
/// organization's session lifetime (counted from the authentication).
pub(crate) fn capped_absolute(
    now: OffsetDateTime,
    lifetime: Duration,
    auth_time: OffsetDateTime,
    cap: Option<Duration>,
) -> OffsetDateTime {
    let configured = after(now, lifetime);
    match cap {
        Some(cap) => configured.min(after(auth_time, cap)),
        None => configured,
    }
}

impl SessionService {
    /// Checks that `user` may activate `org` when signing in with `method`
    /// from `ctx.client_ip` (SES-17, ORG-07): active membership in an
    /// active organization (otherwise `not_found` — another tenant's
    /// organization is indistinguishable from a missing one, ORG-10), the
    /// organization's IP allow-list and allowed login methods. The MFA
    /// requirement of the organization is the login pipeline's job.
    pub async fn verify_login_org(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: UserId,
        org: OrgId,
        method: LoginMethod,
    ) -> Result<VerifiedOrg, AuthError> {
        let policy = authn_org::policies_for_user(conn, user)
            .await?
            .into_iter()
            .find_map(|(id, policy)| (id == org).then_some(policy))
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if !policy.allows_ip(ctx.client_ip) {
            return Err(AuthError::new(codes::org::ORG_POLICY_IP_DENIED));
        }
        if !policy.allows_login_method(method) {
            return Err(AuthError::new(codes::session::LOGIN_METHOD_NOT_ALLOWED));
        }
        Ok(VerifiedOrg {
            user_id: user,
            org_id: org,
            policy,
        })
    }

    /// The login-CSRF checks of a web login request (SES-04): allowed
    /// `Origin` (or `Sec-Fetch-Site: same-origin`) and the pre-session
    /// token in `X-CSRF-Token` matching the `__Host-authn_csrf` cookie. The
    /// returned proof is required by [`ClientChannel::Web`].
    pub fn verify_login_csrf(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<LoginCsrfVerified, AuthError> {
        self.csrf().verify_login(headers).inspect_err(|_| {
            metrics::csrf_rejected();
        })
    }

    /// The login-CSRF proof of a web login request (SES-04) that may come
    /// from a browser which is already signed in: a cookie-authenticated
    /// state-changing request already passed the session CSRF checks in the
    /// middleware (origin + session-bound token — `GET /v1/csrf` returns the
    /// session token while a session exists); otherwise the pre-session
    /// checks of [`Self::verify_login_csrf`] apply.
    pub fn verify_login_csrf_request(
        &self,
        headers: &axum::http::HeaderMap,
        current: Option<&crate::model::CurrentSession>,
    ) -> Result<LoginCsrfVerified, AuthError> {
        if current.is_some_and(crate::model::CurrentSession::csrf_verified) {
            return Ok(LoginCsrfVerified::session_checked());
        }
        self.verify_login_csrf(headers)
    }

    /// Creates a session in the caller's transaction (SES-03, SES-05) and
    /// returns its credentials. The caller has completed the whole login
    /// (primary authentication, second factor, required actions, risk) and
    /// records the `login.succeeded` audit event in the same transaction.
    ///
    /// * The session id and token are always fresh: whatever the browser
    ///   presented before the login is never reused (fixation, SES-03).
    /// * Lifetimes per SES-06 / SES-07; the absolute expiry is capped by the
    ///   organization's session lifetime and is never extended later.
    /// * With `session.max_concurrent_sessions`, the oldest sessions beyond
    ///   the limit are revoked (`concurrent_limit`, SES-14); concurrent
    ///   logins of one user are serialized for that.
    pub async fn establish(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        request: EstablishSession,
    ) -> Result<EstablishedSession, AuthError> {
        let now = self.now();
        let amr = normalize_amr(&request.amr)?;
        if request.auth_time > now {
            return Err(AuthError::internal("auth_time lies in the future"));
        }
        if let Some(org) = &request.org
            && org.user_id != request.user_id
        {
            // A membership proof of another user would activate an
            // organization this user does not belong to (ORG-10).
            return Err(AuthError::internal(
                "the verified organization belongs to another user",
            ));
        }
        let kind = request.client.kind();
        let shape = SessionShape::of(
            kind == ClientKind::Native,
            request.remember_me,
            request.shared_device,
        );
        let lifetime = self.settings().lifetime(shape);
        let cap = request
            .org
            .as_ref()
            .and_then(|o| o.policy.session_lifetime_cap());
        let absolute = capped_absolute(now, lifetime.absolute_timeout, request.auth_time, cap);
        if absolute <= now {
            return Err(AuthError::new(codes::common::STEP_UP_REQUIRED)
                .with_context("organization session lifetime already exceeded"));
        }
        let idle = after(now, lifetime.idle_timeout).min(absolute);
        let limit = self.settings().session.max_concurrent_sessions;
        if limit.is_some() {
            sessions::lock_user_sessions(&mut *conn, request.user_id).await?;
        }

        let id = SessionId::generate();
        let web_token = match kind {
            ClientKind::Web => Some(OpaqueToken::generate().map_err(AuthError::from)?),
            ClientKind::Native => None,
        };
        let web_hash = web_token.as_ref().map(OpaqueToken::hash);
        let mut device = request.device;
        // The request context fills whatever the caller left out.
        if device.ip.is_none() {
            device.ip = Some(ctx.client_ip);
        }
        if device.user_agent.is_none() {
            device.user_agent.clone_from(&ctx.user_agent);
        }
        if device.device_id.is_none() {
            device.device_id.clone_from(&ctx.device_id);
        }
        let new_device_id = if kind == ClientKind::Web && device.device_id.is_none() {
            let fresh = OpaqueToken::generate().map_err(AuthError::from)?;
            device.device_id = Some(fresh.expose().to_owned());
            device.device_id.clone()
        } else {
            None
        };
        let scopes = self.settings().session.default_scopes.clone();
        let record = sessions::insert(
            &mut *conn,
            &NewSession {
                id,
                user_id: request.user_id,
                client_kind: kind,
                token_hash: web_hash.as_ref(),
                remember_me: kind == ClientKind::Web
                    && request.remember_me
                    && !request.shared_device,
                shared_device: request.shared_device,
                amr: &amr,
                acr: request.acr.as_deref(),
                auth_time: request.auth_time,
                active_org_id: request.org.as_ref().map(VerifiedOrg::org_id),
                impersonator_user_id: None,
                impersonation_read_only: None,
                impersonation_reason: None,
                device_id: device.device_id.as_deref(),
                device_name: device.device_name.as_deref(),
                user_agent: device.user_agent.as_deref(),
                ip: device.ip,
                created_at: now,
                idle_expires_at: idle,
                absolute_expires_at: absolute,
                login_method: Some(request.method),
                scopes: &scopes,
            },
        )
        .await?;

        let credentials = match web_token {
            Some(token) => self.web_credentials(&record, token, new_device_id, now)?,
            None => self.start_refresh_family(&mut *conn, &record, now).await?,
        };

        let mut evicted = Vec::new();
        if let Some(limit) = limit {
            for surplus in
                sessions::surplus_sessions(&mut *conn, request.user_id, limit, now).await?
            {
                self.pg_revoker()
                    .revoke(
                        &mut *conn,
                        Target::One(surplus),
                        RevocationReason::ConcurrentLimit,
                        None,
                        None,
                    )
                    .await?;
                evicted.push(surplus);
            }
        }
        if let Some(org) = record.active_org_id {
            let mut event = DomainEvent::new(
                DomainEventKind::SessionCreated,
                now,
                serde_json::json!({ "session_id": record.id, "client": kind.as_str() }),
            );
            event.org_id = Some(org);
            event.user_id = Some(record.user_id);
            self.deps().events.publish(&mut *conn, event).await?;
        }
        metrics::sessions_created(kind.as_str());
        Ok(EstablishedSession {
            session: record,
            credentials,
            evicted,
        })
    }

    /// Web credentials for a (new or rotated) token.
    pub(crate) fn web_credentials(
        &self,
        record: &SessionRecord,
        token: OpaqueToken,
        new_device_id: Option<String>,
        now: OffsetDateTime,
    ) -> Result<IssuedCredentials, AuthError> {
        let csrf_token = self.csrf().session_token(record.id, &token.hash())?;
        let persistent_for = (record.shape() == SessionShape::RememberMe)
            .then(|| remaining(now, record.absolute_expires_at));
        Ok(IssuedCredentials::Web {
            session_token: token.into_sensitive(),
            csrf_token,
            persistent_for,
            new_device_id,
        })
    }

    /// Generation 0 of a native session's refresh-token family plus an
    /// access token.
    pub(crate) async fn start_refresh_family(
        &self,
        conn: &mut PgConnection,
        record: &SessionRecord,
        now: OffsetDateTime,
    ) -> Result<IssuedCredentials, AuthError> {
        let (refresh_token, refresh_expires_at) = self
            .insert_refresh_token(conn, record, None, 0, now)
            .await?;
        let (access_token, access_token_expires_at) = self.issue_access_token(record, now).await?;
        Ok(IssuedCredentials::Native {
            access_token,
            access_token_expires_at,
            refresh_token,
            refresh_token_expires_at: refresh_expires_at,
        })
    }

    /// Inserts a refresh token of `record`'s family; the idle expiry is
    /// capped by the session's absolute expiry (SES-06).
    pub(crate) async fn insert_refresh_token(
        &self,
        conn: &mut PgConnection,
        record: &SessionRecord,
        parent: Option<RefreshTokenId>,
        generation: i32,
        now: OffsetDateTime,
    ) -> Result<(SensitiveString, OffsetDateTime), AuthError> {
        let token = OpaqueToken::generate().map_err(AuthError::from)?;
        let idle = after(now, self.settings().session.refresh_token.idle_timeout)
            .min(record.absolute_expires_at);
        refresh::insert(
            conn,
            &NewRefreshToken {
                id: RefreshTokenId::generate(),
                session_id: record.id,
                token_hash: &token.hash(),
                parent_id: parent,
                generation,
                created_at: now,
                idle_expires_at: idle,
                absolute_expires_at: record.absolute_expires_at,
            },
        )
        .await?;
        Ok((token.into_sensitive(), idle))
    }

    /// Rotates the native credentials of a locked session after a
    /// privilege change: the live refresh token is retired (its successor is
    /// returned) and a fresh access token carries the new state.
    pub(crate) async fn rotate_native_credentials(
        &self,
        conn: &mut PgConnection,
        record: &SessionRecord,
        now: OffsetDateTime,
    ) -> Result<IssuedCredentials, AuthError> {
        let live = refresh::lock_live_of(&mut *conn, record.id)
            .await?
            .ok_or_else(|| AuthError::new(codes::session::INVALID_REFRESH_TOKEN))?;
        if !refresh::retire(&mut *conn, live.id, now).await? {
            return Err(AuthError::new(codes::session::INVALID_REFRESH_TOKEN));
        }
        let (successor, token, idle) = self
            .insert_successor(&mut *conn, record, live.id, live.generation, now)
            .await?;
        refresh::link_successor(&mut *conn, live.id, successor, None).await?;
        let (access_token, access_token_expires_at) = self.issue_access_token(record, now).await?;
        Ok(IssuedCredentials::Native {
            access_token,
            access_token_expires_at,
            refresh_token: token.into_sensitive(),
            refresh_token_expires_at: idle,
        })
    }

    /// Inserts the successor of a retired refresh token.
    pub(crate) async fn insert_successor(
        &self,
        conn: &mut PgConnection,
        record: &SessionRecord,
        parent: RefreshTokenId,
        parent_generation: i32,
        now: OffsetDateTime,
    ) -> Result<(RefreshTokenId, OpaqueToken, OffsetDateTime), AuthError> {
        let successor = RefreshTokenId::generate();
        let token = OpaqueToken::generate().map_err(AuthError::from)?;
        let idle = after(now, self.settings().session.refresh_token.idle_timeout)
            .min(record.absolute_expires_at);
        refresh::insert(
            conn,
            &NewRefreshToken {
                id: successor,
                session_id: record.id,
                token_hash: &token.hash(),
                parent_id: Some(parent),
                generation: parent_generation.saturating_add(1),
                created_at: now,
                idle_expires_at: idle,
                absolute_expires_at: record.absolute_expires_at,
            },
        )
        .await?;
        Ok((successor, token, idle))
    }
}
