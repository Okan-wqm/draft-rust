//! Session domain types.

use std::net::IpAddr;
use std::time::Duration;

use authn_core::domain::{
    AuthMethodRef, ClientKind, FactorKind, Impersonation, LoginMethod, Principal,
    PrincipalCredential, Subject,
};
use authn_core::id::{OrgId, SessionId, UserId};
use authn_core::secret::SensitiveString;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::settings::SessionShape;

/// A row of `sessions` (the token hash is never part of it).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SessionRecord {
    /// Session id (also the refresh-token family id).
    pub id: SessionId,
    /// Owner.
    pub user_id: UserId,
    /// Web (cookie) or native (tokens).
    pub client_kind: ClientKind,
    /// "Remember me" (persistent cookie, SES-06).
    pub remember_me: bool,
    /// "Not my device" (SES-07).
    pub shared_device: bool,
    /// Authentication methods (RFC 8176).
    pub amr: Vec<AuthMethodRef>,
    /// Authentication context class.
    pub acr: Option<String>,
    /// Time of the last (re-)authentication (SES-13).
    pub auth_time: OffsetDateTime,
    /// Active organization (SES-17).
    pub active_org_id: Option<OrgId>,
    /// Impersonating admin (ADM-04).
    pub impersonator_user_id: Option<UserId>,
    /// Read-only impersonation.
    pub impersonation_read_only: Option<bool>,
    /// Device id (request context).
    pub device_id: Option<String>,
    /// Human-readable device description.
    pub device_name: Option<String>,
    /// IP at creation.
    pub created_ip: Option<IpAddr>,
    /// IP at the last touch.
    pub last_seen_ip: Option<IpAddr>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last touch.
    pub last_seen_at: OffsetDateTime,
    /// Idle expiry (extended by activity, never beyond the absolute one).
    pub idle_expires_at: OffsetDateTime,
    /// Absolute expiry (never extended, SES-06).
    pub absolute_expires_at: OffsetDateTime,
    /// Primary login method (`None` for impersonation sessions).
    pub login_method: Option<LoginMethod>,
    /// Scopes of the access tokens (SES-08).
    pub scopes: Vec<String>,
    /// Second factors verified for this session (K-78): what produced its
    /// `mfa`. Never a risk confirmation e-mail (RSK-03). Empty for sessions
    /// whose `mfa` has no recorded factor (passkey login, provider MFA,
    /// sessions created before migration 2002).
    pub mfa_factors: Vec<FactorKind>,
}

impl SessionRecord {
    /// The lifetime class of the session.
    #[must_use]
    pub fn shape(&self) -> SessionShape {
        SessionShape::of(
            self.client_kind == ClientKind::Native,
            self.remember_me,
            self.shared_device,
        )
    }

    /// Whether an admin impersonates the user (ADM-04).
    #[must_use]
    pub fn is_impersonation(&self) -> bool {
        self.impersonator_user_id.is_some()
    }

    /// Impersonation details for the [`Principal`].
    #[must_use]
    pub fn impersonation(&self) -> Option<Impersonation> {
        self.impersonator_user_id.map(|admin| Impersonation {
            admin_user_id: admin,
            read_only: self.impersonation_read_only.unwrap_or(true),
            expires_at: self.absolute_expires_at,
        })
    }

    /// Whether the session is usable at `now`.
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.idle_expires_at > now && self.absolute_expires_at > now
    }

    /// The principal of a request authenticated by this session.
    #[must_use]
    pub fn principal(
        &self,
        credential: PrincipalCredential,
        user_is_platform_admin: bool,
    ) -> Principal {
        let impersonation = self.impersonation();
        Principal {
            subject: Subject::User {
                user_id: self.user_id,
            },
            credential,
            active_org: self.active_org_id,
            amr: self.amr.clone(),
            acr: self.acr.clone(),
            auth_time: Some(self.auth_time),
            scopes: self.scopes.clone(),
            // An impersonated principal never carries platform-admin rights.
            is_platform_admin: user_is_platform_admin && impersonation.is_none(),
            impersonation,
        }
    }
}

/// Device facts recorded with a session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Validated device id.
    pub device_id: Option<String>,
    /// Sanitized user agent (≤ 512 bytes).
    pub user_agent: Option<String>,
    /// "Firefox on Linux"…
    pub device_name: Option<String>,
    /// Client IP.
    pub ip: Option<IpAddr>,
}

impl DeviceInfo {
    /// The device facts of a request.
    #[must_use]
    pub fn from_context(ctx: &authn_core::http::RequestContext) -> Self {
        Self {
            device_id: ctx.device_id.clone(),
            user_agent: ctx.user_agent.clone(),
            device_name: Some(authn_protect::risk::useragent::describe(
                ctx.user_agent.as_deref(),
            )),
            ip: Some(ctx.client_ip),
        }
    }
}

/// Credentials handed to the client after a session was established or
/// rotated.
#[derive(Clone, PartialEq, Eq)]
pub enum IssuedCredentials {
    /// Web: the cookie value and the synchronizer CSRF token.
    Web {
        /// Opaque session token (cookie value, SES-03).
        session_token: SensitiveString,
        /// CSRF synchronizer token for `X-CSRF-Token` (SES-04).
        csrf_token: String,
        /// `Max-Age` of the cookie; `None` = browser-session cookie.
        persistent_for: Option<Duration>,
        /// A device id to set as `__Host-authn_device` when the browser had
        /// none.
        new_device_id: Option<String>,
    },
    /// Native: access + refresh token (SES-05).
    Native {
        /// JWT access token.
        access_token: SensitiveString,
        /// Expiry of the access token.
        access_token_expires_at: OffsetDateTime,
        /// Opaque refresh token.
        refresh_token: SensitiveString,
        /// Expiry of the refresh token (idle; never beyond the session's
        /// absolute expiry).
        refresh_token_expires_at: OffsetDateTime,
    },
}

impl std::fmt::Debug for IssuedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Web { persistent_for, .. } => f
                .debug_struct("Web")
                .field("persistent_for", persistent_for)
                .finish_non_exhaustive(),
            Self::Native {
                access_token_expires_at,
                refresh_token_expires_at,
                ..
            } => f
                .debug_struct("Native")
                .field("access_token_expires_at", access_token_expires_at)
                .field("refresh_token_expires_at", refresh_token_expires_at)
                .finish_non_exhaustive(),
        }
    }
}

/// A new session and its credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedSession {
    /// The stored session.
    pub session: SessionRecord,
    /// What the client receives.
    pub credentials: IssuedCredentials,
    /// Sessions revoked by the concurrent-session limit (SES-14).
    pub evicted: Vec<SessionId>,
}

impl EstablishedSession {
    /// The port representation (`SessionIssuer`).
    #[must_use]
    pub fn to_issued_session(&self) -> authn_core::ports::IssuedSession {
        let (session_token, access_token, access_token_expires_at, refresh_token) =
            match &self.credentials {
                IssuedCredentials::Web { session_token, .. } => {
                    (Some(session_token.clone()), None, None, None)
                }
                IssuedCredentials::Native {
                    access_token,
                    access_token_expires_at,
                    refresh_token,
                    ..
                } => (
                    None,
                    Some(access_token.clone()),
                    Some(*access_token_expires_at),
                    Some(refresh_token.clone()),
                ),
            };
        authn_core::ports::IssuedSession {
            session_id: self.session.id,
            user_id: self.session.user_id,
            client: self.session.client_kind,
            session_token,
            access_token,
            access_token_expires_at,
            refresh_token,
            idle_expires_at: self.session.idle_expires_at,
            absolute_expires_at: self.session.absolute_expires_at,
            browser_session_only: !matches!(
                &self.credentials,
                IssuedCredentials::Web {
                    persistent_for: Some(_),
                    ..
                }
            ),
        }
    }
}

/// The session behind the current request, inserted into the request
/// extensions by the authentication middleware next to the [`Principal`].
#[derive(Clone, PartialEq, Eq)]
pub struct CurrentSession {
    pub(crate) record: SessionRecord,
    pub(crate) token_hash: Option<[u8; 32]>,
    pub(crate) token_id: Option<Uuid>,
    /// Set by the middleware when this state-changing cookie request passed
    /// the CSRF checks (origin + session-bound token).
    pub(crate) csrf_verified: bool,
    /// Hash of the token presented in the `x-impersonation-session` header
    /// (K-12) when that header authenticated the request; `None` otherwise.
    /// Such a session must never be answered with a `Set-Cookie`.
    pub(crate) impersonation_header_hash: Option<[u8; 32]>,
}

impl std::fmt::Debug for CurrentSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CurrentSession")
            .field("session_id", &self.record.id)
            .field("client_kind", &self.record.client_kind)
            .finish_non_exhaustive()
    }
}

impl CurrentSession {
    /// The session.
    #[must_use]
    pub fn record(&self) -> &SessionRecord {
        &self.record
    }

    /// The session id.
    #[must_use]
    pub fn id(&self) -> SessionId {
        self.record.id
    }

    /// Whether the request was authenticated by the session cookie.
    #[must_use]
    pub fn is_cookie(&self) -> bool {
        self.token_hash.is_some()
    }

    /// Whether this (state-changing, cookie) request passed the CSRF
    /// checks of the middleware.
    #[must_use]
    pub fn csrf_verified(&self) -> bool {
        self.csrf_verified
    }

    /// Whether the request was authenticated by the web impersonation
    /// header `x-impersonation-session` (ADM-04, K-12). Responses to such a
    /// request must carry a rotated token in the body, never in a cookie.
    #[must_use]
    pub fn is_impersonation_header(&self) -> bool {
        self.impersonation_header_hash.is_some()
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for CurrentSession {
    type Rejection = authn_core::AuthError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CurrentSession>()
            .cloned()
            .ok_or_else(|| {
                authn_core::AuthError::new(authn_core::error::codes::common::UNAUTHENTICATED)
            })
    }
}

impl<S: Send + Sync> axum::extract::OptionalFromRequestParts<S> for CurrentSession {
    type Rejection = authn_core::AuthError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<CurrentSession>().cloned())
    }
}
