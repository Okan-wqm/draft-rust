//! The authenticated caller of a request.
//!
//! `authn-session` (cookie / bearer token) and `authn-org` (API keys)
//! authenticate requests and insert a [`Principal`] into the request
//! extensions. Handlers in any crate obtain it with the `Principal` (or
//! `Option<Principal>`) extractor implemented here, which only *reads* the
//! extension — it never authenticates anything itself.

use std::time::Duration;

use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use http::request::Parts;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::AuthMethodRef;
use crate::error::{AuthError, codes};
use crate::id::{ApiKeyId, OrgId, ServiceAccountId, SessionId, UserId};

/// Who is acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Subject {
    /// A human user.
    User {
        /// The user.
        user_id: UserId,
    },
    /// A non-human service account of an organization (ORG-09).
    ServiceAccount {
        /// The service account.
        service_account_id: ServiceAccountId,
        /// The organization owning it.
        org_id: OrgId,
    },
}

/// How the principal proved its identity on this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PrincipalCredential {
    /// Web session cookie (SES-03).
    SessionCookie {
        /// The session.
        session_id: SessionId,
    },
    /// Bearer JWT access token (SES-05).
    AccessToken {
        /// The session / refresh-token family the token belongs to.
        session_id: SessionId,
        /// The token's `jti`.
        token_id: Uuid,
    },
    /// API key (ORG-08).
    ApiKey {
        /// The key.
        api_key_id: ApiKeyId,
    },
}

/// Impersonation details when an admin acts as a user (ADM-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Impersonation {
    /// The real actor (platform admin).
    pub admin_user_id: UserId,
    /// Read-only impersonation rejects state-changing requests.
    pub read_only: bool,
    /// Hard end of the impersonation.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// The authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Who is acting.
    pub subject: Subject,
    /// How they authenticated on this request.
    pub credential: PrincipalCredential,
    /// Active organization (SES-17); for service accounts / org API keys this
    /// is always their own organization.
    pub active_org: Option<OrgId>,
    /// Authentication methods used for the session (RFC 8176).
    pub amr: Vec<AuthMethodRef>,
    /// Authentication context class reference, if any.
    pub acr: Option<String>,
    /// Time of the last (re-)authentication; drives step-up (SES-13).
    #[serde(with = "time::serde::rfc3339::option")]
    pub auth_time: Option<OffsetDateTime>,
    /// Granted scopes (access tokens / API keys).
    pub scopes: Vec<String>,
    /// Set when an admin impersonates the user.
    pub impersonation: Option<Impersonation>,
    /// Platform administrator (ADM-01).
    pub is_platform_admin: bool,
}

impl Principal {
    /// The acting user, if the subject is a human user.
    #[must_use]
    pub fn user_id(&self) -> Option<UserId> {
        match self.subject {
            Subject::User { user_id } => Some(user_id),
            Subject::ServiceAccount { .. } => None,
        }
    }

    /// The acting user or `forbidden` for non-human principals.
    pub fn require_user(&self) -> Result<UserId, AuthError> {
        self.user_id()
            .ok_or_else(|| AuthError::new(codes::common::FORBIDDEN))
    }

    /// The session behind the request, if any.
    #[must_use]
    pub fn session_id(&self) -> Option<SessionId> {
        match self.credential {
            PrincipalCredential::SessionCookie { session_id }
            | PrincipalCredential::AccessToken { session_id, .. } => Some(session_id),
            PrincipalCredential::ApiKey { .. } => None,
        }
    }

    /// Whether this request is made under impersonation.
    #[must_use]
    pub fn is_impersonated(&self) -> bool {
        self.impersonation.is_some()
    }

    /// Whether a scope was granted.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Step-up guard (SES-13): fails with `step_up_required` unless the
    /// principal (re-)authenticated within `max_age` before `now`.
    /// Principals without `auth_time` (API keys) and impersonated principals
    /// never satisfy step-up.
    pub fn require_recent_authentication(
        &self,
        now: OffsetDateTime,
        max_age: Duration,
    ) -> Result<(), AuthError> {
        if self.is_impersonated() {
            return Err(AuthError::new(codes::common::FORBIDDEN));
        }
        let Some(auth_time) = self.auth_time else {
            return Err(AuthError::new(codes::common::STEP_UP_REQUIRED));
        };
        let age = now - auth_time;
        if age.is_negative() || age <= max_age {
            Ok(())
        } else {
            Err(AuthError::new(codes::common::STEP_UP_REQUIRED))
        }
    }

    /// Rejects state-changing requests during read-only impersonation
    /// (ADM-04).
    pub fn require_writable(&self) -> Result<(), AuthError> {
        match self.impersonation {
            Some(Impersonation {
                read_only: true, ..
            }) => Err(AuthError::new(codes::common::FORBIDDEN)),
            _ => Ok(()),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Principal {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for Principal {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Principal>().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(auth_time: Option<OffsetDateTime>) -> Principal {
        Principal {
            subject: Subject::User {
                user_id: UserId::generate(),
            },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: vec![AuthMethodRef::Pwd],
            acr: None,
            auth_time,
            scopes: vec![],
            impersonation: None,
            is_platform_admin: false,
        }
    }

    #[test]
    fn ses_13_step_up_window() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let ten_min = Duration::from_secs(600);
        let fresh = principal(Some(now - Duration::from_secs(599)));
        assert!(fresh.require_recent_authentication(now, ten_min).is_ok());
        let stale = principal(Some(now - Duration::from_secs(601)));
        let err = stale
            .require_recent_authentication(now, ten_min)
            .unwrap_err();
        assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
        let none = principal(None);
        assert!(none.require_recent_authentication(now, ten_min).is_err());
    }

    #[test]
    fn adm_04_read_only_impersonation_blocks_writes_and_step_up() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let mut p = principal(Some(now));
        assert!(p.require_writable().is_ok());
        p.impersonation = Some(Impersonation {
            admin_user_id: UserId::generate(),
            read_only: true,
            expires_at: now,
        });
        assert_eq!(
            p.require_writable().unwrap_err().code(),
            codes::common::FORBIDDEN
        );
        assert!(
            p.require_recent_authentication(now, Duration::from_secs(600))
                .is_err()
        );
    }

    #[test]
    fn service_accounts_are_not_users() {
        let mut p = principal(None);
        p.subject = Subject::ServiceAccount {
            service_account_id: ServiceAccountId::generate(),
            org_id: OrgId::generate(),
        };
        assert!(p.user_id().is_none());
        assert!(p.require_user().is_err());
    }
}
