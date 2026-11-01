//! Token introspection for resource servers (SES-10, RFC 7662).
//!
//! * Client authentication is mandatory: an organization API key
//!   (`Authorization: Bearer ak_…` or `X-API-Key`), verified by authn-org's
//!   `authenticate_api_key` (expiry, revocation, rate limits, audit). The
//!   endpoint authenticates the key itself — the authentication middleware
//!   turns API keys into principals only on organization routes.
//! * Only access tokens of this service are introspected. `active: true`
//!   needs a valid signature, unexpired claims **and** a live session, so a
//!   revoked session yields `active: false` at once.
//! * Tenant isolation (ARC-10): a key of organization A sees only tokens
//!   whose active organization is A; every other token is `active: false`
//!   (indistinguishable from an invalid one). Personal tokens (no active
//!   organization) can be verified offline with the JWKS.
//! * Inactive responses carry no other member (RFC 7662 §2.2).

use authn_core::domain::{AuthMethodRef, PrincipalCredential};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::OrgId;
use authn_core::ports::RateLimitKey;
use authn_org::middleware::{ApiKeyCredential, extract_api_key};
use axum::http::HeaderMap;
use serde::Serialize;
use utoipa::ToSchema;

use super::SessionService;
use crate::claims::ActorClaim;
use crate::metrics;
use crate::store::sessions;

/// Rate-limit action of `POST /v1/token/introspect` (per API key).
pub const INTROSPECTION_ACTION: &str = "token_introspection";
/// Longest token inspected.
const MAX_TOKEN_LEN: usize = authn_crypto::jwt::MAX_TOKEN_LEN;

/// RFC 7662 response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct IntrospectionResponse {
    /// Whether the token is active.
    pub active: bool,
    /// Scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Client the token was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// `Bearer`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Expiry (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issue time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Not before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Subject (user id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audiences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Token id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Session id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Authentication time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Authentication methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<AuthMethodRef>>,
    /// Authentication context class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Active organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<OrgId>,
    /// Impersonating admin (RFC 8693).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub act: Option<ActorClaimView>,
    /// Read-only impersonation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

/// `act` member of an introspection response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ActorClaimView {
    /// The acting admin.
    pub sub: String,
}

impl From<ActorClaim> for ActorClaimView {
    fn from(a: ActorClaim) -> Self {
        Self { sub: a.sub }
    }
}

impl IntrospectionResponse {
    /// `{"active": false}`.
    #[must_use]
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
            sid: None,
            auth_time: None,
            amr: None,
            acr: None,
            org_id: None,
            act: None,
            read_only: None,
        }
    }
}

impl SessionService {
    /// Authenticates the introspecting client (an organization API key) and
    /// returns its organization.
    async fn introspection_client(
        &self,
        ctx: &RequestContext,
        headers: &HeaderMap,
    ) -> Result<OrgId, AuthError> {
        let ApiKeyCredential::Present(key) = extract_api_key(headers) else {
            return Err(AuthError::new(codes::common::UNAUTHENTICATED)
                .with_context("introspection requires an API key"));
        };
        let principal = self
            .deps()
            .orgs
            .authenticate_api_key(ctx, key.expose())
            .await?;
        let PrincipalCredential::ApiKey { api_key_id } = principal.credential else {
            return Err(AuthError::new(codes::common::UNAUTHENTICATED));
        };
        let org = principal
            .active_org
            .ok_or_else(|| AuthError::new(codes::common::UNAUTHENTICATED))?;
        self.deps()
            .rate_limiter
            .check(
                &RateLimitKey::account(INTROSPECTION_ACTION, &format!("api_key:{api_key_id}")),
                self.settings().session.introspection_per_client,
                1,
            )
            .await?
            .into_result()?;
        Ok(org)
    }

    /// RFC 7662 introspection (SES-10).
    pub async fn introspect(
        &self,
        ctx: &RequestContext,
        headers: &HeaderMap,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<IntrospectionResponse, AuthError> {
        let client_org = self.introspection_client(ctx, headers).await?;
        if token.is_empty()
            || token.len() > MAX_TOKEN_LEN
            || token_type_hint.is_some_and(|h| h == "refresh_token")
        {
            metrics::introspection("inactive");
            return Ok(IntrospectionResponse::inactive());
        }
        let Ok(verified) = self.verify_access_token(token).await else {
            metrics::introspection("inactive");
            return Ok(IntrospectionResponse::inactive());
        };
        let live = sessions::find_live_by_id(self.pool(), verified.session_id, self.now()).await?;
        let active = live.is_some_and(|l| {
            l.record.user_id == verified.user_id && l.record.active_org_id == verified.claims.org_id
        }) && verified.claims.org_id == Some(client_org);
        if !active {
            metrics::introspection("inactive");
            return Ok(IntrospectionResponse::inactive());
        }
        metrics::introspection("active");
        let claims = verified.claims;
        Ok(IntrospectionResponse {
            active: true,
            scope: Some(claims.scope),
            client_id: Some(claims.client_id),
            token_type: Some("Bearer".to_owned()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            nbf: Some(claims.nbf),
            sub: Some(claims.sub),
            aud: Some(claims.aud),
            iss: Some(claims.iss),
            jti: Some(claims.jti),
            sid: Some(claims.sid),
            auth_time: Some(claims.auth_time),
            amr: Some(claims.amr),
            acr: claims.acr,
            org_id: claims.org_id,
            act: claims.act.map(ActorClaimView::from),
            read_only: claims.read_only,
        })
    }
}
