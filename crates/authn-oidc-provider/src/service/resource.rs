//! UserInfo (OIDP-10), introspection (RFC 7662) and revocation (RFC 7009)
//! (OIDP-11).
//!
//! A provider access token is accepted only when its signature, `typ`,
//! `iss`, lifetime **and** its `jti` record check out: the record ties it
//! to a grant that is neither revoked nor expired and whose session is
//! still live (OIDP-12). Native access tokens have no such record and are
//! never accepted here (OIDP-08).

use std::collections::BTreeMap;

use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::RateLimitKey;
use authn_crypto::jwt::{JwtValidation, TYP_ACCESS_TOKEN};
use authn_crypto::token::OpaqueToken;
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::OidcProviderService;
use super::token::client_credentials;
use crate::claims::ProviderAccessTokenClaims;
use crate::error::{OAuthError, ProtocolError};
use crate::store::{self, ClientRow, GrantRow};

/// Claims returned by `userinfo` (OIDC Core §5.3), by scope.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserInfo {
    /// Subject (always).
    pub sub: String,
    /// `profile`: display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `profile`: preferred language (BCP 47).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// `profile`: IANA time zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// `email`: address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// `email`: whether it is verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// Introspection response (RFC 7662 §2.2). Inactive tokens answer only
/// `{"active": false}`.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct IntrospectionResponse {
    /// Whether the token is active.
    pub active: bool,
    /// Scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Client the token was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// `access_token` or `refresh_token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issue time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Subject.
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
    /// Authentication time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Authentication context class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
}

impl IntrospectionResponse {
    fn inactive() -> Self {
        Self::default()
    }
}

/// A verified provider access token.
struct VerifiedProviderToken {
    claims: ProviderAccessTokenClaims,
    jti: Uuid,
    user: UserId,
    grant: GrantRow,
}

impl OidcProviderService {
    /// Verifies a provider access token for `audience` (`None`: any
    /// audience — introspection decides by client) and checks its record,
    /// grant and session. `Ok(None)` for every invalid token.
    async fn verify_access_token(
        &self,
        token: &str,
        audience: Option<&str>,
    ) -> Result<Option<VerifiedProviderToken>, AuthError> {
        let settings = self.settings();
        let verifier = self.keys().verifier().await?;
        let validation = JwtValidation {
            issuer: settings.issuer.clone(),
            audience: audience.unwrap_or_default().to_owned(),
            typ: TYP_ACCESS_TOKEN.to_owned(),
            leeway: settings.jwt_leeway,
            max_lifetime: Some(settings.access_token_ttl),
        };
        let now = self.now();
        let verified = match audience {
            Some(_) => verifier.verify::<ProviderAccessTokenClaims>(token, &validation, now),
            None => {
                // Audience-agnostic: validate against the token's own
                // first audience after the signature check.
                let peek = verifier.verify::<serde_json::Value>(
                    token,
                    &JwtValidation {
                        audience: String::new(),
                        ..validation.clone()
                    },
                    now,
                );
                match peek {
                    Err(authn_crypto::jwt::JwtError::WrongAudience) => {
                        // Re-run with the token's real audience (signature
                        // already proven valid by reaching the aud check).
                        let aud = first_audience(token);
                        match aud {
                            Some(aud) => verifier.verify::<ProviderAccessTokenClaims>(
                                token,
                                &JwtValidation {
                                    audience: aud,
                                    ..validation
                                },
                                now,
                            ),
                            None => return Ok(None),
                        }
                    }
                    Err(e) => Err(e),
                    Ok(_) => return Ok(None),
                }
            }
        };
        let Ok(verified) = verified else {
            return Ok(None);
        };
        let claims = verified.claims;
        let (Ok(jti), Ok(user)) = (
            authn_core::id::parse_canonical_uuid(&claims.jti),
            claims.sub.parse::<UserId>(),
        ) else {
            return Ok(None);
        };
        let mut conn = self.pool().acquire().await?;
        let Some(record) = store::find_access_token(&mut *conn, jti).await? else {
            return Ok(None);
        };
        if record.revoked_at.is_some() || record.expires_at <= now {
            return Ok(None);
        }
        let Some(grant) = store::find_grant(&mut *conn, record.grant_id).await? else {
            return Ok(None);
        };
        if grant.user_id != user || !self.grant_usable(&mut conn, &grant, now).await? {
            return Ok(None);
        }
        Ok(Some(VerifiedProviderToken {
            claims,
            jti,
            user,
            grant,
        }))
    }

    /// `GET|POST /v1/oauth2/userinfo` (OIDP-10). The token must carry the
    /// `userinfo` audience (granted with `openid`).
    pub async fn userinfo(
        &self,
        ctx: &RequestContext,
        authorization: Option<&str>,
    ) -> Result<UserInfo, ProtocolError> {
        self.limit(
            &RateLimitKey::ip("oauth2_userinfo", ctx.client_ip),
            self.settings().userinfo_per_ip,
        )
        .await?;
        let token = authorization
            .and_then(|h| h.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token.trim())
            .filter(|t| !t.is_empty())
            .ok_or_else(OAuthError::missing_token)?;
        let audience = self.settings().userinfo_url();
        let verified = self
            .verify_access_token(token, Some(&audience))
            .await?
            .ok_or_else(|| OAuthError::invalid_token("invalid_access_token"))?;
        let scopes: Vec<&str> = verified.claims.scope.split(' ').collect();
        if !scopes.contains(&"openid") {
            return Err(OAuthError::insufficient_scope().into());
        }
        let profile = self
            .deps()
            .accounts
            .profile_of(verified.user)
            .await?
            .ok_or_else(|| OAuthError::invalid_token("unknown_user"))?;
        let mut info = UserInfo {
            sub: verified.user.to_string(),
            name: None,
            locale: None,
            zoneinfo: None,
            email: None,
            email_verified: None,
        };
        if scopes.contains(&"profile") {
            info.name = profile.display_name.clone();
            info.locale = Some(profile.locale.as_str().to_owned());
            info.zoneinfo = Some(profile.time_zone.clone());
        }
        if scopes.contains(&"email") {
            info.email = profile.email.clone();
            info.email_verified = Some(profile.email_verified);
        }
        Ok(info)
    }

    /// `POST /v1/oauth2/introspect` (RFC 7662, OIDP-11). Only confidential
    /// clients may introspect; a token is reported active only to the
    /// client it was issued to or to a client named in its audience.
    pub async fn introspect(
        &self,
        ctx: &RequestContext,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<IntrospectionResponse, ProtocolError> {
        let form = super::token::parse_form(body)?;
        let caller = self.confidential_caller(ctx, authorization, &form).await?;
        let token = form
            .get("token")
            .ok_or_else(|| OAuthError::invalid_request("token is required"))?;
        let now = self.now();
        if token.contains('.') {
            let Some(verified) = self.verify_access_token(token, None).await? else {
                return Ok(IntrospectionResponse::inactive());
            };
            let claims = verified.claims;
            let entitled =
                claims.client_id == caller.client_id || claims.aud.contains(&caller.client_id);
            if !entitled {
                return Ok(IntrospectionResponse::inactive());
            }
            return Ok(IntrospectionResponse {
                active: true,
                scope: Some(claims.scope),
                client_id: Some(claims.client_id),
                token_type: Some("access_token".to_owned()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                sub: Some(claims.sub),
                aud: Some(claims.aud),
                iss: Some(claims.iss),
                jti: Some(verified.jti.hyphenated().to_string()),
                auth_time: Some(claims.auth_time),
                acr: Some(claims.acr),
            });
        }
        let Ok(token) = OpaqueToken::parse(token) else {
            return Ok(IntrospectionResponse::inactive());
        };
        let mut conn = self.pool().acquire().await?;
        let Some(row) = store::find_refresh(&mut *conn, token.hash().as_bytes()).await? else {
            return Ok(IntrospectionResponse::inactive());
        };
        let Some(grant) = store::find_grant(&mut *conn, row.grant_id).await? else {
            return Ok(IntrospectionResponse::inactive());
        };
        if grant.client_id != caller.id
            || row.consumed_at.is_some()
            || row.expires_at <= now
            || !self.grant_usable(&mut conn, &grant, now).await?
        {
            return Ok(IntrospectionResponse::inactive());
        }
        Ok(IntrospectionResponse {
            active: true,
            scope: Some(grant.scopes.join(" ")),
            client_id: Some(caller.client_id.clone()),
            token_type: Some("refresh_token".to_owned()),
            exp: Some(row.expires_at.unix_timestamp()),
            sub: Some(grant.user_id.to_string()),
            iss: Some(self.settings().issuer.clone()),
            auth_time: Some(grant.auth_time.unix_timestamp()),
            acr: grant.acr.clone(),
            ..IntrospectionResponse::default()
        })
    }

    async fn confidential_caller(
        &self,
        ctx: &RequestContext,
        authorization: Option<&str>,
        form: &BTreeMap<String, String>,
    ) -> Result<ClientRow, ProtocolError> {
        let credentials = client_credentials(authorization, form)?;
        let client = self.authenticate_client(ctx, &credentials).await?;
        if !client.is_confidential() {
            return Err(OAuthError::invalid_client(credentials.basic).into());
        }
        Ok(client)
    }

    /// `POST /v1/oauth2/revoke` (RFC 7009, OIDP-11). Revoking a refresh
    /// token revokes its whole grant (and so every access token of it);
    /// revoking an access token revokes that token. Tokens of other
    /// clients, unknown and invalid tokens are ignored (`200` either way,
    /// RFC 7009 §2.2).
    pub async fn revoke(
        &self,
        ctx: &RequestContext,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<(), ProtocolError> {
        let form = super::token::parse_form(body)?;
        let credentials = client_credentials(authorization, &form)?;
        let client = self.authenticate_client(ctx, &credentials).await?;
        let token = form
            .get("token")
            .ok_or_else(|| OAuthError::invalid_request("token is required"))?;
        let now: OffsetDateTime = self.now();
        if token.contains('.') {
            if let Some(verified) = self.verify_access_token(token, None).await?
                && verified.claims.client_id == client.client_id
                && verified.grant.client_id == client.id
            {
                let mut conn = self.pool().acquire().await?;
                store::revoke_access_token(&mut conn, verified.jti, now).await?;
            }
            return Ok(());
        }
        let Ok(token) = OpaqueToken::parse(token) else {
            return Ok(());
        };
        let mut tx = authn_store::begin(self.pool()).await?;
        if let Some(row) = store::find_refresh(&mut *tx, token.hash().as_bytes()).await?
            && let Some(grant) = store::find_grant(&mut *tx, row.grant_id).await?
            && grant.client_id == client.id
        {
            store::revoke_grant(&mut tx, grant.id, "client_revoked", now).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

/// The first `aud` of a JWT payload, read **only** after its signature was
/// verified (the caller reached the audience check).
fn first_audience(token: &str) -> Option<String> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    match value.get("aud")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(items) => items.first()?.as_str().map(str::to_owned),
        _ => None,
    }
}
