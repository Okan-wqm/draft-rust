//! Token endpoint and client authentication (OIDP-06, OIDP-07, OIDP-08).

use std::collections::BTreeMap;

use authn_core::domain::AuthMethodRef;
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::ports::{Actor, RateLimitKey, SecurityEvent, SecurityEventKind};
use authn_crypto::jwt::TYP_ACCESS_TOKEN;
use authn_crypto::token::OpaqueToken;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{OidcProviderService, after};
use crate::claims::{self, IdTokenClaims, ProviderAccessTokenClaims, TYP_ID_TOKEN};
use crate::error::{OAuthError, ProtocolError};
use crate::pkce;
use crate::store::{self, ClientRow, GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN, GrantRow};

/// Longest form body field value accepted by the token-family endpoints.
const MAX_FIELD_LEN: usize = 8 * 1024;
/// Most form fields.
const MAX_FIELDS: usize = 32;

/// The token response (RFC 6749 §5.1, OIDC Core §3.1.3.3).
#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    /// JWT access token (RFC 9068).
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: &'static str,
    /// Access-token lifetime in seconds.
    pub expires_in: i64,
    /// Rotating refresh token (when the client may use `refresh_token`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// ID token (when `openid` was granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Granted scopes.
    pub scope: String,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// The client credentials of a request (RFC 6749 §2.3.1): HTTP Basic,
/// form fields or, for public clients, the bare `client_id`.
#[derive(Clone, Default)]
pub struct ClientCredentials {
    /// `client_id`.
    pub client_id: Option<String>,
    /// `client_secret`.
    pub client_secret: Option<String>,
    /// The credentials came in an `Authorization: Basic` header.
    pub basic: bool,
}

impl std::fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("client_id", &self.client_id)
            .field("basic", &self.basic)
            .finish_non_exhaustive()
    }
}

/// Decodes one `application/x-www-form-urlencoded` value (RFC 6749
/// §2.3.1, Appendix B): `+` is a space, `%XX` an octet. Every other byte
/// is literal — a raw `&` or `=` is data, never a field separator (parsing
/// the value as a form would let `oc_a&v=oc_b` select the client `oc_b`).
/// Malformed escapes and non-UTF-8 results are refused.
fn form_decode(value: &str) -> Option<String> {
    fn hex(b: u8) -> Option<u8> {
        char::from(b)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    }
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let high = hex(bytes.next()?)?;
                let low = hex(bytes.next()?)?;
                out.push(high << 4 | low);
            }
            other => out.push(other),
        }
    }
    String::from_utf8(out).ok()
}

/// Parses a form body: every field at most once (RFC 6749 §3.2), bounded
/// size.
pub fn parse_form(body: &[u8]) -> Result<BTreeMap<String, String>, OAuthError> {
    let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body)
        .map_err(|_| OAuthError::invalid_request("the request body is not a valid form"))?;
    if pairs.len() > MAX_FIELDS {
        return Err(OAuthError::invalid_request("too many parameters"));
    }
    let mut map = BTreeMap::new();
    for (name, value) in pairs {
        if value.len() > MAX_FIELD_LEN || name.len() > 64 {
            return Err(OAuthError::invalid_request("a parameter is too long"));
        }
        if map.insert(name, value).is_some() {
            return Err(OAuthError::invalid_request("a parameter was repeated"));
        }
    }
    Ok(map)
}

/// Extracts the client credentials from the `Authorization` header (if
/// any) and the form.
pub fn client_credentials(
    authorization: Option<&str>,
    form: &BTreeMap<String, String>,
) -> Result<ClientCredentials, OAuthError> {
    let body_id = form.get("client_id").cloned();
    let body_secret = form.get("client_secret").cloned();
    let Some(header) = authorization else {
        return Ok(ClientCredentials {
            client_id: body_id,
            client_secret: body_secret,
            basic: false,
        });
    };
    let (scheme, encoded) = header
        .split_once(' ')
        .ok_or_else(|| OAuthError::invalid_client(true))?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(OAuthError::invalid_client(true));
    }
    let decoded = STANDARD
        .decode(encoded.trim())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| OAuthError::invalid_client(true))?;
    let (id, secret) = decoded
        .split_once(':')
        .ok_or_else(|| OAuthError::invalid_client(true))?;
    let id = form_decode(id).ok_or_else(|| OAuthError::invalid_client(true))?;
    let secret = form_decode(secret).ok_or_else(|| OAuthError::invalid_client(true))?;
    // One authentication method per request (RFC 6749 §2.3).
    if body_secret.is_some() || body_id.as_ref().is_some_and(|b| *b != id) {
        return Err(OAuthError::invalid_request(
            "use exactly one client authentication method",
        ));
    }
    Ok(ClientCredentials {
        client_id: Some(id),
        client_secret: Some(secret),
        basic: true,
    })
}

impl OidcProviderService {
    /// Authenticates the client of a token-family request: confidential
    /// clients by secret (constant-time hash comparison), public clients
    /// by `client_id` alone (they are bound to the grant by PKCE and by
    /// the grant's client). Every failure is `401 invalid_client`.
    pub async fn authenticate_client(
        &self,
        ctx: &RequestContext,
        credentials: &ClientCredentials,
    ) -> Result<ClientRow, ProtocolError> {
        self.limit(
            &RateLimitKey::ip("oauth2_token", ctx.client_ip),
            self.settings().token_per_ip,
        )
        .await?;
        let fail = || ProtocolError::from(OAuthError::invalid_client(credentials.basic));
        let Some(client_id) = credentials.client_id.as_deref() else {
            return Err(fail());
        };
        if client_id.is_empty() || client_id.len() > 64 {
            return Err(fail());
        }
        let client = store::find_client(self.pool(), client_id).await?;
        let ok = match (&client, credentials.client_secret.as_deref()) {
            (Some(c), Some(secret)) if c.is_confidential() => Self::secret_matches(c, secret),
            (Some(c), None) => !c.is_confidential(),
            // A public client presenting a secret, or an unknown client:
            // hash anyway so the response time does not depend on it.
            (_, secret) => {
                let _ = authn_crypto::sha256(secret.unwrap_or_default().as_bytes());
                false
            }
        };
        let client = match client {
            Some(c) if ok && !c.disabled => c,
            _ => return Err(fail()),
        };
        self.limit(
            &RateLimitKey::account("oauth2_client", &client.client_id),
            self.settings().token_per_client,
        )
        .await?;
        Ok(client)
    }

    /// `POST /v1/oauth2/token`.
    pub async fn token(
        &self,
        ctx: &RequestContext,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<TokenResponse, ProtocolError> {
        let form = parse_form(body)?;
        let credentials = client_credentials(authorization, &form)?;
        let client = self.authenticate_client(ctx, &credentials).await?;
        match form.get("grant_type").map(String::as_str) {
            Some(GRANT_AUTHORIZATION_CODE) => {
                if !client.allows_grant(GRANT_AUTHORIZATION_CODE) {
                    return Err(OAuthError::unauthorized_client().into());
                }
                self.exchange_code(ctx, &client, &form).await
            }
            Some(GRANT_REFRESH_TOKEN) => {
                if !client.allows_grant(GRANT_REFRESH_TOKEN) {
                    return Err(OAuthError::unauthorized_client().into());
                }
                self.refresh(ctx, &client, &form).await
            }
            Some(_) => Err(OAuthError::unsupported_grant_type().into()),
            None => Err(OAuthError::invalid_request("grant_type is required").into()),
        }
    }

    /// `authorization_code` (OIDP-06): single-use code bound to the client,
    /// the redirect URI and the PKCE challenge. A replayed code revokes the
    /// grant and every token issued from it (RFC 6749 §4.1.2).
    async fn exchange_code(
        &self,
        ctx: &RequestContext,
        client: &ClientRow,
        form: &BTreeMap<String, String>,
    ) -> Result<TokenResponse, ProtocolError> {
        let code = form
            .get("code")
            .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
        let redirect_uri = form
            .get("redirect_uri")
            .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;
        let verifier = form
            .get("code_verifier")
            .ok_or_else(|| OAuthError::invalid_request("code_verifier is required (PKCE)"))?;
        let code =
            OpaqueToken::parse(code).map_err(|_| OAuthError::invalid_grant("malformed_code"))?;
        let now = self.now();
        let mut tx = authn_store::begin(self.pool()).await?;
        let row = store::lock_code(&mut tx, code.hash().as_bytes())
            .await?
            .ok_or_else(|| OAuthError::invalid_grant("unknown_code"))?;
        let grant = store::find_grant(&mut *tx, row.grant_id)
            .await?
            .ok_or_else(|| OAuthError::invalid_grant("unknown_grant"))?;
        if grant.client_id != client.id {
            // Another client's code (code injection): untouched, refused.
            return Err(OAuthError::invalid_grant("client_mismatch").into());
        }
        if row.consumed_at.is_some() {
            let revoked = store::revoke_grant(&mut tx, grant.id, "code_replayed", now).await?;
            let event = SecurityEvent::new(SecurityEventKind::OAuthCodeReplayDetected, now)
                .with_context(ctx)
                .with_actor(Actor::Anonymous)
                .with_subject(grant.user_id)
                .with_resource("oauth_client", &client.client_id)
                .with_meta("grant_revoked", revoked);
            self.deps().audit.record_in_tx(&mut tx, event).await?;
            tx.commit().await?;
            return Err(OAuthError::invalid_grant("code_replayed").into());
        }
        if row.expires_at <= now {
            return Err(OAuthError::invalid_grant("code_expired").into());
        }
        if row.redirect_uri != *redirect_uri {
            return Err(OAuthError::invalid_grant("redirect_uri_mismatch").into());
        }
        if !pkce::verify(verifier, &row.code_challenge) {
            // Burn the code: a wrong verifier is an injection attempt.
            store::consume_code(&mut tx, row.id, now).await?;
            tx.commit().await?;
            return Err(OAuthError::invalid_grant("pkce_mismatch").into());
        }
        store::consume_code(&mut tx, row.id, now).await?;
        if !self.grant_usable(&mut tx, &grant, now).await? {
            store::revoke_grant(&mut tx, grant.id, "session_ended", now).await?;
            tx.commit().await?;
            return Err(OAuthError::invalid_grant("session_ended").into());
        }
        let response = self
            .mint(
                &mut tx,
                client,
                &grant,
                &grant.scopes,
                grant.nonce.as_deref(),
                now,
            )
            .await?;
        let event = SecurityEvent::new(SecurityEventKind::OAuthTokensIssued, now)
            .with_context(ctx)
            .with_actor(Actor::User(grant.user_id))
            .with_subject(grant.user_id)
            .with_resource("oauth_client", &client.client_id)
            .with_meta("grant_type", GRANT_AUTHORIZATION_CODE)
            .with_meta("scope", response.scope.clone());
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(response)
    }

    /// `refresh_token` (OIDP-07): rotation on every use; a rotated token
    /// presented again revokes the grant (no grace period: concurrent
    /// refreshes of one token count as a replay, like SES-05).
    async fn refresh(
        &self,
        ctx: &RequestContext,
        client: &ClientRow,
        form: &BTreeMap<String, String>,
    ) -> Result<TokenResponse, ProtocolError> {
        let token = form
            .get("refresh_token")
            .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
        let token = OpaqueToken::parse(token)
            .map_err(|_| OAuthError::invalid_grant("malformed_refresh_token"))?;
        let now = self.now();
        let mut tx = authn_store::begin(self.pool()).await?;
        let row = store::lock_refresh(&mut tx, token.hash().as_bytes())
            .await?
            .ok_or_else(|| OAuthError::invalid_grant("unknown_refresh_token"))?;
        let grant = store::find_grant(&mut *tx, row.grant_id)
            .await?
            .ok_or_else(|| OAuthError::invalid_grant("unknown_grant"))?;
        if grant.client_id != client.id {
            return Err(OAuthError::invalid_grant("client_mismatch").into());
        }
        if row.consumed_at.is_some() {
            let revoked =
                store::revoke_grant(&mut tx, grant.id, "refresh_token_replayed", now).await?;
            let event = SecurityEvent::new(SecurityEventKind::OAuthRefreshTokenReplayDetected, now)
                .with_context(ctx)
                .with_actor(Actor::Anonymous)
                .with_subject(grant.user_id)
                .with_resource("oauth_client", &client.client_id)
                .with_meta("grant_revoked", revoked);
            self.deps().audit.record_in_tx(&mut tx, event).await?;
            tx.commit().await?;
            return Err(OAuthError::invalid_grant("refresh_token_replayed").into());
        }
        if row.expires_at <= now {
            return Err(OAuthError::invalid_grant("refresh_token_expired").into());
        }
        let scopes = match form.get("scope") {
            None => grant.scopes.clone(),
            Some(requested) => {
                let requested: Vec<String> = requested
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                if requested.is_empty() || !requested.iter().all(|s| grant.scopes.contains(s)) {
                    return Err(OAuthError::invalid_scope().into());
                }
                grant
                    .scopes
                    .iter()
                    .filter(|s| requested.contains(s))
                    .cloned()
                    .collect()
            }
        };
        store::consume_refresh(&mut tx, row.id, now).await?;
        if !self.grant_usable(&mut tx, &grant, now).await? {
            store::revoke_grant(&mut tx, grant.id, "session_ended", now).await?;
            tx.commit().await?;
            return Err(OAuthError::invalid_grant("session_ended").into());
        }
        let response = self
            .mint(&mut tx, client, &grant, &scopes, None, now)
            .await?;
        tx.commit().await?;
        Ok(response)
    }

    /// Whether a grant may still produce tokens: not revoked, not expired,
    /// its session live and its user allowed to sign in (OIDP-12).
    pub(crate) async fn grant_usable(
        &self,
        conn: &mut PgConnection,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        if grant.revoked_at.is_some() || grant.expires_at <= now {
            return Ok(false);
        }
        self.deps()
            .liveness
            .is_active(conn, grant.session_id, grant.user_id, now)
            .await
    }

    /// Signs the access token (and refresh / ID token) of a grant inside
    /// the caller's transaction.
    async fn mint(
        &self,
        conn: &mut PgConnection,
        client: &ClientRow,
        grant: &GrantRow,
        scopes: &[String],
        nonce: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<TokenResponse, AuthError> {
        let settings = self.settings();
        let openid = scopes.iter().any(|s| s == "openid");
        let mut aud: Vec<String> = if grant.resources.is_empty() {
            vec![client.client_id.clone()]
        } else {
            grant.resources.clone()
        };
        if openid {
            aud.push(settings.userinfo_url());
        }
        if aud.iter().any(|a| settings.is_reserved_audience(a)) {
            // Registration refuses these; never mint a token a native
            // verifier could accept (OIDP-08).
            return Err(AuthError::internal("reserved audience in a provider grant"));
        }
        let expires_at = after(now, settings.access_token_ttl).min(grant.expires_at);
        let jti = Uuid::now_v7();
        let amr: Vec<AuthMethodRef> = grant.amr.iter().filter_map(|a| a.parse().ok()).collect();
        let acr = grant
            .acr
            .clone()
            .unwrap_or_else(|| claims::acr_for(&amr).to_owned());
        let at_claims = ProviderAccessTokenClaims {
            iss: settings.issuer.clone(),
            sub: grant.user_id.to_string(),
            aud,
            exp: expires_at.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: jti.hyphenated().to_string(),
            client_id: client.client_id.clone(),
            scope: scopes.join(" "),
            auth_time: grant.auth_time.unix_timestamp(),
            acr: acr.clone(),
        };
        let signer = self.keys().signer_in(&mut *conn).await?;
        let access_token = signer
            .sign(TYP_ACCESS_TOKEN, &at_claims)
            .map_err(AuthError::from)?;
        store::insert_access_token(&mut *conn, jti, grant.id, expires_at).await?;

        let refresh_token = if client.allows_grant(GRANT_REFRESH_TOKEN) {
            let token = OpaqueToken::generate().map_err(AuthError::from)?;
            let refresh_expires = after(now, settings.refresh_token_idle_ttl).min(grant.expires_at);
            store::insert_refresh(
                &mut *conn,
                Uuid::now_v7(),
                grant.id,
                token.hash().as_bytes(),
                now,
                refresh_expires,
            )
            .await?;
            Some(token.expose().to_owned())
        } else {
            None
        };

        let id_token = if openid {
            let id_claims = IdTokenClaims {
                iss: settings.issuer.clone(),
                sub: grant.user_id.to_string(),
                aud: vec![client.client_id.clone()],
                azp: client.client_id.clone(),
                exp: after(now, settings.id_token_ttl).unix_timestamp(),
                iat: now.unix_timestamp(),
                auth_time: grant.auth_time.unix_timestamp(),
                nonce: nonce.map(str::to_owned),
                amr,
                acr,
                at_hash: claims::at_hash(&access_token),
                sid: grant.session_id.to_string(),
            };
            Some(
                signer
                    .sign(TYP_ID_TOKEN, &id_claims)
                    .map_err(AuthError::from)?,
            )
        } else {
            None
        };
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: (expires_at - now).whole_seconds(),
            refresh_token,
            id_token,
            scope: scopes.join(" "),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidp_06_basic_credentials_are_form_decoded_and_exclusive() {
        let form = BTreeMap::new();
        let header = format!("Basic {}", STANDARD.encode("oc_a%3Ab:s%2Bcret"));
        let c = client_credentials(Some(&header), &form).unwrap();
        assert_eq!(c.client_id.as_deref(), Some("oc_a:b"));
        assert_eq!(c.client_secret.as_deref(), Some("s+cret"));
        assert!(c.basic);
        let mut both = BTreeMap::new();
        both.insert("client_secret".to_owned(), "x".to_owned());
        assert_eq!(
            client_credentials(Some(&header), &both)
                .unwrap_err()
                .error(),
            "invalid_request"
        );
        assert_eq!(
            client_credentials(Some("Bearer abc"), &form)
                .unwrap_err()
                .error(),
            "invalid_client"
        );
    }

    #[test]
    fn oidp_06_basic_credentials_decode_raw_ampersand_and_equals_literally() {
        // RFC 6749 §2.3.1 / Appendix B: each part is percent-decoded and `+`
        // is a space; a raw `&` or `=` is data, never a field separator that
        // would let one Basic username select another client id.
        let form = BTreeMap::new();
        let header = format!("Basic {}", STANDARD.encode("oc_a&v=oc_b:p&v=q%3D+x"));
        let c = client_credentials(Some(&header), &form).unwrap();
        assert_eq!(c.client_id.as_deref(), Some("oc_a&v=oc_b"));
        assert_eq!(c.client_secret.as_deref(), Some("p&v=q= x"));
        // Malformed escapes are refused, not passed through.
        let header = format!("Basic {}", STANDARD.encode("oc_a%ZZ:s"));
        assert_eq!(
            client_credentials(Some(&header), &form)
                .unwrap_err()
                .error(),
            "invalid_client"
        );
    }

    #[test]
    fn oidp_06_form_fields_may_not_repeat() {
        assert!(parse_form(b"grant_type=authorization_code&code=a").is_ok());
        assert_eq!(
            parse_form(b"code=a&code=b").unwrap_err().error(),
            "invalid_request"
        );
    }
}
