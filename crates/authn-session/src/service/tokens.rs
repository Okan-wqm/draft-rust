//! Access tokens (SES-05, SES-08) and the JWKS (SES-09).

use authn_core::error::{AuthError, codes};
use authn_core::id::{SessionId, UserId};
use authn_core::secret::SensitiveString;
use authn_crypto::jwt::{JwkSet, JwtError, JwtValidation, TYP_ACCESS_TOKEN};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{SessionService, after};
use crate::claims::{AccessTokenClaims, ActorClaim, FIRST_PARTY_CLIENT_ID};
use crate::keys::peek_kid;
use crate::metrics;
use crate::model::SessionRecord;

/// A verified access token (signature, `typ`, `iss`, `aud`, `exp`, `nbf`,
/// `iat`, lifetime). Whether its session is still active is a separate
/// check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccessToken {
    /// The claims.
    pub claims: AccessTokenClaims,
    /// `sub`.
    pub user_id: UserId,
    /// `sid`.
    pub session_id: SessionId,
    /// `jti`.
    pub token_id: Uuid,
    /// Signing key.
    pub kid: String,
}

fn reject(reason: &'static str) -> AuthError {
    metrics::bearer_rejected(reason);
    AuthError::new(codes::common::UNAUTHENTICATED).with_context(reason)
}

fn jwt_reason(err: JwtError) -> &'static str {
    match err {
        JwtError::Malformed => "malformed",
        JwtError::UnsupportedAlgorithm => "algorithm",
        JwtError::WrongType => "type",
        JwtError::UnknownKey => "unknown_key",
        JwtError::BadSignature => "signature",
        JwtError::InvalidClaim(_) => "claim",
        JwtError::WrongIssuer => "issuer",
        JwtError::WrongAudience => "audience",
        JwtError::Expired => "expired",
        JwtError::NotYetValid => "not_yet_valid",
        JwtError::InvalidIssuedAt => "issued_at",
        _ => "other",
    }
}

impl SessionService {
    /// Signs an access token for `session` (SES-08). The expiry never
    /// exceeds the session's absolute expiry.
    pub(crate) async fn issue_access_token(
        &self,
        session: &SessionRecord,
        now: OffsetDateTime,
    ) -> Result<(SensitiveString, OffsetDateTime), AuthError> {
        let settings = self.settings();
        let expires_at =
            after(now, settings.session.access_token_ttl).min(session.absolute_expires_at);
        if expires_at <= now {
            return Err(AuthError::new(codes::session::INVALID_REFRESH_TOKEN)
                .with_context("session ends before an access token could be used"));
        }
        let impersonation = session.impersonation();
        let claims = AccessTokenClaims {
            iss: settings.issuer.clone(),
            sub: session.user_id.to_string(),
            aud: settings.audiences.clone(),
            exp: expires_at.unix_timestamp(),
            iat: now.unix_timestamp(),
            nbf: now.unix_timestamp(),
            jti: Uuid::now_v7().hyphenated().to_string(),
            sid: session.id.to_string(),
            auth_time: session.auth_time.unix_timestamp(),
            amr: session.amr.clone(),
            acr: session.acr.clone(),
            org_id: session.active_org_id,
            scope: session.scopes.join(" "),
            client_id: FIRST_PARTY_CLIENT_ID.to_owned(),
            act: impersonation.map(|i| ActorClaim {
                sub: i.admin_user_id.to_string(),
            }),
            read_only: impersonation.map(|i| i.read_only),
        };
        let signer = self.key_cache().signer().await?;
        let token = signer
            .sign(TYP_ACCESS_TOKEN, &claims)
            .map_err(AuthError::from)?;
        Ok((SensitiveString::new(token), expires_at))
    }

    /// Verifies an access token issued by this service: fixed algorithm
    /// (EdDSA), `typ: at+jwt`, known `kid`, `iss`, this API's audience,
    /// `exp` / `nbf` / `iat` with the configured leeway and a lifetime of at
    /// most `access_token_ttl` (CRY-09). Every failure is `unauthenticated`.
    pub async fn verify_access_token(&self, token: &str) -> Result<VerifiedAccessToken, AuthError> {
        let settings = self.settings();
        let kid = peek_kid(token);
        let verifier = self.key_cache().verifier_for(kid.as_deref()).await?;
        let validation =
            JwtValidation::access_token(settings.issuer.clone(), settings.own_audience())
                .with_leeway(settings.jwt_leeway)
                .with_max_lifetime(settings.session.access_token_ttl);
        let verified = verifier
            .verify::<AccessTokenClaims>(token, &validation, self.now())
            .map_err(|e| reject(jwt_reason(e)))?;
        let user_id = verified
            .claims
            .sub
            .parse::<UserId>()
            .map_err(|_| reject("subject"))?;
        let session_id = verified
            .claims
            .sid
            .parse::<SessionId>()
            .map_err(|_| reject("session"))?;
        let token_id = authn_core::id::parse_canonical_uuid(&verified.claims.jti)
            .map_err(|_| reject("token_id"))?;
        Ok(VerifiedAccessToken {
            claims: verified.claims,
            user_id,
            session_id,
            token_id,
            kid: verified.kid,
        })
    }

    /// The JSON Web Key Set: public keys only (SES-09, CRY-10).
    pub async fn jwks(&self) -> Result<JwkSet, AuthError> {
        self.key_cache().jwks().await
    }
}
