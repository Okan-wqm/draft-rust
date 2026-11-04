//! Resolving the credential of a request into a [`Principal`] (SES-03,
//! SES-05, SES-08).
//!
//! * **Cookie:** the opaque token is parsed (garbage never reaches SQL) and
//!   looked up by its SHA-256; the session must be unrevoked, within its
//!   idle and absolute expiry, and its owner usable (not suspended,
//!   disabled, deleted or locked). Activity extends the idle expiry, never
//!   the absolute one (SES-06); writes are throttled by
//!   `session.touch_interval`.
//! * **Bearer:** the access token is verified (CRY-09). With
//!   `session.access_token_session_check` (default on) its session must
//!   also still be active and match the token (owner, active organization),
//!   so a revocation takes effect on the next request. The principal keeps
//!   the token's own `amr` / `auth_time`: a token minted before a step-up
//!   never benefits from it. Without the check, revocation takes effect
//!   when the token expires (≤ `access_token_ttl`) and the principal never
//!   carries platform-admin rights.

use authn_core::domain::{ClientKind, Impersonation, Principal, PrincipalCredential, Subject};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_crypto::token::OpaqueToken;
use time::OffsetDateTime;

use super::{SessionService, after};
use crate::metrics;
use crate::model::{CurrentSession, SessionRecord};
use crate::store::sessions;

/// The outcome of a successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// The caller.
    pub principal: Principal,
    /// The session behind it.
    pub session: CurrentSession,
}

fn unauthenticated(reason: &'static str) -> AuthError {
    metrics::bearer_rejected(reason);
    AuthError::new(codes::common::UNAUTHENTICATED).with_context(reason)
}

impl SessionService {
    /// Resolves a session cookie. `Ok(None)` for unknown, malformed,
    /// revoked or expired tokens.
    pub async fn authenticate_cookie(
        &self,
        ctx: &RequestContext,
        cookie: &str,
    ) -> Result<Option<Authenticated>, AuthError> {
        let Ok(token) = OpaqueToken::parse(cookie) else {
            return Ok(None);
        };
        let hash = token.hash();
        let now = self.now();
        let Some(live) = sessions::find_live_by_token(self.pool(), &hash, now).await? else {
            return Ok(None);
        };
        self.touch(&live.record, ctx, now).await?;
        let principal = live.record.principal(
            PrincipalCredential::SessionCookie {
                session_id: live.record.id,
            },
            live.is_platform_admin,
        );
        Ok(Some(Authenticated {
            principal,
            session: CurrentSession {
                record: live.record,
                token_hash: Some(*hash.as_bytes()),
                token_id: None,
                csrf_verified: false,
                impersonation_header_hash: None,
            },
        }))
    }

    /// Resolves the token of a **web impersonation** session presented in
    /// the `x-impersonation-session` header (ADM-04, K-12). Only live
    /// impersonation web sessions are accepted: a regular session token in
    /// that header is refused (`Ok(None)`), so the header can never be used
    /// to replay a normal session without its cookie's CSRF protection.
    /// The returned session is not marked as cookie-authenticated (logout
    /// clears no cookie; the admin's own session cookie stays untouched).
    pub async fn authenticate_impersonation_token(
        &self,
        ctx: &RequestContext,
        token: &str,
    ) -> Result<Option<Authenticated>, AuthError> {
        let Ok(token) = OpaqueToken::parse(token) else {
            return Ok(None);
        };
        let hash = token.hash();
        let now = self.now();
        let Some(live) = sessions::find_live_by_token(self.pool(), &hash, now).await? else {
            return Ok(None);
        };
        if !live.record.is_impersonation() || live.record.client_kind != ClientKind::Web {
            metrics::bearer_rejected("impersonation_header_not_impersonation");
            return Ok(None);
        }
        self.touch(&live.record, ctx, now).await?;
        let principal = live.record.principal(
            PrincipalCredential::SessionCookie {
                session_id: live.record.id,
            },
            live.is_platform_admin,
        );
        Ok(Some(Authenticated {
            principal,
            session: CurrentSession {
                record: live.record,
                token_hash: None,
                token_id: None,
                csrf_verified: false,
                impersonation_header_hash: Some(*hash.as_bytes()),
            },
        }))
    }

    async fn touch(
        &self,
        record: &SessionRecord,
        ctx: &RequestContext,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let interval = self.settings().session.touch_interval;
        let not_after = now - time::Duration::try_from(interval).unwrap_or(time::Duration::ZERO);
        if record.last_seen_at >= not_after {
            return Ok(());
        }
        let idle = if record.is_impersonation() {
            record.absolute_expires_at
        } else {
            after(now, self.settings().lifetime(record.shape()).idle_timeout)
        };
        sessions::touch(
            self.pool(),
            record.id,
            now,
            Some(ctx.client_ip),
            idle,
            not_after,
        )
        .await?;
        Ok(())
    }

    /// Resolves a bearer access token. Every failure is `401
    /// unauthenticated`.
    pub async fn authenticate_bearer(&self, token: &str) -> Result<Authenticated, AuthError> {
        let verified = self.verify_access_token(token).await?;
        let claims = &verified.claims;
        let credential = PrincipalCredential::AccessToken {
            session_id: verified.session_id,
            token_id: verified.token_id,
        };
        let auth_time = OffsetDateTime::from_unix_timestamp(claims.auth_time)
            .map_err(|_| unauthenticated("auth_time"))?;
        if !self.settings().session.access_token_session_check {
            let impersonation = match &claims.act {
                Some(actor) => Some(Impersonation {
                    admin_user_id: actor
                        .sub
                        .parse::<UserId>()
                        .map_err(|_| unauthenticated("actor"))?,
                    read_only: claims.read_only.unwrap_or(true),
                    expires_at: OffsetDateTime::from_unix_timestamp(claims.exp)
                        .map_err(|_| unauthenticated("exp"))?,
                }),
                None => None,
            };
            let principal = Principal {
                subject: Subject::User {
                    user_id: verified.user_id,
                },
                credential,
                active_org: claims.org_id,
                amr: claims.amr.clone(),
                acr: claims.acr.clone(),
                auth_time: Some(auth_time),
                scopes: claims
                    .scope
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
                impersonation,
                // Platform-admin rights need the live session check.
                is_platform_admin: false,
            };
            let record = SessionRecord {
                id: verified.session_id,
                user_id: verified.user_id,
                client_kind: ClientKind::Native,
                remember_me: false,
                shared_device: false,
                amr: claims.amr.clone(),
                acr: claims.acr.clone(),
                auth_time,
                active_org_id: claims.org_id,
                impersonator_user_id: principal.impersonation.map(|i| i.admin_user_id),
                impersonation_read_only: principal.impersonation.map(|i| i.read_only),
                device_id: None,
                device_name: None,
                created_ip: None,
                last_seen_ip: None,
                created_at: auth_time,
                last_seen_at: auth_time,
                idle_expires_at: OffsetDateTime::from_unix_timestamp(claims.exp)
                    .map_err(|_| unauthenticated("exp"))?,
                absolute_expires_at: OffsetDateTime::from_unix_timestamp(claims.exp)
                    .map_err(|_| unauthenticated("exp"))?,
                login_method: None,
                scopes: principal.scopes.clone(),
            };
            return Ok(Authenticated {
                principal,
                session: CurrentSession {
                    record,
                    token_hash: None,
                    token_id: Some(verified.token_id),
                    csrf_verified: false,
                    impersonation_header_hash: None,
                },
            });
        }
        let live = sessions::find_live_by_id(self.pool(), verified.session_id, self.now())
            .await?
            .ok_or_else(|| unauthenticated("session_inactive"))?;
        if live.record.user_id != verified.user_id {
            return Err(unauthenticated("session_owner"));
        }
        if live.record.client_kind != ClientKind::Native {
            return Err(unauthenticated("session_kind"));
        }
        if live.record.active_org_id != claims.org_id {
            // Issued before an organization switch: stale context.
            return Err(unauthenticated("stale_org"));
        }
        let mut principal = live.record.principal(credential, live.is_platform_admin);
        principal.amr.clone_from(&claims.amr);
        principal.acr.clone_from(&claims.acr);
        principal.auth_time = Some(auth_time);
        Ok(Authenticated {
            principal,
            session: CurrentSession {
                record: live.record,
                token_hash: None,
                token_id: Some(verified.token_id),
                csrf_verified: false,
                impersonation_header_hash: None,
            },
        })
    }
}

/// Whether `session` is a live, non-impersonation session of `user` at
/// `now`, read **only** through `conn` (the caller's transaction; no pool
/// connection is used). Live = exists, belongs to `user`, not revoked,
/// within its idle and absolute expiry, and its owner may still sign in
/// (not suspended, disabled, deleted or locked). For the identity-linking
/// callback of authn-oidc-client (K-03), which re-validates the session
/// that started the link inside its own transaction.
pub async fn is_session_active_in(
    conn: &mut sqlx::PgConnection,
    session: authn_core::id::SessionId,
    user: UserId,
    now: OffsetDateTime,
) -> Result<bool, AuthError> {
    Ok(sessions::find_live_by_id(&mut *conn, session, now)
        .await?
        .is_some_and(|live| live.record.user_id == user && !live.record.is_impersonation()))
}
