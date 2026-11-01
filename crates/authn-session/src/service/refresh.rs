//! Refresh-token rotation with reuse detection (SES-05, SES-06).
//!
//! * Every successful refresh retires the presented token and returns a new
//!   one; the absolute expiry of the family never moves.
//! * Presenting an already-retired token is a replay: the whole family
//!   (the session) is revoked (`refresh_token_reuse`), a
//!   `session.refresh_token_reused` security event is recorded, and the
//!   answer is the same `invalid_refresh_token` as for any unknown token.
//! * Optional grace window (`session.refresh_reuse_grace`, default 0 = off,
//!   at most 10 s): a retry of the just-retired token within the window,
//!   while its successor is still unused, gets the **same** successor back
//!   (sealed with envelope encryption, AAD bound to the retired row) — never
//!   a second live token.
//! * Concurrency: the session row is locked first, then the token row, so
//!   two concurrent refreshes with the same token serialize; without a
//!   grace window the loser is a replay and revokes the family.

use authn_core::domain::ClientKind;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::ports::{Actor, RateLimitKey, RevocationReason, SecurityEvent, SecurityEventKind};
use authn_core::secret::SensitiveString;
use authn_crypto::envelope::EnvelopeContext;
use authn_crypto::token::OpaqueToken;
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::{SessionService, remaining};
use crate::metrics;
use crate::model::SessionRecord;
use crate::store::refresh::{self, RefreshRow};
use crate::store::sessions::{self, Target};

/// Rate-limit action of `POST /v1/token/refresh`.
pub const REFRESH_ACTION: &str = "token_refresh";

/// New native credentials (`POST /v1/token/refresh`).
#[derive(Clone, Serialize, ToSchema)]
pub struct RefreshedTokens {
    /// JWT access token (`typ: at+jwt`).
    #[schema(value_type = String)]
    pub access_token: SensitiveString,
    /// Always `Bearer`.
    pub token_type: &'static str,
    /// Seconds until the access token expires.
    pub expires_in: u64,
    /// The new refresh token; the presented one is no longer valid.
    #[schema(value_type = String)]
    pub refresh_token: SensitiveString,
    /// Expiry of the new refresh token.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub refresh_token_expires_at: OffsetDateTime,
}

impl std::fmt::Debug for RefreshedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshedTokens")
            .field("expires_in", &self.expires_in)
            .field("refresh_token_expires_at", &self.refresh_token_expires_at)
            .finish_non_exhaustive()
    }
}

fn invalid(outcome: &'static str) -> AuthError {
    metrics::refresh(outcome);
    AuthError::new(codes::session::INVALID_REFRESH_TOKEN).with_context(outcome)
}

fn successor_context(row: &RefreshRow) -> Result<EnvelopeContext, AuthError> {
    EnvelopeContext::new("refresh_tokens", "successor_ciphertext", row.id)
        .map_err(|e| AuthError::internal("envelope context").with_source(e))
}

impl SessionService {
    /// Rotates a refresh token (SES-05). Every failure — unknown, expired,
    /// revoked, replayed — is `invalid_refresh_token`.
    pub async fn refresh(
        &self,
        ctx: &RequestContext,
        presented: &str,
    ) -> Result<RefreshedTokens, AuthError> {
        self.deps()
            .rate_limiter
            .check(
                &RateLimitKey::ip(REFRESH_ACTION, ctx.client_ip),
                self.settings().session.refresh_per_ip,
                1,
            )
            .await?
            .into_result()?;
        let Ok(token) = OpaqueToken::parse(presented) else {
            return Err(invalid("malformed"));
        };
        let hash = token.hash();
        let now = self.now();
        let Some(session_id) = refresh::session_of(self.pool(), &hash).await? else {
            return Err(invalid("unknown"));
        };
        let mut tx = self.begin().await?;
        let Some(live) = sessions::lock_live(&mut tx, session_id, now).await? else {
            return Err(invalid("session_inactive"));
        };
        let record = live.record;
        let Some(row) = refresh::lock(&mut tx, &hash).await? else {
            return Err(invalid("unknown"));
        };
        if row.session_id != record.id || record.client_kind != ClientKind::Native {
            return Err(invalid("mismatch"));
        }
        if row.revoked_at.is_some() {
            return Err(invalid("revoked"));
        }
        if let Some(used_at) = row.used_at {
            if let Some(tokens) = self
                .grace_successor(&mut tx, &record, &row, used_at, now)
                .await?
            {
                authn_store::commit(tx).await?;
                metrics::refresh("grace");
                return Ok(tokens);
            }
            self.revoke_family_on_reuse(&mut tx, ctx, &record, &row)
                .await?;
            authn_store::commit(tx).await?;
            metrics::refresh_reuse();
            return Err(invalid("reused"));
        }
        if row.idle_expires_at <= now || row.absolute_expires_at <= now {
            return Err(invalid("expired"));
        }

        if !refresh::retire(&mut tx, row.id, now).await? {
            return Err(invalid("raced"));
        }
        let (successor, new_token, idle) = self
            .insert_successor(&mut tx, &record, row.id, row.generation, now)
            .await?;
        let sealed = if self.settings().session.refresh_reuse_grace.is_zero() {
            None
        } else {
            Some(
                self.deps()
                    .envelopes
                    .seal(new_token.expose().as_bytes(), &successor_context(&row)?)
                    .await
                    .map_err(AuthError::from)?,
            )
        };
        refresh::link_successor(&mut tx, row.id, successor, sealed.as_deref()).await?;
        sessions::set_native_activity(&mut tx, record.id, now, Some(ctx.client_ip), idle).await?;
        let (access_token, access_expires_at) = self.issue_access_token(&record, now).await?;
        authn_store::commit(tx).await?;
        metrics::refresh("rotated");
        Ok(RefreshedTokens {
            access_token,
            token_type: "Bearer",
            expires_in: remaining(now, access_expires_at).as_secs(),
            refresh_token: new_token.into_sensitive(),
            refresh_token_expires_at: idle,
        })
    }

    /// Within the grace window: the same, still unused successor.
    async fn grace_successor(
        &self,
        conn: &mut sqlx::PgConnection,
        record: &SessionRecord,
        row: &RefreshRow,
        used_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<Option<RefreshedTokens>, AuthError> {
        let grace = self.settings().session.refresh_reuse_grace;
        let (Some(sealed), Some(successor_id)) = (&row.successor_ciphertext, row.replaced_by_id)
        else {
            return Ok(None);
        };
        if grace.is_zero() || remaining(used_at, now) > grace {
            return Ok(None);
        }
        let Some(successor) = refresh::find(conn, successor_id).await? else {
            return Ok(None);
        };
        if successor.used_at.is_some()
            || successor.revoked_at.is_some()
            || successor.idle_expires_at <= now
        {
            return Ok(None);
        }
        let plain = self
            .deps()
            .envelopes
            .open(sealed, &successor_context(row)?)
            .await
            .map_err(AuthError::from)?;
        let text = std::str::from_utf8(plain.expose())
            .map_err(|_| AuthError::internal("sealed successor is not text"))?;
        let token = OpaqueToken::parse(text)
            .map_err(|_| AuthError::internal("sealed successor is malformed"))?;
        let (access_token, access_expires_at) = self.issue_access_token(record, now).await?;
        Ok(Some(RefreshedTokens {
            access_token,
            token_type: "Bearer",
            expires_in: remaining(now, access_expires_at).as_secs(),
            refresh_token: token.into_sensitive(),
            refresh_token_expires_at: successor.idle_expires_at,
        }))
    }

    /// Replay of a retired token: revoke the family, audit, alert.
    async fn revoke_family_on_reuse(
        &self,
        conn: &mut sqlx::PgConnection,
        ctx: &RequestContext,
        record: &SessionRecord,
        row: &RefreshRow,
    ) -> Result<(), AuthError> {
        self.pg_revoker()
            .revoke(
                &mut *conn,
                Target::One(record.id),
                RevocationReason::RefreshTokenReuse,
                None,
                None,
            )
            .await?;
        let event = SecurityEvent::new(SecurityEventKind::RefreshTokenReuseDetected, self.now())
            .with_context(ctx)
            .with_actor(Actor::Anonymous)
            .with_subject(record.user_id)
            .with_resource("session", record.id)
            .failed("refresh_token_reuse")
            .with_meta("generation", row.generation);
        self.deps().audit.record_in_tx(&mut *conn, event).await?;
        tracing::warn!(
            session_id = %record.id,
            user_id = %record.user_id,
            "refresh token replay detected; session revoked"
        );
        Ok(())
    }
}
