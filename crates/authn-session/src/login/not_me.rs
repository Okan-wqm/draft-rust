//! "This wasn't me" (RSK-04).
//!
//! The new-device notification ([`authn_protect::RiskAlerts`]) carries a
//! single-use link (`one_time_tokens` purpose `not_me`, 7 days) issued by
//! [`SessionService`] as the [`NotMeTokenIssuer`]. Consuming it
//! (`POST /v1/login/not-me`, the token in the body — never in a URL path
//! that access logs would keep):
//!
//! * revokes every session of the user (and the impersonations they
//!   started), every trusted device and every pending login;
//! * ends pending e-mail changes (authn-account);
//! * forces a password change at the next password login
//!   (`must_change_password`) and mails a password-reset link.

use async_trait::async_trait;
use authn_core::domain::EmailAddress;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OneTimeTokenId, UserId};
use authn_core::ports::{
    Actor, RevocationReason, RevokeOptions, SecurityEvent, SecurityEventKind, SessionRevoker,
};
use authn_core::secret::{SecretString, SensitiveString};
use authn_crypto::token::OpaqueToken;
use authn_protect::NotMeTokenIssuer;
use authn_store::{
    NewOneTimeToken, OneTimeTokenRepository, TokenPurpose, TokenSubject, UserRepository,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::service::{SessionService, after};

/// Lifetime of a "this wasn't me" link.
pub const NOT_ME_TTL: std::time::Duration = std::time::Duration::from_secs(7 * 86_400);

/// Body of `POST /v1/login/not-me`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NotMeRequest {
    /// The token from the notification link.
    #[schema(value_type = String)]
    pub token: SecretString,
}

impl std::fmt::Debug for NotMeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotMeRequest").finish_non_exhaustive()
    }
}

#[async_trait]
impl NotMeTokenIssuer for SessionService {
    async fn issue_not_me_token(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<SensitiveString, AuthError> {
        let token = OpaqueToken::generate().map_err(AuthError::from)?;
        OneTimeTokenRepository::create(
            conn,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose: TokenPurpose::NotMe,
                token_hash: token.hash(),
                subject: TokenSubject::user(user),
                group_id: None,
                target: None,
                max_attempts: 1,
                metadata: serde_json::json!({}),
                created_ip: None,
                created_at: now,
                expires_at: after(now, NOT_ME_TTL),
            },
            false,
        )
        .await?;
        Ok(token.into_sensitive())
    }
}

impl SessionService {
    /// RSK-04: the user disowns a login. Returns the number of revoked
    /// sessions.
    pub async fn report_not_me(
        &self,
        ctx: &RequestContext,
        request: NotMeRequest,
    ) -> Result<u64, AuthError> {
        let invalid = || AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN);
        let token = OpaqueToken::parse(request.token.expose_secret()).map_err(|_| invalid())?;
        let now = self.now();
        // Validate before any side effect.
        let record = OneTimeTokenRepository::find_active_link(
            self.pool(),
            TokenPurpose::NotMe,
            &token.hash(),
            now,
        )
        .await?
        .ok_or_else(invalid)?;
        let user = record.user_id.ok_or_else(invalid)?;
        let has_password = UserRepository::find_password(self.pool(), user)
            .await?
            .is_some();
        if has_password {
            self.deps()
                .passwords
                .set_must_change_password(ctx, Actor::User(user), user, true)
                .await?;
        }
        let mut tx = self.begin().await?;
        OneTimeTokenRepository::consume_link(&mut tx, TokenPurpose::NotMe, &token.hash(), now)
            .await?
            .ok_or_else(invalid)?;
        let revoked = self
            .pg_revoker()
            .revoke_all_for_user(
                &mut tx,
                user,
                RevocationReason::NotMe,
                RevokeOptions {
                    also_trusted_devices: true,
                },
            )
            .await?;
        self.deps()
            .accounts
            .on_sessions_revoked_in_tx(&mut tx, user, RevocationReason::NotMe)
            .await?;
        let event = SecurityEvent::new(SecurityEventKind::SessionsRevoked, now)
            .with_context(ctx)
            .with_actor(Actor::User(user))
            .with_subject(user)
            .with_meta("reason", RevocationReason::NotMe.as_str())
            .with_meta("sessions_revoked", revoked)
            .with_meta("password_change_forced", has_password);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        let email = UserRepository::find_by_id(&mut *tx, user)
            .await?
            .and_then(|u| u.email)
            .and_then(|e| EmailAddress::parse(&e).ok());
        authn_store::commit(tx).await?;
        if has_password
            && let Some(email) = email
            && let Err(err) = self.deps().passwords.request_reset(ctx, &email).await
        {
            tracing::warn!(error = %err, "password reset after not-me failed");
        }
        Ok(revoked)
    }
}
