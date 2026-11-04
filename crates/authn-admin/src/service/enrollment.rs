//! Break-glass passkey enrollment through a single-use link (ADM-05, K-11).
//!
//! `create-admin --passkey-link` ([`crate::create_break_glass_admin_with_passkey_link`])
//! creates the account without a password and a link token. The page
//! behind the link (token in the URL fragment, never sent to a server log)
//! posts the token to:
//!
//! 1. [`AdminService::start_break_glass_enrollment`] — the token must
//!    belong to a live link of an active break-glass admin; a passwordless
//!    registration ceremony is started, bound to the account and to the
//!    token's SHA-256 (no session exists yet);
//! 2. [`AdminService::finish_break_glass_enrollment`] — the ceremony is
//!    consumed and the authenticator response verified by authn-webauthn;
//!    then **one** transaction consumes the link (single use), stores the
//!    passkey, and records a high-priority `admin.action`
//!    (`break_glass_passkey_enrolled`).
//!
//! Unknown, consumed and expired tokens all answer the same
//! `invalid_or_expired_token`. Both steps are rate limited per client IP
//! and subject to the `[admin] ip_allow_list` (the same network rule as
//! the console, K-13). Tokens are compared only through their SHA-256 in an
//! indexed equality lookup (no secret-dependent comparison in this code);
//! they never appear in logs, errors or `Debug` output.

use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{Actor, RateLimitKey, SecurityEvent, SecurityEventKind};
use authn_crypto::token::OpaqueToken;
use authn_store::UserRepository;
use authn_webauthn::{PasskeySummary, RegistrationStart, RegistrationVerifyRequest};

use super::AdminService;
use super::limits::keys;
use crate::store;

fn invalid_link() -> AuthError {
    AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN)
}

impl AdminService {
    /// IP allow-list and per-IP budget of the public enrollment steps.
    async fn enrollment_gate(&self, ctx: &RequestContext) -> Result<(), AuthError> {
        let allow = &self.settings().ip_allow_list;
        if !allow.is_empty() && !allow.iter().any(|net| net.contains(&ctx.client_ip)) {
            crate::metrics::denied("ip_not_allowed");
            return Err(AuthError::new(codes::common::FORBIDDEN).with_context("ip_not_allowed"));
        }
        self.deps()
            .rate_limiter
            .check(
                &RateLimitKey::ip(keys::ENROLLMENT, ctx.client_ip),
                self.settings().enrollment_per_ip,
                1,
            )
            .await?
            .into_result()?;
        Ok(())
    }

    /// The SHA-256 of a well-formed token and the break-glass account of
    /// its live link.
    async fn live_link(&self, token: &str) -> Result<([u8; 32], UserId), AuthError> {
        let token = OpaqueToken::parse(token).map_err(|_| invalid_link())?;
        let hash = *token.hash().as_bytes();
        let user = store::live_enrollment(self.pool(), &hash, self.now())
            .await?
            .ok_or_else(invalid_link)?;
        let account = UserRepository::find_by_id(self.pool(), user)
            .await?
            .ok_or_else(invalid_link)?;
        if !(account.is_break_glass
            && account.is_platform_admin
            && account.status == authn_core::domain::AccountStatus::Active)
        {
            return Err(invalid_link());
        }
        Ok((hash, user))
    }

    /// Step 1: registration options for the account of a live link.
    pub async fn start_break_glass_enrollment(
        &self,
        ctx: &RequestContext,
        token: &str,
    ) -> Result<RegistrationStart, AuthError> {
        self.enrollment_gate(ctx).await?;
        let (hash, user) = self.live_link(token).await?;
        self.deps()
            .webauthn
            .start_enrollment_registration(ctx, user, hash)
            .await
    }

    /// Step 2: verifies the authenticator response, consumes the link and
    /// stores the passkey (one transaction with the audit event).
    pub async fn finish_break_glass_enrollment(
        &self,
        ctx: &RequestContext,
        token: &str,
        request: RegistrationVerifyRequest,
    ) -> Result<PasskeySummary, AuthError> {
        self.enrollment_gate(ctx).await?;
        let (hash, user) = self.live_link(token).await?;
        // Consumes the ceremony on its own transaction, then verifies; no
        // connection is held afterwards.
        let verified = self
            .deps()
            .webauthn
            .verify_enrollment_registration(ctx, user, hash, request)
            .await?;
        let now = self.now();
        let mut tx = self.begin().await?;
        if !store::consume_enrollment(&mut tx, &hash, user, now).await? {
            return Err(invalid_link());
        }
        let summary = self
            .deps()
            .webauthn
            .store_enrollment_in_tx(&mut tx, ctx, verified)
            .await?;
        let event = SecurityEvent::new(SecurityEventKind::AdminAction, now)
            .with_context(ctx)
            .with_actor(Actor::User(user))
            .with_subject(user)
            .with_resource("passkey", summary.id)
            .with_meta("action", "break_glass_passkey_enrolled")
            .with_meta("surface", "enrollment_link")
            .with_meta("break_glass", true)
            .with_meta("priority", "high");
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        crate::metrics::action("break_glass_passkey_enrolled");
        tracing::warn!(admin = %user, "break-glass passkey enrolled through a link (high priority)");
        Ok(summary)
    }
}
