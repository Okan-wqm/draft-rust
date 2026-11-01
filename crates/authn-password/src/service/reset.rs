//! Password reset (PWD-07, PWD-08, PWD-09).
//!
//! **Request** ([`PasswordService::request_reset`]): per-IP and per-address
//! rate limits (keyed on the *submitted* address, so they behave the same
//! for known and unknown accounts), then the account-specific work is handed
//! to a tracked background job and the caller immediately gets the same
//! `202`. The response therefore cannot differ — in status, body or
//! timing — between existing and non-existing accounts. The job itself also
//! does equivalent work on both paths (token generation and hashing, the
//! same reads, an audit event).
//!
//! The job issues a 256-bit link token (`password_reset`) and, when
//! enabled, a 6-digit code (`password_reset_code`) for mobile clients in
//! one `group_id`; creating them revokes every earlier reset token and code
//! of the user. Only their hashes are stored, together with the normalized
//! address they were sent to (`target`). The notifier receives the raw
//! token; links are built by authn-notify from `server.public_base_url`
//! only — the `Host` header is never involved (PWD-08).
//!
//! Eligibility is re-checked with the user row locked when the secrets are
//! issued *and* when they are redeemed: the account must be eligible, still
//! own the address the secrets were sent to, and still have a password (a
//! reset replaces a password; adding one needs step-up, PWD-10).
//!
//! **Completion** ([`PasswordService::complete_reset`]): the link token or
//! the e-mail + code proof is consumed atomically (`UPDATE … RETURNING`;
//! exactly one of concurrent attempts wins), the new password must satisfy
//! the policy, and in the same transaction the password is replaced (and
//! `must_change_password` cleared), every other reset token is revoked,
//! **all** sessions and refresh-token families are revoked together with
//! trusted devices (`RevokeOptions { also_trusted_devices: true }`), the
//! user is notified and the event audited. No session is issued: the next
//! login runs the full flow including MFA (PWD-09).

use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OneTimeTokenId, UserId};
use authn_core::ports::{
    Actor, Notification, NotificationKind, PasswordContext, RateLimitKey, RevocationReason,
    RevokeOptions, SecurityEventKind,
};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::otp::OtpCode;
use authn_crypto::password::PasswordHashRecord;
use authn_crypto::token::{OpaqueToken, TokenHash};
use authn_store::{
    CodeVerification, NewOneTimeToken, NewPasswordHash, OneTimeTokenRepository, TokenPurpose,
    TokenSubject, UserRecord, UserRepository, begin, commit,
};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{PasswordService, actions, after};
use crate::metrics;

/// Proof presented to complete a reset.
#[derive(Debug, Clone)]
pub enum ResetProof {
    /// The token of the e-mailed link (PWD-07).
    Link {
        /// Raw link token.
        token: SecretString,
    },
    /// The e-mailed 6-digit code together with the address (PWD-08, mobile).
    Code {
        /// The address the code was sent to.
        email: EmailAddress,
        /// The code as typed.
        code: SecretString,
    },
}

/// Accounts that may reset their password: normal, temporarily locked
/// (PRT-03: a soft lock must not block recovery) and not yet verified.
/// Suspended, disabled and deleted accounts — and accounts without a
/// password (PWD-10 requires step-up to add one) — never receive a reset.
const fn reset_allowed(status: AccountStatus) -> bool {
    matches!(
        status,
        AccountStatus::Active | AccountStatus::Locked | AccountStatus::PendingVerification
    )
}

/// Whether `user` currently owns the address a reset token was bound to.
/// Tokens without a bound address never match.
fn owns_address(user: &UserRecord, target: Option<&str>) -> bool {
    matches!(
        (user.email_normalized.as_deref(), target),
        (Some(current), Some(target)) if current == target
    )
}

fn invalid_token() -> AuthError {
    AuthError::new(codes::common::INVALID_OR_EXPIRED_TOKEN)
}

fn invalid_code() -> AuthError {
    AuthError::new(codes::common::INVALID_CODE)
}

/// Link token and code generated for every request (both paths).
struct IssuedSecrets {
    token: OpaqueToken,
    token_hash: TokenHash,
    code: Option<(OtpCode, TokenHash)>,
}

impl PasswordService {
    /// Accepts a reset request (PWD-07). Fails only with `rate_limited`
    /// (keyed on IP and on the submitted address); otherwise the work is
    /// dispatched to a background job and `Ok` is returned at once, whether
    /// or not the account exists.
    pub async fn request_reset(
        &self,
        ctx: &RequestContext,
        email: &EmailAddress,
    ) -> Result<(), AuthError> {
        let reset = &self.config().reset;
        self.limit(
            &RateLimitKey::ip(actions::RESET_REQUEST, ctx.client_ip),
            reset.per_ip,
        )
        .await?;
        self.limit(
            &RateLimitKey::account(actions::RESET_REQUEST, email.normalized()),
            reset.per_email,
        )
        .await?;
        metrics::reset_requested();

        if self.inner.jobs.len() >= super::MAX_PENDING_RESET_JOBS {
            // Same answer as always; the e-mail is not sent. Logged without
            // the address.
            tracing::warn!("password reset backlog full; request dropped");
            metrics::reset_dropped();
            return Ok(());
        }
        let service = self.clone();
        let ctx = ctx.clone();
        let email = email.clone();
        let permits = self.inner.job_permits.clone();
        self.inner.jobs.spawn(async move {
            let Ok(_permit) = permits.acquire_owned().await else {
                return;
            };
            if let Err(err) = service.process_reset_request(&ctx, &email).await {
                tracing::error!(
                    error = %err,
                    request_id = %ctx.request_id,
                    "password reset request could not be processed"
                );
            }
        });
        Ok(())
    }

    /// The background part of [`Self::request_reset`].
    async fn process_reset_request(
        &self,
        ctx: &RequestContext,
        email: &EmailAddress,
    ) -> Result<(), AuthError> {
        let now = self.now();
        // Equivalent work on every path: generate and hash the secrets first.
        let secrets = self.generate_secrets()?;
        let user = UserRepository::find_by_email(self.pool(), email).await?;
        // Same query on every path (the nil id never exists).
        let lookup = user
            .as_ref()
            .filter(|u| reset_allowed(u.status))
            .map_or_else(|| UserId::from_uuid(Uuid::nil()), |u| u.id);
        let has_password = UserRepository::find_password(self.pool(), lookup)
            .await?
            .is_some();

        match user {
            Some(user) if reset_allowed(user.status) && has_password => {
                self.issue_reset(ctx, &user, email, secrets, now).await
            }
            Some(user) => {
                let event = self
                    .event(SecurityEventKind::PasswordResetRequested, ctx)
                    .with_subject(user.id)
                    .failed("account_not_eligible");
                self.deps().audit.record(event).await
            }
            None => {
                let event = self
                    .event(SecurityEventKind::PasswordResetRequested, ctx)
                    .failed("unknown_account");
                self.deps().audit.record(event).await
            }
        }
    }

    fn generate_secrets(&self) -> Result<IssuedSecrets, AuthError> {
        let token = OpaqueToken::generate()?;
        let token_hash = token.hash();
        let code = if self.config().reset.code_enabled {
            let code = OtpCode::generate()?;
            let hash = self
                .deps()
                .otp
                .hash(TokenPurpose::PasswordResetCode.as_str(), &code);
            Some((code, hash))
        } else {
            None
        };
        Ok(IssuedSecrets {
            token,
            token_hash,
            code,
        })
    }

    /// Stores the new link (+ code), revoking earlier ones, and enqueues the
    /// e-mail — one transaction.
    ///
    /// The lookup that chose this account ran without a lock, so eligibility
    /// is re-checked with the user row locked: the account must still be
    /// eligible, still own the requested address (an e-mail change may have
    /// committed meanwhile — the token must never go to an address the
    /// account no longer has) and still have a password (a reset replaces a
    /// password, it never adds one: PWD-10 requires step-up). Both secrets
    /// are bound to the address (`target`), which completion re-checks.
    async fn issue_reset(
        &self,
        ctx: &RequestContext,
        user: &UserRecord,
        requested: &EmailAddress,
        secrets: IssuedSecrets,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let reset = &self.config().reset;
        let hints = self.profile(user.id).await;
        let link_expires = after(now, reset.token_ttl)?;
        let code_expires = after(now, reset.code_ttl)?;
        let group = Uuid::now_v7();
        let subject = TokenSubject::user(user.id);
        let target = requested.normalized();

        let mut tx = begin(self.pool()).await?;
        // Serializes with completions and concurrent requests of this user
        // (lock order everywhere: user row, then tokens).
        let Some(locked) = UserRepository::lock_for_update(&mut tx, user.id).await? else {
            return Ok(());
        };
        if !Self::still_resettable(&mut tx, &locked, Some(target)).await? {
            tracing::debug!(
                user_id = %locked.id,
                "reset request skipped: account changed since the lookup"
            );
            return Ok(());
        }
        let Some(recipient) = Self::recipient(&locked, &hints) else {
            return Ok(());
        };
        OneTimeTokenRepository::create(
            &mut tx,
            &NewOneTimeToken {
                id: OneTimeTokenId::generate(),
                purpose: TokenPurpose::PasswordReset,
                token_hash: secrets.token_hash,
                subject,
                group_id: Some(group),
                target: Some(target),
                max_attempts: 1,
                metadata: serde_json::json!({}),
                created_ip: Some(ctx.client_ip),
                created_at: now,
                expires_at: link_expires,
            },
            true,
        )
        .await?;
        let (code, expires_at) = match secrets.code {
            Some((code, code_hash)) => {
                OneTimeTokenRepository::create(
                    &mut tx,
                    &NewOneTimeToken {
                        id: OneTimeTokenId::generate(),
                        purpose: TokenPurpose::PasswordResetCode,
                        token_hash: code_hash,
                        subject,
                        group_id: Some(group),
                        target: Some(target),
                        max_attempts: reset.code_max_attempts,
                        metadata: serde_json::json!({}),
                        created_ip: Some(ctx.client_ip),
                        created_at: now,
                        expires_at: code_expires,
                    },
                    true,
                )
                .await?;
                (Some(code.into_sensitive()), link_expires.min(code_expires))
            }
            None => {
                OneTimeTokenRepository::revoke_active(
                    &mut tx,
                    subject,
                    TokenPurpose::PasswordResetCode,
                    now,
                )
                .await?;
                (None, link_expires)
            }
        };
        let notification = Notification {
            recipient,
            locale: hints.locale.unwrap_or(ctx.locale),
            kind: NotificationKind::PasswordReset {
                token: secrets.token.into_sensitive(),
                code,
                expires_at,
            },
        };
        self.deps()
            .notifier
            .notify_in_tx(&mut tx, notification)
            .await?;
        let event = self
            .event(SecurityEventKind::PasswordResetRequested, ctx)
            .with_subject(user.id)
            .with_meta("code_issued", self.config().reset.code_enabled);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        commit(tx).await
    }

    /// Completes a reset (PWD-08, PWD-09). Errors: `invalid_or_expired_token`
    /// (link), `invalid_code` (code — also for unknown addresses, wrong,
    /// expired and locked-out codes), `password_policy_violation`,
    /// `rate_limited`.
    pub async fn complete_reset(
        &self,
        ctx: &RequestContext,
        proof: ResetProof,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        self.limit(
            &RateLimitKey::ip(actions::RESET_VERIFY, ctx.client_ip),
            self.config().reset.verify_per_ip,
        )
        .await?;
        match proof {
            ResetProof::Link { token } => self.complete_with_link(ctx, &token, new_password).await,
            ResetProof::Code { email, code } => {
                self.complete_with_code(ctx, &email, &code, new_password)
                    .await
            }
        }
    }

    async fn complete_with_link(
        &self,
        ctx: &RequestContext,
        token: &SecretString,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        let token = OpaqueToken::parse(token.expose_secret()).map_err(|_| invalid_token())?;
        let hash = token.hash();
        let now = self.now();
        // Look (without consuming) so that a policy violation does not burn
        // the link; consumption below is atomic.
        let record = OneTimeTokenRepository::find_active_link(
            self.pool(),
            TokenPurpose::PasswordReset,
            &hash,
            now,
        )
        .await?
        .ok_or_else(invalid_token)?;
        let user_id = record.user_id.ok_or_else(invalid_token)?;
        let user = UserRepository::find_by_id(self.pool(), user_id)
            .await?
            .filter(|u| reset_allowed(u.status) && owns_address(u, record.target.as_deref()))
            .ok_or_else(invalid_token)?;
        let hints = self.profile(user_id).await;
        let context = Self::password_context(&user, &hints, ctx.locale);
        self.inner.policy.enforce(new_password, &context).await?;
        let new_hash = self.deps().hasher.hash(new_password).await?;

        let mut tx = begin(self.pool()).await?;
        let user = UserRepository::lock_for_update(&mut tx, user_id)
            .await?
            .ok_or_else(invalid_token)?;
        let consumed =
            OneTimeTokenRepository::consume_link(&mut tx, TokenPurpose::PasswordReset, &hash, now)
                .await?
                .filter(|r| r.user_id == Some(user_id))
                .ok_or_else(invalid_token)?;
        // Re-checked under the lock; an error rolls the consumption back.
        if !Self::still_resettable(&mut tx, &user, consumed.target.as_deref()).await? {
            return Err(invalid_token());
        }
        self.finish_reset(&mut tx, ctx, &user, &hints, &new_hash, now, "link")
            .await?;
        commit(tx).await?;
        tracing::debug!(token_id = %consumed.id, "password reset completed with link");
        metrics::reset_completed("link");
        Ok(())
    }

    async fn complete_with_code(
        &self,
        ctx: &RequestContext,
        email: &EmailAddress,
        code: &SecretString,
        new_password: &SecretString,
    ) -> Result<(), AuthError> {
        let started = tokio::time::Instant::now();
        let reset = &self.config().reset;
        self.limit(
            &RateLimitKey::account(actions::RESET_CODE, email.normalized()),
            reset.code_attempts_per_email,
        )
        .await?;
        if !reset.code_enabled {
            return Err(invalid_code());
        }
        // Policy before the code is touched (a verified code is consumed).
        // Only caller-supplied inputs are used here so that the answer can
        // never depend on account data (no enumeration oracle).
        let context = PasswordContext {
            email: Some(email.clone()),
            display_name: None,
            locale: ctx.locale,
        };
        self.inner.policy.enforce(new_password, &context).await?;
        let code = OtpCode::parse(code.expose_secret()).map_err(|_| invalid_code())?;
        let candidate = self
            .deps()
            .otp
            .hash(TokenPurpose::PasswordResetCode.as_str(), &code);

        let now = self.now();
        let user = UserRepository::find_by_email(self.pool(), email)
            .await?
            .filter(|u| reset_allowed(u.status));
        // Unknown accounts verify against a fresh id that has no codes: the
        // same transaction shape as a known account without an active code.
        let subject = TokenSubject::user(user.as_ref().map_or_else(UserId::generate, |u| u.id));
        let verification = OneTimeTokenRepository::verify_code(
            self.pool(),
            TokenPurpose::PasswordResetCode,
            subject,
            &candidate,
            now,
        )
        .await?;
        let (user, record) = match (user, verification) {
            (Some(user), CodeVerification::Verified(record)) => (user, record),
            (user, outcome) => {
                // Equivalent work on both paths (contracts §11): known and
                // unknown addresses both write one audit event.
                let reason = match (&user, outcome) {
                    (None, _) => "unknown_account",
                    (Some(_), CodeVerification::LockedOut) => "code_locked_out",
                    (Some(_), CodeVerification::NotFound) => "no_active_code",
                    (Some(_), _) => "wrong_code",
                };
                let mut event = self
                    .event(SecurityEventKind::PasswordResetCompleted, ctx)
                    .with_meta("method", "code")
                    .failed(reason);
                if let Some(user) = &user {
                    event = event.with_subject(user.id);
                }
                if let Err(err) = self.deps().audit.record(event).await {
                    tracing::warn!(error = %err, "audit of failed reset code failed");
                }
                let floor = self.inner.settings.code_failure_floor;
                tokio::time::sleep(floor.saturating_sub(started.elapsed())).await;
                return Err(invalid_code());
            }
        };

        // The code is consumed (its own committed transaction, so failed
        // guesses always count). Apply the new password.
        let new_hash = self.deps().hasher.hash(new_password).await?;
        let hints = self.profile(user.id).await;
        let mut tx = begin(self.pool()).await?;
        let user = UserRepository::lock_for_update(&mut tx, user.id)
            .await?
            .ok_or_else(invalid_code)?;
        // The code must have been sent to the submitted address, which the
        // account must still own, and there must be a password to replace.
        if record.target.as_deref() != Some(email.normalized())
            || !Self::still_resettable(&mut tx, &user, record.target.as_deref()).await?
        {
            return Err(invalid_code());
        }
        self.finish_reset(&mut tx, ctx, &user, &hints, &new_hash, now, "code")
            .await?;
        commit(tx).await?;
        tracing::debug!(token_id = %record.id, "password reset completed with code");
        metrics::reset_completed("code");
        Ok(())
    }

    /// Whether the *locked* `user` may still be reset by a token bound to
    /// `target`: an eligible status, still the owner of the address the
    /// token was sent to (an e-mail change since then invalidates it) and
    /// still a password to replace (a reset never *adds* a password —
    /// PWD-10 requires step-up for that).
    async fn still_resettable(
        conn: &mut PgConnection,
        user: &UserRecord,
        target: Option<&str>,
    ) -> Result<bool, AuthError> {
        if !reset_allowed(user.status) || !owns_address(user, target) {
            return Ok(false);
        }
        Ok(UserRepository::find_password(&mut *conn, user.id)
            .await?
            .is_some())
    }

    /// The common tail of both completion paths (PWD-09), in the caller's
    /// transaction.
    #[allow(clippy::too_many_arguments)]
    async fn finish_reset(
        &self,
        conn: &mut PgConnection,
        ctx: &RequestContext,
        user: &UserRecord,
        hints: &crate::hooks::ProfileHints,
        new_hash: &PasswordHashRecord,
        now: OffsetDateTime,
        method: &'static str,
    ) -> Result<(), AuthError> {
        UserRepository::set_password(
            conn,
            user.id,
            &NewPasswordHash {
                password_hash: &new_hash.hash,
                algorithm: new_hash.algorithm.as_str(),
                pepper_version: new_hash.pepper_version,
            },
            false,
            now,
        )
        .await?;
        OneTimeTokenRepository::revoke_for_user(
            conn,
            user.id,
            &[TokenPurpose::PasswordReset, TokenPurpose::PasswordResetCode],
            now,
        )
        .await?;
        let revoked = self
            .deps()
            .sessions
            .revoke_all_for_user(
                conn,
                user.id,
                RevocationReason::PasswordReset,
                RevokeOptions {
                    also_trusted_devices: true,
                },
            )
            .await?;
        self.notify_password_changed(conn, ctx, user, hints, now)
            .await?;
        let event = self
            .event(SecurityEventKind::PasswordResetCompleted, ctx)
            .with_actor(Actor::User(user.id))
            .with_subject(user.id)
            .with_meta("method", method)
            .with_meta("sessions_revoked", revoked);
        self.deps().audit.record_in_tx(conn, event).await
    }
}
