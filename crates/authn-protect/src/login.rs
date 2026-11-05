//! Login throttling, CAPTCHA escalation and the soft lock (PRT-02, PRT-03,
//! PRT-04, PRT-05) — the protection steps of the SES-01 login flow.
//!
//! Every counter and the lock itself are keyed on the **submitted
//! identifier** (normalized e-mail), not on the account: an identifier that
//! matches no account is throttled, escalated to CAPTCHA and soft-locked
//! exactly like an existing one, so none of these responses (body, status,
//! timing) reveal whether an account exists.
//!
//! The soft lock does not lock the *account*: it only refuses **password**
//! attempts from devices that are neither a trusted device (MFA-09 token,
//! verified by authn-session) nor a known device of the user. Passkey
//! logins, trusted/known devices and password reset keep working, so an
//! attacker cannot lock a victim out (no DoS by lockout).
//!
//! The per-identifier budgets (CAPTCHA escalation, soft lock) are
//! **consumed atomically by [`LoginProtection::check_attempt`]**, before the
//! credential is verified, and refunded by
//! [`LoginProtection::record_success`]. Counting only *after* a failed
//! verification would leave a check-then-act window: every attempt already
//! in flight (e.g. queued on the Argon2 semaphore, or sent in parallel from
//! many IPs) would pass the check before the first failure is counted, so
//! a burst of N concurrent guesses would get N password verifications
//! without CAPTCHA or soft lock. An attempt is therefore treated as a failure
//! until it is proven successful.
//!
//! Flow for authn-session:
//!
//! ```ignore
//! protection.check_attempt(&attempt, &ctx).await?;      // 429 / captcha_* / login_temporarily_blocked
//! match verify_password(...) {
//!     Ok(user) => protection.record_success(&attempt, &ctx).await?,
//!     Err(_) => { protection.record_failure(&attempt, &ctx).await?; return Err(invalid_credentials) }
//! }
//! ```

use std::sync::Arc;
use std::time::Duration;

use authn_core::config::common::CaptchaPolicy;
use authn_core::config::protect::{ProtectConfig, RateLimitConfig};
use authn_core::domain::LoginMethod;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, AuditSink, Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimitStep,
    RateLimiter, SecurityEvent, SecurityEventKind,
};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::captcha::CaptchaService;
use crate::risk::{FAILURE_ACTION, RiskStore};

/// Rate-limit action: login attempts per IP (PRT-02).
pub const LOGIN_ACTION: &str = "login";
/// Rate-limit action: password attempts per identifier not (yet) proven
/// successful, counted for CAPTCHA escalation (consumed by
/// [`LoginProtection::check_attempt`], reset on success).
pub const CAPTCHA_FAILURES_ACTION: &str = "login_failures_captcha";
/// Rate-limit action: password attempts per identifier not (yet) proven
/// successful, counted for the soft lock (consumed by
/// [`LoginProtection::check_attempt`], reset on success).
pub const LOCK_FAILURES_ACTION: &str = "login_failures_lock";
/// Rate-limit action: the soft-lock marker itself.
pub const SOFT_LOCK_ACTION: &str = "login_soft_lock";
/// CAPTCHA action name used for logins.
pub const CAPTCHA_LOGIN_ACTION: &str = "login";

const AUDIT_THROTTLE: Duration = Duration::from_secs(15 * 60);

const UPSERT_LOCK_SQL: &str = "\
INSERT INTO login_soft_locks (user_id, locked_until, failure_count, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET
    locked_until = GREATEST(login_soft_locks.locked_until, EXCLUDED.locked_until),
    failure_count = EXCLUDED.failure_count";
const DELETE_LOCK_SQL: &str = "DELETE FROM login_soft_locks WHERE user_id = $1";
const SELECT_LOCK_SQL: &str =
    "SELECT locked_until FROM login_soft_locks WHERE user_id = $1 AND locked_until > $2";
const PURGE_LOCKS_SQL: &str = "DELETE FROM login_soft_locks WHERE locked_until <= $1";

/// One login attempt as seen by the protection layer. `Debug` masks the
/// identifier (personal data) and redacts the CAPTCHA response.
#[derive(Clone, Copy)]
pub struct LoginAttempt<'a> {
    /// The submitted identifier, normalized (`EmailAddress::normalized`).
    /// Keys every counter — also for identifiers matching no account.
    pub identifier: &'a str,
    /// The account the identifier matched, if any. Used only for the
    /// known-device check and bookkeeping, never to change the response.
    pub user_id: Option<UserId>,
    /// How the user is signing in.
    pub method: LoginMethod,
    /// The request carries a valid trusted-device token (MFA-09) for this
    /// user — verified by authn-session.
    pub trusted_device: bool,
    /// CAPTCHA response sent by the client, if any.
    pub captcha_response: Option<&'a str>,
}

impl std::fmt::Debug for LoginAttempt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginAttempt")
            .field(
                "identifier",
                &authn_core::redact::mask_email(self.identifier),
            )
            .field("user_id", &self.user_id)
            .field("method", &self.method)
            .field("trusted_device", &self.trusted_device)
            .field(
                "captcha_response",
                &self.captcha_response.map(|_| authn_core::secret::REDACTED),
            )
            .finish()
    }
}

/// Login protection service. Cheap to clone.
#[derive(Clone)]
pub struct LoginProtection {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    limiter: Arc<dyn RateLimiter>,
    audit: Arc<dyn AuditSink>,
    captcha: CaptchaService,
    devices: RiskStore,
    limits: RateLimitConfig,
    captcha_policy: CaptchaPolicy,
    failure_policy: RateLimitPolicy,
}

impl std::fmt::Debug for LoginProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginProtection")
            .field("captcha_policy", &self.captcha_policy)
            .finish_non_exhaustive()
    }
}

fn lock_policy(duration: Duration) -> RateLimitPolicy {
    RateLimitPolicy::new(1, duration)
}

impl LoginProtection {
    /// Creates the service from `[protect]`.
    #[must_use]
    pub fn new(
        pool: PgPool,
        clock: Arc<dyn Clock>,
        limiter: Arc<dyn RateLimiter>,
        audit: Arc<dyn AuditSink>,
        captcha: CaptchaService,
        devices: RiskStore,
        config: &ProtectConfig,
    ) -> Self {
        Self {
            pool,
            clock,
            limiter,
            audit,
            captcha,
            devices,
            limits: config.rate_limit.clone(),
            captcha_policy: config.captcha.login_policy,
            failure_policy: RateLimitPolicy::new(
                config.risk.failure_threshold,
                config.risk.failure_window,
            ),
        }
    }

    fn lock_key(identifier: &str) -> RateLimitKey {
        RateLimitKey::account(SOFT_LOCK_ACTION, identifier)
    }

    /// The remaining soft-lock time for an identifier, if locked.
    pub async fn soft_lock_remaining(
        &self,
        identifier: &str,
    ) -> Result<Option<Duration>, AuthError> {
        let decision = self
            .limiter
            .peek(
                &Self::lock_key(identifier),
                lock_policy(self.limits.soft_lock_duration),
            )
            .await?;
        Ok((!decision.allowed).then(|| decision.retry_after.unwrap_or(Duration::from_secs(1))))
    }

    /// Whether the device may bypass a soft lock: trusted-device token, or a
    /// device id already known for the user. The known-device query runs
    /// for unknown accounts too (placeholder id), keeping the timing equal.
    async fn device_is_trusted(
        &self,
        attempt: &LoginAttempt<'_>,
        ctx: &RequestContext,
    ) -> Result<bool, AuthError> {
        let user = attempt.user_id.unwrap_or_else(UserId::generate);
        let device = ctx.device_id.as_deref().unwrap_or("");
        let known = self.devices.is_known_device(user, device).await?;
        Ok(attempt.user_id.is_some() && (attempt.trusted_device || (known && !device.is_empty())))
    }

    /// Runs **before** the credential is verified. For password attempts it
    /// atomically reserves one unit of the identifier's CAPTCHA budget and —
    /// once the CAPTCHA gate is passed — one unit of its soft-lock budget;
    /// [`LoginProtection::record_success`] gives them back. Concurrent
    /// attempts therefore cannot outrun the counters. Errors:
    /// * `rate_limited` (429 + `Retry-After`) — too many attempts from the
    ///   IP (all methods);
    /// * `login_temporarily_blocked` (429 + `Retry-After`) — password
    ///   attempt on a soft-locked identifier from an untrusted device (the
    ///   attempt that exhausts the soft-lock budget engages the lock);
    /// * `captcha_required` / `captcha_failed` — password attempt on an
    ///   identifier whose CAPTCHA budget is exhausted (or policy `always`).
    pub async fn check_attempt(
        &self,
        attempt: &LoginAttempt<'_>,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let password = attempt.method == LoginMethod::Password;
        // Known-device query first (same work for unknown accounts): the
        // soft-lock step of the chain below depends on it.
        let trusted = if password {
            self.device_is_trusted(attempt, ctx).await?
        } else {
            false
        };
        let ip_key = RateLimitKey::ip(LOGIN_ACTION, ctx.client_ip);
        let lock_key = Self::lock_key(attempt.identifier);
        let captcha_key = RateLimitKey::account(CAPTCHA_FAILURES_ACTION, attempt.identifier);
        let lock_failures_key = RateLimitKey::account(LOCK_FAILURES_ACTION, attempt.identifier);
        // K-128: the limiter steps of one attempt in one chain (one
        // statement on PostgreSQL), in the order of the single calls they
        // replace; a denial that ends the attempt stops the chain, so a
        // later budget is never consumed for it:
        // 1. per-IP limit (all methods);
        // 2. soft lock (peek; ends the attempt unless the device is
        //    trusted);
        // 3. CAPTCHA budget (reserve one unit);
        // 4. soft-lock budget — only when an admitted CAPTCHA budget
        //    certainly passes the CAPTCHA gate (policy does not demand a
        //    CAPTCHA anyway); otherwise it is reserved after the gate, so
        //    wrong or missing CAPTCHA answers never count.
        let mut steps = vec![RateLimitStep::check(&ip_key, self.limits.login_per_ip)];
        let lock_in_chain = !self.captcha.is_required(self.captcha_policy, false);
        if password {
            steps.push(
                RateLimitStep::peek(&lock_key, lock_policy(self.limits.soft_lock_duration))
                    .stop_if_denied(!trusted),
            );
            steps.push(RateLimitStep::check(
                &captcha_key,
                self.limits.login_per_account_captcha,
            ));
            if lock_in_chain {
                steps.push(RateLimitStep::check(
                    &lock_failures_key,
                    self.limits.login_per_account_soft_lock,
                ));
            }
        }
        let decisions = self.limiter.check_chain(&steps).await?;
        let decision = decisions
            .first()
            .copied()
            .ok_or_else(|| AuthError::internal("rate-limit chain without a decision"))?;
        if !decision.allowed {
            metrics::counter!("authn_rate_limit_triggered_total", "action" => LOGIN_ACTION)
                .increment(1);
            let event = SecurityEvent::new(SecurityEventKind::RateLimitTriggered, self.clock.now())
                .with_context(ctx)
                .failed("login_per_ip")
                .with_meta("action", LOGIN_ACTION);
            crate::audit::record_throttled(
                &self.limiter,
                &self.audit,
                &RateLimitKey::ip("audit_login_rate_limited", ctx.client_ip),
                AUDIT_THROTTLE,
                event,
            )
            .await;
            decision.into_result()?;
        }
        if !password {
            // Passkeys, magic links and codes are never soft-locked or
            // CAPTCHA-escalated here (PRT-03).
            return Ok(());
        }

        let soft_lock = Self::step(&decisions, 1)?;
        if !soft_lock.allowed && !trusted {
            return Err(Self::blocked(
                soft_lock.retry_after.unwrap_or(Duration::from_secs(1)),
            ));
        }

        // The CAPTCHA budget was reserved by the chain (atomic check-and-
        // consume). Once it is exhausted the attempt needs a CAPTCHA; a
        // denied check consumes nothing.
        let captcha_budget = Self::step(&decisions, 2)?;
        let risky = !captcha_budget.allowed && !trusted;
        self.captcha
            .enforce(
                CAPTCHA_LOGIN_ACTION,
                self.captcha_policy,
                risky,
                attempt.captcha_response,
                ctx,
            )
            .await?;

        // Only attempts that cleared the CAPTCHA gate reserve a unit of the
        // soft-lock budget, so engaging the lock costs the attacker the
        // CAPTCHAs on the way.
        let lock_budget = match decisions.get(3) {
            Some(decision) => *decision,
            None => {
                self.limiter
                    .check(
                        &lock_failures_key,
                        self.limits.login_per_account_soft_lock,
                        1,
                    )
                    .await?
            }
        };
        if !lock_budget.allowed {
            let remaining = self.engage_soft_lock(attempt, ctx).await?;
            if !trusted {
                return Err(Self::blocked(remaining));
            }
        }
        Ok(())
    }

    fn step(decisions: &[RateLimitDecision], index: usize) -> Result<RateLimitDecision, AuthError> {
        decisions
            .get(index)
            .copied()
            .ok_or_else(|| AuthError::internal("rate-limit chain ended early"))
    }

    fn blocked(remaining: Duration) -> AuthError {
        AuthError::new(codes::protect::LOGIN_TEMPORARILY_BLOCKED).with_retry_after(remaining)
    }

    /// Runs after a **failed** credential verification: counts the failure
    /// for the risk velocity signal (per user and per IP, RSK-02). The
    /// per-identifier CAPTCHA and soft-lock budgets were already consumed by
    /// [`LoginProtection::check_attempt`] and are not counted again.
    ///
    /// The same limiter work is done whether or not the identifier matched
    /// an account (a throw-away key stands in for the missing user), so the
    /// failure path takes the same time for existing and unknown accounts.
    pub async fn record_failure(
        &self,
        attempt: &LoginAttempt<'_>,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        let user = attempt.user_id.unwrap_or_else(UserId::generate);
        let user_key = RateLimitKey::user(FAILURE_ACTION, user);
        let ip_key = RateLimitKey::ip(FAILURE_ACTION, ctx.client_ip);
        // Both counters always count (no step ends the chain): one
        // statement on PostgreSQL (K-128).
        self.limiter
            .check_chain(&[
                RateLimitStep::check(&user_key, self.failure_policy).stop_if_denied(false),
                RateLimitStep::check(&ip_key, self.failure_policy).stop_if_denied(false),
            ])
            .await?;
        Ok(())
    }

    /// Engages the soft lock of the attempt's identifier (idempotent) and
    /// returns the remaining lock time.
    async fn engage_soft_lock(
        &self,
        attempt: &LoginAttempt<'_>,
        ctx: &RequestContext,
    ) -> Result<Duration, AuthError> {
        let duration = self.limits.soft_lock_duration;
        let newly_engaged = self
            .limiter
            .check(
                &Self::lock_key(attempt.identifier),
                lock_policy(duration),
                1,
            )
            .await?
            .allowed;
        if !newly_engaged {
            // Engaged by an earlier (or concurrent) attempt.
            return Ok(self
                .soft_lock_remaining(attempt.identifier)
                .await?
                .unwrap_or(duration));
        }
        metrics::counter!("authn_soft_lock_engaged_total").increment(1);
        let now = self.clock.now();
        let mut event = SecurityEvent::new(SecurityEventKind::SoftLockEngaged, now)
            .with_context(ctx)
            .with_actor(Actor::Anonymous)
            .with_meta("duration_secs", duration.as_secs());
        if let Some(user) = attempt.user_id {
            event = event.with_subject(user);
            let mut tx = self.pool.begin().await?;
            sqlx::query(UPSERT_LOCK_SQL)
                .bind(user)
                .bind(now + duration)
                .bind(
                    i32::try_from(self.limits.login_per_account_soft_lock.limit)
                        .unwrap_or(i32::MAX),
                )
                .bind(now)
                .execute(&mut *tx)
                .await?;
            self.audit.record_in_tx(&mut tx, event).await?;
            tx.commit().await?;
        } else if let Err(err) = self.audit.record(event).await {
            tracing::error!(error = %err, "failed to record soft-lock event");
        }
        Ok(duration)
    }

    /// Runs after a **successful** credential verification: clears the
    /// identifier's CAPTCHA and soft-lock budgets (including the unit this
    /// attempt reserved in [`LoginProtection::check_attempt`]). An engaged lock
    /// stays until it expires (or [`LoginProtection::unlock`]); the risk
    /// velocity counters are kept on purpose (a success right after many
    /// failures is itself a risk signal).
    pub async fn record_success(
        &self,
        attempt: &LoginAttempt<'_>,
        _ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        self.limiter
            .reset_many(&[
                &RateLimitKey::account(CAPTCHA_FAILURES_ACTION, attempt.identifier),
                &RateLimitKey::account(LOCK_FAILURES_ACTION, attempt.identifier),
            ])
            .await
    }

    /// Lifts a soft lock and clears the failure counters (admin "unlock",
    /// ADM-03). `identifier` is the user's normalized e-mail.
    pub async fn unlock(&self, user: UserId, identifier: &str) -> Result<(), AuthError> {
        for key in [
            Self::lock_key(identifier),
            RateLimitKey::account(CAPTCHA_FAILURES_ACTION, identifier),
            RateLimitKey::account(LOCK_FAILURES_ACTION, identifier),
            RateLimitKey::user(FAILURE_ACTION, user),
        ] {
            self.limiter.reset(&key).await?;
        }
        sqlx::query(DELETE_LOCK_SQL)
            .bind(user)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The recorded soft lock of an existing user (admin / user views).
    pub async fn locked_until(&self, user: UserId) -> Result<Option<OffsetDateTime>, AuthError> {
        Ok(sqlx::query_scalar(SELECT_LOCK_SQL)
            .bind(user)
            .bind(self.clock.now())
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Deletes expired soft-lock records (background job, OPS-06).
    pub async fn purge_expired(&self) -> Result<u64, AuthError> {
        Ok(sqlx::query(PURGE_LOCKS_SQL)
            .bind(self.clock.now())
            .execute(&self.pool)
            .await?
            .rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (security review): the derived `Debug` printed the raw
    /// e-mail and the CAPTCHA token into any log line that formats it.
    #[test]
    fn prt_03_login_attempt_debug_masks_personal_data_and_tokens() {
        let attempt = LoginAttempt {
            identifier: "alice.secret@example.com",
            user_id: None,
            method: LoginMethod::Password,
            trusted_device: false,
            captcha_response: Some("0.captcha-token-abc"),
        };
        let debug = format!("{attempt:?}");
        assert!(!debug.contains("alice.secret"), "{debug}");
        assert!(!debug.contains("captcha-token-abc"), "{debug}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
    }
}
