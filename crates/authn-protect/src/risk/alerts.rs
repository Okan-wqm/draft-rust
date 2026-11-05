//! User-facing consequences of risk decisions: new-device notification with
//! a "this wasn't me" link (RSK-04) and the blocked-login notice (RSK-03).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::domain::Locale;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, AuditSink, Clock, Notification, NotificationKind, Notifier, RateLimitKey,
    RateLimitPolicy, RateLimiter, Recipient, RiskAssessment, RiskInput, SecurityEvent,
    SecurityEventKind,
};
use authn_core::redact::mask_ip;
use authn_core::secret::SensitiveString;
use sqlx::PgConnection;
use time::OffsetDateTime;

use super::{DefaultRiskEvaluator, Novelty};

/// Blocked-login notices per user are limited to one per this window, so an
/// attacker holding the password cannot mail-bomb the victim.
const BLOCK_NOTICE_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Issues the single-use "this wasn't me" link token (`one_time_tokens`
/// purpose `not_me`, owned by authn-session) **inside the caller's
/// transaction**. Consuming it revokes all sessions and forces a password
/// reset (session's responsibility).
#[async_trait]
pub trait NotMeTokenIssuer: Send + Sync {
    /// Creates the token for `user` at `now` and returns its clear text
    /// (sent only inside the sealed notification).
    async fn issue_not_me_token(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<SensitiveString, AuthError>;
}

/// Result of [`RiskAlerts::on_successful_login`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLoginOutcome {
    /// What was new.
    pub novelty: Novelty,
    /// Whether the new-device notification was queued.
    pub notified: bool,
    /// The device description used.
    pub device_name: String,
}

/// RSK-03 / RSK-04 side effects. Cheap to clone.
#[derive(Clone)]
pub struct RiskAlerts {
    evaluator: DefaultRiskEvaluator,
    notifier: Arc<dyn Notifier>,
    audit: Arc<dyn AuditSink>,
    limiter: Arc<dyn RateLimiter>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for RiskAlerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RiskAlerts").finish_non_exhaustive()
    }
}

impl RiskAlerts {
    /// Creates the service.
    #[must_use]
    pub fn new(
        evaluator: DefaultRiskEvaluator,
        notifier: Arc<dyn Notifier>,
        audit: Arc<dyn AuditSink>,
        limiter: Arc<dyn RateLimiter>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            evaluator,
            notifier,
            audit,
            limiter,
            clock,
        }
    }

    /// Call after a **successful** login (instead of
    /// `RiskEvaluator::record_successful_login`). In one transaction:
    /// records device and network, and — when the device is new for a user
    /// who has a login history — issues a "not me" token, queues the
    /// `NewDeviceLogin` notification (device, approximate location if a
    /// GeoIP provider is configured, masked IP, time) and records the
    /// `risk.new_device_login` audit event (RSK-04).
    pub async fn on_successful_login(
        &self,
        input: &RiskInput,
        recipient: Recipient,
        locale: Locale,
        not_me: &dyn NotMeTokenIssuer,
        ctx: &RequestContext,
    ) -> Result<DeviceLoginOutcome, AuthError> {
        let user = input
            .user_id
            .ok_or_else(|| AuthError::internal("new-device alert without a user"))?;
        let observation = self.evaluator.observation(input).await;
        let store = self.evaluator.store();
        let mut tx = store.pool().begin().await?;
        let novelty = store.record(&mut tx, user, &observation).await?;
        let notify = novelty.new_device && !novelty.first_login;
        if notify {
            let token = not_me
                .issue_not_me_token(&mut tx, user, self.clock.now())
                .await?;
            let notification = Notification {
                recipient,
                locale,
                kind: NotificationKind::NewDeviceLogin {
                    device: observation.device_name.clone(),
                    approximate_location: observation.approximate_location.clone(),
                    ip_masked: mask_ip(input.ip),
                    at: input.at,
                    not_me_token: token,
                },
            };
            self.notifier.notify_in_tx(&mut tx, notification).await?;
            let event = SecurityEvent::new(SecurityEventKind::NewDeviceLogin, self.clock.now())
                .with_context(ctx)
                .with_actor(Actor::User(user))
                .with_subject(user)
                // No device description in the metadata (AUD-03, AUD-05):
                // it is free text derived from the user agent, which is
                // personal data kept in the erasable `audit_event_pii`
                // (`with_context` above), never in the immutable chain.
                .with_meta("new_network", novelty.new_network);
            self.audit.record_in_tx(&mut tx, event).await?;
        }
        tx.commit().await?;
        Ok(DeviceLoginOutcome {
            novelty,
            notified: notify,
            device_name: observation.device_name,
        })
    }

    /// Call when [`super::decide`] answered `Block` (credentials were
    /// already verified, SES-01). Records `risk.high_blocked`, notifies the
    /// user (at most once per 15 minutes) and returns the error to send:
    /// `suspicious_login_blocked`.
    pub async fn on_blocked_login(
        &self,
        input: &RiskInput,
        assessment: &RiskAssessment,
        recipient: Recipient,
        locale: Locale,
        ctx: &RequestContext,
    ) -> AuthError {
        let reasons: Vec<&str> = assessment.reasons.iter().map(|r| r.as_str()).collect();
        let mut event = SecurityEvent::new(SecurityEventKind::RiskHighBlocked, self.clock.now())
            .with_context(ctx)
            .with_actor(Actor::Anonymous)
            .failed("risk_high")
            .with_meta("reasons", reasons);
        if let Some(user) = input.user_id {
            event = event.with_subject(user);
            let first = self
                .limiter
                .check(
                    &RateLimitKey::user("risk_block_notice", user),
                    RateLimitPolicy::new(1, BLOCK_NOTICE_WINDOW),
                    1,
                )
                .await
                .map_or(true, |d| d.allowed);
            if first {
                let notification = Notification {
                    recipient,
                    locale,
                    kind: NotificationKind::SuspiciousLoginBlocked {
                        device: super::useragent::describe(input.user_agent.as_deref()),
                        ip_masked: mask_ip(input.ip),
                        at: input.at,
                    },
                };
                if let Err(err) = self.notifier.notify(notification).await {
                    tracing::error!(error = %err, "failed to queue the blocked-login notice");
                }
            }
        }
        if let Err(err) = self.audit.record(event).await {
            tracing::error!(error = %err, "failed to record risk.high_blocked");
        }
        AuthError::new(codes::protect::SUSPICIOUS_LOGIN_BLOCKED)
    }
}
