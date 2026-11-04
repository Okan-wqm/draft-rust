//! Background jobs (OPS-06, contracts §15.5).
//!
//! Every job is safe with several instances: the module functions claim
//! their rows with `FOR UPDATE SKIP LOCKED`, advisory locks or idempotent
//! deletes. Each job runs on its own interval; a failing run is logged and
//! retried at the next tick, never stopping the server. [`run_maintenance_once`]
//! runs every cleanup once (tests, `maintenance` operations).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_audit::{HandlerError, OutboxHandler, OutboxHandlers, OutboxMessage};
use authn_core::error::AuthError;
use authn_core::ports::CaptchaProvider;
use authn_notify::{DeliveryFailure, DeliveryRequest, NotificationDeliverer};
use authn_store::{OneTimeTokenRepository, SigningKeyRepository};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::services::Services;

/// Rows handled per batch by the cleanup jobs.
const BATCH: u32 = 500;
/// Tick of the frequent cleanups.
const FREQUENT: Duration = Duration::from_secs(60);
/// Tick of the hourly jobs.
const HOURLY: Duration = Duration::from_secs(3600);
/// Tick of the daily audit maintenance.
const DAILY: Duration = Duration::from_secs(86_400);

/// Delivers `notification.*` outbox rows through authn-notify (AUD-06,
/// NTF-03).
pub struct NotificationBridge(pub Arc<NotificationDeliverer>);

#[async_trait]
impl OutboxHandler for NotificationBridge {
    async fn handle(&self, m: &OutboxMessage) -> Result<(), HandlerError> {
        let request = DeliveryRequest {
            id: m.id,
            topic: &m.topic,
            payload: &m.payload,
            sealed_payload: m
                .sealed_payload
                .as_ref()
                .map(authn_audit::outbox::SealedPayload::as_bytes),
            attempt: m.attempts,
            max_attempts: m.max_attempts,
        };
        self.0
            .deliver(request)
            .await
            .map_err(|failure| match failure {
                DeliveryFailure::Retry {
                    reason,
                    retry_after,
                } => HandlerError::Retry {
                    reason: reason.into(),
                    retry_after,
                },
                DeliveryFailure::Permanent { reason } => HandlerError::permanent(reason),
            })
    }
}

/// The outbox handlers: webhooks / domain events (authn-audit) and
/// notifications (authn-notify).
pub fn outbox_handlers(services: &Services) -> Result<OutboxHandlers, AuthError> {
    let handlers = services.audit.outbox_handlers(services.http.clone())?;
    match &services.notify {
        Some(notify) => handlers.register(
            authn_notify::NOTIFICATION_TOPIC_PREFIX,
            Arc::new(NotificationBridge(notify.deliverer.clone())),
        ),
        None => Ok(handlers),
    }
}

/// Activates a due signing key or creates the first one (CRY-10). Must
/// run before the first token is issued.
pub async fn rotate_signing_keys(services: &Services) -> Result<(), AuthError> {
    let mut conn = services.pool.acquire().await?;
    let report = SigningKeyRepository::rotate_if_due(
        &mut conn,
        &services.crypto.envelopes,
        services.clock.now(),
        &services.config.crypto.signing_keys,
    )
    .await
    .map_err(|e| AuthError::internal("signing key rotation failed").with_source(e))?;
    tracing::debug!(?report, "signing key rotation checked");
    Ok(())
}

/// What one maintenance run removed (logged; tests assert on it).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceTotals {
    /// Rows / records removed or released across all jobs.
    pub removed: u64,
    /// Jobs that failed (logged).
    pub failed: u32,
}

fn tally<T>(
    totals: &mut MaintenanceTotals,
    job: &'static str,
    result: Result<T, AuthError>,
    count: impl Fn(&T) -> u64,
) {
    match result {
        Ok(value) => totals.removed += count(&value),
        Err(err) => {
            totals.failed += 1;
            tracing::error!(job, error = %err, "maintenance job failed");
        }
    }
}

/// Runs every cleanup once (OPS-06).
pub async fn run_maintenance_once(services: &Services) -> MaintenanceTotals {
    let mut t = MaintenanceTotals::default();
    let s = services;
    tally(
        &mut t,
        "sessions",
        s.sessions.purge_expired(i64::from(BATCH)).await,
        |r| r.sessions + r.challenges + r.successors,
    );
    tally(
        &mut t,
        "unverified_accounts",
        s.accounts.purge_unverified_accounts(BATCH).await,
        |n| *n,
    );
    tally(
        &mut t,
        "account_deletions",
        s.accounts.purge_due_deletions(BATCH).await,
        |r| r.purged,
    );
    tally(
        &mut t,
        "account_locks",
        s.accounts.release_expired_locks(BATCH).await,
        |n| *n,
    );
    tally(
        &mut t,
        "address_reservations",
        s.accounts.purge_expired_reservations(BATCH).await,
        |n| *n,
    );
    tally(
        &mut t,
        "org_deletions",
        s.orgs.purge_due_deletions(BATCH).await,
        |n| *n,
    );
    tally(
        &mut t,
        "invitations",
        s.orgs.expire_invitations().await,
        |n| *n,
    );
    tally(&mut t, "mfa", s.mfa.purge_expired().await, |r| {
        r.pending_factors + r.trusted_devices
    });
    tally(
        &mut t,
        "passkey_ceremonies",
        s.webauthn.purge_expired_ceremonies().await,
        |n| *n,
    );
    tally(
        &mut t,
        "soft_locks",
        s.protection.purge_expired().await,
        |n| *n,
    );
    if s.config.protect.rate_limit.backend
        == authn_core::config::protect::RateLimitBackend::Postgres
    {
        let hasher = authn_protect::KeyHasher::new(&s.crypto.keys);
        let result = match hasher {
            Ok(hasher) => {
                authn_protect::rate_limit::PostgresRateLimiter::new(
                    s.pool.clone(),
                    s.clock.clone(),
                    hasher,
                )
                .purge_expired(i64::from(BATCH))
                .await
            }
            Err(err) => Err(err),
        };
        tally(&mut t, "rate_limits", result, |n| *n);
    }
    if s.config.protect.captcha.provider == CaptchaProvider::ProofOfWork {
        let result = match authn_protect::captcha::ProofOfWorkCaptcha::new(
            s.pool.clone(),
            s.clock.clone(),
            &s.crypto.keys,
            s.config.protect.captcha.pow_difficulty,
            s.config.protect.captcha.pow_ttl,
        ) {
            Ok(pow) => pow.purge_expired().await,
            Err(err) => Err(err),
        };
        tally(&mut t, "captcha", result, |n| *n);
    }
    let tokens = async {
        let mut conn = s.pool.acquire().await?;
        Ok::<u64, AuthError>(
            OneTimeTokenRepository::delete_expired(&mut conn, s.clock.now(), BATCH).await?,
        )
    }
    .await;
    tally(&mut t, "one_time_tokens", tokens, |n| *n);
    tally(&mut t, "signing_keys", rotate_signing_keys(s).await, |()| 0);
    t
}

/// Starts every background job; they stop when `shutdown` is cancelled.
pub fn spawn(services: Services, shutdown: CancellationToken) -> Result<JoinSet<()>, AuthError> {
    let mut jobs = JoinSet::new();
    // Outbox delivery (notifications, webhooks, domain events).
    let worker = services.audit.outbox_worker(outbox_handlers(&services)?);
    let stop = shutdown.clone();
    jobs.spawn(async move { worker.run(stop.cancelled_owned()).await });

    // Frequent cleanups.
    let s = services.clone();
    let stop = shutdown.clone();
    jobs.spawn(async move {
        every(FREQUENT, stop, || {
            let s = s.clone();
            async move {
                let totals = run_maintenance_once(&s).await;
                tracing::debug!(?totals, "maintenance run");
            }
        })
        .await;
    });

    // Signing-key rotation check (CRY-10).
    let s = services.clone();
    let stop = shutdown.clone();
    jobs.spawn(async move {
        every(HOURLY, stop, || {
            let s = s.clone();
            async move {
                if let Err(err) = rotate_signing_keys(&s).await {
                    tracing::error!(error = %err, "signing key rotation failed");
                }
            }
        })
        .await;
    });

    // Audit retention and checkpoints (AUD-03), maintenance role pool.
    let s = services;
    jobs.spawn(async move {
        every(DAILY, shutdown, || {
            let s = s.clone();
            async move {
                if let Err(err) = s.audit.run_maintenance(&s.pool).await {
                    tracing::error!(error = %err, "audit maintenance failed");
                }
            }
        })
        .await;
    });
    Ok(jobs)
}

/// Calls `job` every `period` until `stop` is cancelled.
async fn every<F, Fut>(period: Duration, stop: CancellationToken, mut job: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = interval.tick() => job().await,
        }
    }
}
