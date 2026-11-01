//! The outbox worker (AUD-06, OPS-06): claim, dispatch, retry, dead-letter.

use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use authn_core::config::audit::OutboxConfig;
use authn_core::error::AuthError;
use authn_core::id::{OrgId, OutboxMessageId};
use authn_core::ports::Clock;
use futures::FutureExt as _;
use futures::StreamExt as _;
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;

use super::{OutboxMessage, OutboxRepository, SealedPayload, is_valid_topic};

/// Longest stored error text (schema limit).
const MAX_ERROR_CHARS: usize = 1000;
/// Upper bound of any retry delay a handler may request.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(86_400);
/// How often the worker refreshes the queue-depth gauge.
const DEPTH_GAUGE_INTERVAL: Duration = Duration::from_secs(15);

/// Why a handler did not complete a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// Temporary failure: try again later (with backoff, or after
    /// `retry_after` when given).
    Retry {
        /// Sanitized, non-secret reason (stored in `last_error`).
        reason: Cow<'static, str>,
        /// Requested delay before the next attempt.
        retry_after: Option<Duration>,
    },
    /// The message can never succeed: dead-letter it now.
    Permanent {
        /// Sanitized, non-secret reason.
        reason: Cow<'static, str>,
    },
}

impl HandlerError {
    /// A temporary failure with the worker's backoff.
    #[must_use]
    pub fn retry(reason: impl Into<Cow<'static, str>>) -> Self {
        Self::Retry {
            reason: reason.into(),
            retry_after: None,
        }
    }

    /// A temporary failure with an explicit delay.
    #[must_use]
    pub fn retry_after(reason: impl Into<Cow<'static, str>>, delay: Duration) -> Self {
        Self::Retry {
            reason: reason.into(),
            retry_after: Some(delay),
        }
    }

    /// A permanent failure.
    #[must_use]
    pub fn permanent(reason: impl Into<Cow<'static, str>>) -> Self {
        Self::Permanent {
            reason: reason.into(),
        }
    }
}

/// Delivers messages of one topic prefix.
///
/// Implementations must be idempotent: a message may be handled more than
/// once (at-least-once delivery). Use [`OutboxMessage::idempotency_key`].
/// Reasons returned in errors are stored and logged: never put secrets,
/// payload data or response bodies into them.
#[async_trait]
pub trait OutboxHandler: Send + Sync {
    /// Handles one message.
    async fn handle(&self, message: &OutboxMessage) -> Result<(), HandlerError>;

    /// Called once when the message enters the dead-letter state (e.g. to
    /// mark a webhook delivery as dead). Errors are logged.
    async fn on_dead_letter(&self, message: &OutboxMessage) -> Result<(), AuthError> {
        let _ = message;
        Ok(())
    }
}

/// Topic-prefix → handler registry. A handler registered for `webhook`
/// receives `webhook` and `webhook.*` topics; the longest matching prefix
/// wins.
#[derive(Clone, Default)]
pub struct OutboxHandlers {
    entries: Vec<(String, Arc<dyn OutboxHandler>)>,
}

impl std::fmt::Debug for OutboxHandlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.entries.iter().map(|(prefix, _)| prefix))
            .finish()
    }
}

impl OutboxHandlers {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers (or replaces) the handler of a topic prefix.
    pub fn register(
        mut self,
        prefix: &str,
        handler: Arc<dyn OutboxHandler>,
    ) -> Result<Self, AuthError> {
        if !is_valid_topic(prefix) {
            return Err(AuthError::internal("invalid outbox topic prefix"));
        }
        self.entries.retain(|(p, _)| p != prefix);
        self.entries.push((prefix.to_owned(), handler));
        Ok(self)
    }

    /// Adds every handler of `other` (replacing equal prefixes).
    pub fn merge(mut self, other: Self) -> Self {
        for (prefix, handler) in other.entries {
            self.entries.retain(|(p, _)| *p != prefix);
            self.entries.push((prefix, handler));
        }
        self
    }

    /// The registered prefixes.
    #[must_use]
    pub fn prefixes(&self) -> Vec<String> {
        self.entries.iter().map(|(p, _)| p.clone()).collect()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The handler for `topic` (longest matching prefix) and that prefix.
    #[must_use]
    pub fn handler_for(&self, topic: &str) -> Option<(&str, Arc<dyn OutboxHandler>)> {
        self.entries
            .iter()
            .filter(|(prefix, _)| {
                topic == prefix
                    || topic
                        .strip_prefix(prefix.as_str())
                        .is_some_and(|rest| rest.starts_with('.'))
            })
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(prefix, handler)| (prefix.as_str(), handler.clone()))
    }
}

/// Exponential backoff: `base · 2^(attempt-1)`, capped at `max`.
#[must_use]
pub fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let exponent = attempt.saturating_sub(1).min(31);
    let factor = 1_u32 << exponent;
    base.checked_mul(factor).unwrap_or(max).min(max)
}

/// "Equal jitter": a uniformly random delay in `[delay/2, delay]` (CSPRNG),
/// so that failed messages of one outage do not retry in lockstep.
#[must_use]
pub fn jittered(delay: Duration) -> Duration {
    let half = delay / 2;
    let span_ms = u32::try_from((delay - half).as_millis()).unwrap_or(u32::MAX);
    let offset = authn_crypto::random::uniform_below(span_ms.saturating_add(1)).unwrap_or(0);
    half + Duration::from_millis(u64::from(offset))
}

/// Strips control characters and bounds the length of an error text.
fn sanitize_error(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_CHARS)
        .collect()
}

/// What happened to the messages of one batch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchReport {
    /// Messages claimed.
    pub claimed: usize,
    /// Delivered successfully.
    pub delivered: usize,
    /// Scheduled for another attempt.
    pub retried: usize,
    /// Moved to the dead-letter state.
    pub dead: usize,
    /// Results discarded because the lease had been taken over.
    pub lost_leases: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Delivered,
    Retried,
    Dead,
    LostLease,
}

#[derive(sqlx::FromRow)]
struct ClaimRow {
    id: OutboxMessageId,
    topic: String,
    org_id: Option<OrgId>,
    payload: sqlx::types::Json<Value>,
    sealed_payload: Option<Vec<u8>>,
    attempts: i32,
    max_attempts: i32,
    created_at: OffsetDateTime,
}

impl From<ClaimRow> for OutboxMessage {
    fn from(row: ClaimRow) -> Self {
        Self {
            id: row.id,
            topic: row.topic,
            org_id: row.org_id,
            payload: row.payload.0,
            sealed_payload: row.sealed_payload.map(SealedPayload::new),
            attempts: u32::try_from(row.attempts).unwrap_or(0),
            max_attempts: u32::try_from(row.max_attempts).unwrap_or(1),
            created_at: row.created_at,
        }
    }
}

/// The outbox worker. Run one or more per process / instance: claiming
/// uses `FOR UPDATE SKIP LOCKED`, so workers never handle the same message
/// concurrently while their leases are valid.
#[derive(Clone)]
pub struct OutboxWorker {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    handlers: OutboxHandlers,
    config: OutboxConfig,
    worker_id: String,
}

impl std::fmt::Debug for OutboxWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxWorker")
            .field("worker_id", &self.worker_id)
            .field("handlers", &self.handlers)
            .finish_non_exhaustive()
    }
}

impl OutboxWorker {
    /// Creates a worker with a random id.
    #[must_use]
    pub fn new(
        pool: PgPool,
        clock: Arc<dyn Clock>,
        handlers: OutboxHandlers,
        config: OutboxConfig,
    ) -> Self {
        let suffix = authn_crypto::random::bytes::<8>()
            .map_or_else(|_| "0".to_owned(), |b| crate::canonical::hex(&b));
        Self {
            pool,
            clock,
            handlers,
            config,
            worker_id: format!("outbox-{suffix}"),
        }
    }

    /// Overrides the worker id (≤ 64 characters; shown in `locked_by`).
    #[must_use]
    pub fn with_worker_id(mut self, id: &str) -> Self {
        self.worker_id = sanitize_error(id).chars().take(64).collect();
        self
    }

    /// The worker id.
    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Claims and processes one batch.
    pub async fn run_once(&self) -> Result<BatchReport, AuthError> {
        if self.handlers.is_empty() {
            return Ok(BatchReport::default());
        }
        let now = self.clock.now();
        let lease_until = now + self.config.lease;
        let rows: Vec<ClaimRow> = sqlx::query_as(
            "UPDATE outbox o SET status = 'processing', attempts = o.attempts + 1, \
             locked_until = $2, locked_by = $3 \
             FROM (SELECT id FROM outbox \
                   WHERE ((status = 'pending' AND available_at <= $1) \
                          OR (status = 'processing' AND locked_until <= $1)) \
                     AND EXISTS (SELECT 1 FROM unnest($4::text[]) AS p(prefix) \
                                 WHERE outbox.topic = p.prefix \
                                    OR starts_with(outbox.topic, p.prefix || '.')) \
                   ORDER BY available_at, id \
                   LIMIT $5 \
                   FOR UPDATE SKIP LOCKED) AS due \
             WHERE o.id = due.id \
             RETURNING o.id, o.topic, o.org_id, o.payload, o.sealed_payload, o.attempts, \
                       o.max_attempts, o.created_at",
        )
        .bind(now)
        .bind(lease_until)
        .bind(&self.worker_id)
        .bind(self.handlers.prefixes())
        .bind(i64::from(self.config.batch_size.max(1)))
        .fetch_all(&self.pool)
        .await?;

        let mut report = BatchReport {
            claimed: rows.len(),
            ..BatchReport::default()
        };
        let concurrency = usize::try_from(self.config.concurrency.max(1)).unwrap_or(1);
        let outcomes: Vec<Outcome> =
            futures::stream::iter(rows.into_iter().map(OutboxMessage::from))
                .map(|message| self.process(message))
                .buffer_unordered(concurrency)
                .collect()
                .await;
        for outcome in outcomes {
            match outcome {
                Outcome::Delivered => report.delivered += 1,
                Outcome::Retried => report.retried += 1,
                Outcome::Dead => report.dead += 1,
                Outcome::LostLease => report.lost_leases += 1,
            }
        }
        Ok(report)
    }

    /// Runs until `shutdown` resolves. The current batch is always finished
    /// (messages are never abandoned mid-delivery by a graceful shutdown).
    pub async fn run<F>(self, shutdown: F)
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let mut last_gauge: Option<Instant> = None;
        tracing::info!(worker_id = %self.worker_id, handlers = ?self.handlers, "outbox worker started");
        loop {
            if last_gauge.is_none_or(|at| at.elapsed() >= DEPTH_GAUGE_INTERVAL) {
                self.publish_depth().await;
                last_gauge = Some(Instant::now());
            }
            let full_batch = match self.run_once().await {
                Ok(report) => {
                    report.claimed >= usize::try_from(self.config.batch_size).unwrap_or(usize::MAX)
                }
                Err(err) => {
                    tracing::error!(error = %err, "outbox batch failed");
                    false
                }
            };
            if full_batch {
                if (&mut shutdown).now_or_never().is_some() {
                    break;
                }
                continue;
            }
            tokio::select! {
                () = &mut shutdown => break,
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }
        tracing::info!(worker_id = %self.worker_id, "outbox worker stopped");
    }

    async fn publish_depth(&self) {
        match OutboxRepository::depth(&self.pool).await {
            Ok(depth) => {
                #[allow(clippy::cast_precision_loss)] // gauge values
                {
                    metrics::gauge!("authn_outbox_queue_depth", "status" => "pending")
                        .set(depth.pending as f64);
                    metrics::gauge!("authn_outbox_queue_depth", "status" => "processing")
                        .set(depth.processing as f64);
                    metrics::gauge!("authn_outbox_queue_depth", "status" => "dead")
                        .set(depth.dead as f64);
                }
            }
            Err(err) => tracing::warn!(error = %err, "outbox depth query failed"),
        }
    }

    async fn process(&self, message: OutboxMessage) -> Outcome {
        let Some((prefix, handler)) = self.handlers.handler_for(&message.topic) else {
            // Not claimable without a handler; defensive only.
            return self
                .retry(
                    &message,
                    "no handler registered",
                    Some(self.config.poll_interval),
                )
                .await;
        };
        let prefix = prefix.to_owned();
        // A message waits in the batch until a concurrency slot is free; its
        // claim-time lease may have expired meanwhile and another worker may
        // own it now. Renew the lease (only while it is still ours and
        // valid) before doing any work, so a message is never handled by two
        // workers at once and the handler gets a full lease.
        match self.renew_lease(&message).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(topic = %message.topic, message.id = %message.id, "outbox lease expired before handling; message left for re-claim");
                return Outcome::LostLease;
            }
            Err(err) => {
                tracing::error!(topic = %message.topic, message.id = %message.id, error = %err, "outbox lease renewal failed");
                return Outcome::LostLease;
            }
        }
        let outcome = if message.attempts > message.max_attempts {
            // Lease expired on the final attempt (crashed worker): give up.
            self.dead(&message, &handler, "attempts exhausted").await
        } else {
            let timeout = self.config.lease.mul_f64(0.8);
            let task_handler = handler.clone();
            let task_message = message.clone();
            let joined = tokio::spawn(async move {
                tokio::time::timeout(timeout, task_handler.handle(&task_message)).await
            })
            .await;
            match joined {
                Ok(Ok(Ok(()))) => self.delivered(&message).await,
                Ok(Ok(Err(HandlerError::Retry {
                    reason,
                    retry_after,
                }))) => {
                    if message.is_last_attempt() {
                        self.dead(&message, &handler, &reason).await
                    } else {
                        self.retry(&message, &reason, retry_after).await
                    }
                }
                Ok(Ok(Err(HandlerError::Permanent { reason }))) => {
                    self.dead(&message, &handler, &reason).await
                }
                Ok(Err(_elapsed)) => {
                    if message.is_last_attempt() {
                        self.dead(&message, &handler, "handler timed out").await
                    } else {
                        self.retry(&message, "handler timed out", None).await
                    }
                }
                Err(_join_error) => {
                    tracing::error!(topic = %message.topic, message.id = %message.id, "outbox handler panicked");
                    if message.is_last_attempt() {
                        self.dead(&message, &handler, "handler panicked").await
                    } else {
                        self.retry(&message, "handler panicked", None).await
                    }
                }
            }
        };
        metrics::counter!(
            "authn_outbox_messages_total",
            "prefix" => prefix,
            "outcome" => match outcome {
                Outcome::Delivered => "delivered",
                Outcome::Retried => "retried",
                Outcome::Dead => "dead",
                Outcome::LostLease => "lost_lease",
            }
        )
        .increment(1);
        outcome
    }

    /// Extends the lease of a claimed message while this worker still
    /// holds a valid lease on it. Returns `false` when the lease expired or
    /// was taken over.
    async fn renew_lease(&self, message: &OutboxMessage) -> Result<bool, sqlx::Error> {
        let now = self.clock.now();
        let result = sqlx::query(
            "UPDATE outbox SET locked_until = $2 \
             WHERE id = $1 AND status = 'processing' AND locked_by = $3 AND locked_until > $4",
        )
        .bind(message.id)
        .bind(now + self.config.lease)
        .bind(&self.worker_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn delivered(&self, message: &OutboxMessage) -> Outcome {
        // The sealed (secret) payload is wiped together with the status
        // change; the schema refuses a delivered row that still has one.
        let result = sqlx::query(
            "UPDATE outbox SET status = 'delivered', delivered_at = $2, sealed_payload = NULL, \
             locked_until = NULL, locked_by = NULL, last_error = NULL \
             WHERE id = $1 AND status = 'processing' AND locked_by = $3",
        )
        .bind(message.id)
        .bind(self.clock.now())
        .bind(&self.worker_id)
        .execute(&self.pool)
        .await;
        self.finish(message, result, Outcome::Delivered)
    }

    async fn retry(
        &self,
        message: &OutboxMessage,
        reason: &str,
        retry_after: Option<Duration>,
    ) -> Outcome {
        let delay = retry_after.map_or_else(
            || {
                jittered(backoff_delay(
                    message.attempts,
                    self.config.backoff_base,
                    self.config.backoff_max,
                ))
            },
            |d| d.min(MAX_RETRY_DELAY),
        );
        let result = sqlx::query(
            "UPDATE outbox SET status = 'pending', available_at = $2, last_error = $3, \
             locked_until = NULL, locked_by = NULL \
             WHERE id = $1 AND status = 'processing' AND locked_by = $4",
        )
        .bind(message.id)
        .bind(self.clock.now() + delay)
        .bind(sanitize_error(reason))
        .bind(&self.worker_id)
        .execute(&self.pool)
        .await;
        tracing::debug!(topic = %message.topic, message.id = %message.id, attempts = message.attempts, delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX), "outbox message scheduled for retry");
        self.finish(message, result, Outcome::Retried)
    }

    async fn dead(
        &self,
        message: &OutboxMessage,
        handler: &Arc<dyn OutboxHandler>,
        reason: &str,
    ) -> Outcome {
        let result = sqlx::query(
            "UPDATE outbox SET status = 'dead', last_error = $2, sealed_payload = NULL, \
             locked_until = NULL, locked_by = NULL \
             WHERE id = $1 AND status = 'processing' AND locked_by = $3",
        )
        .bind(message.id)
        .bind(sanitize_error(reason))
        .bind(&self.worker_id)
        .execute(&self.pool)
        .await;
        let outcome = self.finish(message, result, Outcome::Dead);
        if outcome == Outcome::Dead {
            tracing::warn!(topic = %message.topic, message.id = %message.id, attempts = message.attempts, "outbox message moved to dead letter");
            if let Err(err) = handler.on_dead_letter(message).await {
                tracing::error!(topic = %message.topic, message.id = %message.id, error = %err, "dead-letter hook failed");
            }
        }
        outcome
    }

    fn finish(
        &self,
        message: &OutboxMessage,
        result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
        outcome: Outcome,
    ) -> Outcome {
        match result {
            Ok(r) if r.rows_affected() == 1 => outcome,
            Ok(_) => {
                tracing::warn!(topic = %message.topic, message.id = %message.id, "outbox lease lost; result discarded");
                Outcome::LostLease
            }
            Err(err) => {
                // The lease expires and the message is retried (at least once).
                tracing::error!(topic = %message.topic, message.id = %message.id, error = %err, "outbox status update failed");
                Outcome::LostLease
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Noop;

    #[async_trait]
    impl OutboxHandler for Noop {
        async fn handle(&self, _message: &OutboxMessage) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    #[test]
    fn aud_06_backoff_is_exponential_and_capped() {
        let base = Duration::from_secs(2);
        let max = Duration::from_secs(3600);
        assert_eq!(backoff_delay(1, base, max), Duration::from_secs(2));
        assert_eq!(backoff_delay(2, base, max), Duration::from_secs(4));
        assert_eq!(backoff_delay(5, base, max), Duration::from_secs(32));
        assert_eq!(backoff_delay(20, base, max), max);
        assert_eq!(backoff_delay(u32::MAX, base, max), max);
        assert_eq!(backoff_delay(0, base, max), base);
    }

    #[test]
    fn aud_06_jitter_stays_within_half_and_full_delay() {
        let delay = Duration::from_secs(10);
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..200 {
            let j = jittered(delay);
            assert!(j >= delay / 2 && j <= delay, "{j:?}");
            distinct.insert(j);
        }
        assert!(distinct.len() > 10, "jitter must vary");
        assert_eq!(jittered(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn aud_06_longest_prefix_wins() {
        let a: Arc<dyn OutboxHandler> = Arc::new(Noop);
        let b: Arc<dyn OutboxHandler> = Arc::new(Noop);
        let handlers = OutboxHandlers::new()
            .register("webhook", a)
            .unwrap()
            .register("webhook.delivery", b)
            .unwrap();
        assert_eq!(
            handlers.handler_for("webhook.delivery").unwrap().0,
            "webhook.delivery"
        );
        assert_eq!(handlers.handler_for("webhook.other").unwrap().0, "webhook");
        assert_eq!(handlers.handler_for("webhook").unwrap().0, "webhook");
        assert!(handlers.handler_for("webhooks").is_none());
        assert!(handlers.handler_for("notification.email").is_none());
        assert!(
            OutboxHandlers::new()
                .register("Bad Prefix", Arc::new(Noop))
                .is_err()
        );
    }

    #[test]
    fn aud_06_error_text_is_bounded_and_clean() {
        let text = format!("bad\n\u{0}{}", "x".repeat(2000));
        let clean = sanitize_error(&text);
        assert!(!clean.contains('\n') && !clean.contains('\u{0}'));
        assert_eq!(clean.chars().count(), MAX_ERROR_CHARS);
    }
}
