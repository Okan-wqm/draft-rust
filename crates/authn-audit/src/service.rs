//! [`AuditService`]: everything the HTTP handlers and the background jobs
//! of this crate need, cheap to clone (ARC-03).

use std::sync::Arc;
use std::time::Duration;

use authn_core::config::audit::AuditConfig;
use authn_core::domain::{Principal, PrincipalCredential, Subject};
use authn_core::error::AuthError;
use authn_core::ports::{Clock, HttpClient, RateLimitKey, RateLimitPolicy, RateLimiter};
use authn_crypto::envelope::EnvelopeCipher;
use sqlx::PgPool;

use crate::outbox::{
    DOMAIN_EVENT_TOPIC, OutboxEventPublisher, OutboxHandlers, OutboxRepository, OutboxWorker,
};
use crate::policy::AuditAccessPolicy;
use crate::retention::{self, PurgeReport};
use crate::sink::PgAuditSink;
use crate::webhooks::{WEBHOOK_TOPIC_PREFIX, WebhookDeliverer, WebhookFanout, WebhookManager};

/// Construction parameters of [`AuditService`].
#[derive(Clone)]
pub struct AuditServiceParts {
    /// Database pool (application role).
    pub pool: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Envelope encryption for webhook secrets (CRY-08).
    pub cipher: EnvelopeCipher,
    /// Organization authorization (implemented by the server with
    /// authn-org RBAC).
    pub policy: Arc<dyn AuditAccessPolicy>,
    /// Rate limiter (authn-protect).
    pub rate_limiter: Arc<dyn RateLimiter>,
    /// `[audit]` configuration.
    pub config: AuditConfig,
    /// Step-up window for webhook changes (`session.step_up_max_age`).
    pub step_up_max_age: Duration,
}

struct Inner {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    cipher: EnvelopeCipher,
    sink: PgAuditSink,
    policy: Arc<dyn AuditAccessPolicy>,
    rate_limiter: Arc<dyn RateLimiter>,
    webhooks: WebhookManager,
    config: AuditConfig,
    step_up_max_age: Duration,
}

/// The audit module's service.
#[derive(Clone)]
pub struct AuditService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for AuditService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditService").finish_non_exhaustive()
    }
}

/// Outcome of [`AuditService::run_maintenance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// Audit retention purge.
    pub audit: PurgeReport,
    /// Outbox messages deleted.
    pub outbox_deleted: u64,
    /// Finished webhook deliveries deleted.
    pub deliveries_deleted: u64,
}

impl AuditService {
    /// Builds the service.
    #[must_use]
    pub fn new(parts: AuditServiceParts) -> Self {
        let sink = PgAuditSink::new(parts.pool.clone(), parts.clock.clone());
        let webhooks = WebhookManager::new(
            parts.pool.clone(),
            parts.clock.clone(),
            parts.cipher.clone(),
            sink.clone(),
            parts.config.webhooks,
        );
        Self {
            inner: Arc::new(Inner {
                pool: parts.pool,
                clock: parts.clock,
                cipher: parts.cipher,
                sink,
                policy: parts.policy,
                rate_limiter: parts.rate_limiter,
                webhooks,
                config: parts.config,
                step_up_max_age: parts.step_up_max_age,
            }),
        }
    }

    /// The `AuditSink` implementation (share it as `Arc<dyn AuditSink>`).
    #[must_use]
    pub fn sink(&self) -> PgAuditSink {
        self.inner.sink.clone()
    }

    /// The `EventPublisher` implementation.
    #[must_use]
    pub fn event_publisher(&self) -> OutboxEventPublisher {
        OutboxEventPublisher::new(
            self.inner.clock.clone(),
            self.inner.config.outbox.max_attempts,
        )
    }

    /// Webhook endpoint management.
    #[must_use]
    pub fn webhooks(&self) -> &WebhookManager {
        &self.inner.webhooks
    }

    /// Database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.inner.pool
    }

    /// Clock.
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.inner.clock
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &AuditConfig {
        &self.inner.config
    }

    pub(crate) fn policy(&self) -> &dyn AuditAccessPolicy {
        self.inner.policy.as_ref()
    }

    /// The outbox handlers of this crate: `domain_event` (webhook fan-out)
    /// and `webhook.*` (signed delivery through `http`, which must be the
    /// SSRF-protected client of authn-protect). The server merges its
    /// `notification` bridge into the result.
    pub fn outbox_handlers(&self, http: Arc<dyn HttpClient>) -> Result<OutboxHandlers, AuthError> {
        let inner = &self.inner;
        OutboxHandlers::new()
            .register(
                DOMAIN_EVENT_TOPIC,
                Arc::new(WebhookFanout::new(
                    inner.pool.clone(),
                    inner.clock.clone(),
                    inner.config.webhooks.max_attempts,
                )),
            )?
            .register(
                WEBHOOK_TOPIC_PREFIX,
                Arc::new(WebhookDeliverer::new(
                    inner.pool.clone(),
                    inner.clock.clone(),
                    inner.cipher.clone(),
                    http,
                    inner.sink.clone(),
                    inner.config.webhooks,
                )),
            )
    }

    /// An outbox worker over `handlers`.
    #[must_use]
    pub fn outbox_worker(&self, handlers: OutboxHandlers) -> OutboxWorker {
        OutboxWorker::new(
            self.inner.pool.clone(),
            self.inner.clock.clone(),
            handlers,
            self.inner.config.outbox,
        )
    }

    /// Daily maintenance (OPS-06): audit retention purge, outbox and
    /// delivery-history cleanup. `maintenance_pool` is the pool of a role
    /// allowed to delete audit events (see migration 1700); pass the
    /// application pool when no separate role is used.
    pub async fn run_maintenance(
        &self,
        maintenance_pool: &PgPool,
    ) -> Result<MaintenanceReport, AuthError> {
        let inner = &self.inner;
        let now = inner.clock.now();
        let audit = retention::purge_expired(
            maintenance_pool,
            inner.clock.as_ref(),
            inner.config.retention,
        )
        .await?;
        let outbox_deleted = OutboxRepository::purge(
            maintenance_pool,
            now - inner.config.outbox.delivered_retention,
            now - inner.config.outbox.dead_retention,
        )
        .await?;
        let deliveries_deleted = sqlx::query(
            "DELETE FROM webhook_deliveries WHERE created_at < $1 AND status IN ('succeeded', 'dead')",
        )
        .bind(now - inner.config.webhooks.delivery_retention)
        .execute(maintenance_pool)
        .await?
        .rows_affected();
        Ok(MaintenanceReport {
            audit,
            outbox_deleted,
            deliveries_deleted,
        })
    }

    /// Consumes one unit of a rate limit (`429` + `Retry-After` when
    /// exhausted).
    pub(crate) async fn rate_limit(
        &self,
        key: RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<(), AuthError> {
        self.inner
            .rate_limiter
            .check(&key, policy, 1)
            .await?
            .into_result()
            .map(|_| ())
    }

    /// Rate-limit key of a principal for read endpoints.
    pub(crate) fn principal_key(action: &'static str, principal: &Principal) -> RateLimitKey {
        match principal.subject {
            Subject::User { user_id } => RateLimitKey::user(action, user_id),
            Subject::ServiceAccount {
                service_account_id, ..
            } => RateLimitKey::account(action, &service_account_id.to_string()),
        }
    }

    /// Step-up for sensitive webhook changes (SES-13): humans must have
    /// re-authenticated recently; API-key principals (machine credentials,
    /// scope-checked by the policy) are exempt; impersonation never passes.
    pub(crate) fn require_step_up(&self, principal: &Principal) -> Result<(), AuthError> {
        match principal.credential {
            PrincipalCredential::ApiKey { .. } if !principal.is_impersonated() => Ok(()),
            _ => principal
                .require_recent_authentication(self.inner.clock.now(), self.inner.step_up_max_age),
        }
    }
}
