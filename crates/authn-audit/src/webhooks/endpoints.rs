//! Webhook endpoint management (AUD-07): CRUD, event-type subscriptions,
//! envelope-encrypted signing secrets with rotation, delivery history and
//! manual redelivery. Every query is scoped by `org_id` (ARC-10); every
//! change is audited in the same transaction.

use std::sync::Arc;

use authn_core::config::audit::WebhookConfig;
use authn_core::domain::{Cursor, Page, PageRequest};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{
    EventId, OrgId, OutboxMessageId, UserId, WebhookDeliveryId, WebhookEndpointId,
};
use authn_core::ports::{
    Actor, AuditSink as _, Clock, DomainEventKind, SecurityEvent, SecurityEventKind,
};
use authn_crypto::envelope::{EnvelopeCipher, EnvelopeContext};
use authn_crypto::webhook::WebhookSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use super::delivery::WEBHOOK_DELIVERY_TOPIC;
use super::urls::validate_webhook_url;
use crate::outbox::{NewOutboxMessage, OutboxRepository};
use crate::sink::PgAuditSink;

/// Longest description (schema limit).
pub const MAX_DESCRIPTION_CHARS: usize = 500;
/// Most event types per endpoint (schema limit).
pub const MAX_EVENT_TYPES: usize = 64;
const TABLE: &str = "webhook_endpoints";
const SECRET_COLUMN: &str = "secret_ciphertext";
const PREVIOUS_SECRET_COLUMN: &str = "previous_secret_ciphertext";

macro_rules! endpoint_columns {
    () => {
        "id, org_id, url, description, event_types, status, consecutive_failures, \
         disabled_reason, failing_since, last_success_at, previous_secret_expires_at, \
         created_at, updated_at"
    };
}

macro_rules! delivery_columns {
    () => {
        "id, event_id, event_type, payload, status, attempts, next_attempt_at, \
         last_attempt_at, response_status, response_ms, last_error, created_at"
    };
}

/// A webhook endpoint as returned by the API (never contains secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct WebhookEndpointView {
    /// Endpoint id.
    pub id: WebhookEndpointId,
    /// Owning organization.
    pub org_id: OrgId,
    /// Delivery URL (`https`).
    pub url: String,
    /// Free-text description.
    pub description: Option<String>,
    /// Subscribed event types (e.g. `user.created`).
    pub event_types: Vec<String>,
    /// `active` or `disabled`.
    pub status: String,
    /// Failed attempts since the last success.
    pub consecutive_failures: i32,
    /// Why the endpoint is disabled (`manual`, `consecutive_failures`).
    pub disabled_reason: Option<String>,
    /// Start of the current failure streak.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub failing_since: Option<OffsetDateTime>,
    /// Last successful delivery.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_success_at: Option<OffsetDateTime>,
    /// Until when the previous secret still signs (rotation overlap).
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub previous_secret_expires_at: Option<OffsetDateTime>,
    /// Creation time.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
    /// Last change.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: OffsetDateTime,
}

/// An endpoint together with its signing secret — returned exactly once,
/// on creation and on rotation.
#[derive(Clone, Serialize, utoipa::ToSchema)]
pub struct WebhookEndpointWithSecret {
    /// The endpoint.
    pub endpoint: WebhookEndpointView,
    /// The new signing secret (`whsec_…`). Store it now: it is never shown
    /// again.
    pub secret: String,
}

impl std::fmt::Debug for WebhookEndpointWithSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookEndpointWithSecret")
            .field("endpoint", &self.endpoint)
            .field("secret", &authn_core::secret::REDACTED)
            .finish()
    }
}

impl Drop for WebhookEndpointWithSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

/// Body of `POST /v1/orgs/{org_id}/webhooks`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookEndpoint {
    /// Public `https` URL (no credentials, no fragment).
    pub url: String,
    /// Optional description (≤ 500 characters).
    #[serde(default)]
    pub description: Option<String>,
    /// Event types to subscribe to (at least one).
    pub event_types: Vec<String>,
}

/// Body of `PATCH /v1/orgs/{org_id}/webhooks/{endpoint_id}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateWebhookEndpoint {
    /// New URL.
    #[serde(default)]
    pub url: Option<String>,
    /// New description; an empty string clears it.
    #[serde(default)]
    pub description: Option<String>,
    /// New subscription list.
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
    /// Enable (resets the failure counter) or disable the endpoint.
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl UpdateWebhookEndpoint {
    /// Whether the change redirects or widens deliveries (needs step-up).
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        self.url.is_some() || self.event_types.is_some() || self.enabled == Some(true)
    }
}

/// One delivery of the history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct WebhookDeliveryView {
    /// Delivery id.
    pub id: WebhookDeliveryId,
    /// Event id (= `webhook-id` header).
    pub event_id: EventId,
    /// Event type.
    pub event_type: String,
    /// The JSON body sent.
    #[schema(value_type = Object)]
    pub payload: sqlx::types::Json<Value>,
    /// `pending`, `failed` (will retry), `succeeded`, `dead`.
    pub status: String,
    /// Attempts made.
    pub attempts: i32,
    /// Next scheduled attempt.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub next_attempt_at: Option<OffsetDateTime>,
    /// Last attempt.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub last_attempt_at: Option<OffsetDateTime>,
    /// HTTP status of the last attempt.
    pub response_status: Option<i32>,
    /// Duration of the last attempt in milliseconds.
    pub response_ms: Option<i32>,
    /// Sanitized error of the last attempt (never the response body).
    pub last_error: Option<String>,
    /// When the delivery was created.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: OffsetDateTime,
}

/// Who performs a management action (for the audit trail).
#[derive(Debug, Clone)]
pub struct ActingPrincipal {
    /// Audit actor.
    pub actor: Actor,
    /// Impersonating admin, if any.
    pub impersonator: Option<UserId>,
    /// Request context.
    pub context: Option<RequestContext>,
}

impl ActingPrincipal {
    fn user(&self) -> Option<UserId> {
        match self.actor {
            Actor::User(user) => Some(user),
            _ => None,
        }
    }
}

/// Validates and normalizes a subscription list (known types, deduplicated,
/// sorted).
pub fn validate_event_types(input: &[String]) -> Result<Vec<String>, AuthError> {
    if input.is_empty() || input.len() > MAX_EVENT_TYPES {
        return Err(AuthError::new(codes::common::VALIDATION_FAILED)
            .with_details(json!({"field": "event_types"})));
    }
    let mut out = Vec::with_capacity(input.len());
    for raw in input {
        let kind: DomainEventKind = raw.parse().map_err(|_| {
            AuthError::new(codes::common::VALIDATION_FAILED)
                .with_details(json!({"field": "event_types"}))
        })?;
        out.push(kind.as_str().to_owned());
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn validate_description(input: Option<String>) -> Result<Option<String>, AuthError> {
    let Some(text) = input else {
        return Ok(None);
    };
    let text = text.trim().to_owned();
    if text.is_empty() {
        return Ok(None);
    }
    if text.chars().count() > MAX_DESCRIPTION_CHARS || text.chars().any(char::is_control) {
        return Err(AuthError::new(codes::common::VALIDATION_FAILED)
            .with_details(json!({"field": "description"})));
    }
    Ok(Some(text))
}

fn not_found() -> AuthError {
    AuthError::new(codes::common::NOT_FOUND)
}

/// Envelope AAD of the current signing secret.
pub(crate) fn secret_context(id: WebhookEndpointId) -> Result<EnvelopeContext, AuthError> {
    Ok(EnvelopeContext::new(TABLE, SECRET_COLUMN, id)?)
}

/// Envelope AAD of the previous signing secret.
pub(crate) fn previous_secret_context(id: WebhookEndpointId) -> Result<EnvelopeContext, AuthError> {
    Ok(EnvelopeContext::new(TABLE, PREVIOUS_SECRET_COLUMN, id)?)
}

/// Opens a sealed `whsec_…` secret.
pub(crate) async fn open_secret(
    cipher: &EnvelopeCipher,
    sealed: &[u8],
    context: &EnvelopeContext,
) -> Result<WebhookSecret, AuthError> {
    let plain = cipher.open(sealed, context).await?;
    let text = std::str::from_utf8(plain.expose())
        .map_err(|_| AuthError::internal("webhook secret is not utf-8"))?;
    Ok(WebhookSecret::parse(text)?)
}

/// Webhook endpoint management.
#[derive(Clone)]
pub struct WebhookManager {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    cipher: EnvelopeCipher,
    sink: PgAuditSink,
    config: WebhookConfig,
}

impl std::fmt::Debug for WebhookManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookManager").finish_non_exhaustive()
    }
}

impl WebhookManager {
    /// Creates the manager.
    #[must_use]
    pub fn new(
        pool: PgPool,
        clock: Arc<dyn Clock>,
        cipher: EnvelopeCipher,
        sink: PgAuditSink,
        config: WebhookConfig,
    ) -> Self {
        Self {
            pool,
            clock,
            cipher,
            sink,
            config,
        }
    }

    fn audit_event(
        &self,
        kind: SecurityEventKind,
        org: OrgId,
        endpoint: WebhookEndpointId,
        by: &ActingPrincipal,
    ) -> SecurityEvent {
        let mut event = SecurityEvent::new(kind, self.clock.now())
            .with_actor(by.actor)
            .with_org(org)
            .with_resource("webhook_endpoint", endpoint);
        event.impersonator = by.impersonator;
        if let Some(ctx) = &by.context {
            event = event.with_context(ctx);
        }
        event
    }

    /// Lists the endpoints of an organization.
    pub async fn list(&self, org: OrgId) -> Result<Vec<WebhookEndpointView>, AuthError> {
        Ok(sqlx::query_as(concat!(
            "SELECT ",
            endpoint_columns!(),
            " FROM webhook_endpoints WHERE org_id = $1 ORDER BY created_at, id"
        ))
        .bind(org)
        .fetch_all(&self.pool)
        .await?)
    }

    /// One endpoint of an organization (`not_found` for other tenants).
    pub async fn get(
        &self,
        org: OrgId,
        id: WebhookEndpointId,
    ) -> Result<WebhookEndpointView, AuthError> {
        sqlx::query_as(concat!(
            "SELECT ",
            endpoint_columns!(),
            " FROM webhook_endpoints WHERE id = $1 AND org_id = $2"
        ))
        .bind(id)
        .bind(org)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(not_found)
    }

    /// Creates an endpoint with a fresh signing secret.
    pub async fn create(
        &self,
        org: OrgId,
        input: CreateWebhookEndpoint,
        by: &ActingPrincipal,
    ) -> Result<WebhookEndpointWithSecret, AuthError> {
        let url = validate_webhook_url(&input.url)?;
        let event_types = validate_event_types(&input.event_types)?;
        let description = validate_description(input.description)?;
        let id = WebhookEndpointId::generate();
        let secret = WebhookSecret::generate()?;
        let secret_text = secret.to_text();
        let sealed = self
            .cipher
            .seal(secret_text.as_bytes(), &secret_context(id)?)
            .await?;
        let now = self.clock.now();

        let mut tx = self.pool.begin().await?;
        lock_org(&mut tx, org).await?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM webhook_endpoints WHERE org_id = $1")
                .bind(org)
                .fetch_one(&mut *tx)
                .await?;
        if count >= i64::from(self.config.max_endpoints_per_org) {
            return Err(AuthError::new(codes::audit::WEBHOOK_ENDPOINT_LIMIT_REACHED));
        }
        let endpoint: WebhookEndpointView = sqlx::query_as(concat!(
            "INSERT INTO webhook_endpoints (id, org_id, url, description, event_types, status, \
             secret_ciphertext, consecutive_failures, created_by, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, 'active', $6, 0, $7, $8, $8) RETURNING ",
            endpoint_columns!()
        ))
        .bind(id)
        .bind(org)
        .bind(url.as_str())
        .bind(&description)
        .bind(&event_types)
        .bind(&sealed)
        .bind(by.user())
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match authn_store::StoreError::from(e) {
            // The organization was deleted concurrently.
            authn_store::StoreError::ForeignKeyViolation { .. } => not_found(),
            other => AuthError::from(other),
        })?;
        let event = self
            .audit_event(SecurityEventKind::WebhookEndpointCreated, org, id, by)
            .with_meta("event_types", event_types.clone());
        self.sink.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(WebhookEndpointWithSecret {
            endpoint,
            secret: secret_text.to_string(),
        })
    }

    /// Changes an endpoint.
    pub async fn update(
        &self,
        org: OrgId,
        id: WebhookEndpointId,
        input: UpdateWebhookEndpoint,
        by: &ActingPrincipal,
    ) -> Result<WebhookEndpointView, AuthError> {
        let url = input.url.as_deref().map(validate_webhook_url).transpose()?;
        let event_types = input
            .event_types
            .as_deref()
            .map(validate_event_types)
            .transpose()?;
        let description_changed = input.description.is_some();
        let description = validate_description(input.description)?;

        let mut tx = self.pool.begin().await?;
        let current: WebhookEndpointView = sqlx::query_as(concat!(
            "SELECT ",
            endpoint_columns!(),
            " FROM webhook_endpoints WHERE id = $1 AND org_id = $2 FOR UPDATE"
        ))
        .bind(id)
        .bind(org)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(not_found)?;

        let mut changed: Vec<&'static str> = Vec::new();
        if url.is_some() {
            changed.push("url");
        }
        if event_types.is_some() {
            changed.push("event_types");
        }
        if description_changed {
            changed.push("description");
        }
        let (status, disabled_reason, reset): (String, Option<String>, bool) = match input.enabled {
            Some(true) => {
                changed.push("enabled");
                ("active".to_owned(), None, true)
            }
            Some(false) => {
                changed.push("enabled");
                ("disabled".to_owned(), Some("manual".to_owned()), false)
            }
            None => (
                current.status.clone(),
                current.disabled_reason.clone(),
                false,
            ),
        };
        let endpoint: WebhookEndpointView = sqlx::query_as(concat!(
            "UPDATE webhook_endpoints SET \
               url = coalesce($3, url), \
               description = CASE WHEN $4 THEN $5 ELSE description END, \
               event_types = coalesce($6, event_types), \
               status = $7, \
               disabled_reason = $8, \
               consecutive_failures = CASE WHEN $9 THEN 0 ELSE consecutive_failures END, \
               failing_since = CASE WHEN $9 THEN NULL ELSE failing_since END \
             WHERE id = $1 AND org_id = $2 RETURNING ",
            endpoint_columns!()
        ))
        .bind(id)
        .bind(org)
        .bind(url.as_ref().map(url::Url::as_str))
        .bind(description_changed)
        .bind(&description)
        .bind(&event_types)
        .bind(&status)
        .bind(&disabled_reason)
        .bind(reset)
        .fetch_one(&mut *tx)
        .await?;
        let event = self
            .audit_event(SecurityEventKind::WebhookEndpointUpdated, org, id, by)
            .with_meta("changed", changed)
            .with_meta("status", status.clone());
        self.sink.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(endpoint)
    }

    /// Deletes an endpoint (its delivery history goes with it).
    pub async fn delete(
        &self,
        org: OrgId,
        id: WebhookEndpointId,
        by: &ActingPrincipal,
    ) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await?;
        let deleted = sqlx::query("DELETE FROM webhook_endpoints WHERE id = $1 AND org_id = $2")
            .bind(id)
            .bind(org)
            .execute(&mut *tx)
            .await?;
        if deleted.rows_affected() != 1 {
            return Err(not_found());
        }
        let event = self.audit_event(SecurityEventKind::WebhookEndpointDeleted, org, id, by);
        self.sink.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Rotates the signing secret. The previous secret keeps signing for
    /// `secret_rotation_overlap` (deliveries carry both signatures), unless
    /// `immediate` (suspected leak) — then it is discarded at once.
    pub async fn rotate_secret(
        &self,
        org: OrgId,
        id: WebhookEndpointId,
        immediate: bool,
        by: &ActingPrincipal,
    ) -> Result<WebhookEndpointWithSecret, AuthError> {
        let now = self.clock.now();
        let mut tx = self.pool.begin().await?;
        let current: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT secret_ciphertext FROM webhook_endpoints WHERE id = $1 AND org_id = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(org)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((current_sealed,)) = current else {
            return Err(not_found());
        };
        let immediate = immediate || self.config.secret_rotation_overlap.is_zero();
        let (previous_sealed, previous_expires_at) = if immediate {
            (None, None)
        } else {
            let old = open_secret(&self.cipher, &current_sealed, &secret_context(id)?).await?;
            let resealed = self
                .cipher
                .seal(old.to_text().as_bytes(), &previous_secret_context(id)?)
                .await?;
            (
                Some(resealed),
                Some(now + self.config.secret_rotation_overlap),
            )
        };
        let secret = WebhookSecret::generate()?;
        let secret_text = secret.to_text();
        let sealed = self
            .cipher
            .seal(secret_text.as_bytes(), &secret_context(id)?)
            .await?;
        let endpoint: WebhookEndpointView = sqlx::query_as(concat!(
            "UPDATE webhook_endpoints SET secret_ciphertext = $3, \
             previous_secret_ciphertext = $4, previous_secret_expires_at = $5 \
             WHERE id = $1 AND org_id = $2 RETURNING ",
            endpoint_columns!()
        ))
        .bind(id)
        .bind(org)
        .bind(&sealed)
        .bind(&previous_sealed)
        .bind(previous_expires_at)
        .fetch_one(&mut *tx)
        .await?;
        let event = self
            .audit_event(SecurityEventKind::WebhookSecretRotated, org, id, by)
            .with_meta("immediate", immediate);
        self.sink.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(WebhookEndpointWithSecret {
            endpoint,
            secret: secret_text.to_string(),
        })
    }

    /// Delivery history of an endpoint, newest first.
    pub async fn deliveries(
        &self,
        org: OrgId,
        endpoint: WebhookEndpointId,
        page: &PageRequest,
    ) -> Result<Page<WebhookDeliveryView>, AuthError> {
        let cursor = page.cursor()?;
        let limit = page.limit();
        self.get(org, endpoint).await?;
        let (after_ts, after_id) = match cursor {
            Some(c) => (Some(crate::query::micros_to_time(c.sort_key)?), Some(c.id)),
            None => (None, None),
        };
        let rows: Vec<WebhookDeliveryView> = sqlx::query_as(concat!(
            "SELECT ",
            delivery_columns!(),
            " FROM webhook_deliveries WHERE org_id = $1 AND endpoint_id = $2 \
              AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4)) \
             ORDER BY created_at DESC, id DESC LIMIT $5"
        ))
        .bind(org)
        .bind(endpoint)
        .bind(after_ts)
        .bind(after_id)
        .bind(i64::from(limit) + 1)
        .fetch_all(&self.pool)
        .await?;
        Ok(Page::from_overfetch(rows, limit, |row| Cursor {
            sort_key: crate::query::time_to_micros(row.created_at),
            id: row.id.as_uuid(),
        }))
    }

    /// Schedules a finished (succeeded or dead) delivery again.
    pub async fn redeliver(
        &self,
        org: OrgId,
        endpoint: WebhookEndpointId,
        delivery: WebhookDeliveryId,
        by: &ActingPrincipal,
    ) -> Result<WebhookDeliveryView, AuthError> {
        let now = self.clock.now();
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, String, Option<OffsetDateTime>)> = sqlx::query_as(
            "SELECT d.status, e.status, d.redacted_at FROM webhook_deliveries d \
             JOIN webhook_endpoints e ON e.id = d.endpoint_id AND e.org_id = d.org_id \
             WHERE d.id = $1 AND d.endpoint_id = $2 AND d.org_id = $3 FOR UPDATE OF d",
        )
        .bind(delivery)
        .bind(endpoint)
        .bind(org)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((delivery_status, endpoint_status, redacted_at)) = row else {
            return Err(not_found());
        };
        // K-58: the subject's account was erased and the payload redacted;
        // there is nothing left to send.
        if redacted_at.is_some() {
            return Err(not_found());
        }
        if endpoint_status != "active" {
            return Err(AuthError::new(codes::audit::WEBHOOK_ENDPOINT_DISABLED));
        }
        if delivery_status == "pending" || delivery_status == "failed" {
            return Err(AuthError::new(codes::audit::WEBHOOK_DELIVERY_IN_PROGRESS));
        }
        let view: WebhookDeliveryView = sqlx::query_as(concat!(
            "UPDATE webhook_deliveries SET status = 'pending', next_attempt_at = $2 \
             WHERE id = $1 RETURNING ",
            delivery_columns!()
        ))
        .bind(delivery)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        enqueue_delivery(&mut tx, org, delivery, self.config.max_attempts, now).await?;
        let event = self
            .audit_event(
                SecurityEventKind::WebhookRedeliveryRequested,
                org,
                endpoint,
                by,
            )
            .with_meta("delivery_id", delivery.to_string());
        self.sink.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(view)
    }
}

/// Serializes endpoint creation per organization (endpoint limit).
async fn lock_org(conn: &mut PgConnection, org: OrgId) -> Result<(), AuthError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('authn-audit:webhook-endpoints:' || $1::text, 0))")
        .bind(org.to_string())
        .execute(conn)
        .await?;
    Ok(())
}

/// Enqueues a `webhook.delivery` outbox message for a delivery row.
pub(crate) async fn enqueue_delivery(
    conn: &mut PgConnection,
    org: OrgId,
    delivery: WebhookDeliveryId,
    max_attempts: u32,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    OutboxRepository::enqueue(
        conn,
        &NewOutboxMessage {
            id: OutboxMessageId::generate(),
            topic: WEBHOOK_DELIVERY_TOPIC.to_owned(),
            org_id: Some(org),
            payload: json!({ "delivery_id": delivery }),
            sealed_payload: None,
            max_attempts,
            available_at: now,
            created_at: now,
        },
    )
    .await?;
    Ok(())
}

/// Re-wraps every sealed webhook secret with the current KEK (KEK
/// rotation, CRY-08; called by the `rotate-kek` / `reencrypt` command).
/// Returns the number of rows changed.
pub async fn rewrap_webhook_secrets(
    pool: &PgPool,
    cipher: &EnvelopeCipher,
) -> Result<u64, AuthError> {
    let rows: Vec<(WebhookEndpointId, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT id, secret_ciphertext, previous_secret_ciphertext FROM webhook_endpoints",
    )
    .fetch_all(pool)
    .await?;
    let mut changed = 0;
    for (id, current, previous) in rows {
        let new_current = cipher.rewrap(&current, &secret_context(id)?).await?;
        let new_previous = match &previous {
            Some(sealed) => cipher.rewrap(sealed, &previous_secret_context(id)?).await?,
            None => None,
        };
        if new_current.is_none() && new_previous.is_none() {
            continue;
        }
        sqlx::query(
            "UPDATE webhook_endpoints SET secret_ciphertext = coalesce($2, secret_ciphertext), \
             previous_secret_ciphertext = coalesce($3, previous_secret_ciphertext) \
             WHERE id = $1 AND secret_ciphertext = $4",
        )
        .bind(id)
        .bind(&new_current)
        .bind(&new_previous)
        .bind(&current)
        .execute(pool)
        .await?;
        changed += 1;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aud_07_event_types_are_validated_and_normalized() {
        let ok = validate_event_types(&[
            "user.created".to_owned(),
            "member.added".to_owned(),
            "user.created".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            ok,
            vec!["member.added".to_owned(), "user.created".to_owned()]
        );
        for bad in [vec![], vec!["user.hacked".to_owned()], vec!["*".to_owned()]] {
            let err = validate_event_types(&bad).unwrap_err();
            assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
        }
    }

    #[test]
    fn aud_07_description_rules() {
        assert_eq!(validate_description(Some("  ".into())).unwrap(), None);
        assert_eq!(
            validate_description(Some(" Billing sync ".into())).unwrap(),
            Some("Billing sync".into())
        );
        assert!(validate_description(Some("a\u{0}b".into())).is_err());
        assert!(validate_description(Some("x".repeat(501))).is_err());
    }

    #[test]
    fn aud_07_secret_is_redacted_in_debug() {
        let view = WebhookEndpointView {
            id: WebhookEndpointId::generate(),
            org_id: OrgId::generate(),
            url: "https://hooks.example.com/".into(),
            description: None,
            event_types: vec!["user.created".into()],
            status: "active".into(),
            consecutive_failures: 0,
            disabled_reason: None,
            failing_since: None,
            last_success_at: None,
            previous_secret_expires_at: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let with_secret = WebhookEndpointWithSecret {
            endpoint: view,
            secret: "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw".into(),
        };
        let debug = format!("{with_secret:?}");
        assert!(!debug.contains("MfKQ9r8"), "{debug}");
    }
}
