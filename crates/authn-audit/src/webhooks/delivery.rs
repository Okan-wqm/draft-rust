//! Webhook delivery (AUD-07): the `webhook.delivery` outbox handler.
//!
//! Each attempt signs the stored body with Standard Webhooks headers
//! (`webhook-id` = event id, stable across retries; `webhook-timestamp`;
//! `webhook-signature` with one `v1,` entry per valid secret — two during a
//! rotation overlap) and sends it through the `HttpClient` port with
//! [`OutboundTarget::UserSupplied`] (SSRF protection, PRT-12). Outcomes are
//! written to `webhook_deliveries` (history) and the endpoint's failure
//! streak; sustained failures disable the endpoint automatically.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use authn_core::config::audit::WebhookConfig;
use authn_core::error::AuthError;
use authn_core::id::{EventId, OrgId, WebhookDeliveryId, WebhookEndpointId};
use authn_core::ports::{
    Actor, AuditSink as _, Clock, HttpClient, OutboundRequest, OutboundTarget, SecurityEvent,
    SecurityEventKind,
};
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::webhook::{WebhookError, WebhookSecret, sign};
use http::header::{CONTENT_TYPE, RETRY_AFTER, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use url::Url;

use super::endpoints::{open_secret, previous_secret_context, secret_context};
use crate::canonical;
use crate::outbox::{HandlerError, OutboxHandler, OutboxMessage, backoff_delay, jittered};
use crate::sink::PgAuditSink;

/// Topic of delivery messages.
pub const WEBHOOK_DELIVERY_TOPIC: &str = "webhook.delivery";
/// Prefix under which [`WebhookDeliverer`] is registered.
pub const WEBHOOK_TOPIC_PREFIX: &str = "webhook";
/// Largest body sent to a receiver.
pub const MAX_WEBHOOK_BODY_BYTES: usize = 256 * 1024;
/// Receiver responses are read up to this size (and never stored).
pub const MAX_RESPONSE_BYTES: usize = 4096;
/// `User-Agent` of deliveries.
pub const WEBHOOK_USER_AGENT: &str = "rust-authentication-webhooks/1";

/// The headers of one signed delivery attempt: `content-type`,
/// `user-agent` and the Standard Webhooks `webhook-id`,
/// `webhook-timestamp`, `webhook-signature` (one `v1,` entry per secret).
pub fn signed_delivery_headers(
    secrets: &[WebhookSecret],
    webhook_id: &str,
    at: OffsetDateTime,
    body: &[u8],
) -> Result<HeaderMap, WebhookError> {
    if body.len() > MAX_WEBHOOK_BODY_BYTES {
        return Err(WebhookError::Signing);
    }
    let signed = sign(secrets, webhook_id, at, body)?;
    let header = |value: &str| HeaderValue::from_str(value).map_err(|_| WebhookError::Signing);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(USER_AGENT, HeaderValue::from_static(WEBHOOK_USER_AGENT));
    headers.insert(HeaderName::from_static("webhook-id"), header(&signed.id)?);
    headers.insert(
        HeaderName::from_static("webhook-timestamp"),
        header(&signed.timestamp)?,
    );
    headers.insert(
        HeaderName::from_static("webhook-signature"),
        header(&signed.signature)?,
    );
    Ok(headers)
}

/// Builds the signed `POST` of one delivery attempt.
///
/// The request targets [`OutboundTarget::UserSupplied`]: the `HttpClient`
/// implementation enforces `https`, public destinations, the pinned IP,
/// no redirects, the timeout and the response-size limit.
pub fn build_signed_request(
    url: Url,
    secrets: &[WebhookSecret],
    webhook_id: &str,
    at: OffsetDateTime,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<OutboundRequest, WebhookError> {
    let headers = signed_delivery_headers(secrets, webhook_id, at, &body)?;
    let mut request = OutboundRequest::post(url, body, OutboundTarget::UserSupplied);
    request.headers = headers;
    request.timeout = Some(timeout);
    request.max_response_bytes = Some(MAX_RESPONSE_BYTES);
    Ok(request)
}

/// Parses `Retry-After` given in seconds (HTTP dates are ignored).
fn retry_after_seconds(value: Option<&HeaderValue>) -> Option<Duration> {
    let text = value?.to_str().ok()?.trim();
    if text.is_empty() || text.len() > 9 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().map(Duration::from_secs)
}

#[derive(sqlx::FromRow)]
struct DeliveryRow {
    id: WebhookDeliveryId,
    org_id: OrgId,
    endpoint_id: WebhookEndpointId,
    event_id: EventId,
    payload: sqlx::types::Json<Value>,
    status: String,
    url: String,
    endpoint_status: String,
    secret_ciphertext: Vec<u8>,
    previous_secret_ciphertext: Option<Vec<u8>>,
    previous_secret_expires_at: Option<OffsetDateTime>,
}

/// Result of one HTTP attempt.
#[derive(Debug, Clone)]
struct Attempt {
    success: bool,
    response_status: Option<i32>,
    response_ms: i32,
    error: Option<String>,
    retry_after: Option<Duration>,
}

/// The `webhook.*` outbox handler.
#[derive(Clone)]
pub struct WebhookDeliverer {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    cipher: EnvelopeCipher,
    http: Arc<dyn HttpClient>,
    sink: PgAuditSink,
    config: WebhookConfig,
}

impl std::fmt::Debug for WebhookDeliverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookDeliverer").finish_non_exhaustive()
    }
}

impl WebhookDeliverer {
    /// Creates the deliverer.
    #[must_use]
    pub fn new(
        pool: PgPool,
        clock: Arc<dyn Clock>,
        cipher: EnvelopeCipher,
        http: Arc<dyn HttpClient>,
        sink: PgAuditSink,
        config: WebhookConfig,
    ) -> Self {
        Self {
            pool,
            clock,
            cipher,
            http,
            sink,
            config,
        }
    }

    async fn load(&self, id: WebhookDeliveryId) -> Result<Option<DeliveryRow>, AuthError> {
        Ok(sqlx::query_as(
            "SELECT d.id, d.org_id, d.endpoint_id, d.event_id, d.payload, d.status, \
             e.url, e.status AS endpoint_status, e.secret_ciphertext, \
             e.previous_secret_ciphertext, e.previous_secret_expires_at \
             FROM webhook_deliveries d \
             JOIN webhook_endpoints e ON e.id = d.endpoint_id AND e.org_id = d.org_id \
             WHERE d.id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn secrets(
        &self,
        row: &DeliveryRow,
        now: OffsetDateTime,
    ) -> Result<Vec<WebhookSecret>, AuthError> {
        let mut secrets = vec![
            open_secret(
                &self.cipher,
                &row.secret_ciphertext,
                &secret_context(row.endpoint_id)?,
            )
            .await?,
        ];
        if let (Some(sealed), Some(expires_at)) = (
            &row.previous_secret_ciphertext,
            row.previous_secret_expires_at,
        ) && expires_at > now
        {
            secrets.push(
                open_secret(
                    &self.cipher,
                    sealed,
                    &previous_secret_context(row.endpoint_id)?,
                )
                .await?,
            );
        }
        Ok(secrets)
    }

    async fn mark_dead(&self, id: WebhookDeliveryId, error: Option<&str>) -> Result<(), AuthError> {
        sqlx::query(concat!(
            "UPDATE webhook_deliveries SET status = 'dead', next_attempt_at = NULL, \
                 last_error = coalesce($2, last_error), ",
            crate::webhooks::redact_if_erased!("'dead'", "$3"),
            " WHERE id = $1 AND status <> 'succeeded'"
        ))
        .bind(id)
        .bind(error)
        .bind(self.clock.now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn send(&self, request: OutboundRequest) -> Attempt {
        let started = Instant::now();
        let result = self.http.execute(request).await;
        let response_ms = i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
        match result {
            Ok(response) if response.status.is_success() => Attempt {
                success: true,
                response_status: Some(i32::from(response.status.as_u16())),
                response_ms,
                error: None,
                retry_after: None,
            },
            Ok(response) => Attempt {
                success: false,
                response_status: Some(i32::from(response.status.as_u16())),
                response_ms,
                // Never the body: it is attacker-controlled and may reflect
                // anything.
                error: Some(format!("http_status_{}", response.status.as_u16())),
                retry_after: retry_after_seconds(response.headers.get(RETRY_AFTER)),
            },
            Err(err) => Attempt {
                success: false,
                response_status: None,
                response_ms,
                error: Some(format!("transport_error:{}", err.code().code())),
                retry_after: None,
            },
        }
    }

    /// Records the attempt; returns whether the endpoint was disabled now.
    async fn record_attempt(
        &self,
        row: &DeliveryRow,
        attempt: &Attempt,
        final_attempt: bool,
        next_attempt_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        let status = if attempt.success {
            "succeeded"
        } else if final_attempt {
            "dead"
        } else {
            "failed"
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query(concat!(
            "UPDATE webhook_deliveries SET attempts = attempts + 1, last_attempt_at = $2, \
                 response_status = $3, response_ms = $4, last_error = $5, status = $6, \
                 next_attempt_at = $7, ",
            crate::webhooks::redact_if_erased!("$6", "$2"),
            " WHERE id = $1"
        ))
        .bind(row.id)
        .bind(now)
        .bind(attempt.response_status)
        .bind(attempt.response_ms)
        .bind(&attempt.error)
        .bind(status)
        .bind(if attempt.success || final_attempt {
            None
        } else {
            next_attempt_at
        })
        .execute(&mut *tx)
        .await?;

        let endpoint: Option<(String, i32, Option<OffsetDateTime>)> = sqlx::query_as(
            "SELECT status, consecutive_failures, failing_since FROM webhook_endpoints \
             WHERE id = $1 AND org_id = $2 FOR UPDATE",
        )
        .bind(row.endpoint_id)
        .bind(row.org_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((endpoint_status, failures, failing_since)) = endpoint else {
            tx.commit().await?;
            return Ok(false);
        };
        let mut disabled_now = false;
        if attempt.success {
            sqlx::query(
                "UPDATE webhook_endpoints SET consecutive_failures = 0, failing_since = NULL, \
                 last_success_at = $3 WHERE id = $1 AND org_id = $2",
            )
            .bind(row.endpoint_id)
            .bind(row.org_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        } else {
            let failures = failures.saturating_add(1);
            let failing_since = failing_since.unwrap_or(now);
            let threshold = i32::try_from(self.config.disable_after_failures).unwrap_or(i32::MAX);
            disabled_now = endpoint_status == "active"
                && failures >= threshold
                && now - failing_since >= self.config.disable_after;
            sqlx::query(
                "UPDATE webhook_endpoints SET consecutive_failures = $3, failing_since = $4, \
                 status = CASE WHEN $5 THEN 'disabled' ELSE status END, \
                 disabled_reason = CASE WHEN $5 THEN 'consecutive_failures' ELSE disabled_reason END \
                 WHERE id = $1 AND org_id = $2",
            )
            .bind(row.endpoint_id)
            .bind(row.org_id)
            .bind(failures)
            .bind(failing_since)
            .bind(disabled_now)
            .execute(&mut *tx)
            .await?;
            if disabled_now {
                let event = SecurityEvent::new(SecurityEventKind::WebhookEndpointAutoDisabled, now)
                    .with_actor(Actor::System)
                    .with_org(row.org_id)
                    .with_resource("webhook_endpoint", row.endpoint_id)
                    .with_meta("consecutive_failures", failures);
                self.sink.record_in_tx(&mut tx, event).await?;
            }
        }
        tx.commit().await?;
        Ok(disabled_now)
    }
}

#[async_trait]
impl OutboxHandler for WebhookDeliverer {
    async fn handle(&self, message: &OutboxMessage) -> Result<(), HandlerError> {
        if message.topic != WEBHOOK_DELIVERY_TOPIC {
            return Err(HandlerError::permanent("unknown webhook topic"));
        }
        let Some(delivery_id) = message
            .payload
            .get("delivery_id")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<WebhookDeliveryId>().ok())
        else {
            return Err(HandlerError::permanent("malformed delivery message"));
        };
        let row = self
            .load(delivery_id)
            .await
            .map_err(|_| HandlerError::retry("database unavailable"))?;
        // Endpoint or delivery deleted, or already finished (duplicate
        // message): nothing to do.
        let Some(row) = row else {
            return Ok(());
        };
        if row.status == "succeeded" || row.status == "dead" {
            return Ok(());
        }
        if row.endpoint_status != "active" {
            self.mark_dead(row.id, Some("endpoint_disabled"))
                .await
                .map_err(|_| HandlerError::retry("database unavailable"))?;
            return Ok(());
        }

        let now = self.clock.now();
        let body = match canonical::to_canonical_vec(&row.payload.0) {
            Ok(body) if body.len() <= MAX_WEBHOOK_BODY_BYTES => body,
            _ => {
                let _ = self.mark_dead(row.id, Some("payload_invalid")).await;
                return Err(HandlerError::permanent(
                    "webhook payload invalid or too large",
                ));
            }
        };
        let Ok(url) = Url::parse(&row.url) else {
            let _ = self.mark_dead(row.id, Some("url_invalid")).await;
            return Err(HandlerError::permanent("stored webhook url invalid"));
        };
        let secrets = self.secrets(&row, now).await.map_err(|err| {
            tracing::error!(endpoint.id = %row.endpoint_id, error = %err, "webhook secret unavailable");
            HandlerError::retry("signing secret unavailable")
        })?;
        let request = build_signed_request(
            url,
            &secrets,
            &row.event_id.to_string(),
            now,
            body,
            self.config.timeout,
        )
        .map_err(|_| HandlerError::permanent("webhook signing failed"))?;
        drop(secrets);

        let attempt = self.send(request).await;
        let final_attempt = !attempt.success && message.is_last_attempt();
        let delay = {
            let backoff = jittered(backoff_delay(
                message.attempts,
                self.config.backoff_base,
                self.config.backoff_max,
            ));
            attempt.retry_after.map_or(backoff, |requested| {
                backoff.max(requested.min(self.config.backoff_max))
            })
        };
        let now = self.clock.now();
        let disabled = self
            .record_attempt(&row, &attempt, final_attempt, Some(now + delay), now)
            .await
            .map_err(|_| HandlerError::retry("delivery outcome not recorded"))?;
        if attempt.success {
            tracing::debug!(delivery.id = %row.id, endpoint.id = %row.endpoint_id, "webhook delivered");
            return Ok(());
        }
        tracing::info!(
            delivery.id = %row.id,
            endpoint.id = %row.endpoint_id,
            status = attempt.response_status.unwrap_or(0),
            attempts = message.attempts,
            "webhook delivery failed"
        );
        if disabled {
            tracing::warn!(endpoint.id = %row.endpoint_id, "webhook endpoint disabled after sustained failures");
            return Err(HandlerError::permanent(
                "endpoint disabled after sustained failures",
            ));
        }
        let reason = attempt
            .error
            .unwrap_or_else(|| "delivery failed".to_owned());
        Err(HandlerError::retry_after(reason, delay))
    }

    async fn on_dead_letter(&self, message: &OutboxMessage) -> Result<(), AuthError> {
        let Some(delivery_id) = message
            .payload
            .get("delivery_id")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<WebhookDeliveryId>().ok())
        else {
            return Ok(());
        };
        self.mark_dead(delivery_id, None).await
    }
}

#[cfg(test)]
mod tests {
    use authn_crypto::webhook::{SignedHeaders, verify};

    use super::*;

    #[test]
    fn aud_07_signed_request_verifies_with_every_secret_and_targets_user_supplied() {
        let a = WebhookSecret::generate().unwrap();
        let b = WebhookSecret::generate().unwrap();
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let body = br#"{"type":"user.created"}"#.to_vec();
        let request = build_signed_request(
            Url::parse("https://hooks.example.com/in").unwrap(),
            &[a.clone(), b.clone()],
            "0192f3a4-1b2c-7d3e-8f90-0123456789ab",
            at,
            body.clone(),
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(request.target, OutboundTarget::UserSupplied);
        assert_eq!(request.max_response_bytes, Some(MAX_RESPONSE_BYTES));
        let get = |name: &str| {
            request
                .headers
                .get(name)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        };
        let headers = SignedHeaders {
            id: get("webhook-id"),
            timestamp: get("webhook-timestamp"),
            signature: get("webhook-signature"),
        };
        assert_eq!(headers.timestamp, "1800000000");
        for secret in [a, b] {
            assert!(verify(&[secret], &headers, &body, at, 300).is_ok());
        }
        let debug = format!("{request:?}");
        assert!(!debug.contains("v1,"), "{debug}");
    }

    #[test]
    fn aud_07_oversized_bodies_and_bad_ids_are_refused() {
        let secret = WebhookSecret::generate().unwrap();
        let url = Url::parse("https://hooks.example.com/in").unwrap();
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert!(
            build_signed_request(
                url.clone(),
                std::slice::from_ref(&secret),
                "id",
                at,
                vec![b'x'; MAX_WEBHOOK_BODY_BYTES + 1],
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            build_signed_request(
                url,
                &[secret],
                "a.b",
                at,
                b"{}".to_vec(),
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    #[test]
    fn aud_07_retry_after_parsing() {
        let v = |s: &'static str| HeaderValue::from_static(s);
        assert_eq!(
            retry_after_seconds(Some(&v("120"))),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            retry_after_seconds(Some(&v("Wed, 21 Oct 2015 07:28:00 GMT"))),
            None
        );
        assert_eq!(retry_after_seconds(Some(&v("-1"))), None);
        assert_eq!(retry_after_seconds(Some(&v("9999999999"))), None);
        assert_eq!(retry_after_seconds(None), None);
    }
}
