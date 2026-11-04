//! Provider JWKS cache (SOC-03).
//!
//! * Keys are cached per JWKS URL for `oidc_client.jwks_cache_ttl`.
//! * A token whose `kid` is not in a fresh cache forces one download (key
//!   rotation), but at most once per `jwks_refresh_min_interval` per URL:
//!   tokens with random `kid` values cannot turn into a request flood to
//!   the provider.
//! * Concurrent refreshes of one URL are coalesced (per-URL async lock);
//!   providers do not block each other.
//! * When a download fails, a stale cache that has the key is still used
//!   (the provider's key did not change by being unreachable).
//! * Failed downloads back off per URL (K-16): after the n-th consecutive
//!   failure no download is attempted for
//!   `min(JWKS_BACKOFF_BASE · 2^(n-1), JWKS_BACKOFF_MAX)`; meanwhile
//!   verifications use the stale key if there is one and otherwise fail
//!   fast with `service_unavailable` (no request to the provider). During
//!   a provider outage a flood of logins therefore costs at most one
//!   download attempt per backoff interval, not one per login. The first
//!   successful download resets the backoff.
//! * Entries that are not signature keys (`use` ≠ `sig`), unparseable keys
//!   and symmetric keys are dropped; at most [`MAX_KEYS`] keys are kept.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use authn_core::error::AuthError;
use authn_core::ports::{HttpClient, OutboundTarget};
use openidconnect::JsonWebKey as _;
use openidconnect::core::{CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse};
use time::OffsetDateTime;
use url::Url;

use crate::outbound;

/// Most keys kept from one JWKS document.
pub const MAX_KEYS: usize = 64;
/// Wait after the first failed download of a JWKS URL (K-16).
pub const JWKS_BACKOFF_BASE: Duration = Duration::from_secs(5);
/// Longest wait between two download attempts of a failing JWKS URL.
pub const JWKS_BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Backoff after `failures` consecutive failed downloads (≥ 1).
#[must_use]
pub fn backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(16);
    JWKS_BACKOFF_BASE
        .saturating_mul(1_u32 << exponent)
        .min(JWKS_BACKOFF_MAX)
}

#[derive(Clone)]
struct Entry {
    keys: Arc<Vec<CoreJsonWebKey>>,
    fetched_at: OffsetDateTime,
}

impl Entry {
    fn find(&self, kid: &str) -> Option<CoreJsonWebKey> {
        self.keys
            .iter()
            .find(|k| k.key_id().is_some_and(|id| id.as_str() == kid))
            .cloned()
    }
}

/// Per-URL state: the cached keys and the download backoff.
#[derive(Default)]
struct SlotState {
    entry: Option<Entry>,
    /// Consecutive failed downloads.
    failures: u32,
    /// No download before this instant (set after a failure).
    retry_at: Option<OffsetDateTime>,
}

type Slot = Arc<tokio::sync::Mutex<SlotState>>;

/// The JWKS cache. Cheap to clone (shared state).
#[derive(Clone)]
pub struct JwksCache {
    slots: Arc<Mutex<HashMap<String, Slot>>>,
    ttl: Duration,
    min_refresh: Duration,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("ttl", &self.ttl)
            .field("min_refresh", &self.min_refresh)
            .finish_non_exhaustive()
    }
}

/// Parses a JWKS document into usable signature keys.
pub fn parse_jwks(body: &[u8]) -> Result<Vec<CoreJsonWebKey>, AuthError> {
    #[derive(serde::Deserialize)]
    struct Document {
        keys: Vec<serde_json::Value>,
    }
    let doc: Document = serde_json::from_slice(body)
        .map_err(|_| AuthError::internal("provider JWKS is not a JWK set"))?;
    Ok(doc
        .keys
        .into_iter()
        .filter_map(|raw| serde_json::from_value::<CoreJsonWebKey>(raw).ok())
        .filter(|key| key.key_id().is_some())
        .filter(|key| !matches!(key.key_type(), CoreJsonWebKeyType::Symmetric))
        .filter(|key| {
            key.key_use()
                .is_none_or(|u| matches!(u, CoreJsonWebKeyUse::Signature))
        })
        .take(MAX_KEYS)
        .collect())
}

fn unavailable() -> AuthError {
    AuthError::new(authn_core::error::codes::common::SERVICE_UNAVAILABLE)
        .with_context("provider JWKS unavailable")
}

fn age(now: OffsetDateTime, then: OffsetDateTime) -> Duration {
    let diff = now - then;
    if diff.is_negative() {
        Duration::ZERO
    } else {
        diff.unsigned_abs()
    }
}

impl JwksCache {
    /// A cache keeping keys for `ttl`, forcing a refresh on an unknown `kid`
    /// at most every `min_refresh`.
    #[must_use]
    pub fn new(ttl: Duration, min_refresh: Duration) -> Self {
        Self {
            slots: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            min_refresh,
        }
    }

    fn slot(&self, url: &Url) -> Slot {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slots.entry(url.as_str().to_owned()).or_default().clone()
    }

    /// The key `kid` of the JWKS at `url`, downloading it when the cache is
    /// stale or (rate-limited) when the key is unknown. `Ok(None)`: no such
    /// key.
    pub async fn key(
        &self,
        http: &dyn HttpClient,
        url: &Url,
        target: OutboundTarget,
        kid: &str,
        now: OffsetDateTime,
    ) -> Result<Option<CoreJsonWebKey>, AuthError> {
        let slot = self.slot(url);
        let mut guard = slot.lock().await;
        if let Some(entry) = guard.entry.as_ref() {
            let fresh = age(now, entry.fetched_at) < self.ttl;
            if fresh {
                if let Some(key) = entry.find(kid) {
                    return Ok(Some(key));
                }
                if age(now, entry.fetched_at) < self.min_refresh {
                    tracing::info!(
                        host = url.host_str().unwrap_or_default(),
                        "unknown JWKS kid; refresh rate-limited"
                    );
                    return Ok(None);
                }
            }
        }
        if let Some(retry_at) = guard.retry_at
            && now < retry_at
        {
            // Backing off after failed downloads: no request to the
            // provider; a stale key still verifies (K-16).
            crate::metrics::jwks_failure("backoff");
            return match guard.entry.as_ref().and_then(|e| e.find(kid)) {
                Some(stale) => Ok(Some(stale)),
                None => Err(unavailable()),
            };
        }
        let fetched = outbound::get(http, url.clone(), target, None, None)
            .await
            .and_then(|r| {
                if r.status.is_success() {
                    parse_jwks(&r.body)
                } else {
                    Err(AuthError::internal("provider JWKS request failed"))
                }
            });
        match fetched {
            Ok(keys) => {
                let entry = Entry {
                    keys: Arc::new(keys),
                    fetched_at: now,
                };
                let found = entry.find(kid);
                *guard = SlotState {
                    entry: Some(entry),
                    failures: 0,
                    retry_at: None,
                };
                Ok(found)
            }
            Err(_) => {
                crate::metrics::jwks_failure("failed");
                guard.failures = guard.failures.saturating_add(1);
                let wait = backoff(guard.failures);
                guard.retry_at = time::Duration::try_from(wait)
                    .ok()
                    .and_then(|w| now.checked_add(w));
                tracing::warn!(
                    host = url.host_str().unwrap_or_default(),
                    failures = guard.failures,
                    backoff_secs = wait.as_secs(),
                    "JWKS download failed"
                );
                match guard.entry.as_ref().and_then(|e| e.find(kid)) {
                    Some(stale) => Ok(Some(stale)),
                    None => Err(unavailable()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_03_jwks_backoff_is_exponential_and_bounded() {
        assert_eq!(backoff(1), Duration::from_secs(5));
        assert_eq!(backoff(2), Duration::from_secs(10));
        assert_eq!(backoff(3), Duration::from_secs(20));
        assert_eq!(backoff(7), Duration::from_secs(300));
        assert_eq!(backoff(u32::MAX), JWKS_BACKOFF_MAX);
        assert_eq!(backoff(0), JWKS_BACKOFF_BASE);
    }

    #[test]
    fn soc_03_jwks_parsing_drops_symmetric_encryption_and_unnamed_keys() {
        let body = serde_json::json!({ "keys": [
            { "kty": "oct", "kid": "hmac", "k": "c2VjcmV0" },
            { "kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "good", "use": "sig", "n": "AQAB", "e": "AQAB" },
            { "kty": "weird", "kid": "x" },
            "garbage"
        ]});
        let keys = parse_jwks(body.to_string().as_bytes()).unwrap();
        let kids: Vec<&str> = keys
            .iter()
            .filter_map(|k| k.key_id().map(|id| id.as_str()))
            .collect();
        assert_eq!(kids, vec!["good"]);
        assert!(parse_jwks(b"[]").is_err());
    }
}
