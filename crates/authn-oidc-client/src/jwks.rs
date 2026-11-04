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

type Slot = Arc<tokio::sync::Mutex<Option<Entry>>>;

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
        if let Some(entry) = guard.as_ref() {
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
                *guard = Some(entry);
                Ok(found)
            }
            Err(_) => {
                tracing::warn!(
                    host = url.host_str().unwrap_or_default(),
                    "JWKS download failed"
                );
                match guard.as_ref().and_then(|e| e.find(kid)) {
                    Some(stale) => Ok(Some(stale)),
                    None => Err(AuthError::new(
                        authn_core::error::codes::common::SERVICE_UNAVAILABLE,
                    )
                    .with_context("provider JWKS unavailable")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
