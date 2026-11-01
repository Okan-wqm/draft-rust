//! Per-process cache of the JWT signing keys (CRY-10, SES-05, SES-09).
//!
//! The signer (active key, private part opened from its envelope), the
//! verifier (every publishable key) and the JWKS are loaded together and
//! kept for `session.signing_key_cache_ttl` (default 30 s). A token whose
//! `kid` is unknown triggers at most one early reload per
//! [`MIN_RELOAD_INTERVAL`], so a newly activated key is picked up at once
//! without letting garbage `kid`s hammer the database.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use authn_core::error::{AuthError, codes};
use authn_core::ports::Clock;
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::jwt::{JwkSet, JwtSigner, JwtVerifier};
use authn_store::{SigningKeyError, SigningKeyRepository};
use sqlx::PgPool;
use time::OffsetDateTime;

/// Shortest interval between two reloads triggered by an unknown `kid`.
pub const MIN_RELOAD_INTERVAL: Duration = Duration::from_secs(5);

/// One consistent view of the keys.
pub(crate) struct KeySnapshot {
    pub(crate) loaded_at: OffsetDateTime,
    pub(crate) signer: Option<JwtSigner>,
    pub(crate) verifier: JwtVerifier,
    pub(crate) jwks: JwkSet,
}

/// The cache.
pub(crate) struct KeyCache {
    pool: PgPool,
    cipher: EnvelopeCipher,
    clock: Arc<dyn Clock>,
    ttl: Duration,
    current: RwLock<Option<Arc<KeySnapshot>>>,
    reload: tokio::sync::Mutex<()>,
}

fn age(now: OffsetDateTime, then: OffsetDateTime) -> Duration {
    let diff = now - then;
    if diff.is_negative() {
        // The clock went backwards: treat the snapshot as stale.
        Duration::MAX
    } else {
        diff.unsigned_abs()
    }
}

impl KeyCache {
    pub(crate) fn new(
        pool: PgPool,
        cipher: EnvelopeCipher,
        clock: Arc<dyn Clock>,
        ttl: Duration,
    ) -> Self {
        Self {
            pool,
            cipher,
            clock,
            ttl,
            current: RwLock::new(None),
            reload: tokio::sync::Mutex::new(()),
        }
    }

    fn cached(&self) -> Option<Arc<KeySnapshot>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Drops the cached keys (tests, emergency rotation in-process).
    pub(crate) fn invalidate(&self) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// A fresh snapshot; `reload_if_older_than` forces a reload of a
    /// snapshot older than the given age (unknown `kid`).
    pub(crate) async fn snapshot(
        &self,
        reload_if_older_than: Option<Duration>,
    ) -> Result<Arc<KeySnapshot>, AuthError> {
        let max_age = reload_if_older_than.map_or(self.ttl, |a| a.min(self.ttl));
        if let Some(snapshot) = self.cached()
            && age(self.clock.now(), snapshot.loaded_at) < max_age
        {
            return Ok(snapshot);
        }
        let _guard = self.reload.lock().await;
        // Another task may have reloaded while we waited.
        if let Some(snapshot) = self.cached()
            && age(self.clock.now(), snapshot.loaded_at) < max_age
        {
            return Ok(snapshot);
        }
        let snapshot = Arc::new(self.load().await?);
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(snapshot.clone());
        Ok(snapshot)
    }

    async fn load(&self) -> Result<KeySnapshot, AuthError> {
        let now = self.clock.now();
        let keys = SigningKeyRepository::publishable(&self.pool, now).await?;
        let verifier = JwtVerifier::new(keys.iter().map(|k| (k.kid(), k.public_key)));
        let pairs: Vec<(String, _)> = keys.iter().map(|k| (k.kid(), k.public_key)).collect();
        let jwks = JwkSet::from_keys(pairs.iter().map(|(kid, key)| (kid.as_str(), key)));
        let signer = match SigningKeyRepository::load_active_signer(&self.pool, &self.cipher).await
        {
            Ok(signer) => Some(signer),
            Err(SigningKeyError::NoActiveKey) => {
                tracing::warn!("no active JWT signing key; access tokens cannot be issued");
                None
            }
            Err(err) => return Err(err.into()),
        };
        Ok(KeySnapshot {
            loaded_at: now,
            signer,
            verifier,
            jwks,
        })
    }

    /// The active signer.
    pub(crate) async fn signer(&self) -> Result<JwtSigner, AuthError> {
        let snapshot = self.snapshot(None).await?;
        if let Some(signer) = &snapshot.signer {
            return Ok(signer.clone());
        }
        // No active key in the snapshot: try once more (a key may have been
        // activated since).
        let snapshot = self.snapshot(Some(MIN_RELOAD_INTERVAL)).await?;
        snapshot.signer.clone().ok_or_else(|| {
            AuthError::new(codes::common::SERVICE_UNAVAILABLE).with_context("no active signing key")
        })
    }

    /// The verifier, reloaded early if it does not know `kid`.
    pub(crate) async fn verifier_for(&self, kid: Option<&str>) -> Result<JwtVerifier, AuthError> {
        let snapshot = self.snapshot(None).await?;
        match kid {
            Some(kid) if !snapshot.verifier.contains(kid) => Ok(self
                .snapshot(Some(MIN_RELOAD_INTERVAL))
                .await?
                .verifier
                .clone()),
            _ => Ok(snapshot.verifier.clone()),
        }
    }

    /// The JWKS (public keys only, SES-09).
    pub(crate) async fn jwks(&self) -> Result<JwkSet, AuthError> {
        Ok(self.snapshot(None).await?.jwks.clone())
    }
}

/// The `kid` of a compact JWS, read without verifying anything (used only
/// to decide whether an early cache reload is worthwhile; the verifier
/// re-parses and checks the header strictly).
pub(crate) fn peek_kid(token: &str) -> Option<String> {
    let header = token.split('.').next()?;
    if header.is_empty() || header.len() > 512 {
        return None;
    }
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(header.as_bytes())
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("kid")?.as_str().map(str::to_owned)
}
