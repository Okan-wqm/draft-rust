//! Signing keys of provider tokens (OIDP-08).
//!
//! The provider signs with the **same** key set as the native tokens
//! (CRY-09/CRY-10: `signing_keys`, `pending → active → retired → revoked`,
//! emergency rotation, the JWKS of SES-09); it never creates keys. This is
//! a small per-process snapshot of the active signer and the publishable
//! verifier, reloaded after [`KEY_TTL`] at most — so an emergency
//! revocation (ADM-06) stops verification here within seconds even
//! without a change notification — and dropped at once by
//! [`KeyCache::invalidate`] (in-process emergency rotation).
//!
//! **Pool pattern (K-58):** issuance inside a transaction reloads through
//! the caller's connection ([`KeyCache::signer_in`]); reloads through the
//! pool happen only outside transactions.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use authn_core::error::AuthError;
use authn_core::ports::Clock;
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::jwt::{JwtSigner, JwtVerifier};
use authn_store::{SigningKeyError, SigningKeyRepository};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

/// Longest age of a key snapshot.
pub const KEY_TTL: Duration = Duration::from_secs(5);

struct Snapshot {
    loaded_at: OffsetDateTime,
    signer: Option<JwtSigner>,
    verifier: Arc<JwtVerifier>,
}

/// The key snapshot cache.
pub(crate) struct KeyCache {
    pool: PgPool,
    cipher: EnvelopeCipher,
    clock: Arc<dyn Clock>,
    current: RwLock<Option<Arc<Snapshot>>>,
}

impl KeyCache {
    pub(crate) fn new(pool: PgPool, cipher: EnvelopeCipher, clock: Arc<dyn Clock>) -> Self {
        Self {
            pool,
            cipher,
            clock,
            current: RwLock::new(None),
        }
    }

    /// Drops the snapshot.
    pub(crate) fn invalidate(&self) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn fresh(&self) -> Option<Arc<Snapshot>> {
        let now = self.clock.now();
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .filter(|s| {
                let age = now - s.loaded_at;
                !age.is_negative() && age.unsigned_abs() < KEY_TTL
            })
    }

    async fn load(&self, conn: &mut PgConnection) -> Result<Arc<Snapshot>, AuthError> {
        let now = self.clock.now();
        let verifier = SigningKeyRepository::verifier(&mut *conn, now).await?;
        let signer = match SigningKeyRepository::load_active_signer(&mut *conn, &self.cipher).await
        {
            Ok(signer) => Some(signer),
            Err(SigningKeyError::NoActiveKey) => None,
            Err(err) => return Err(err.into()),
        };
        let snapshot = Arc::new(Snapshot {
            loaded_at: now,
            signer,
            verifier: Arc::new(verifier),
        });
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// The active signer, reloading through `conn` when stale.
    pub(crate) async fn signer_in(&self, conn: &mut PgConnection) -> Result<JwtSigner, AuthError> {
        let snapshot = match self.fresh() {
            Some(s) if s.signer.is_some() => s,
            _ => self.load(conn).await?,
        };
        snapshot.signer.clone().ok_or_else(|| {
            AuthError::new(authn_core::error::codes::common::SERVICE_UNAVAILABLE)
                .with_context("no active JWT signing key")
        })
    }

    /// The verifier of every publishable key (pool; call outside a
    /// transaction).
    pub(crate) async fn verifier(&self) -> Result<Arc<JwtVerifier>, AuthError> {
        if let Some(s) = self.fresh() {
            return Ok(s.verifier.clone());
        }
        let mut conn = self.pool.acquire().await?;
        Ok(self.load(&mut conn).await?.verifier.clone())
    }
}
