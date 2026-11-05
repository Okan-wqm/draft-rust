//! Per-process cache of the JWT signing keys (CRY-10, SES-05, SES-09).
//!
//! The signer (active key, private part opened from its envelope), the
//! verifier (every publishable key) and the JWKS are loaded together and
//! kept for `session.signing_key_cache_ttl` (default 30 s). A token whose
//! `kid` is unknown triggers at most one early reload per
//! [`MIN_RELOAD_INTERVAL`], so a newly activated key is picked up at once
//! without letting garbage `kid`s hammer the database.
//!
//! **Cross-instance invalidation (K-58).** Every change of `signing_keys`
//! (rotation, activation, emergency rotation, revocation — whether made by
//! this process, another instance or the CLI) sends a PostgreSQL
//! notification on [`SIGNING_KEYS_CHANNEL`] at commit (trigger of migration
//! `2001`). [`KeyCache::run_listener`] (wired by the server as a background
//! task, see `SessionService::run_signing_key_listener`) drops the cache on
//! every notification, so an emergency-revoked key stops verifying on every
//! instance within the notification latency instead of the cache lifetime.
//! Notifications are lost while the listener is disconnected; therefore the
//! cache is also dropped on every (re)connection, and while the listener is
//! down the cache lifetime shrinks to [`MIN_RELOAD_INTERVAL`].
//!
//! **No second pooled connection (K-58, pool pattern).** Token issuance
//! inside a transaction reloads an expired snapshot through the caller's
//! own connection ([`KeyCache::signer_in`]); it never waits for another
//! pooled connection while holding one. Reloads through the pool only
//! happen outside transactions (verification, JWKS).
//!
//! **Invalidation races.** Every invalidation bumps a generation counter;
//! a reload that started before an invalidation is never stored (and is
//! repeated), so a snapshot read just before a rotation committed cannot
//! survive the notification of that rotation.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use authn_core::error::{AuthError, codes};
use authn_core::ports::Clock;
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::jwt::{JwkSet, JwtSigner, JwtVerifier};
use authn_store::{SigningKeyError, SigningKeyRepository};
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

/// Shortest interval between two reloads triggered by an unknown `kid`;
/// also the cache lifetime while the change listener is disconnected.
pub const MIN_RELOAD_INTERVAL: Duration = Duration::from_secs(5);

/// PostgreSQL notification channel of signing-key changes (migration
/// `2001_signing_key_notify.sql`).
pub const SIGNING_KEYS_CHANNEL: &str = "authn_signing_keys";

/// Reloads attempted when invalidations keep racing a reload.
const MAX_RELOAD_ROUNDS: usize = 3;

/// Longest wait between two listener reconnection attempts.
const MAX_LISTENER_BACKOFF: Duration = Duration::from_secs(30);

/// Listener states ([`KeyCache::listener_state`]).
const LISTENER_NOT_RUNNING: u8 = 0;
const LISTENER_CONNECTED: u8 = 1;
const LISTENER_DOWN: u8 = 2;

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
    /// Bumped by every invalidation.
    generation: AtomicU64,
    /// Whether the change listener runs and is connected.
    listener: AtomicU8,
    /// Serializes reloads through the pool (never held by a caller that
    /// holds a connection).
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

/// Where a reload reads the keys from.
enum Source<'c> {
    /// A pooled connection (no transaction of the caller is open).
    Pool,
    /// The caller's connection (inside its transaction).
    Conn(&'c mut PgConnection),
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
            generation: AtomicU64::new(0),
            listener: AtomicU8::new(LISTENER_NOT_RUNNING),
            reload: tokio::sync::Mutex::new(()),
        }
    }

    fn cached(&self) -> Option<Arc<KeySnapshot>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Drops the cached keys: the next use reloads them. Called by the
    /// change listener, after an in-process emergency rotation and in
    /// tests.
    pub(crate) fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// The cache lifetime in force: the configured one, or
    /// [`MIN_RELOAD_INTERVAL`] while a started listener is disconnected
    /// (changes may go unnoticed).
    fn effective_ttl(&self) -> Duration {
        if self.listener.load(Ordering::SeqCst) == LISTENER_DOWN {
            self.ttl.min(MIN_RELOAD_INTERVAL)
        } else {
            self.ttl
        }
    }

    fn fresh(&self, max_age: Duration) -> Option<Arc<KeySnapshot>> {
        self.cached()
            .filter(|snapshot| age(self.clock.now(), snapshot.loaded_at) < max_age)
    }

    /// A fresh snapshot; `reload_if_older_than` forces a reload of a
    /// snapshot older than the given age (unknown `kid`).
    async fn snapshot(
        &self,
        reload_if_older_than: Option<Duration>,
        source: Source<'_>,
    ) -> Result<Arc<KeySnapshot>, AuthError> {
        let ttl = self.effective_ttl();
        let max_age = reload_if_older_than.map_or(ttl, |a| a.min(ttl));
        if let Some(snapshot) = self.fresh(max_age) {
            return Ok(snapshot);
        }
        match source {
            Source::Conn(conn) => self.reload(max_age, conn).await,
            Source::Pool => {
                let _guard = self.reload.lock().await;
                // Another task may have reloaded while we waited.
                if let Some(snapshot) = self.fresh(max_age) {
                    return Ok(snapshot);
                }
                let mut conn = self.pool.acquire().await?;
                self.reload(max_age, &mut conn).await
            }
        }
    }

    /// Loads and stores a snapshot through `conn`. A load that an
    /// invalidation overtook is neither stored nor trusted: it is repeated
    /// (at most [`MAX_RELOAD_ROUNDS`] times).
    async fn reload(
        &self,
        max_age: Duration,
        conn: &mut PgConnection,
    ) -> Result<Arc<KeySnapshot>, AuthError> {
        let mut last = None;
        for _ in 0..MAX_RELOAD_ROUNDS {
            if let Some(snapshot) = self.fresh(max_age) {
                return Ok(snapshot);
            }
            let generation = self.generation.load(Ordering::SeqCst);
            let snapshot = Arc::new(self.load(&mut *conn).await?);
            {
                let mut current = self
                    .current
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // Compared under the write lock: `invalidate` bumps the
                // generation before it takes this lock, so it either sees
                // this store (and clears it) or makes this check fail.
                if self.generation.load(Ordering::SeqCst) == generation {
                    *current = Some(snapshot.clone());
                    return Ok(snapshot);
                }
            }
            last = Some(snapshot);
        }
        // Invalidations keep arriving: answer with the newest load, uncached.
        last.ok_or_else(|| AuthError::internal("signing key reload did not run"))
    }

    async fn load(&self, conn: &mut PgConnection) -> Result<KeySnapshot, AuthError> {
        let now = self.clock.now();
        let keys = SigningKeyRepository::publishable(&mut *conn, now).await?;
        let verifier = JwtVerifier::new(keys.iter().map(|k| (k.kid(), k.public_key)));
        let pairs: Vec<(String, _)> = keys.iter().map(|k| (k.kid(), k.public_key)).collect();
        let jwks = JwkSet::from_keys(pairs.iter().map(|(kid, key)| (kid.as_str(), key)));
        let signer = match SigningKeyRepository::load_active_signer(&mut *conn, &self.cipher).await
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

    /// The active signer, reloading an expired snapshot through the pool
    /// (call only while no connection of this task is checked out).
    pub(crate) async fn signer(&self) -> Result<JwtSigner, AuthError> {
        let snapshot = self.snapshot(None, Source::Pool).await?;
        if let Some(signer) = &snapshot.signer {
            return Ok(signer.clone());
        }
        // No active key in the snapshot: try once more (a key may have been
        // activated since).
        let snapshot = self
            .snapshot(Some(MIN_RELOAD_INTERVAL), Source::Pool)
            .await?;
        snapshot.signer.clone().ok_or_else(no_active_key)
    }

    /// The active signer for issuance inside the caller's transaction: an
    /// expired snapshot is reloaded through `conn`, never through a second
    /// pooled connection.
    pub(crate) async fn signer_in(&self, conn: &mut PgConnection) -> Result<JwtSigner, AuthError> {
        let snapshot = self.snapshot(None, Source::Conn(&mut *conn)).await?;
        if let Some(signer) = &snapshot.signer {
            return Ok(signer.clone());
        }
        let snapshot = self
            .snapshot(Some(MIN_RELOAD_INTERVAL), Source::Conn(conn))
            .await?;
        snapshot.signer.clone().ok_or_else(no_active_key)
    }

    /// The verifier, reloaded early if it does not know `kid`.
    pub(crate) async fn verifier_for(&self, kid: Option<&str>) -> Result<JwtVerifier, AuthError> {
        let snapshot = self.snapshot(None, Source::Pool).await?;
        match kid {
            Some(kid) if !snapshot.verifier.contains(kid) => Ok(self
                .snapshot(Some(MIN_RELOAD_INTERVAL), Source::Pool)
                .await?
                .verifier
                .clone()),
            _ => Ok(snapshot.verifier.clone()),
        }
    }

    /// The JWKS (public keys only, SES-09).
    pub(crate) async fn jwks(&self) -> Result<JwkSet, AuthError> {
        Ok(self.snapshot(None, Source::Pool).await?.jwks.clone())
    }

    /// Whether the change listener is running and connected.
    pub(crate) fn listener_connected(&self) -> bool {
        self.listener.load(Ordering::SeqCst) == LISTENER_CONNECTED
    }

    /// Listens for [`SIGNING_KEYS_CHANNEL`] until `shutdown` completes and
    /// drops the cache on every notification and every (re)connection.
    /// Uses its own dedicated connection (not one of the application
    /// pool's), reconnecting with exponential backoff (1 s … 30 s).
    pub(crate) async fn run_listener<S>(&self, shutdown: S)
    where
        S: std::future::Future<Output = ()> + Send,
    {
        let options = (*self.pool.connect_options()).clone();
        let dedicated = PgPoolOptions::new()
            .max_connections(1)
            .min_connections(0)
            .max_lifetime(None)
            .idle_timeout(None)
            .acquire_timeout(Duration::from_secs(10))
            .connect_lazy_with(options);
        tokio::pin!(shutdown);
        self.listener.store(LISTENER_DOWN, Ordering::SeqCst);
        let mut backoff = Duration::from_secs(1);
        loop {
            let connected = tokio::select! {
                () = &mut shutdown => break,
                result = Self::subscribe(&dedicated) => result,
            };
            match connected {
                Ok(mut listener) => {
                    backoff = Duration::from_secs(1);
                    // Changes made while we were not listening are unknown.
                    self.invalidate();
                    self.listener.store(LISTENER_CONNECTED, Ordering::SeqCst);
                    tracing::info!("listening for signing-key changes");
                    let stopped = loop {
                        let received = tokio::select! {
                            () = &mut shutdown => break true,
                            received = listener.try_recv() => received,
                        };
                        match received {
                            Ok(Some(_)) => {
                                self.invalidate();
                                crate::metrics::signing_keys_invalidated("notification");
                            }
                            Ok(None) => {
                                // The connection was lost. `PgListener`
                                // would reconnect silently inside the next
                                // `try_recv`, with this task still reporting
                                // "connected" (30 s cache) while
                                // notifications are lost — possibly for the
                                // whole acquire timeout. Report "down" (5 s
                                // cache) and resubscribe explicitly, so the
                                // cache is dropped again only once LISTEN is
                                // back (K-58 audit).
                                tracing::warn!(
                                    "signing-key listener lost its connection; resubscribing"
                                );
                                self.listener.store(LISTENER_DOWN, Ordering::SeqCst);
                                self.invalidate();
                                crate::metrics::signing_keys_invalidated("reconnect");
                                break false;
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "signing-key listener lost its connection");
                                self.listener.store(LISTENER_DOWN, Ordering::SeqCst);
                                self.invalidate();
                                break false;
                            }
                        }
                    };
                    // Release the connection before closing its pool.
                    drop(listener);
                    if stopped {
                        break;
                    }
                }
                Err(err) => {
                    self.listener.store(LISTENER_DOWN, Ordering::SeqCst);
                    tracing::warn!(error = %err, retry_in = ?backoff, "signing-key listener cannot connect");
                    tokio::select! {
                        () = &mut shutdown => break,
                        () = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(MAX_LISTENER_BACKOFF);
                }
            }
        }
        self.listener.store(LISTENER_NOT_RUNNING, Ordering::SeqCst);
        dedicated.close().await;
    }

    async fn subscribe(pool: &PgPool) -> Result<PgListener, sqlx::Error> {
        let mut listener = PgListener::connect_with(pool).await?;
        listener.listen(SIGNING_KEYS_CHANNEL).await?;
        Ok(listener)
    }
}

fn no_active_key() -> AuthError {
    AuthError::new(codes::common::SERVICE_UNAVAILABLE).with_context("no active signing key")
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
