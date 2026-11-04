//! Hooks implemented by `authn-server` (authn-admin may not depend on
//! authn-session, contracts §2).

/// Drops the in-process cache of JWT signing keys after an emergency
/// rotation (ADM-06). The server implements it with
/// `authn_session::SessionService::invalidate_signing_keys()`.
///
/// Other instances keep their cached keys until the cache expires
/// (`session.signing_key_cache_ttl`); the rotation itself takes effect in
/// the database at once.
pub trait SigningKeyCache: Send + Sync {
    /// Forgets the cached signing / verification keys.
    fn invalidate_signing_keys(&self);
}

/// No cache to invalidate (tests, processes that do not verify tokens).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSigningKeyCache;

impl SigningKeyCache for NoSigningKeyCache {
    fn invalidate_signing_keys(&self) {}
}
