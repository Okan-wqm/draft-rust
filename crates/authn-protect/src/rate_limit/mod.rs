//! `RateLimiter` implementations (PRT-01, PRT-02, PRT-04).
//!
//! | backend | type | use |
//! |---------|------|-----|
//! | memory | [`MemoryRateLimiter`] | single instance, development, tests |
//! | PostgreSQL | [`PostgresRateLimiter`] | default; distributed via one atomic UPSERT |
//! | Redis | `RedisRateLimiter` (feature `redis`) | distributed via one atomic Lua script |
//!
//! All three run the same GCRA arithmetic ([`gcra`]) on the injected
//! [`Clock`] (ARC-04), store only keyed hashes of the keys
//! ([`crate::keys::KeyHasher`]) and report `retry_after` on
//! denial so callers answer `429` + `Retry-After` (PRT-04) instead of
//! sleeping.
//!
//! [`http_rate_limit`] is the coarse per-IP middleware for the OPS-02
//! "rate limit" slot; per-action limits (login, reset, registration…) are
//! applied by the owning modules through the port.

pub mod gcra;
mod layer;
mod memory;
mod postgres;
#[cfg(feature = "redis")]
mod redis;

use std::sync::Arc;

use authn_core::config::protect::{RateLimitBackend, RateLimitConfig};
use authn_core::error::AuthError;
use authn_core::ports::{Clock, RateLimiter};
use sqlx::PgPool;

pub use layer::{HttpRateLimit, http_rate_limit};
pub use memory::MemoryRateLimiter;
pub use postgres::PostgresRateLimiter;
#[cfg(feature = "redis")]
pub use redis::RedisRateLimiter;

use crate::keys::KeyHasher;

/// Builds the configured backend (`protect.rate_limit.backend`). Fails fast
/// when the Redis backend is selected but the `redis` feature is not
/// compiled in, or Redis is unreachable at start-up.
pub async fn build_rate_limiter(
    config: &RateLimitConfig,
    pool: PgPool,
    clock: Arc<dyn Clock>,
    hasher: KeyHasher,
) -> Result<Arc<dyn RateLimiter>, AuthError> {
    match config.backend {
        RateLimitBackend::Memory => Ok(Arc::new(MemoryRateLimiter::new(clock, hasher))),
        RateLimitBackend::Postgres => Ok(Arc::new(PostgresRateLimiter::new(pool, clock, hasher))),
        RateLimitBackend::Redis => build_redis(config, clock, hasher).await,
    }
}

#[cfg(feature = "redis")]
async fn build_redis(
    config: &RateLimitConfig,
    clock: Arc<dyn Clock>,
    hasher: KeyHasher,
) -> Result<Arc<dyn RateLimiter>, AuthError> {
    let url = config
        .redis_url
        .as_ref()
        .ok_or_else(|| AuthError::internal("protect.rate_limit.redis_url is required"))?;
    Ok(Arc::new(
        RedisRateLimiter::connect(url, clock, hasher).await?,
    ))
}

#[cfg(not(feature = "redis"))]
async fn build_redis(
    _config: &RateLimitConfig,
    _clock: Arc<dyn Clock>,
    _hasher: KeyHasher,
) -> Result<Arc<dyn RateLimiter>, AuthError> {
    Err(AuthError::internal(
        "protect.rate_limit.backend = \"redis\" requires the `redis` cargo feature",
    ))
}
