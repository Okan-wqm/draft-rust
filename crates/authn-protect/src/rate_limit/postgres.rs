//! Distributed GCRA rate limiter on PostgreSQL (PRT-01, default backend).
//!
//! State lives in the UNLOGGED `rate_limit_buckets` table, one row per keyed
//! hash. A decision is a **single** `INSERT … ON CONFLICT DO UPDATE …
//! RETURNING` statement: the conflict path takes the row lock, evaluates the
//! GCRA condition against the *current* row and either advances the TAT or
//! leaves it untouched, recording which in `allowed` (migration 1600). Two
//! instances racing on the same key are therefore serialised by PostgreSQL;
//! there is no read-modify-write window.

use std::sync::Arc;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use sqlx::PgPool;
use time::OffsetDateTime;

use super::gcra::{self, Plan};
use crate::keys::KeyHasher;

/// One atomic GCRA step. `$1` key hash, `$2` now, `$3` increment (µs),
/// `$4` effective period (µs).
const CHECK_SQL: &str = "\
INSERT INTO rate_limit_buckets AS b (key_hash, tat, expires_at, allowed)
VALUES ($1, $2 + $3 * interval '1 microsecond', $2 + $3 * interval '1 microsecond', true)
ON CONFLICT (key_hash) DO UPDATE SET
    allowed = GREATEST(b.tat, $2) + $3 * interval '1 microsecond'
              <= $2 + $4 * interval '1 microsecond',
    tat = CASE
        WHEN GREATEST(b.tat, $2) + $3 * interval '1 microsecond'
             <= $2 + $4 * interval '1 microsecond'
        THEN GREATEST(b.tat, $2) + $3 * interval '1 microsecond'
        ELSE b.tat END,
    expires_at = CASE
        WHEN GREATEST(b.tat, $2) + $3 * interval '1 microsecond'
             <= $2 + $4 * interval '1 microsecond'
        THEN GREATEST(b.tat, $2) + $3 * interval '1 microsecond'
        ELSE b.expires_at END
RETURNING tat, allowed";

const PEEK_SQL: &str = "SELECT tat FROM rate_limit_buckets WHERE key_hash = $1";
const RESET_SQL: &str = "DELETE FROM rate_limit_buckets WHERE key_hash = $1";
const PURGE_SQL: &str = "\
DELETE FROM rate_limit_buckets WHERE key_hash IN (
    SELECT key_hash FROM rate_limit_buckets WHERE expires_at <= $1 LIMIT $2
)";

/// The PostgreSQL rate limiter. Cheap to clone.
#[derive(Clone)]
pub struct PostgresRateLimiter {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    hasher: KeyHasher,
}

impl std::fmt::Debug for PostgresRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresRateLimiter")
            .finish_non_exhaustive()
    }
}

#[derive(sqlx::FromRow)]
struct CheckRow {
    tat: OffsetDateTime,
    allowed: bool,
}

impl PostgresRateLimiter {
    /// A limiter over `pool`.
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>, hasher: KeyHasher) -> Self {
        Self {
            pool,
            clock,
            hasher,
        }
    }

    /// Deletes up to `batch` expired buckets (background job, OPS-06).
    /// Returns the number of rows removed.
    pub async fn purge_expired(&self, batch: i64) -> Result<u64, AuthError> {
        let now = self.clock.now();
        let result = sqlx::query(PURGE_SQL)
            .bind(now)
            .bind(batch.max(1))
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    fn now_micros(&self) -> Result<(OffsetDateTime, i64), AuthError> {
        let now_us = gcra::unix_micros(self.clock.now());
        // Truncate to the storage precision so SQL and Rust agree exactly.
        Ok((gcra::from_unix_micros(now_us)?, now_us))
    }
}

#[async_trait]
impl RateLimiter for PostgresRateLimiter {
    async fn check(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
    ) -> Result<RateLimitDecision, AuthError> {
        let params = match gcra::plan(policy, cost)? {
            Plan::Reject(decision) => return Ok(decision),
            Plan::Gcra(params) => params,
        };
        let hash = self.hasher.rate_limit_key(key);
        let (now, now_us) = self.now_micros()?;
        let row: CheckRow = sqlx::query_as(CHECK_SQL)
            .bind(hash.as_slice())
            .bind(now)
            .bind(params.increment_us)
            .bind(params.period_us)
            .fetch_one(&self.pool)
            .await?;
        let tat = gcra::unix_micros(row.tat);
        Ok(if row.allowed {
            RateLimitDecision::allow(gcra::remaining_after(tat, now_us, params))
        } else {
            gcra::denial_for(tat, now_us, params)
        })
    }

    async fn peek(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError> {
        let params = match gcra::plan(policy, 1)? {
            Plan::Reject(decision) => return Ok(decision),
            Plan::Gcra(params) => params,
        };
        let hash = self.hasher.rate_limit_key(key);
        let (_, now_us) = self.now_micros()?;
        let stored: Option<OffsetDateTime> = sqlx::query_scalar(PEEK_SQL)
            .bind(hash.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        let stored = stored.map(gcra::unix_micros);
        Ok(gcra::decide(stored, now_us, params).decision())
    }

    async fn reset(&self, key: &RateLimitKey) -> Result<(), AuthError> {
        let hash = self.hasher.rate_limit_key(key);
        sqlx::query(RESET_SQL)
            .bind(hash.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
