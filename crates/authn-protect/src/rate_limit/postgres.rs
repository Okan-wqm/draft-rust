//! Distributed GCRA rate limiter on PostgreSQL (PRT-01, default backend).
//!
//! State lives in the UNLOGGED `rate_limit_buckets` table, one row per keyed
//! hash. A decision is a **single** `INSERT … ON CONFLICT DO UPDATE …
//! RETURNING` statement: the conflict path takes the row lock, evaluates the
//! GCRA condition against the *current* row and either advances the TAT or
//! leaves it untouched, recording which in `allowed` (migration 1600). Two
//! instances racing on the same key are therefore serialised by PostgreSQL;
//! there is no read-modify-write window.
//!
//! [`RateLimiter::check_chain`], [`RateLimiter::peek_many`] and
//! [`RateLimiter::reset_many`] run in **one** statement (K-128): a chain is
//! one data-modifying CTE per step (the same conditional UPSERT, so every
//! step keeps its row-lock atomicity), each guarded by the `allowed` of the
//! earlier steps that end the chain when denied — a step after a denial
//! inserts / updates nothing. All steps share the statement's `now`.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::Arc;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{
    Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimitStep, RateLimiter, StepMode,
};
use sqlx::PgPool;
use time::OffsetDateTime;

use super::gcra::{self, GcraParams, Plan};
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
const PEEK_MANY_SQL: &str = "\
SELECT k.i AS idx, b.tat
FROM unnest($1::bytea[]) WITH ORDINALITY AS k(key_hash, i)
LEFT JOIN rate_limit_buckets b ON b.key_hash = k.key_hash";
const RESET_SQL: &str = "DELETE FROM rate_limit_buckets WHERE key_hash = $1";
const RESET_MANY_SQL: &str = "DELETE FROM rate_limit_buckets WHERE key_hash = ANY($1)";

/// The conditional UPSERT of one chain step: `{k}` key hash, `{inc}`
/// increment (µs), `{per}` effective period (µs), `{gate}` the guard;
/// `$1` is the shared `now`. Same arithmetic as [`CHECK_SQL`].
const CHAIN_CHECK_STEP: &str = "\
INSERT INTO rate_limit_buckets AS b (key_hash, tat, expires_at, allowed)
SELECT {k}, $1 + {inc} * interval '1 microsecond', $1 + {inc} * interval '1 microsecond', true
WHERE {gate}
ON CONFLICT (key_hash) DO UPDATE SET
    allowed = GREATEST(b.tat, $1) + {inc} * interval '1 microsecond'
              <= $1 + {per} * interval '1 microsecond',
    tat = CASE
        WHEN GREATEST(b.tat, $1) + {inc} * interval '1 microsecond'
             <= $1 + {per} * interval '1 microsecond'
        THEN GREATEST(b.tat, $1) + {inc} * interval '1 microsecond'
        ELSE b.tat END,
    expires_at = CASE
        WHEN GREATEST(b.tat, $1) + {inc} * interval '1 microsecond'
             <= $1 + {per} * interval '1 microsecond'
        THEN GREATEST(b.tat, $1) + {inc} * interval '1 microsecond'
        ELSE b.expires_at END
RETURNING tat, allowed";

/// The read of one peek step (the decision `check` would make).
const CHAIN_PEEK_STEP: &str = "\
SELECT p.tat, (p.tat IS NULL
        OR GREATEST(p.tat, $1) + {inc} * interval '1 microsecond'
           <= $1 + {per} * interval '1 microsecond') AS allowed
FROM (SELECT (SELECT tat FROM rate_limit_buckets WHERE key_hash = {k}) AS tat WHERE {gate}) p";
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

#[derive(sqlx::FromRow)]
struct ChainRow {
    idx: i32,
    tat: Option<OffsetDateTime>,
    allowed: bool,
}

/// A chain step that needs storage.
struct SqlStep {
    hash: [u8; 32],
    params: GcraParams,
    peek: bool,
    stop_if_denied: bool,
}

/// What [`PostgresRateLimiter::check_chain`] does for one step.
enum Planned {
    /// Decided without storage (`Plan::Reject`).
    Known(RateLimitDecision, bool),
    /// Index into the SQL steps.
    Sql(usize),
}

/// The statement of a chain (the text depends only on the shape: number,
/// modes and guards of the steps; values are bound).
fn chain_sql(steps: &[SqlStep]) -> String {
    let mut sql = String::from("WITH ");
    let mut gates: Vec<String> = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let base = 2 + 3 * i;
        let gate = if gates.is_empty() {
            "true".to_owned()
        } else {
            gates.join(" AND ")
        };
        let template = if step.peek {
            CHAIN_PEEK_STEP
        } else {
            CHAIN_CHECK_STEP
        };
        let body = template
            .replace("{k}", &format!("${base}::bytea"))
            .replace("{inc}", &format!("${}::bigint", base + 1))
            .replace("{per}", &format!("${}::bigint", base + 2))
            .replace("{gate}", &gate);
        if i > 0 {
            sql.push_str(",\n");
        }
        let _ = write!(sql, "s{i} AS ({body})");
        if step.stop_if_denied {
            gates.push(format!("COALESCE((SELECT allowed FROM s{i}), false)"));
        }
    }
    sql.push('\n');
    for i in 0..steps.len() {
        if i > 0 {
            sql.push_str(" UNION ALL ");
        }
        let _ = write!(sql, "SELECT {i}::int4 AS idx, tat, allowed FROM s{i}");
    }
    sql
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

    /// The single calls of a chain (keys repeating within one chain cannot
    /// share one statement: a row may be modified once per statement).
    async fn chain_one_by_one(
        &self,
        steps: &[RateLimitStep<'_>],
    ) -> Result<Vec<RateLimitDecision>, AuthError> {
        let mut decisions = Vec::with_capacity(steps.len());
        for step in steps {
            let decision = match step.mode {
                StepMode::Check { cost } => self.check(step.key, step.policy, cost).await?,
                StepMode::Peek => self.peek(step.key, step.policy).await?,
            };
            let stop = step.stop_if_denied && !decision.allowed;
            decisions.push(decision);
            if stop {
                break;
            }
        }
        Ok(decisions)
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

    async fn check_chain(
        &self,
        steps: &[RateLimitStep<'_>],
    ) -> Result<Vec<RateLimitDecision>, AuthError> {
        let mut planned = Vec::with_capacity(steps.len());
        let mut sql_steps: Vec<SqlStep> = Vec::with_capacity(steps.len());
        let mut seen = HashSet::new();
        for step in steps {
            let cost = match step.mode {
                StepMode::Check { cost } => cost,
                StepMode::Peek => 1,
            };
            match gcra::plan(step.policy, cost)? {
                Plan::Reject(decision) => {
                    planned.push(Planned::Known(decision, step.stop_if_denied));
                    if step.stop_if_denied {
                        // Nothing after a certain denial runs.
                        break;
                    }
                }
                Plan::Gcra(params) => {
                    let hash = self.hasher.rate_limit_key(step.key);
                    if !seen.insert(hash) {
                        return self.chain_one_by_one(steps).await;
                    }
                    planned.push(Planned::Sql(sql_steps.len()));
                    sql_steps.push(SqlStep {
                        hash,
                        params,
                        peek: step.mode == StepMode::Peek,
                        stop_if_denied: step.stop_if_denied,
                    });
                }
            }
        }
        // One `now` for the statement and the decisions.
        let (now, now_us) = self.now_micros()?;
        let rows: Vec<ChainRow> = if sql_steps.is_empty() {
            Vec::new()
        } else {
            // Built from the constant step templates and `$n` placeholders
            // only; every value is bound.
            let sql = chain_sql(&sql_steps);
            let mut query = sqlx::query_as::<_, ChainRow>(sqlx::AssertSqlSafe(sql)).bind(now);
            for step in &sql_steps {
                query = query
                    .bind(step.hash.as_slice().to_vec())
                    .bind(step.params.increment_us)
                    .bind(step.params.period_us);
            }
            query.fetch_all(&self.pool).await?
        };
        let mut decisions = Vec::with_capacity(planned.len());
        for item in planned {
            let (decision, stop_if_denied) = match item {
                Planned::Known(decision, stop) => (decision, stop),
                Planned::Sql(i) => {
                    let step = &sql_steps[i];
                    let row = rows
                        .iter()
                        .find(|r| usize::try_from(r.idx).ok() == Some(i))
                        .ok_or_else(|| {
                            AuthError::internal("rate-limit chain step without a result")
                        })?;
                    (step_decision(step, row, now_us)?, step.stop_if_denied)
                }
            };
            let stop = stop_if_denied && !decision.allowed;
            decisions.push(decision);
            if stop {
                break;
            }
        }
        Ok(decisions)
    }

    async fn peek_many(
        &self,
        keys: &[(&RateLimitKey, RateLimitPolicy)],
    ) -> Result<Vec<RateLimitDecision>, AuthError> {
        let mut out: Vec<Option<RateLimitDecision>> = Vec::with_capacity(keys.len());
        let mut lookups: Vec<(usize, GcraParams)> = Vec::with_capacity(keys.len());
        let mut hashes: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
        for (index, (key, policy)) in keys.iter().enumerate() {
            match gcra::plan(*policy, 1)? {
                Plan::Reject(decision) => out.push(Some(decision)),
                Plan::Gcra(params) => {
                    out.push(None);
                    lookups.push((index, params));
                    hashes.push(self.hasher.rate_limit_key(key).to_vec());
                }
            }
        }
        if !lookups.is_empty() {
            let (_, now_us) = self.now_micros()?;
            let rows: Vec<(i64, Option<OffsetDateTime>)> = sqlx::query_as(PEEK_MANY_SQL)
                .bind(&hashes)
                .fetch_all(&self.pool)
                .await?;
            for (position, (index, params)) in lookups.iter().enumerate() {
                let ordinal = i64::try_from(position + 1).unwrap_or(i64::MAX);
                let stored = rows
                    .iter()
                    .find(|(i, _)| *i == ordinal)
                    .ok_or_else(|| AuthError::internal("rate-limit peek without a result"))?
                    .1
                    .map(gcra::unix_micros);
                if let Some(slot) = out.get_mut(*index) {
                    *slot = Some(gcra::decide(stored, now_us, *params).decision());
                }
            }
        }
        out.into_iter()
            .map(|d| d.ok_or_else(|| AuthError::internal("rate-limit peek without a result")))
            .collect()
    }

    async fn reset_many(&self, keys: &[&RateLimitKey]) -> Result<(), AuthError> {
        if keys.is_empty() {
            return Ok(());
        }
        let hashes: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| self.hasher.rate_limit_key(k).to_vec())
            .collect();
        sqlx::query(RESET_MANY_SQL)
            .bind(&hashes)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// The decision of one chain step from its row (the storage verdict
/// `allowed` is authoritative; a peek whose local arithmetic disagrees is
/// an internal error, never an admission).
fn step_decision(
    step: &SqlStep,
    row: &ChainRow,
    now_us: i64,
) -> Result<RateLimitDecision, AuthError> {
    let tat = row.tat.map(gcra::unix_micros);
    if step.peek {
        return match (gcra::decide(tat, now_us, step.params), row.allowed) {
            (outcome @ gcra::Outcome::Allow { .. }, true)
            | (outcome @ gcra::Outcome::Deny { .. }, false) => Ok(outcome.decision()),
            _ => Err(AuthError::internal("rate-limit peek verdicts disagree")),
        };
    }
    let tat = tat.ok_or_else(|| AuthError::internal("rate-limit step without a TAT"))?;
    Ok(if row.allowed {
        RateLimitDecision::allow(gcra::remaining_after(tat, now_us, step.params))
    } else {
        gcra::denial_for(tat, now_us, step.params)
    })
}
