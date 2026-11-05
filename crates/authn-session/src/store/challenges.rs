//! `auth_challenges` queries (SES-02, SES-13, SES-22).

use std::net::IpAddr;

use authn_core::domain::{AuthMethodRef, ClientKind, FactorKind, LoginMethod};
use authn_core::id::{ChallengeId, OrgId, SessionId, UserId};
use authn_core::ports::{RequiredAction, RiskLevel};
use authn_crypto::token::TokenHash;
use authn_store::StoreError;
use sqlx::PgConnection;
use time::OffsetDateTime;

/// A row of `auth_challenges` (the token hash is never part of it).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub(crate) struct ChallengeRow {
    pub(crate) id: ChallengeId,
    pub(crate) kind: String,
    pub(crate) user_id: UserId,
    pub(crate) session_id: Option<SessionId>,
    pub(crate) client_kind: ClientKind,
    pub(crate) amr: Vec<AuthMethodRef>,
    pub(crate) first_factor_at: Option<OffsetDateTime>,
    pub(crate) allowed_factors: Vec<FactorKind>,
    pub(crate) required_actions: Vec<RequiredAction>,
    pub(crate) remember_me: bool,
    pub(crate) shared_device: bool,
    pub(crate) requested_org_id: Option<OrgId>,
    pub(crate) risk_level: Option<RiskLevel>,
    pub(crate) attempts: i32,
    pub(crate) max_attempts: i32,
    pub(crate) device_id: Option<String>,
    pub(crate) metadata: serde_json::Value,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) primary_method: Option<LoginMethod>,
}

/// Input of [`insert`].
pub(crate) struct NewChallengeRow<'a> {
    pub(crate) id: ChallengeId,
    pub(crate) kind: &'a str,
    pub(crate) user_id: UserId,
    pub(crate) token_hash: &'a TokenHash,
    pub(crate) session_id: Option<SessionId>,
    pub(crate) client_kind: ClientKind,
    pub(crate) amr: &'a [AuthMethodRef],
    pub(crate) first_factor_at: Option<OffsetDateTime>,
    pub(crate) allowed_factors: &'a [FactorKind],
    pub(crate) required_actions: &'a [RequiredAction],
    pub(crate) remember_me: bool,
    pub(crate) shared_device: bool,
    pub(crate) requested_org_id: Option<OrgId>,
    pub(crate) risk_level: Option<RiskLevel>,
    pub(crate) max_attempts: i32,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) user_agent: Option<&'a str>,
    pub(crate) device_id: Option<&'a str>,
    pub(crate) metadata: &'a serde_json::Value,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) primary_method: Option<LoginMethod>,
}

/// Inserts a challenge.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    new: &NewChallengeRow<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO auth_challenges (id, kind, user_id, token_hash, session_id, client_kind, \
         amr, first_factor_at, allowed_factors, required_actions, remember_me, shared_device, \
         requested_org_id, risk_level, max_attempts, ip, user_agent, device_id, metadata, \
         created_at, expires_at, primary_method) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
         $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)",
    )
    .bind(new.id)
    .bind(new.kind)
    .bind(new.user_id)
    .bind(new.token_hash.as_bytes().as_slice())
    .bind(new.session_id)
    .bind(new.client_kind)
    .bind(new.amr)
    .bind(new.first_factor_at)
    .bind(new.allowed_factors)
    .bind(new.required_actions)
    .bind(new.remember_me)
    .bind(new.shared_device)
    .bind(new.requested_org_id)
    .bind(new.risk_level)
    .bind(new.max_attempts)
    .bind(new.ip)
    .bind(new.user_agent)
    .bind(new.device_id)
    .bind(new.metadata)
    .bind(new.created_at)
    .bind(new.expires_at)
    .bind(new.primary_method)
    .execute(conn)
    .await?;
    Ok(())
}

/// Row-locks the open challenge with this token hash (unconsumed,
/// unexpired, attempts left).
pub(crate) async fn lock_open(
    conn: &mut PgConnection,
    token_hash: &TokenHash,
    now: OffsetDateTime,
) -> Result<Option<ChallengeRow>, StoreError> {
    let sql = "SELECT id, kind, user_id, session_id, client_kind, amr, first_factor_at, \
         allowed_factors, required_actions, remember_me, shared_device, requested_org_id, \
         risk_level, attempts, max_attempts, device_id, metadata, created_at, expires_at, \
         primary_method FROM auth_challenges WHERE token_hash = $1 AND consumed_at IS NULL \
         AND expires_at > $2 AND attempts < max_attempts FOR UPDATE";
    Ok(sqlx::query_as::<_, ChallengeRow>(sql)
        .bind(token_hash.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(conn)
        .await?)
}

/// Counts a failed attempt; the attempt that reaches the limit burns the
/// challenge. Returns `(attempts, max_attempts)` or `None` if the challenge
/// is no longer open.
pub(crate) async fn register_failure(
    conn: &mut PgConnection,
    id: ChallengeId,
    now: OffsetDateTime,
) -> Result<Option<(i32, i32)>, StoreError> {
    Ok(sqlx::query_as(
        "UPDATE auth_challenges SET attempts = attempts + 1, \
         consumed_at = CASE WHEN attempts + 1 >= max_attempts THEN $2 ELSE consumed_at END \
         WHERE id = $1 AND consumed_at IS NULL AND attempts < max_attempts \
         RETURNING attempts, max_attempts",
    )
    .bind(id)
    .bind(now)
    .fetch_optional(conn)
    .await?)
}

/// Records progress of an open challenge (factor verified, action done).
pub(crate) async fn update_progress(
    conn: &mut PgConnection,
    id: ChallengeId,
    amr: &[AuthMethodRef],
    allowed_factors: &[FactorKind],
    required_actions: &[RequiredAction],
    metadata: &serde_json::Value,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE auth_challenges SET amr = $2, allowed_factors = $3, required_actions = $4, \
         metadata = $5 WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(id)
    .bind(amr)
    .bind(allowed_factors)
    .bind(required_actions)
    .bind(metadata)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Consumes an open challenge exactly once.
pub(crate) async fn consume(
    conn: &mut PgConnection,
    id: ChallengeId,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE auth_challenges SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL \
         AND expires_at > $2 AND attempts < max_attempts",
    )
    .bind(id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Closes the open challenges of `user` (or of every user with `None`),
/// except step-up challenges bound to `keep`. Used by bulk revocations: a
/// login that is still pending (second factor, required actions) must not
/// survive a password reset, a suspension or "sign out everywhere".
/// `keep_in_flight_steps`: leave the challenges whose outstanding steps
/// include `change_password` or `verify_email` open (a `password_changed`
/// revocation made from inside such a step, SES-22).
pub(crate) async fn close_open(
    conn: &mut PgConnection,
    user: Option<UserId>,
    keep: Option<SessionId>,
    keep_in_flight_steps: bool,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "UPDATE auth_challenges SET consumed_at = $3 WHERE consumed_at IS NULL \
         AND ($1::uuid IS NULL OR user_id = $1) \
         AND ($2::uuid IS NULL OR session_id IS DISTINCT FROM $2) \
         AND NOT ($4 AND required_actions && ARRAY['change_password', 'verify_email']::text[])",
    )
    .bind(user)
    .bind(keep)
    .bind(now)
    .bind(keep_in_flight_steps)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

/// Deletes challenges that expired or were consumed before `before`.
pub(crate) async fn purge(
    conn: &mut PgConnection,
    before: OffsetDateTime,
    limit: i64,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "DELETE FROM auth_challenges WHERE id IN (SELECT id FROM auth_challenges \
         WHERE expires_at < $1 OR consumed_at < $1 LIMIT $2 FOR UPDATE SKIP LOCKED)",
    )
    .bind(before)
    .bind(limit)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}
