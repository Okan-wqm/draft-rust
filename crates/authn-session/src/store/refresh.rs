//! `refresh_tokens` queries (SES-05).
//!
//! One rotation lineage ("family") per native session; at most one live
//! (unused, unrevoked) token per family (`refresh_tokens_one_live_per_family_idx`).
//! Lock order everywhere: the `sessions` row first, then refresh tokens —
//! the same order as revocation, so rotation and revocation never deadlock.

use authn_core::id::{RefreshTokenId, SessionId};
use authn_crypto::token::TokenHash;
use authn_store::StoreError;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;
use uuid::Uuid;

/// A refresh-token row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct RefreshRow {
    pub(crate) id: RefreshTokenId,
    pub(crate) session_id: SessionId,
    pub(crate) generation: i32,
    pub(crate) idle_expires_at: OffsetDateTime,
    pub(crate) absolute_expires_at: OffsetDateTime,
    pub(crate) used_at: Option<OffsetDateTime>,
    pub(crate) replaced_by_id: Option<RefreshTokenId>,
    pub(crate) successor_ciphertext: Option<Vec<u8>>,
    pub(crate) revoked_at: Option<OffsetDateTime>,
    /// `jti` of the access token issued with this refresh token (K-58;
    /// `None` for rows written before migration 2001).
    pub(crate) access_token_id: Option<Uuid>,
}

/// Input of [`insert`].
pub(crate) struct NewRefreshToken<'a> {
    pub(crate) id: RefreshTokenId,
    pub(crate) session_id: SessionId,
    pub(crate) token_hash: &'a TokenHash,
    pub(crate) parent_id: Option<RefreshTokenId>,
    pub(crate) generation: i32,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) idle_expires_at: OffsetDateTime,
    pub(crate) absolute_expires_at: OffsetDateTime,
    /// `jti` of the access token issued together with it.
    pub(crate) access_token_id: Uuid,
}

/// Inserts a refresh token.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    new: &NewRefreshToken<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO refresh_tokens (id, session_id, token_hash, parent_id, generation, \
         created_at, idle_expires_at, absolute_expires_at, access_token_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(new.id)
    .bind(new.session_id)
    .bind(new.token_hash.as_bytes().as_slice())
    .bind(new.parent_id)
    .bind(new.generation)
    .bind(new.created_at)
    .bind(new.idle_expires_at)
    .bind(new.absolute_expires_at)
    .bind(new.access_token_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// The family of a presented token (no lock; the caller locks the session
/// first and then calls [`lock`]).
pub(crate) async fn session_of<'e>(
    executor: impl PgExecutor<'e>,
    token_hash: &TokenHash,
) -> Result<Option<SessionId>, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT session_id FROM refresh_tokens WHERE token_hash = $1")
            .bind(token_hash.as_bytes().as_slice())
            .fetch_optional(executor)
            .await?,
    )
}

/// Row-locks the presented token.
pub(crate) async fn lock(
    conn: &mut PgConnection,
    token_hash: &TokenHash,
) -> Result<Option<RefreshRow>, StoreError> {
    let sql = "SELECT id, session_id, generation, idle_expires_at, absolute_expires_at, \
               used_at, replaced_by_id, successor_ciphertext, revoked_at, access_token_id \
               FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE";
    Ok(sqlx::query_as::<_, RefreshRow>(sql)
        .bind(token_hash.as_bytes().as_slice())
        .fetch_optional(conn)
        .await?)
}

/// Row-locks the live token of a family (server-side rotation after a
/// privilege change).
pub(crate) async fn lock_live_of(
    conn: &mut PgConnection,
    session: SessionId,
) -> Result<Option<RefreshRow>, StoreError> {
    Ok(sqlx::query_as::<_, RefreshRow>(
        "SELECT id, session_id, generation, idle_expires_at, absolute_expires_at, \
         used_at, replaced_by_id, successor_ciphertext, revoked_at, access_token_id \
         FROM refresh_tokens WHERE session_id = $1 AND used_at IS NULL AND revoked_at IS NULL \
         FOR UPDATE",
    )
    .bind(session)
    .fetch_optional(conn)
    .await?)
}

/// A token by id (the successor during the grace window).
pub(crate) async fn find(
    conn: &mut PgConnection,
    id: RefreshTokenId,
) -> Result<Option<RefreshRow>, StoreError> {
    Ok(sqlx::query_as::<_, RefreshRow>(
        "SELECT id, session_id, generation, idle_expires_at, absolute_expires_at, \
         used_at, replaced_by_id, successor_ciphertext, revoked_at, access_token_id \
         FROM refresh_tokens WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?)
}

/// Retires a live token (step 1 of a rotation). The successor is linked
/// with [`link_successor`] once inserted: the "one live token per family"
/// index forbids inserting it first, the foreign key forbids linking it
/// first.
pub(crate) async fn retire(
    conn: &mut PgConnection,
    id: RefreshTokenId,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET used_at = $2 \
         WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Links a retired token to its successor (step 3 of a rotation).
/// `successor_ciphertext` keeps the successor (envelope-encrypted) only
/// while the grace window is on. The sealed successor of the retired
/// token's own parent is wiped: it is not needed once this token was used.
pub(crate) async fn link_successor(
    conn: &mut PgConnection,
    id: RefreshTokenId,
    successor: RefreshTokenId,
    successor_ciphertext: Option<&[u8]>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE refresh_tokens SET replaced_by_id = $2, successor_ciphertext = $3 WHERE id = $1",
    )
    .bind(id)
    .bind(successor)
    .bind(successor_ciphertext)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE refresh_tokens SET successor_ciphertext = NULL \
         WHERE replaced_by_id = $1 AND successor_ciphertext IS NOT NULL",
    )
    .bind(id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Pairs a live refresh token with a newly issued access token (grace
/// window retry: the same successor goes out with a new access token).
pub(crate) async fn pair_access_token(
    conn: &mut PgConnection,
    id: RefreshTokenId,
    access_token_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE refresh_tokens SET access_token_id = $2 WHERE id = $1")
        .bind(id)
        .bind(access_token_id)
        .execute(conn)
        .await?;
    Ok(())
}

/// Wipes sealed successors whose grace window ended before `before`.
pub(crate) async fn wipe_successors(
    conn: &mut PgConnection,
    before: OffsetDateTime,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET successor_ciphertext = NULL \
         WHERE successor_ciphertext IS NOT NULL AND used_at < $1",
    )
    .bind(before)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}
