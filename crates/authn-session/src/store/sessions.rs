//! `sessions` queries.

use std::net::IpAddr;

use authn_core::domain::{AuthMethodRef, ClientKind, LoginMethod};
use authn_core::id::{OrgId, SessionId, UserId};
use authn_crypto::token::TokenHash;
use authn_store::StoreError;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;

use crate::model::SessionRecord;

macro_rules! session_columns {
    () => {
        "s.id, s.user_id, s.client_kind, s.remember_me, s.shared_device, s.amr, s.acr, \
         s.auth_time, s.active_org_id, s.impersonator_user_id, s.impersonation_read_only, \
         s.device_id, s.device_name, s.created_ip, s.last_seen_ip, s.created_at, \
         s.last_seen_at, s.idle_expires_at, s.absolute_expires_at, s.login_method, s.scopes"
    };
}

/// User facts joined into authentication lookups (defence in depth: a
/// session of a suspended / disabled / deleted / currently locked account
/// never authenticates, even if a revocation was missed). An impersonation
/// session (ADM-04) additionally needs its acting admin to still be an
/// active platform administrator: demoting or suspending the admin ends
/// every impersonation they started at once.
macro_rules! usable_user {
    () => {
        " JOIN users u ON u.id = s.user_id \
          AND u.status NOT IN ('suspended', 'disabled', 'deleted') \
          AND NOT (u.status = 'locked' AND (u.locked_until IS NULL OR u.locked_until > $2)) \
          AND (s.impersonator_user_id IS NULL OR EXISTS (SELECT 1 FROM users a \
               WHERE a.id = s.impersonator_user_id AND a.is_platform_admin \
               AND a.status = 'active')) "
    };
}

/// A live session with the owner's platform-admin flag.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct LiveSession {
    #[sqlx(flatten)]
    pub(crate) record: SessionRecord,
    pub(crate) is_platform_admin: bool,
}

/// Input of [`insert`].
pub(crate) struct NewSession<'a> {
    pub(crate) id: SessionId,
    pub(crate) user_id: UserId,
    pub(crate) client_kind: ClientKind,
    pub(crate) token_hash: Option<&'a TokenHash>,
    pub(crate) remember_me: bool,
    pub(crate) shared_device: bool,
    pub(crate) amr: &'a [AuthMethodRef],
    pub(crate) acr: Option<&'a str>,
    pub(crate) auth_time: OffsetDateTime,
    pub(crate) active_org_id: Option<OrgId>,
    pub(crate) impersonator_user_id: Option<UserId>,
    pub(crate) impersonation_read_only: Option<bool>,
    pub(crate) impersonation_reason: Option<&'a str>,
    pub(crate) device_id: Option<&'a str>,
    pub(crate) device_name: Option<&'a str>,
    pub(crate) user_agent: Option<&'a str>,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) idle_expires_at: OffsetDateTime,
    pub(crate) absolute_expires_at: OffsetDateTime,
    pub(crate) login_method: Option<LoginMethod>,
    pub(crate) scopes: &'a [String],
}

/// Inserts a session and returns it.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    new: &NewSession<'_>,
) -> Result<SessionRecord, StoreError> {
    let sql = concat!(
        "INSERT INTO sessions AS s (id, user_id, client_kind, token_hash, remember_me, \
         shared_device, amr, acr, auth_time, active_org_id, impersonator_user_id, \
         impersonation_read_only, impersonation_reason, device_id, device_name, user_agent, \
         created_ip, last_seen_ip, created_at, last_seen_at, idle_expires_at, \
         absolute_expires_at, login_method, scopes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
         $17, $18, $18, $19, $20, $21, $22) RETURNING ",
        session_columns!()
    );
    Ok(sqlx::query_as::<_, SessionRecord>(sql)
        .bind(new.id)
        .bind(new.user_id)
        .bind(new.client_kind)
        .bind(new.token_hash.map(|h| h.as_bytes().to_vec()))
        .bind(new.remember_me)
        .bind(new.shared_device)
        .bind(new.amr)
        .bind(new.acr)
        .bind(new.auth_time)
        .bind(new.active_org_id)
        .bind(new.impersonator_user_id)
        .bind(new.impersonation_read_only)
        .bind(new.impersonation_reason)
        .bind(new.device_id)
        .bind(new.device_name)
        .bind(new.user_agent)
        .bind(new.ip)
        .bind(new.created_at)
        .bind(new.idle_expires_at)
        .bind(new.absolute_expires_at)
        .bind(new.login_method)
        .bind(new.scopes)
        .fetch_one(conn)
        .await?)
}

/// The live web session with this token hash (authentication lookup).
pub(crate) async fn find_live_by_token<'e>(
    executor: impl PgExecutor<'e>,
    token_hash: &TokenHash,
    now: OffsetDateTime,
) -> Result<Option<LiveSession>, StoreError> {
    let sql = concat!(
        "SELECT ",
        session_columns!(),
        ", u.is_platform_admin FROM sessions s",
        usable_user!(),
        "WHERE s.token_hash = $1 AND s.client_kind = 'web' AND s.revoked_at IS NULL \
         AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2"
    );
    Ok(sqlx::query_as::<_, LiveSession>(sql)
        .bind(token_hash.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(executor)
        .await?)
}

/// The live session with this id (bearer tokens, introspection).
pub(crate) async fn find_live_by_id<'e>(
    executor: impl PgExecutor<'e>,
    id: SessionId,
    now: OffsetDateTime,
) -> Result<Option<LiveSession>, StoreError> {
    let sql = concat!(
        "SELECT ",
        session_columns!(),
        ", u.is_platform_admin FROM sessions s",
        usable_user!(),
        "WHERE s.id = $1 AND s.revoked_at IS NULL \
         AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2"
    );
    Ok(sqlx::query_as::<_, LiveSession>(sql)
        .bind(id)
        .bind(now)
        .fetch_optional(executor)
        .await?)
}

/// Row-locks the live session `id` of `user` (rotation, step-up,
/// organization switch, refresh). `None` when it is gone, revoked or
/// expired.
pub(crate) async fn lock_live(
    conn: &mut PgConnection,
    id: SessionId,
    now: OffsetDateTime,
) -> Result<Option<LiveSession>, StoreError> {
    let sql = concat!(
        "SELECT ",
        session_columns!(),
        ", u.is_platform_admin FROM sessions s",
        usable_user!(),
        "WHERE s.id = $1 AND s.revoked_at IS NULL \
         AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2 FOR UPDATE OF s"
    );
    Ok(sqlx::query_as::<_, LiveSession>(sql)
        .bind(id)
        .bind(now)
        .fetch_optional(conn)
        .await?)
}

/// The web token hash of a session (locked by the caller).
pub(crate) async fn token_hash(
    conn: &mut PgConnection,
    id: SessionId,
) -> Result<Option<TokenHash>, StoreError> {
    let raw: Option<Option<Vec<u8>>> =
        sqlx::query_scalar("SELECT token_hash FROM sessions WHERE id = $1")
            .bind(id)
            .fetch_optional(conn)
            .await?;
    match raw.flatten() {
        Some(bytes) => TokenHash::from_slice(&bytes)
            .map(Some)
            .map_err(|_| StoreError::Corrupt("sessions.token_hash")),
        None => Ok(None),
    }
}

/// Records activity: last seen time / IP and the extended idle expiry
/// (capped by the absolute expiry). Only writes when the last touch is
/// older than `not_after` (write throttling).
pub(crate) async fn touch(
    executor: impl PgExecutor<'_>,
    id: SessionId,
    now: OffsetDateTime,
    ip: Option<IpAddr>,
    idle_expires_at: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE sessions SET last_seen_at = $2, last_seen_ip = COALESCE($3, last_seen_ip), \
         idle_expires_at = LEAST($4, absolute_expires_at) \
         WHERE id = $1 AND revoked_at IS NULL AND last_seen_at < $5 AND idle_expires_at > $2",
    )
    .bind(id)
    .bind(now)
    .bind(ip)
    .bind(idle_expires_at)
    .bind(not_after)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// What a privilege change writes into the locked session.
pub(crate) struct SessionUpdate<'a> {
    pub(crate) new_token_hash: Option<&'a TokenHash>,
    pub(crate) amr: &'a [AuthMethodRef],
    pub(crate) auth_time: OffsetDateTime,
    pub(crate) active_org_id: Option<OrgId>,
    pub(crate) absolute_expires_at: OffsetDateTime,
    pub(crate) idle_expires_at: OffsetDateTime,
    pub(crate) now: OffsetDateTime,
    pub(crate) ip: Option<IpAddr>,
}

/// Applies a privilege change (step-up, organization switch) and rotates
/// the web token (SES-03 fixation defence) in one statement.
pub(crate) async fn apply_update(
    conn: &mut PgConnection,
    id: SessionId,
    update: &SessionUpdate<'_>,
) -> Result<SessionRecord, StoreError> {
    let sql = concat!(
        "UPDATE sessions AS s SET token_hash = COALESCE($2, s.token_hash), amr = $3, \
         auth_time = $4, active_org_id = $5, absolute_expires_at = $6, \
         idle_expires_at = LEAST($7, $6), last_seen_at = $8, \
         last_seen_ip = COALESCE($9, s.last_seen_ip) \
         WHERE s.id = $1 AND s.revoked_at IS NULL RETURNING ",
        session_columns!()
    );
    Ok(sqlx::query_as::<_, SessionRecord>(sql)
        .bind(id)
        .bind(update.new_token_hash.map(|h| h.as_bytes().to_vec()))
        .bind(update.amr)
        .bind(update.auth_time)
        .bind(update.active_org_id)
        .bind(update.absolute_expires_at)
        .bind(update.idle_expires_at)
        .bind(update.now)
        .bind(update.ip)
        .fetch_one(conn)
        .await?)
}

/// Sets the idle expiry of a native session after a refresh.
pub(crate) async fn set_native_activity(
    conn: &mut PgConnection,
    id: SessionId,
    now: OffsetDateTime,
    ip: Option<IpAddr>,
    idle_expires_at: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE sessions SET last_seen_at = $2, last_seen_ip = COALESCE($3, last_seen_ip), \
         idle_expires_at = LEAST($4, absolute_expires_at) WHERE id = $1",
    )
    .bind(id)
    .bind(now)
    .bind(ip)
    .bind(idle_expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// The user's live sessions, newest first (SES-11).
pub(crate) async fn list_live_for_user<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
    now: OffsetDateTime,
) -> Result<Vec<SessionRecord>, StoreError> {
    let sql = concat!(
        "SELECT ",
        session_columns!(),
        " FROM sessions s WHERE s.user_id = $1 AND s.revoked_at IS NULL \
         AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2 \
         ORDER BY s.created_at DESC, s.id DESC LIMIT 200"
    );
    Ok(sqlx::query_as::<_, SessionRecord>(sql)
        .bind(user)
        .bind(now)
        .fetch_all(executor)
        .await?)
}

/// Whether `id` is a live session of `user` (ownership check, ORG-10
/// style: another user's session is indistinguishable from none).
pub(crate) async fn is_live_session_of<'e>(
    executor: impl PgExecutor<'e>,
    id: SessionId,
    user: UserId,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2 \
         AND revoked_at IS NULL AND idle_expires_at > $3 AND absolute_expires_at > $3)",
    )
    .bind(id)
    .bind(user)
    .bind(now)
    .fetch_one(executor)
    .await?)
}

/// Every session of the user, for the personal data export (ACC-10).
pub(crate) async fn list_all_for_user<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
) -> Result<Vec<SessionRecord>, StoreError> {
    let sql = concat!(
        "SELECT ",
        session_columns!(),
        " FROM sessions s WHERE s.user_id = $1 ORDER BY s.created_at, s.id LIMIT 1000"
    );
    Ok(sqlx::query_as::<_, SessionRecord>(sql)
        .bind(user)
        .fetch_all(executor)
        .await?)
}

/// A revoked session (id and organization, for events).
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct Revoked {
    pub(crate) id: SessionId,
    pub(crate) user_id: UserId,
    pub(crate) active_org_id: Option<OrgId>,
}

/// Which sessions a bulk revocation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    One(SessionId),
    User(UserId),
    UserExcept(UserId, SessionId),
    UserInOrg(UserId, OrgId),
    Org(OrgId),
    Everything,
}

/// Revokes the targeted unrevoked sessions and their refresh-token families
/// in the caller's transaction. Expired-but-unrevoked sessions are revoked
/// too (harmless, keeps the state explicit).
///
/// [`Target::User`] / [`Target::UserExcept`] also cover the impersonation
/// sessions the user started as an admin (ADM-04): suspending, resetting or
/// signing out a compromised admin must end the sessions they act in.
pub(crate) async fn revoke(
    conn: &mut PgConnection,
    target: Target,
    reason: &str,
    now: OffsetDateTime,
) -> Result<Vec<Revoked>, StoreError> {
    let query = match target {
        Target::One(id) => sqlx::query_as::<_, Revoked>(
            "UPDATE sessions SET revoked_at = $1, revoked_reason = $2, token_hash = NULL \
             WHERE revoked_at IS NULL AND id = $3 RETURNING id, user_id, active_org_id",
        )
        .bind(now)
        .bind(reason)
        .bind(id),
        Target::User(user) => sqlx::query_as::<_, Revoked>(
            "UPDATE sessions SET revoked_at = $1, revoked_reason = $2, token_hash = NULL \
             WHERE revoked_at IS NULL AND (user_id = $3 OR impersonator_user_id = $3) \
             RETURNING id, user_id, active_org_id",
        )
        .bind(now)
        .bind(reason)
        .bind(user),
        Target::UserExcept(user, keep) => sqlx::query_as::<_, Revoked>(
            "UPDATE sessions SET revoked_at = $1, revoked_reason = $2, token_hash = NULL \
             WHERE revoked_at IS NULL AND (user_id = $3 OR impersonator_user_id = $3) \
             AND id <> $4 RETURNING id, user_id, active_org_id",
        )
        .bind(now)
        .bind(reason)
        .bind(user)
        .bind(keep),
        Target::UserInOrg(user, org) => sqlx::query_as::<_, Revoked>(
            "UPDATE sessions SET revoked_at = $1, revoked_reason = $2, token_hash = NULL \
             WHERE revoked_at IS NULL AND user_id = $3 AND active_org_id = $4 \
             RETURNING id, user_id, active_org_id",
        )
        .bind(now)
        .bind(reason)
        .bind(user)
        .bind(org),
        Target::Org(org) => sqlx::query_as::<_, Revoked>(
            "UPDATE sessions SET revoked_at = $1, revoked_reason = $2, token_hash = NULL \
             WHERE revoked_at IS NULL AND active_org_id = $3 \
             RETURNING id, user_id, active_org_id",
        )
        .bind(now)
        .bind(reason)
        .bind(org),
        Target::Everything => sqlx::query_as::<_, Revoked>(
            "UPDATE sessions SET revoked_at = $1, revoked_reason = $2, token_hash = NULL \
             WHERE revoked_at IS NULL RETURNING id, user_id, active_org_id",
        )
        .bind(now)
        .bind(reason),
    };
    let revoked = query.fetch_all(&mut *conn).await?;
    if !revoked.is_empty() {
        let ids: Vec<SessionId> = revoked.iter().map(|r| r.id).collect();
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = $2, successor_ciphertext = NULL \
             WHERE session_id = ANY($1) AND revoked_at IS NULL",
        )
        .bind(&ids)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    }
    Ok(revoked)
}

/// Serializes session creation for one user (concurrent-session limit,
/// SES-14) with a transaction-scoped advisory lock.
pub(crate) async fn lock_user_sessions(
    conn: &mut PgConnection,
    user: UserId,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2000))")
        .bind(format!("authn-session/user-sessions/{user}"))
        .execute(conn)
        .await?;
    Ok(())
}

/// Live, non-impersonation sessions of the user beyond the newest `keep`
/// (oldest first) — the ones the concurrent-session limit evicts.
pub(crate) async fn surplus_sessions(
    conn: &mut PgConnection,
    user: UserId,
    keep: u32,
    now: OffsetDateTime,
) -> Result<Vec<SessionId>, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM sessions WHERE user_id = $1 AND revoked_at IS NULL \
         AND impersonator_user_id IS NULL AND idle_expires_at > $3 AND absolute_expires_at > $3 \
         ORDER BY created_at DESC, id DESC OFFSET $2",
    )
    .bind(user)
    .bind(i64::from(keep))
    .bind(now)
    .fetch_all(conn)
    .await?)
}

/// The admin's session to inherit authentication methods from
/// (impersonation, ADM-04): the given one, or the most recently
/// authenticated live non-impersonation session.
pub(crate) async fn admin_session<'e>(
    executor: impl PgExecutor<'e>,
    admin: UserId,
    session: Option<SessionId>,
    now: OffsetDateTime,
) -> Result<Option<SessionRecord>, StoreError> {
    let sql = concat!(
        "SELECT ",
        session_columns!(),
        " FROM sessions s WHERE s.user_id = $1 AND ($2::uuid IS NULL OR s.id = $2) \
         AND s.revoked_at IS NULL AND s.impersonator_user_id IS NULL \
         AND s.idle_expires_at > $3 AND s.absolute_expires_at > $3 \
         ORDER BY s.auth_time DESC, s.id DESC LIMIT 1"
    );
    Ok(sqlx::query_as::<_, SessionRecord>(sql)
        .bind(admin)
        .bind(session)
        .bind(now)
        .fetch_optional(executor)
        .await?)
}

/// Deletes sessions that ended (revoked or expired) before `before`
/// (OPS-06); refresh tokens and step-up ceremonies cascade.
pub(crate) async fn purge_ended(
    conn: &mut PgConnection,
    before: OffsetDateTime,
    limit: i64,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "DELETE FROM sessions WHERE id IN (SELECT id FROM sessions \
         WHERE (revoked_at IS NOT NULL AND revoked_at < $1) OR absolute_expires_at < $1 \
         OR idle_expires_at < $1 LIMIT $2 FOR UPDATE SKIP LOCKED)",
    )
    .bind(before)
    .bind(limit)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}
