//! SQL of authn-admin: only its own table, `admin_action_reasons`
//! (migration `2200`). Every read or write of another module's table goes
//! through that module's API (`UserRepository::{search, stale_passwords,
//! set_admin_flags}` of authn-store; the impersonation event id comes from
//! `SessionIssuer::start_impersonation_audited`). Wave 2B adds its own
//! tables of migration `2201`: `admin_passkey_enrollments` (K-11),
//! `admin_operation_leases` (K-09) and `admin_reason_restrictions` (K-39).

use authn_core::id::{EventId, UserId};
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;
use uuid::Uuid;

/// Stores the justification of an audited admin action.
pub(crate) async fn insert_reason(
    conn: &mut PgConnection,
    event: EventId,
    admin: Option<UserId>,
    subject: Option<UserId>,
    action: &str,
    reason: &str,
    at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_action_reasons \
           (event_id, admin_user_id, subject_user_id, action, reason, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(event)
    .bind(admin)
    .bind(subject)
    .bind(action)
    .bind(reason)
    .bind(at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Justifications of the given audit events.
pub(crate) async fn reasons_for<'e>(
    executor: impl PgExecutor<'e>,
    events: &[Uuid],
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as("SELECT event_id, reason FROM admin_action_reasons WHERE event_id = ANY($1)")
        .bind(events)
        .fetch_all(executor)
        .await
}

// --- K-11: break-glass passkey enrollment links (`admin_passkey_enrollments`)

/// Stores a new enrollment link (only the token's SHA-256).
pub(crate) async fn insert_enrollment(
    conn: &mut PgConnection,
    id: Uuid,
    user: UserId,
    token_hash: &[u8; 32],
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_passkey_enrollments (id, user_id, token_hash, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(user)
    .bind(token_hash.as_slice())
    .bind(created_at)
    .bind(expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// The account of a live (unconsumed, unexpired) enrollment link.
#[cfg(feature = "passkey")]
pub(crate) async fn live_enrollment<'e>(
    executor: impl PgExecutor<'e>,
    token_hash: &[u8; 32],
    now: OffsetDateTime,
) -> Result<Option<UserId>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT user_id FROM admin_passkey_enrollments \
         WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2",
    )
    .bind(token_hash.as_slice())
    .bind(now)
    .fetch_optional(executor)
    .await
}

/// Atomically consumes a live enrollment link of `user` (single use).
#[cfg(feature = "passkey")]
pub(crate) async fn consume_enrollment(
    conn: &mut PgConnection,
    token_hash: &[u8; 32],
    user: UserId,
    now: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE admin_passkey_enrollments SET consumed_at = $3 \
         WHERE token_hash = $1 AND user_id = $2 AND consumed_at IS NULL AND expires_at > $3",
    )
    .bind(token_hash.as_slice())
    .bind(user)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Ends every open enrollment link of `user` (a new link replaces them).
pub(crate) async fn expire_enrollments_of(
    conn: &mut PgConnection,
    user: UserId,
    now: OffsetDateTime,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE admin_passkey_enrollments SET consumed_at = $2 \
         WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

// --- K-09: single-flight leases (`admin_operation_leases`) -----------------

/// Takes the lease `name` for `holder` for `ttl` unless a live lease
/// exists. One auto-committed statement: no connection is held while the
/// operation runs. K-65: every timestamp is the **database** clock
/// (`clock_timestamp()`), the same for every instance — application clock
/// skew between instances cannot make two leases overlap.
pub(crate) async fn acquire_lease<'e>(
    executor: impl PgExecutor<'e>,
    name: &str,
    holder: Uuid,
    ttl: std::time::Duration,
) -> Result<bool, sqlx::Error> {
    let taken: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO admin_operation_leases (name, holder, acquired_at, expires_at) \
         VALUES ($1, $2, clock_timestamp(), clock_timestamp() + make_interval(secs => $3)) \
         ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, \
           acquired_at = EXCLUDED.acquired_at, expires_at = EXCLUDED.expires_at \
         WHERE admin_operation_leases.expires_at <= EXCLUDED.acquired_at \
         RETURNING holder",
    )
    .bind(name)
    .bind(holder)
    .bind(lease_secs(ttl))
    .fetch_optional(executor)
    .await?;
    Ok(taken == Some(holder))
}

/// K-65 heartbeat: extends the lease `name` of `holder` to `ttl` from now
/// (database clock). `false`: the lease is no longer held by `holder` (it
/// expired and was taken over).
pub(crate) async fn renew_lease<'e>(
    executor: impl PgExecutor<'e>,
    name: &str,
    holder: Uuid,
    ttl: std::time::Duration,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE admin_operation_leases \
         SET expires_at = clock_timestamp() + make_interval(secs => $3) \
         WHERE name = $1 AND holder = $2",
    )
    .bind(name)
    .bind(holder)
    .bind(lease_secs(ttl))
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// A lease lifetime in seconds for `make_interval` (at least 1 ms).
fn lease_secs(ttl: std::time::Duration) -> f64 {
    ttl.as_secs_f64().max(0.001)
}

/// Releases the lease `name` if `holder` still holds it.
pub(crate) async fn release_lease<'e>(
    executor: impl PgExecutor<'e>,
    name: &str,
    holder: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM admin_operation_leases WHERE name = $1 AND holder = $2")
        .bind(name)
        .bind(holder)
        .execute(executor)
        .await?;
    Ok(())
}

// --- K-39: export of justifications and legal restrictions ----------------

/// A justification about a subject, as exported to that subject (no staff
/// identity).
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct SubjectReason {
    pub(crate) action: String,
    pub(crate) reason: String,
    pub(crate) created_at: OffsetDateTime,
}

/// Justifications about `subject` not under an **active** restriction at
/// `now` (K-62: a restriction ends at its latest review date) nor belonging
/// to a four-eyes request or decision about the subject that has not
/// expired yet (K-66: no tip-off of a pending containment), oldest first.
pub(crate) async fn reasons_about(
    conn: &mut PgConnection,
    subject: UserId,
    now: OffsetDateTime,
) -> Result<Vec<SubjectReason>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.action, r.reason, r.created_at FROM admin_action_reasons r \
         WHERE r.subject_user_id = $1 \
           AND NOT EXISTS (SELECT 1 FROM admin_reason_restriction_periods p \
                           WHERE p.event_id = r.event_id AND p.review_at > $2) \
           AND NOT EXISTS (SELECT 1 FROM admin_approvals a \
                           WHERE (a.request_event = r.event_id OR a.decision_event = r.event_id) \
                             AND a.expires_at > $2) \
         ORDER BY r.created_at, r.event_id",
    )
    .bind(subject)
    .bind(now)
    .fetch_all(conn)
    .await
}

/// The subject of a stored justification, row-locked (`None`: no
/// justification for that event), and the review date of its restriction
/// (`None`: never restricted; a past date: the restriction lapsed).
pub(crate) async fn lock_reason(
    conn: &mut PgConnection,
    event: EventId,
) -> Result<Option<(Option<UserId>, Option<OffsetDateTime>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT r.subject_user_id, \
                (SELECT max(p.review_at) FROM admin_reason_restriction_periods p \
                 WHERE p.event_id = r.event_id) \
         FROM admin_action_reasons r WHERE r.event_id = $1 FOR UPDATE",
    )
    .bind(event)
    .fetch_optional(conn)
    .await
}

/// Restricts the justification of `event` (append-only; a lapsed
/// restriction keeps its row and gets a new period).
pub(crate) async fn insert_restriction(
    conn: &mut PgConnection,
    event: EventId,
    restricted_by: EventId,
    at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_reason_restrictions (event_id, restricted_by, created_at) \
         VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(event)
    .bind(restricted_by)
    .bind(at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Sets the review date of the restriction of `event` (K-62), recorded by
/// the admin action `set_by`.
pub(crate) async fn insert_restriction_period(
    conn: &mut PgConnection,
    event: EventId,
    review_at: OffsetDateTime,
    set_by: EventId,
    at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_reason_restriction_periods (event_id, review_at, set_by, created_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (event_id, set_by) DO NOTHING",
    )
    .bind(event)
    .bind(review_at)
    .bind(set_by)
    .bind(at)
    .execute(conn)
    .await?;
    Ok(())
}

/// The restriction notes of `event`: the admin actions that restricted it
/// or set its review date (their own justifications are restricted with
/// it, K-62).
pub(crate) async fn restriction_notes(
    conn: &mut PgConnection,
    event: EventId,
) -> Result<Vec<EventId>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT restricted_by FROM admin_reason_restrictions WHERE event_id = $1 \
         UNION SELECT set_by FROM admin_reason_restriction_periods WHERE event_id = $1",
    )
    .bind(event)
    .fetch_all(conn)
    .await
}

// --- K-66: four-eyes approvals (`admin_approvals`) --------------------------

/// Input of [`insert_approval`].
#[derive(Debug)]
pub(crate) struct NewApproval<'a> {
    pub(crate) id: Uuid,
    pub(crate) action: &'static str,
    pub(crate) params: &'a serde_json::Value,
    pub(crate) params_hash: &'a [u8; 32],
    pub(crate) target: Option<UserId>,
    pub(crate) requested_by: UserId,
    pub(crate) request_event: EventId,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
}

/// Stores a new (pending) approval request.
pub(crate) async fn insert_approval(
    conn: &mut PgConnection,
    new: &NewApproval<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin_approvals (id, action, params, params_hash, target_user_id, \
           requested_by, request_event, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(new.id)
    .bind(new.action)
    .bind(sqlx::types::Json(new.params))
    .bind(new.params_hash.as_slice())
    .bind(new.target)
    .bind(new.requested_by)
    .bind(new.request_event)
    .bind(new.created_at)
    .bind(new.expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// An approval request with the requester's justification.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct ApprovalRow {
    pub(crate) id: Uuid,
    pub(crate) action: String,
    pub(crate) params: sqlx::types::Json<serde_json::Value>,
    pub(crate) target_user_id: Option<UserId>,
    pub(crate) requested_by: UserId,
    pub(crate) reason: Option<String>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) decision: Option<String>,
    pub(crate) decided_by: Option<UserId>,
    pub(crate) consumed_at: Option<OffsetDateTime>,
}

impl ApprovalRow {
    pub(crate) fn into_view(self, now: OffsetDateTime) -> crate::service::ApprovalView {
        let status = match (self.decision.as_deref(), self.consumed_at) {
            (_, Some(_)) => "used",
            (Some("denied"), _) => "denied",
            (_, None) if self.expires_at <= now => "expired",
            (Some(_), None) => "approved",
            (None, None) => "pending",
        };
        crate::service::ApprovalView {
            id: self.id,
            action: self.action,
            target_user_id: self.target_user_id,
            params: self.params.0,
            requested_by: self.requested_by,
            reason: self.reason,
            created_at: self.created_at,
            expires_at: self.expires_at,
            status: status.to_owned(),
            decided_by: self.decided_by,
        }
    }
}

macro_rules! approval_select {
    () => {
        "SELECT a.id, a.action, a.params, a.target_user_id, a.requested_by, r.reason, \
         a.created_at, a.expires_at, a.decision, a.decided_by, a.consumed_at \
         FROM admin_approvals a LEFT JOIN admin_action_reasons r ON r.event_id = a.request_event "
    };
}

/// One approval request.
pub(crate) async fn approval<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as(concat!(approval_select!(), "WHERE a.id = $1"))
        .bind(id)
        .fetch_optional(executor)
        .await
}

/// Approval requests created since `since`, newest first.
pub(crate) async fn recent_approvals<'e>(
    executor: impl PgExecutor<'e>,
    since: OffsetDateTime,
    limit: i64,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as(concat!(
        approval_select!(),
        "WHERE a.created_at >= $1 ORDER BY a.created_at DESC, a.id DESC LIMIT $2"
    ))
    .bind(since)
    .bind(limit)
    .fetch_all(executor)
    .await
}

/// The decision-relevant columns of a request, row-locked.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct LockedApproval {
    pub(crate) action: String,
    pub(crate) target_user_id: Option<UserId>,
    pub(crate) requested_by: UserId,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) decision: Option<String>,
}

/// Locks a request for a decision.
pub(crate) async fn lock_approval(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<LockedApproval>, sqlx::Error> {
    sqlx::query_as(
        "SELECT action, target_user_id, requested_by, expires_at, decision \
         FROM admin_approvals WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(conn)
    .await
}

/// Records the (final) decision on a pending request.
pub(crate) async fn decide_approval(
    conn: &mut PgConnection,
    id: Uuid,
    decision: &'static str,
    by: UserId,
    event: EventId,
    at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE admin_approvals SET decision = $2, decided_by = $3, decision_event = $4, \
           decided_at = $5 \
         WHERE id = $1 AND decision IS NULL",
    )
    .bind(id)
    .bind(decision)
    .bind(by)
    .bind(event)
    .bind(at)
    .execute(conn)
    .await?;
    Ok(())
}

/// K-66 request caps: serializes the requests of `requester` (transaction
/// advisory lock) and returns its pending (undecided, unexpired) requests
/// and its requests created since `since`.
pub(crate) async fn lock_and_count_requests(
    conn: &mut PgConnection,
    requester: UserId,
    now: OffsetDateTime,
    since: OffsetDateTime,
) -> Result<(i64, i64), sqlx::Error> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('authn-admin/approval-requests/' || $1::text, 0))",
    )
    .bind(requester)
    .execute(&mut *conn)
    .await?;
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE decision IS NULL AND expires_at > $2), \
                count(*) FILTER (WHERE created_at > $3) \
         FROM admin_approvals WHERE requested_by = $1 AND (expires_at > $2 OR created_at > $3)",
    )
    .bind(requester)
    .bind(now)
    .bind(since)
    .fetch_one(conn)
    .await
}

/// Whether an active, non-break-glass platform admin other than `caller`
/// exists (K-66 single-admin exception; one exact `EXISTS`, the target of
/// the operation included).
pub(crate) async fn other_active_admin_exists(
    conn: &mut PgConnection,
    caller: UserId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users \
           WHERE is_platform_admin AND NOT is_break_glass AND status = 'active' AND id <> $1)",
    )
    .bind(caller)
    .fetch_one(conn)
    .await
}

/// What an operation presents to consume an approval.
#[derive(Debug)]
pub(crate) struct ApprovalUse<'a> {
    pub(crate) id: Uuid,
    pub(crate) requested_by: UserId,
    pub(crate) action: &'static str,
    pub(crate) params_hash: &'a [u8; 32],
    pub(crate) target: Option<UserId>,
    pub(crate) now: OffsetDateTime,
}

/// Consumes an approval (single use) when everything matches; returns the
/// approver. One conditional statement in the operation's transaction:
/// concurrent uses of one approval cannot both succeed.
pub(crate) async fn consume_approval(
    conn: &mut PgConnection,
    used: &ApprovalUse<'_>,
) -> Result<Option<UserId>, sqlx::Error> {
    let approver: Option<Option<UserId>> = sqlx::query_scalar(
        "UPDATE admin_approvals SET consumed_at = $6 \
         WHERE id = $1 AND requested_by = $2 AND action = $3 AND params_hash = $4 \
           AND target_user_id IS NOT DISTINCT FROM $5 \
           AND decision = 'approved' AND consumed_at IS NULL AND expires_at > $6 \
         RETURNING decided_by",
    )
    .bind(used.id)
    .bind(used.requested_by)
    .bind(used.action)
    .bind(used.params_hash.as_slice())
    .bind(used.target)
    .bind(used.now)
    .fetch_optional(conn)
    .await?;
    Ok(approver.flatten())
}

/// Whether [`consume_approval`] would succeed now (read-only pre-check
/// before rate-limit budgets are spent; the consumption stays
/// authoritative).
pub(crate) async fn approval_usable<'e>(
    executor: impl PgExecutor<'e>,
    used: &ApprovalUse<'_>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM admin_approvals \
           WHERE id = $1 AND requested_by = $2 AND action = $3 AND params_hash = $4 \
             AND target_user_id IS NOT DISTINCT FROM $5 \
             AND decision = 'approved' AND consumed_at IS NULL AND expires_at > $6)",
    )
    .bind(used.id)
    .bind(used.requested_by)
    .bind(used.action)
    .bind(used.params_hash.as_slice())
    .bind(used.target)
    .bind(used.now)
    .fetch_one(executor)
    .await
}
