//! Reading the audit log (AUD-04, ADM-07).
//!
//! * [`list_user_security_events`] — a user's own events (subject or actor),
//!   limited to the visible window (default 90 days).
//! * [`list_org_events`] — an organization's audit log with filters
//!   (authorization happens in the HTTP layer through
//!   [`crate::AuditAccessPolicy`]).
//! * [`list_events`] — platform-wide listing for the admin API (ADM-07).
//!
//! All listings use keyset pagination on `(occurred_at, id)` (no `OFFSET`,
//! no internal sequence numbers in cursors). Pseudonyms are resolved back to
//! user ids only while the user still exists (AUD-05).

use std::net::IpAddr;

use authn_core::domain::{Cursor, Page, PageRequest};
use authn_core::error::{AuthError, codes};
use authn_core::id::{EventId, OrgId, RequestId, UserId};
use authn_core::ports::SecurityEventKind;
use authn_core::redact::mask_ip;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::canonical::hex;

/// Unix microseconds of a timestamp (cursor sort key).
pub(crate) fn time_to_micros(at: OffsetDateTime) -> i64 {
    i64::try_from(at.unix_timestamp_nanos() / 1000).unwrap_or(i64::MAX)
}

/// Inverse of [`time_to_micros`]; out-of-range cursors are invalid input.
pub(crate) fn micros_to_time(micros: i64) -> Result<OffsetDateTime, AuthError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1000)
        .map_err(|_| AuthError::new(codes::common::VALIDATION_FAILED))
}

fn invalid(field: &'static str) -> AuthError {
    AuthError::new(codes::common::VALIDATION_FAILED).with_details(json!({ "field": field }))
}

macro_rules! event_select {
    () => {
        "SELECT e.id, e.occurred_at, e.recorded_at, e.kind, e.outcome, e.reason, e.actor_type, \
         e.actor_pseudonym, e.actor_ref, e.impersonator_pseudonym, e.subject_pseudonym, e.org_id, \
         e.resource_type, e.resource_id, e.request_id, e.metadata, e.hash, e.prev_hash, \
         sa.user_id AS actor_user_id, si.user_id AS impersonator_user_id, \
         ss.user_id AS subject_user_id, p.pseudonym AS pii_pseudonym, p.ip AS pii_ip, \
         p.user_agent AS pii_user_agent \
         FROM audit_events e \
         LEFT JOIN audit_subjects sa ON sa.pseudonym = e.actor_pseudonym \
         LEFT JOIN audit_subjects si ON si.pseudonym = e.impersonator_pseudonym \
         LEFT JOIN audit_subjects ss ON ss.pseudonym = e.subject_pseudonym \
         LEFT JOIN audit_event_pii p ON p.event_id = e.id "
    };
}

macro_rules! event_filters {
    () => {
        " AND ($2::uuid IS NULL OR e.subject_pseudonym = $2) \
          AND ($3::uuid IS NULL OR e.actor_pseudonym = $3) \
          AND ($4::text IS NULL OR e.kind = $4) \
          AND ($5::text IS NULL OR split_part(e.kind, '.', 1) = $5) \
          AND ($6::text IS NULL OR e.outcome = $6) \
          AND ($7::text IS NULL OR e.resource_type = $7) \
          AND ($8::timestamptz IS NULL OR e.occurred_at >= $8) \
          AND ($9::timestamptz IS NULL OR e.occurred_at < $9) \
          AND ($10::timestamptz IS NULL OR (e.occurred_at, e.id) < ($10, $11)) \
          ORDER BY e.occurred_at DESC, e.id DESC LIMIT $12"
    };
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: EventId,
    occurred_at: OffsetDateTime,
    recorded_at: OffsetDateTime,
    kind: String,
    outcome: String,
    reason: Option<String>,
    actor_type: String,
    actor_pseudonym: Option<Uuid>,
    actor_ref: Option<Uuid>,
    impersonator_pseudonym: Option<Uuid>,
    subject_pseudonym: Option<Uuid>,
    org_id: Option<OrgId>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    request_id: Option<RequestId>,
    metadata: sqlx::types::Json<Value>,
    hash: Vec<u8>,
    prev_hash: Vec<u8>,
    actor_user_id: Option<UserId>,
    impersonator_user_id: Option<UserId>,
    subject_user_id: Option<UserId>,
    pii_pseudonym: Option<Uuid>,
    pii_ip: Option<IpAddr>,
    pii_user_agent: Option<String>,
}

/// Full detail of an event, for the admin API (ADM-07) and exports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuditEventDetail {
    /// Event id.
    pub id: EventId,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub occurred_at: OffsetDateTime,
    /// When it was recorded.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub recorded_at: OffsetDateTime,
    /// Event kind.
    pub kind: String,
    /// `success` / `failure`.
    pub outcome: String,
    /// Reason code.
    pub reason: Option<String>,
    /// `user`, `service_account`, `api_key`, `system`, `anonymous`.
    pub actor_type: String,
    /// The acting user while the account exists.
    pub actor_user_id: Option<UserId>,
    /// Pseudonym of the acting user.
    pub actor_pseudonym: Option<Uuid>,
    /// Acting service account / API key.
    pub actor_ref: Option<Uuid>,
    /// Impersonating admin while the account exists.
    pub impersonator_user_id: Option<UserId>,
    /// Pseudonym of the impersonating admin.
    pub impersonator_pseudonym: Option<Uuid>,
    /// Subject user while the account exists.
    pub subject_user_id: Option<UserId>,
    /// Pseudonym of the subject user.
    pub subject_pseudonym: Option<Uuid>,
    /// Organization.
    pub org_id: Option<OrgId>,
    /// Resource type.
    pub resource_type: Option<String>,
    /// Resource id.
    pub resource_id: Option<String>,
    /// Request id.
    pub request_id: Option<RequestId>,
    /// Metadata.
    #[schema(value_type = Object)]
    pub metadata: Value,
    /// Client IP (until pseudonymised / purged).
    #[schema(value_type = Option<String>)]
    pub ip: Option<IpAddr>,
    /// Client user agent (until pseudonymised / purged).
    pub user_agent: Option<String>,
    /// Owner pseudonym of the personal data.
    pub pii_pseudonym: Option<Uuid>,
    /// Chain hash (hex).
    pub hash: String,
    /// Previous chain hash (hex).
    pub prev_hash: String,
}

impl From<EventRow> for AuditEventDetail {
    fn from(row: EventRow) -> Self {
        Self {
            id: row.id,
            occurred_at: row.occurred_at,
            recorded_at: row.recorded_at,
            kind: row.kind,
            outcome: row.outcome,
            reason: row.reason,
            actor_type: row.actor_type,
            actor_user_id: row.actor_user_id,
            actor_pseudonym: row.actor_pseudonym,
            actor_ref: row.actor_ref,
            impersonator_user_id: row.impersonator_user_id,
            impersonator_pseudonym: row.impersonator_pseudonym,
            subject_user_id: row.subject_user_id,
            subject_pseudonym: row.subject_pseudonym,
            org_id: row.org_id,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            request_id: row.request_id,
            metadata: row.metadata.0,
            ip: row.pii_ip,
            user_agent: row.pii_user_agent,
            pii_pseudonym: row.pii_pseudonym,
            hash: hex(&row.hash),
            prev_hash: hex(&row.prev_hash),
        }
    }
}

fn cursor_of(detail: &AuditEventDetail) -> Cursor {
    Cursor {
        sort_key: time_to_micros(detail.occurred_at),
        id: detail.id.as_uuid(),
    }
}

/// Who acted, from the point of view of the user reading their own log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActorView {
    /// The user themself.
    #[serde(rename = "self")]
    Myself,
    /// An administrator acting as the user (impersonation, ADM-04).
    Administrator,
    /// Another user (e.g. an organization admin).
    User,
    /// A service account.
    ServiceAccount,
    /// An API key.
    ApiKey,
    /// The system.
    System,
    /// An unauthenticated caller (e.g. a failed login attempt).
    Anonymous,
}

/// One of the user's own security events (AUD-04).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecurityEventView {
    /// Event id.
    pub id: EventId,
    /// Event kind, e.g. `login.failed`.
    pub kind: String,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub occurred_at: OffsetDateTime,
    /// `success` / `failure`.
    pub outcome: String,
    /// Reason code.
    pub reason: Option<String>,
    /// Who acted.
    pub actor: ActorView,
    /// Performed by an administrator impersonating the user.
    pub impersonated: bool,
    /// Organization context.
    pub org_id: Option<OrgId>,
    /// Resource type.
    pub resource_type: Option<String>,
    /// Resource id.
    pub resource_id: Option<String>,
    /// Client IP: complete for the user's own requests, network only
    /// (`/24`, `/48`) for requests of others; absent when it is not the
    /// user's data.
    pub ip: Option<String>,
    /// User agent of the request (only when it is the user's data).
    pub user_agent: Option<String>,
    /// Request id (support).
    pub request_id: Option<RequestId>,
    /// Additional data.
    #[schema(value_type = Object)]
    pub metadata: Value,
}

impl SecurityEventView {
    fn from_detail(detail: AuditEventDetail, me: Uuid) -> Self {
        let impersonated = detail.impersonator_pseudonym.is_some();
        let actor = if impersonated {
            ActorView::Administrator
        } else if detail.actor_pseudonym == Some(me) {
            ActorView::Myself
        } else {
            match detail.actor_type.as_str() {
                "user" => ActorView::User,
                "service_account" => ActorView::ServiceAccount,
                "api_key" => ActorView::ApiKey,
                "system" => ActorView::System,
                _ => ActorView::Anonymous,
            }
        };
        let mine = detail.pii_pseudonym == Some(me);
        let ip = if mine {
            detail.ip.map(|ip| {
                if actor == ActorView::Myself {
                    ip.to_string()
                } else {
                    mask_ip(ip)
                }
            })
        } else {
            None
        };
        Self {
            id: detail.id,
            kind: detail.kind,
            occurred_at: detail.occurred_at,
            outcome: detail.outcome,
            reason: detail.reason,
            actor,
            impersonated,
            org_id: detail.org_id,
            resource_type: detail.resource_type,
            resource_id: detail.resource_id,
            ip,
            user_agent: if mine { detail.user_agent } else { None },
            request_id: detail.request_id,
            metadata: detail.metadata,
        }
    }
}

/// One event of an organization's audit log (AUD-04).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OrgAuditEventView {
    /// Event id.
    pub id: EventId,
    /// Event kind.
    pub kind: String,
    /// When it happened.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub occurred_at: OffsetDateTime,
    /// `success` / `failure`.
    pub outcome: String,
    /// Reason code.
    pub reason: Option<String>,
    /// `user`, `service_account`, `api_key`, `system`, `anonymous`.
    pub actor_type: String,
    /// Acting user (absent once the account is deleted, and for platform
    /// staff actions: impersonation and `admin.*` events).
    pub actor_user_id: Option<UserId>,
    /// Acting service account / API key.
    pub actor_ref: Option<Uuid>,
    /// Performed by a platform administrator impersonating the actor.
    pub impersonated: bool,
    /// Subject user (absent once the account is deleted).
    pub subject_user_id: Option<UserId>,
    /// Resource type.
    pub resource_type: Option<String>,
    /// Resource id.
    pub resource_id: Option<String>,
    /// Network of the client IP (`/24`, `/48`); never shown for platform
    /// staff actions.
    pub ip_network: Option<String>,
    /// User agent; never shown for platform staff actions.
    pub user_agent: Option<String>,
    /// Request id.
    pub request_id: Option<RequestId>,
    /// Additional data.
    #[schema(value_type = Object)]
    pub metadata: Value,
}

impl From<AuditEventDetail> for OrgAuditEventView {
    fn from(detail: AuditEventDetail) -> Self {
        let impersonated = detail.impersonator_pseudonym.is_some();
        let staff = impersonated || detail.kind.starts_with("admin.");
        Self {
            id: detail.id,
            kind: detail.kind,
            occurred_at: detail.occurred_at,
            outcome: detail.outcome,
            reason: detail.reason,
            actor_type: detail.actor_type,
            actor_user_id: if staff { None } else { detail.actor_user_id },
            actor_ref: detail.actor_ref,
            impersonated,
            subject_user_id: detail.subject_user_id,
            resource_type: detail.resource_type,
            resource_id: detail.resource_id,
            ip_network: if staff { None } else { detail.ip.map(mask_ip) },
            user_agent: if staff { None } else { detail.user_agent },
            request_id: detail.request_id,
            metadata: detail.metadata,
        }
    }
}

/// Query parameters of `GET /v1/orgs/{org_id}/audit-events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct AuditEventQuery {
    /// Page size, 1–100 (default 20).
    pub limit: Option<u32>,
    /// Cursor from the previous page.
    pub cursor: Option<String>,
    /// Exact event kind, e.g. `org.member_added`.
    pub kind: Option<String>,
    /// Kind category (first segment), e.g. `org`, `api_key`, `webhook`.
    pub category: Option<String>,
    /// `success` or `failure`.
    pub outcome: Option<String>,
    /// Only events performed by this user.
    pub actor_user_id: Option<UserId>,
    /// Only events about this resource type.
    pub resource_type: Option<String>,
    /// Events at or after this instant (RFC 3339).
    pub since: Option<String>,
    /// Events before this instant (RFC 3339).
    pub until: Option<String>,
}

/// A validated filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditEventFilter {
    /// Organization.
    pub org_id: Option<OrgId>,
    /// Subject user.
    pub subject_user: Option<UserId>,
    /// Acting user.
    pub actor_user: Option<UserId>,
    /// Exact kind.
    pub kind: Option<SecurityEventKind>,
    /// Kind category.
    pub category: Option<String>,
    /// Outcome (`success` / `failure`).
    pub outcome: Option<String>,
    /// Resource type.
    pub resource_type: Option<String>,
    /// Lower bound (inclusive).
    pub since: Option<OffsetDateTime>,
    /// Upper bound (exclusive).
    pub until: Option<OffsetDateTime>,
}

fn parse_time(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<OffsetDateTime>, AuthError> {
    value
        .map(|v| {
            if v.len() > 64 {
                return Err(invalid(field));
            }
            OffsetDateTime::parse(v, &Rfc3339).map_err(|_| invalid(field))
        })
        .transpose()
}

impl AuditEventQuery {
    /// Validates the parameters into a filter and a page request.
    pub fn into_filter(self) -> Result<(AuditEventFilter, PageRequest), AuthError> {
        let kind = self
            .kind
            .as_deref()
            .map(|k| k.parse::<SecurityEventKind>().map_err(|_| invalid("kind")))
            .transpose()?;
        let category = match self.category {
            Some(c)
                if SecurityEventKind::ALL
                    .iter()
                    .any(|k| k.as_str().split('.').next() == Some(c.as_str())) =>
            {
                Some(c)
            }
            Some(_) => return Err(invalid("category")),
            None => None,
        };
        let outcome = match self.outcome.as_deref() {
            None => None,
            Some(o @ ("success" | "failure")) => Some(o.to_owned()),
            Some(_) => return Err(invalid("outcome")),
        };
        let resource_type = match self.resource_type {
            Some(r) if crate::sanitize::is_identifier(&r, 64) => Some(r),
            Some(_) => return Err(invalid("resource_type")),
            None => None,
        };
        let since = parse_time(self.since.as_deref(), "since")?;
        let until = parse_time(self.until.as_deref(), "until")?;
        let page = PageRequest {
            limit: self.limit,
            cursor: self.cursor,
        };
        page.cursor()?;
        Ok((
            AuditEventFilter {
                org_id: None,
                subject_user: None,
                actor_user: self.actor_user_id,
                kind,
                category,
                outcome,
                resource_type,
                since,
                until,
            },
            page,
        ))
    }
}

async fn pseudonym_of(pool: &PgPool, user: UserId) -> Result<Option<Uuid>, AuthError> {
    Ok(
        sqlx::query_scalar("SELECT pseudonym FROM audit_subjects WHERE user_id = $1")
            .bind(user)
            .fetch_optional(pool)
            .await?,
    )
}

/// A user's own security events of the last `window` before `now`
/// (AUD-04): events about the user or performed by the user.
pub async fn list_user_security_events(
    pool: &PgPool,
    user: UserId,
    now: OffsetDateTime,
    window: std::time::Duration,
    page: &PageRequest,
) -> Result<Page<SecurityEventView>, AuthError> {
    let cursor = page.cursor()?;
    let limit = page.limit();
    let Some(me) = pseudonym_of(pool, user).await? else {
        return Ok(Page {
            items: Vec::new(),
            next_cursor: None,
        });
    };
    let (after_ts, after_id) = match cursor {
        Some(c) => (Some(micros_to_time(c.sort_key)?), Some(c.id)),
        None => (None, None),
    };
    let rows: Vec<EventRow> = sqlx::query_as(concat!(
        event_select!(),
        "WHERE (e.subject_pseudonym = $1 OR e.actor_pseudonym = $1) \
           AND e.occurred_at >= $2 \
           AND ($3::timestamptz IS NULL OR (e.occurred_at, e.id) < ($3, $4)) \
         ORDER BY e.occurred_at DESC, e.id DESC LIMIT $5"
    ))
    .bind(me)
    .bind(now - window)
    .bind(after_ts)
    .bind(after_id)
    .bind(i64::from(limit) + 1)
    .fetch_all(pool)
    .await?;
    let details: Vec<AuditEventDetail> = rows.into_iter().map(AuditEventDetail::from).collect();
    let page = Page::from_overfetch(details, limit, cursor_of);
    Ok(Page {
        items: page
            .items
            .into_iter()
            .map(|d| SecurityEventView::from_detail(d, me))
            .collect(),
        next_cursor: page.next_cursor,
    })
}

/// Events matching `filter` (platform-wide unless `filter.org_id` is set),
/// newest first. For the admin API (ADM-07); organization endpoints use
/// [`list_org_events`].
pub async fn list_events(
    pool: &PgPool,
    filter: &AuditEventFilter,
    page: &PageRequest,
) -> Result<Page<AuditEventDetail>, AuthError> {
    run_listing(pool, filter, page, false).await
}

/// An organization's audit log (the organization filter is mandatory).
pub async fn list_org_events(
    pool: &PgPool,
    org: OrgId,
    filter: &AuditEventFilter,
    page: &PageRequest,
) -> Result<Page<OrgAuditEventView>, AuthError> {
    let filter = AuditEventFilter {
        org_id: Some(org),
        ..filter.clone()
    };
    let page = run_listing(pool, &filter, page, true).await?;
    Ok(Page {
        items: page
            .items
            .into_iter()
            .map(OrgAuditEventView::from)
            .collect(),
        next_cursor: page.next_cursor,
    })
}

async fn run_listing(
    pool: &PgPool,
    filter: &AuditEventFilter,
    page: &PageRequest,
    org_scoped: bool,
) -> Result<Page<AuditEventDetail>, AuthError> {
    let cursor = page.cursor()?;
    let limit = page.limit();
    let empty = Page {
        items: Vec::new(),
        next_cursor: None,
    };
    let subject = match filter.subject_user {
        Some(user) => match pseudonym_of(pool, user).await? {
            Some(p) => Some(p),
            None => return Ok(empty),
        },
        None => None,
    };
    let actor = match filter.actor_user {
        Some(user) => match pseudonym_of(pool, user).await? {
            Some(p) => Some(p),
            None => return Ok(empty),
        },
        None => None,
    };
    let (after_ts, after_id) = match cursor {
        Some(c) => (Some(micros_to_time(c.sort_key)?), Some(c.id)),
        None => (None, None),
    };
    let sql = if org_scoped {
        if filter.org_id.is_none() {
            return Err(AuthError::internal(
                "organization listing without organization",
            ));
        }
        concat!(event_select!(), "WHERE e.org_id = $1", event_filters!())
    } else {
        concat!(
            event_select!(),
            "WHERE ($1::uuid IS NULL OR e.org_id = $1)",
            event_filters!()
        )
    };
    let rows: Vec<EventRow> = sqlx::query_as(sql)
        .bind(filter.org_id)
        .bind(subject)
        .bind(actor)
        .bind(filter.kind.map(SecurityEventKind::as_str))
        .bind(&filter.category)
        .bind(&filter.outcome)
        .bind(&filter.resource_type)
        .bind(filter.since)
        .bind(filter.until)
        .bind(after_ts)
        .bind(after_id)
        .bind(i64::from(limit) + 1)
        .fetch_all(pool)
        .await?;
    let details: Vec<AuditEventDetail> = rows.into_iter().map(AuditEventDetail::from).collect();
    Ok(Page::from_overfetch(details, limit, cursor_of))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aud_04_query_validation() {
        let (filter, page) = AuditEventQuery {
            kind: Some("org.member_added".into()),
            category: Some("org".into()),
            outcome: Some("failure".into()),
            since: Some("2026-01-01T00:00:00Z".into()),
            limit: Some(5),
            ..AuditEventQuery::default()
        }
        .into_filter()
        .unwrap();
        assert_eq!(filter.kind, Some(SecurityEventKind::MemberAdded));
        assert_eq!(page.limit(), 5);
        for bad in [
            AuditEventQuery {
                kind: Some("org.unknown".into()),
                ..AuditEventQuery::default()
            },
            AuditEventQuery {
                category: Some("nope".into()),
                ..AuditEventQuery::default()
            },
            AuditEventQuery {
                outcome: Some("maybe".into()),
                ..AuditEventQuery::default()
            },
            AuditEventQuery {
                resource_type: Some("Robert'); DROP TABLE".into()),
                ..AuditEventQuery::default()
            },
            AuditEventQuery {
                since: Some("yesterday".into()),
                ..AuditEventQuery::default()
            },
            AuditEventQuery {
                cursor: Some("!!".into()),
                ..AuditEventQuery::default()
            },
        ] {
            let err = bad.into_filter().unwrap_err();
            assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
        }
    }

    #[test]
    fn aud_04_cursor_time_round_trip() {
        let at = OffsetDateTime::from_unix_timestamp_nanos(1_800_000_000_123_456_000).unwrap();
        assert_eq!(micros_to_time(time_to_micros(at)).unwrap(), at);
        assert!(micros_to_time(i64::MAX).is_err());
    }
}
