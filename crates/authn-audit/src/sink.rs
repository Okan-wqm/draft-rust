//! [`PgAuditSink`]: the PostgreSQL implementation of the `AuditSink` port
//! (AUD-01, AUD-02, AUD-03, AUD-05).
//!
//! Appending an event:
//! 1. the event is sanitized ([`crate::sanitize`]): reason codes, resource,
//!    metadata and user agent are forced into the allowed grammar;
//! 2. every user reference (actor, impersonator, subject, and user ids that
//!    appear in the resource or metadata) is replaced by the user's random
//!    pseudonym from `audit_subjects` (created on first use);
//! 3. IP and user agent go to `audit_event_pii` with a random salt; the
//!    chained record only carries their salted digest;
//! 4. the chain head row is locked (`SELECT … FOR UPDATE`), the record is
//!    hashed onto the current head, inserted, and the head is advanced — all
//!    in one transaction, so concurrent writers can never fork the chain.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::{Actor, AuditSink, Clock, EventOutcome, SecurityEvent};
use authn_store::StoreError;
use serde_json::Value;
use sqlx::{Connection as _, PgConnection, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::chain::{self, ChainRecord};
use crate::sanitize::{self, StringCheck};

/// Session-local setting listing users pseudonymised in the current
/// transaction (see [`PgAuditSink::pseudonymize_subject`]).
const FORGOTTEN_SETTING: &str = "authn.audit_forgotten";

/// Lock wait limit of [`PgAuditSink::record`]: a writer never hangs forever
/// behind a transaction that holds the chain head.
const RECORD_LOCK_TIMEOUT: &str = "SET LOCAL lock_timeout = '10s'";

/// Maximum number of distinct UUIDs checked for being user ids per event.
const MAX_UUID_CANDIDATES: usize = 128;

/// Result of an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendedEvent {
    /// Position in the chain.
    pub seq: i64,
    /// Hash of the event.
    pub hash: [u8; 32],
    /// `true` when an event with the same id already existed (idempotent
    /// retry); nothing was written.
    pub duplicate: bool,
}

/// The PostgreSQL audit sink.
#[derive(Clone)]
pub struct PgAuditSink {
    pool: PgPool,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for PgAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgAuditSink").finish_non_exhaustive()
    }
}

/// A user reference resolved to a pseudonym.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pseudonym {
    value: Uuid,
    /// `false` for a one-off pseudonym of a deleted / unknown user: it is
    /// not stored anywhere and cannot be linked to anything.
    persisted: bool,
}

#[derive(Debug, Clone)]
struct PiiRow {
    pseudonym: Option<Uuid>,
    ip: Option<IpAddr>,
    user_agent: Option<String>,
    salt: [u8; 32],
}

#[derive(Debug, Clone)]
struct Prepared {
    record: ChainRecord,
    pii: Option<PiiRow>,
}

/// A random (version 4) UUID from the OS CSPRNG. Pseudonyms must not leak
/// time information (UUIDv7 would reveal when a user was first audited).
fn random_uuid() -> Result<Uuid, AuthError> {
    let bytes = authn_crypto::random::bytes::<16>().map_err(AuthError::from)?;
    Ok(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

/// Whether a database error (inside an `AuthError`) is worth one retry.
pub(crate) fn is_retryable(err: &AuthError) -> bool {
    std::error::Error::source(err)
        .and_then(|s| s.downcast_ref::<sqlx::Error>())
        .and_then(sqlx::Error::as_database_error)
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "40001" || code == "40P01")
}

#[derive(sqlx::FromRow)]
struct CandidateRow {
    user_id: Uuid,
    deleted: bool,
    forgotten: bool,
    pseudonym: Option<Uuid>,
}

impl PgAuditSink {
    /// Creates the sink.
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>) -> Self {
        Self { pool, clock }
    }

    /// Appends an event in the caller's transaction and reports where it
    /// landed (used by tests and tooling; the port methods wrap it).
    pub async fn append(
        &self,
        conn: &mut PgConnection,
        event: SecurityEvent,
    ) -> Result<AppendedEvent, AuthError> {
        let kind = event.kind;
        let outcome = event.outcome;
        let prepared = self.prepare(conn, event).await?;
        let appended = append_prepared(conn, prepared, self.clock.now()).await?;
        if !appended.duplicate {
            metrics::counter!(
                "authn_audit_events_total",
                "kind" => kind.as_str(),
                "outcome" => match outcome {
                    EventOutcome::Success => "success",
                    EventOutcome::Failure => "failure",
                }
            )
            .increment(1);
        }
        Ok(appended)
    }

    async fn prepare(
        &self,
        conn: &mut PgConnection,
        event: SecurityEvent,
    ) -> Result<Prepared, AuthError> {
        let kind = event.kind.as_str();
        let now = self.clock.now();

        // --- sanitize producer-controlled fields (AUD-03) -----------------
        let (reason, bad_reason) = sanitize::sanitize_reason(event.reason);
        if bad_reason {
            tracing::warn!(
                event.kind = kind,
                "audit reason is not a reason code; replaced"
            );
        }
        let sanitized = sanitize::sanitize_metadata(event.metadata);
        for redaction in &sanitized.redactions {
            tracing::warn!(
                event.kind = kind,
                metadata.path = %redaction.path,
                rule = redaction.rule.as_str(),
                "audit metadata value redacted"
            );
        }
        let mut metadata = Value::Object(sanitized.metadata);
        let (resource_type, mut resource_id) = match event.resource {
            Some(resource) if sanitize::is_identifier(resource.kind, 64) => {
                let id = match sanitize::check_string(&resource.id) {
                    Ok(StringCheck::Keep) => resource.id,
                    Ok(StringCheck::Uuid(uuid)) => uuid.hyphenated().to_string(),
                    Err(rule) => {
                        tracing::warn!(
                            event.kind = kind,
                            rule = rule.as_str(),
                            "audit resource id redacted"
                        );
                        sanitize::REDACTED.to_owned()
                    }
                };
                (Some(resource.kind.to_owned()), Some(id))
            }
            Some(_) => {
                tracing::warn!(event.kind = kind, "audit resource type invalid; dropped");
                (None, None)
            }
            None => (None, None),
        };

        // --- pseudonyms (AUD-05) ------------------------------------------
        let actor_user = match event.actor {
            Actor::User(user) => Some(user),
            _ => None,
        };
        let resource_uuid = resource_id
            .as_deref()
            .filter(|id| id.len() == 36)
            .and_then(|id| Uuid::try_parse(id).ok());
        // UUIDs that must become pseudonyms even when no such user exists
        // (any more): the explicit user references, values under
        // user-reference keys (`removed_user_id`, `previous_owner`, …) and
        // the id of a `user` resource.
        let mut always: Vec<Uuid> = [actor_user, event.impersonator, event.subject_user]
            .into_iter()
            .flatten()
            .map(|u| u.as_uuid())
            .collect();
        sanitize::collect_user_reference_uuids(&metadata, &mut always);
        if resource_type.as_deref() == Some("user")
            && let Some(uuid) = resource_uuid
        {
            always.push(uuid);
        }
        let mut others = Vec::new();
        sanitize::collect_uuids(&metadata, &mut others);
        others.extend(resource_uuid);
        // Explicit references first, then hints, then any other UUID; at
        // most MAX_UUID_CANDIDATES are checked. UUIDs beyond the limit are
        // redacted (fail closed): an unchecked UUID may be a user id that
        // would otherwise stay in the immutable chain.
        let mut seen = HashSet::new();
        let mut candidates: Vec<Uuid> = always
            .iter()
            .chain(others.iter())
            .copied()
            .filter(|uuid| seen.insert(*uuid))
            .collect();
        let unchecked = candidates.len().saturating_sub(MAX_UUID_CANDIDATES);
        candidates.truncate(MAX_UUID_CANDIDATES);
        let checked: HashSet<Uuid> = candidates.iter().copied().collect();
        always.retain(|uuid| checked.contains(uuid));
        always.sort_unstable();
        always.dedup();
        if unchecked > 0 {
            tracing::warn!(
                event.kind = kind,
                unchecked,
                rule = sanitize::RedactionRule::TooManyIdentifiers.as_str(),
                "audit identifiers beyond the per-event limit redacted"
            );
        }
        let resolved = resolve_pseudonyms(conn, &candidates, &always, now).await?;
        let lookup = |user: Option<UserId>| -> Option<Pseudonym> {
            let user = user?.as_uuid();
            resolved.iter().find(|(id, _)| *id == user).map(|(_, p)| *p)
        };
        let actor_pseudonym = lookup(actor_user);
        let impersonator_pseudonym = lookup(event.impersonator);
        let subject_pseudonym = lookup(event.subject_user);

        // User ids inside the resource / metadata become pseudonyms; UUIDs
        // that were not checked are redacted.
        let mut rewrite = |uuid: Uuid| -> Option<String> {
            match resolved.iter().find(|(id, _)| *id == uuid) {
                Some((_, pseudonym)) => Some(pseudonym.value.hyphenated().to_string()),
                None if checked.contains(&uuid) => None,
                None => Some(sanitize::REDACTED.to_owned()),
            }
        };
        sanitize::rewrite_uuids(&mut metadata, &mut rewrite);
        if let Some(uuid) = resource_uuid
            && let Some(replacement) = rewrite(uuid)
        {
            resource_id = Some(replacement);
        }
        let Value::Object(metadata) = metadata else {
            return Err(AuthError::internal("sanitized metadata is not an object"));
        };

        let (actor_type, actor_ref) = match event.actor {
            Actor::User(_) => ("user", None),
            Actor::ServiceAccount(id) => ("service_account", Some(id.as_uuid())),
            Actor::ApiKey(id) => ("api_key", Some(id.as_uuid())),
            Actor::System => ("system", None),
            Actor::Anonymous => ("anonymous", None),
        };

        // --- personal data outside the chain (AUD-05) ----------------------
        let user_agent = sanitize::sanitize_user_agent(event.user_agent);
        let pii_owner = if event.impersonator.is_some() {
            impersonator_pseudonym
        } else if actor_user.is_some() {
            actor_pseudonym
        } else {
            subject_pseudonym
        };
        let pii = match (event.ip, user_agent) {
            (None, None) => None,
            // The owner is a deleted user: personal data is not stored again.
            (_, _) if pii_owner.is_some_and(|p| !p.persisted) => None,
            (ip, user_agent) => Some(PiiRow {
                pseudonym: pii_owner.map(|p| p.value),
                ip,
                user_agent,
                salt: authn_crypto::random::bytes::<32>().map_err(AuthError::from)?,
            }),
        };
        let pii_digest = match &pii {
            Some(row) => Some(
                chain::pii_digest(&row.salt, row.ip, row.user_agent.as_deref())
                    .map_err(|e| AuthError::internal("pii digest").with_source(e))?,
            ),
            None => None,
        };

        let record = ChainRecord {
            id: event.id.as_uuid(),
            occurred_at: chain::normalize_timestamp(event.occurred_at),
            recorded_at: chain::normalize_timestamp(now),
            kind: kind.to_owned(),
            outcome: match event.outcome {
                EventOutcome::Success => "success".to_owned(),
                EventOutcome::Failure => "failure".to_owned(),
            },
            reason,
            actor_type: actor_type.to_owned(),
            actor_pseudonym: actor_pseudonym.map(|p| p.value),
            actor_ref,
            impersonator_pseudonym: impersonator_pseudonym.map(|p| p.value),
            subject_pseudonym: subject_pseudonym.map(|p| p.value),
            org_id: event.org_id.map(|o| o.as_uuid()),
            resource_type,
            resource_id,
            request_id: event.request_id.map(|r| r.as_uuid()),
            metadata,
            pii_digest,
        };
        Ok(Prepared { record, pii })
    }
}

/// Resolves every candidate UUID that is a user id to a pseudonym. Users
/// that are deleted (`status = deleted`) or forgotten in this transaction
/// get a one-off pseudonym — even when a mapping still exists — and so do
/// `always` references that are no user id (any more); other candidates
/// that are not user ids are skipped.
async fn resolve_pseudonyms(
    conn: &mut PgConnection,
    candidates: &[Uuid],
    always: &[Uuid],
    now: OffsetDateTime,
) -> Result<Vec<(Uuid, Pseudonym)>, AuthError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<CandidateRow> = sqlx::query_as(
        "SELECT u.id AS user_id, u.status = 'deleted' AS deleted, \
         u.id::text = ANY(string_to_array(coalesce(current_setting('authn.audit_forgotten', true), ''), ',')) AS forgotten, \
         s.pseudonym \
         FROM unnest($1::uuid[]) AS c(id) \
         JOIN users u ON u.id = c.id \
         LEFT JOIN audit_subjects s ON s.user_id = u.id",
    )
    .bind(candidates)
    .fetch_all(&mut *conn)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let pseudonym = match row.pseudonym {
            _ if row.deleted || row.forgotten => Pseudonym {
                value: random_uuid()?,
                persisted: false,
            },
            Some(value) => Pseudonym {
                value,
                persisted: true,
            },
            None => create_mapping(conn, row.user_id, now).await?,
        };
        out.push((row.user_id, pseudonym));
    }
    for id in always {
        if !out.iter().any(|(user, _)| user == id) {
            out.push((
                *id,
                Pseudonym {
                    value: random_uuid()?,
                    persisted: false,
                },
            ));
        }
    }
    Ok(out)
}

/// Creates the user ↔ pseudonym mapping inside a savepoint; a concurrent
/// deletion of the user degrades to a one-off pseudonym instead of failing
/// the caller's transaction.
async fn create_mapping(
    conn: &mut PgConnection,
    user: Uuid,
    now: OffsetDateTime,
) -> Result<Pseudonym, AuthError> {
    let candidate = random_uuid()?;
    let mut savepoint = conn.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO audit_subjects (pseudonym, user_id, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(candidate)
    .bind(user)
    .bind(now)
    .execute(&mut *savepoint)
    .await;
    match inserted {
        Ok(_) => savepoint.commit().await?,
        Err(err) => {
            let classified = StoreError::from(err);
            savepoint.rollback().await?;
            return if matches!(classified, StoreError::ForeignKeyViolation { .. }) {
                Ok(Pseudonym {
                    value: random_uuid()?,
                    persisted: false,
                })
            } else {
                Err(AuthError::from(classified))
            };
        }
    }
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT pseudonym FROM audit_subjects WHERE user_id = $1")
            .bind(user)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(match existing {
        Some(value) => Pseudonym {
            value,
            persisted: true,
        },
        None => Pseudonym {
            value: random_uuid()?,
            persisted: false,
        },
    })
}

async fn append_prepared(
    conn: &mut PgConnection,
    prepared: Prepared,
    now: OffsetDateTime,
) -> Result<AppendedEvent, AuthError> {
    let Prepared { record, pii } = prepared;
    // Serializes every append (no forks): held until the transaction ends.
    let head: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT last_seq, last_hash FROM audit_chain_head WHERE id FOR UPDATE")
            .fetch_optional(&mut *conn)
            .await?;
    let Some((_, last_hash)) = head else {
        return Err(AuthError::internal("audit chain head row is missing"));
    };
    let prev_hash = chain::hash_from_slice(&last_hash)
        .ok_or_else(|| AuthError::internal("audit chain head hash is malformed"))?;

    // Idempotent retry: an event id is appended at most once.
    let existing: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT seq, hash FROM audit_events WHERE id = $1")
            .bind(record.id)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some((seq, hash)) = existing {
        tracing::warn!(event.id = %record.id, "audit event already recorded; ignoring duplicate");
        return Ok(AppendedEvent {
            seq,
            hash: chain::hash_from_slice(&hash).unwrap_or([0; 32]),
            duplicate: true,
        });
    }

    let hash = record
        .hash(&prev_hash)
        .map_err(|e| AuthError::internal("audit record not canonicalizable").with_source(e))?;
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO audit_events (id, occurred_at, recorded_at, kind, outcome, reason, \
         actor_type, actor_pseudonym, actor_ref, impersonator_pseudonym, subject_pseudonym, \
         org_id, resource_type, resource_id, request_id, metadata, pii_digest, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) \
         RETURNING seq",
    )
    .bind(record.id)
    .bind(record.occurred_at)
    .bind(record.recorded_at)
    .bind(&record.kind)
    .bind(&record.outcome)
    .bind(&record.reason)
    .bind(&record.actor_type)
    .bind(record.actor_pseudonym)
    .bind(record.actor_ref)
    .bind(record.impersonator_pseudonym)
    .bind(record.subject_pseudonym)
    .bind(record.org_id)
    .bind(&record.resource_type)
    .bind(&record.resource_id)
    .bind(record.request_id)
    .bind(sqlx::types::Json(Value::Object(record.metadata.clone())))
    .bind(record.pii_digest.as_ref().map(<[u8; 32]>::as_slice))
    .bind(prev_hash.as_slice())
    .bind(hash.as_slice())
    .fetch_one(&mut *conn)
    .await?;

    if let Some(pii) = pii {
        sqlx::query(
            "INSERT INTO audit_event_pii (event_id, pseudonym, ip, user_agent, salt) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(record.id)
        .bind(pii.pseudonym)
        .bind(pii.ip)
        .bind(&pii.user_agent)
        .bind(pii.salt.as_slice())
        .execute(&mut *conn)
        .await?;
    }

    sqlx::query(
        "UPDATE audit_chain_head SET last_seq = $1, last_hash = $2, updated_at = $3 WHERE id",
    )
    .bind(seq)
    .bind(hash.as_slice())
    .bind(now)
    .execute(&mut *conn)
    .await?;

    Ok(AppendedEvent {
        seq,
        hash,
        duplicate: false,
    })
}

#[async_trait]
impl AuditSink for PgAuditSink {
    async fn record(&self, event: SecurityEvent) -> Result<(), AuthError> {
        let kind = event.kind;
        let mut retried = false;
        loop {
            let mut tx = self.pool.begin().await?;
            sqlx::query(RECORD_LOCK_TIMEOUT).execute(&mut *tx).await?;
            match self.append(&mut tx, event.clone()).await {
                Ok(_) => {
                    tx.commit().await?;
                    return Ok(());
                }
                Err(err) => {
                    if let Err(rollback) = tx.rollback().await {
                        tracing::warn!(error = %rollback, "audit transaction rollback failed");
                    }
                    if !retried && is_retryable(&err) {
                        retried = true;
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                    tracing::error!(event.kind = kind.as_str(), error = %err, "audit event could not be recorded");
                    return Err(err);
                }
            }
        }
    }

    async fn record_in_tx(
        &self,
        conn: &mut PgConnection,
        event: SecurityEvent,
    ) -> Result<(), AuthError> {
        self.append(conn, event).await.map(|_| ())
    }

    async fn pseudonymize_subject(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<(), AuthError> {
        // Remember for the rest of this transaction: no new mapping may be
        // created for this user, whatever the order of the caller's steps.
        sqlx::query(
            "SELECT set_config($1, concat_ws(',', nullif(current_setting($1, true), ''), $2), true)",
        )
        .bind(FORGOTTEN_SETTING)
        .bind(user.to_string())
        .execute(&mut *conn)
        .await?;
        // Deleting the mapping cascades to every PII row of the pseudonym.
        let removed = sqlx::query("DELETE FROM audit_subjects WHERE user_id = $1")
            .bind(user)
            .execute(&mut *conn)
            .await?;
        scrub_erased_subject(&mut *conn, user, self.clock.now()).await?;
        tracing::info!(
            mappings_removed = removed.rows_affected(),
            "audit subject pseudonymised"
        );
        Ok(())
    }
}

/// K-58 (AUD-05, ACC-09): no user id of an erased account outlives the
/// erasure in the outbox or the webhook delivery history. Runs in the
/// erasure transaction. Order matters (see `WebhookFanout`): the outbox
/// rows are flagged before the deliveries are looked up.
///
/// * outbox: dead-letter messages of the user are scrubbed now; pending
///   and in-flight ones are flagged and scrubbed when they finish
///   (delivered messages are always scrubbed at delivery);
/// * webhook deliveries: every delivery of the user is flagged; finished
///   ones (succeeded, dead) are redacted now, unfinished ones when they
///   finish — so receivers still get e.g. `user.deleted`.
async fn scrub_erased_subject(
    conn: &mut PgConnection,
    user: UserId,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    let id = user.to_string();
    let outbox = sqlx::query(
        "UPDATE outbox SET subject_erased = true, \
         payload = CASE WHEN status = 'dead' \
             THEN payload - 'user_id' - 'recipient' - 'data' ELSE payload END \
         WHERE status IN ('pending', 'processing', 'dead') AND payload ->> 'user_id' = $1",
    )
    .bind(&id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE webhook_deliveries SET subject_erased_at = coalesce(subject_erased_at, $2) \
         WHERE subject_user_id = $1",
    )
    .bind(user)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    let redacted = sqlx::query(concat!(
        "UPDATE webhook_deliveries SET ",
        crate::webhooks::redact_if_erased!("status", "$2"),
        " WHERE subject_user_id = $1 AND status IN ('succeeded', 'dead')"
    ))
    .bind(user)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    tracing::info!(
        outbox_rows = outbox.rows_affected(),
        deliveries_redacted = redacted.rows_affected(),
        "erased subject scrubbed from outbox and webhook history"
    );
    Ok(())
}
