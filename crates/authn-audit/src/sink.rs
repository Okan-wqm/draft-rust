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
//!
//! K-77: a keyed sink ([`PgAuditSink::keyed`]) MACs every event with the
//! chain key (`HMAC-SHA-256(K_v, prev_hash ‖ record)`) and records `v`.
//! The version is `max(version at the head, configured version)`, so
//! versions never decrease — also while instances with the old and the new
//! configuration run side by side during a rotation. An unkeyed sink
//! ([`PgAuditSink::new`]) writes legacy SHA-256 events and **refuses** to
//! append once the chain is keyed (that would be a downgrade the verifier
//! reports as a break).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::{Actor, AuditSink, Clock, EventOutcome, SecurityEvent, SecurityEventKind};
use authn_store::StoreError;
use serde_json::Value;
use sqlx::{Connection as _, PgConnection, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::chain::{self, ChainRecord};
use crate::keys::{self, ChainKeys};
use crate::sanitize::{self, StringCheck};
use crate::verify::ChainAnchor;

/// Session-local setting listing users pseudonymised in the current
/// transaction (see [`PgAuditSink::pseudonymize_subject`]).
const FORGOTTEN_SETTING: &str = "authn.audit_forgotten";

/// Lock wait limit of [`PgAuditSink::record`]: a writer never hangs forever
/// behind a transaction that holds the chain head.
const RECORD_LOCK_TIMEOUT: &str = "SET LOCAL lock_timeout = '10s'";
/// `BEGIN` of [`AuditSink::record`]'s own transaction with its lock
/// timeout, sent as one message (one round trip, K-128).
const BEGIN_WITH_LOCK_TIMEOUT: &str = "BEGIN; SET LOCAL lock_timeout = '10s'";

/// The chain head, locked until the transaction ends (serialises every
/// append: no forks), and the event with id `$1` if it was already
/// appended (idempotent retry).
const LOCK_HEAD_SQL: &str = "\
SELECT h.last_hash, h.key_version, e.seq AS duplicate_seq, e.hash AS duplicate_hash
FROM audit_chain_head h
LEFT JOIN audit_events e ON e.id = $1
WHERE h.id
FOR UPDATE OF h";

/// Appends one event: the chained row, its off-chain personal data (when
/// `$21`) and the new head, in one statement. The head update's trigger
/// records a `chain_key_switch` checkpoint on a key-version change
/// (migration 1703); the foreign key of `audit_event_pii` is checked at
/// the end of the statement, after the event row exists. An event id that
/// a concurrent writer committed while this one waited for the head lock
/// (invisible to [`LOCK_HEAD_SQL`]'s snapshot: READ COMMITTED re-checks
/// only the locked head row) inserts nothing and returns no row; nothing
/// else is written then.
const APPEND_SQL: &str = "\
WITH event AS (
    INSERT INTO audit_events (id, occurred_at, recorded_at, kind, outcome, reason,
        actor_type, actor_pseudonym, actor_ref, impersonator_pseudonym, subject_pseudonym,
        org_id, resource_type, resource_id, request_id, metadata, pii_digest, prev_hash, hash,
        chain_key_version)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
        $19, $20)
    ON CONFLICT (id) DO NOTHING
    RETURNING seq, id
), pii AS (
    INSERT INTO audit_event_pii (event_id, pseudonym, ip, user_agent, salt)
    SELECT event.id, $22::uuid, $23::inet, $24::text, $25::bytea FROM event WHERE $21::bool
), head AS (
    UPDATE audit_chain_head SET last_seq = event.seq, last_hash = $19, updated_at = $26,
        key_version = $20
    FROM event WHERE audit_chain_head.id
)
SELECT seq FROM event";

#[derive(sqlx::FromRow)]
struct HeadRow {
    last_hash: Vec<u8>,
    key_version: Option<i16>,
    duplicate_seq: Option<i64>,
    duplicate_hash: Option<Vec<u8>>,
}

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

/// Result of [`PgAuditSink::activate_chain_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainKeyActivation {
    /// Key version at the head before (`None` = legacy, unkeyed).
    pub from_version: Option<u16>,
    /// Key version at the head now.
    pub to_version: u16,
    /// The `chain_key_switch` checkpoint `(seq, hash)` of the rotation
    /// event; `None` when nothing changed.
    pub switch: Option<ChainAnchor>,
}

/// The PostgreSQL audit sink.
#[derive(Clone)]
pub struct PgAuditSink {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    keys: Option<ChainKeys>,
}

impl std::fmt::Debug for PgAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgAuditSink")
            .field("keyed", &self.keys.is_some())
            .finish_non_exhaustive()
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
    /// An **unkeyed** sink: legacy SHA-256 chaining, for tests and tools of
    /// other modules that never see a keyed chain. It refuses to append to
    /// a keyed chain. Production code uses [`PgAuditSink::keyed`].
    #[must_use]
    pub fn new(pool: PgPool, clock: Arc<dyn Clock>) -> Self {
        Self {
            pool,
            clock,
            keys: None,
        }
    }

    /// A keyed sink (K-77): events are MACed with the chain key.
    #[must_use]
    pub fn keyed(pool: PgPool, clock: Arc<dyn Clock>, keys: ChainKeys) -> Self {
        Self {
            pool,
            clock,
            keys: Some(keys),
        }
    }

    /// The chain keys of a keyed sink.
    #[must_use]
    pub fn chain_keys(&self) -> Option<&ChainKeys> {
        self.keys.as_ref()
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
        let appended =
            append_prepared(conn, prepared, self.clock.now(), self.keys.as_ref()).await?;
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

    /// Switches the chain to the configured key version (K-77), at start-up
    /// of the server and from the `rotate-audit-chain-key` command: when the
    /// head is unkeyed (legacy) or uses an older version, appends one
    /// `audit.chain_key_rotated` event MACed with the new key (the first
    /// event of the new version; the database records a `chain_key_switch`
    /// checkpoint for it). Idempotent and safe on several instances (the
    /// head is locked); a no-op when the head already uses this or a newer
    /// version.
    pub async fn activate_chain_key(&self) -> Result<ChainKeyActivation, AuthError> {
        let Some(keys) = &self.keys else {
            return Err(AuthError::internal(
                "audit chain key activation needs a keyed audit sink",
            ));
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query(RECORD_LOCK_TIMEOUT).execute(&mut *tx).await?;
        let (_, head_version) = lock_head(&mut tx).await?;
        let from =
            match head_version {
                None => None,
                Some(v) => Some(keys::version_from_db(v).ok_or_else(|| {
                    AuthError::internal("audit chain head key version is malformed")
                })?),
            };
        let to = next_version(keys, head_version)?;
        if from == Some(to) {
            tx.commit().await?;
            return Ok(ChainKeyActivation {
                from_version: from,
                to_version: to,
                switch: None,
            });
        }
        let event = SecurityEvent::new(SecurityEventKind::AuditChainKeyRotated, self.clock.now())
            .with_actor(Actor::System)
            .with_meta("from_version", from.map_or(0, u64::from))
            .with_meta("to_version", u64::from(to));
        let appended = self.append(&mut tx, event).await?;
        tx.commit().await?;
        let switch = ChainAnchor {
            seq: appended.seq,
            hash: appended.hash,
        };
        tracing::warn!(
            from_version = from.map_or(0, u64::from),
            to_version = to,
            checkpoint_seq = switch.seq,
            checkpoint_hash = %switch.hash_hex(),
            "audit chain key version switched; export this checkpoint (and, after the first switch, set audit.chain.legacy_until_seq = checkpoint_seq - 1)"
        );
        Ok(ChainKeyActivation {
            from_version: from,
            to_version: to,
            switch: Some(switch),
        })
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
    // Runs also without candidates (K-128, CRY-05): an event about an
    // unknown account (no subject) then costs the statements of one about
    // an existing account, so e.g. a failed login for an unknown address
    // takes the same database round trips as a wrong password.
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

/// The chain head, locked until the transaction ends (serializes every
/// append: no forks).
pub(crate) async fn lock_head(
    conn: &mut PgConnection,
) -> Result<(Vec<u8>, Option<i16>), AuthError> {
    let head: Option<(i64, Vec<u8>, Option<i16>)> = sqlx::query_as(
        "SELECT last_seq, last_hash, key_version FROM audit_chain_head WHERE id FOR UPDATE",
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some((_, last_hash, key_version)) = head else {
        return Err(AuthError::internal("audit chain head row is missing"));
    };
    Ok((last_hash, key_version))
}

/// The key version for the next event (K-77): never lower than the
/// version at the head.
fn next_version(keys: &ChainKeys, head_version: Option<i16>) -> Result<u16, AuthError> {
    let at_head = match head_version {
        None => 0,
        Some(v) => keys::version_from_db(v)
            .ok_or_else(|| AuthError::internal("audit chain head key version is malformed"))?,
    };
    Ok(at_head.max(keys.current_version()))
}

async fn append_prepared(
    conn: &mut PgConnection,
    prepared: Prepared,
    now: OffsetDateTime,
    keys: Option<&ChainKeys>,
) -> Result<AppendedEvent, AuthError> {
    let Prepared { record, pii } = prepared;
    // K-128: the head lock and the duplicate check are one statement, and
    // the event, its personal data and the new head are written by a
    // second one — the head stays locked for two round trips (plus the
    // caller's COMMIT) instead of five. The chain is computed exactly as
    // before: the previous hash comes from the locked head.
    let head: Option<HeadRow> = sqlx::query_as(LOCK_HEAD_SQL)
        .bind(record.id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(head) = head else {
        return Err(AuthError::internal("audit chain head row is missing"));
    };
    let head_version = head.key_version;
    let prev_hash = chain::hash_from_slice(&head.last_hash)
        .ok_or_else(|| AuthError::internal("audit chain head hash is malformed"))?;

    // Idempotent retry: an event id is appended at most once.
    if let (Some(seq), Some(hash)) = (head.duplicate_seq, head.duplicate_hash) {
        tracing::warn!(event.id = %record.id, "audit event already recorded; ignoring duplicate");
        return Ok(AppendedEvent {
            seq,
            hash: chain::hash_from_slice(&hash).unwrap_or([0; 32]),
            duplicate: true,
        });
    }

    let (hash, version) = match keys {
        Some(keys) => {
            let version = next_version(keys, head_version)?;
            let key = keys.key(version)?;
            let hash = record.keyed_hash(&key, &prev_hash).map_err(|e| {
                AuthError::internal("audit record not canonicalizable").with_source(e)
            })?;
            (hash, Some(keys::version_to_db(version)?))
        }
        // An unkeyed writer never extends a keyed chain (downgrade).
        None if head_version.is_some() => {
            return Err(AuthError::internal(
                "audit chain is keyed but this audit writer has no chain key",
            ));
        }
        None => (
            record.hash(&prev_hash).map_err(|e| {
                AuthError::internal("audit record not canonicalizable").with_source(e)
            })?,
            None,
        ),
    };
    let appended: Option<i64> = sqlx::query_scalar(APPEND_SQL)
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
        .bind(version)
        .bind(pii.is_some())
        .bind(pii.as_ref().and_then(|p| p.pseudonym))
        .bind(pii.as_ref().and_then(|p| p.ip))
        .bind(pii.as_ref().and_then(|p| p.user_agent.as_deref()))
        .bind(pii.as_ref().map(|p| p.salt.as_slice()))
        .bind(now)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(seq) = appended else {
        // Idempotent retry that raced the head lock (see `APPEND_SQL`).
        let (seq, hash): (i64, Vec<u8>) =
            sqlx::query_as("SELECT seq, hash FROM audit_events WHERE id = $1")
                .bind(record.id)
                .fetch_one(&mut *conn)
                .await?;
        tracing::warn!(event.id = %record.id, "audit event already recorded; ignoring duplicate");
        return Ok(AppendedEvent {
            seq,
            hash: chain::hash_from_slice(&hash)
                .ok_or_else(|| AuthError::internal("audit event hash is malformed"))?,
            duplicate: true,
        });
    };

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
            let mut tx = self.pool.begin_with(BEGIN_WITH_LOCK_TIMEOUT).await?;
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
