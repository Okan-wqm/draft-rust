//! Erasure ledger (K-108; ACC-05, ACC-09; KVKK md. 7, GDPR art. 17).
//!
//! Every erasure writes one `erasure_ledger` row in its own transaction
//! ([`AccountService::finish_erasure`]). A database restored from a backup
//! brings erased accounts back **and** an older copy of the ledger, so the
//! authoritative copy lives outside the database: the operator exports the
//! ledger regularly ([`AccountService::export_erasures`],
//! `rust-authentication export-erasures`) and, after a restore and before
//! starting the server, re-applies it
//! ([`AccountService::reapply_erasure`], `rust-authentication
//! reapply-erasures`).
//!
//! Every exported line carries a MAC ([`ledger_line`], key
//! `KeyPurpose::ErasureLedger` of `crypto.hmac_root_key`) and
//! [`parse_ledger_line`] refuses a line without a valid one: the file lives
//! in storage outside the database, and re-applying it erases accounts
//! irreversibly, so write access to that storage must not be a way to
//! delete arbitrary accounts after the next restore. The MAC does not
//! detect a *removed* line (keep the export storage append-only /
//! versioned; the database copy of the ledger is the second source).
//!
//! Re-applying is idempotent: an account that is gone is only (re)recorded
//! in the ledger; an account that came back is erased through the normal
//! erasure path (audited status change, `user.deleted` event, audit
//! pseudonymisation, erasure hooks, cascading delete). An account that is
//! the last owner of an organization in the restored data is reported and
//! left alone: the operator transfers or deletes the organization first.

use authn_core::domain::AccountStatus;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::Actor;
use authn_crypto::kdf::HmacKey;
use authn_store::UserRepository;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use time::OffsetDateTime;

use super::AccountService;
use crate::lifecycle::{StatusChange, apply_transition};
use crate::repo::DeletionRepository;

/// Reason code of an erasure re-applied after a restore.
pub const REAPPLIED_REASON: &str = "erasure_reapplied";

/// One ledger entry: the JSON line of `export-erasures`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct ErasureRecord {
    /// The erased account.
    pub user_id: UserId,
    /// When it was (first) erased.
    #[serde(with = "time::serde::rfc3339")]
    pub erased_at: OffsetDateTime,
    /// Reason code of the erasure (`grace_period_elapsed`,
    /// `unverified_expired`, …).
    pub reason: String,
}

/// Domain separation of the ledger line MAC (version 1).
const LEDGER_MAC_DOMAIN: &[u8] = b"authn/erasure-ledger/v1";

/// One exported line: the record and its MAC (hex).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerLine {
    user_id: UserId,
    #[serde(with = "time::serde::rfc3339")]
    erased_at: OffsetDateTime,
    reason: String,
    mac: String,
}

/// The MAC input: canonical, length-prefixed fields (the time as Unix
/// nanoseconds, so no RFC 3339 spelling variant changes it).
fn ledger_mac(key: &HmacKey, user_id: UserId, erased_at: OffsetDateTime, reason: &str) -> [u8; 32] {
    let user = user_id.to_string();
    let at = erased_at.unix_timestamp_nanos().to_string();
    key.sign_fields(&[
        LEDGER_MAC_DOMAIN,
        user.as_bytes(),
        at.as_bytes(),
        reason.as_bytes(),
    ])
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The `export-erasures` JSON line of `record`, with its MAC under `key`
/// (`KeyPurpose::ErasureLedger`, K-108).
#[must_use]
pub fn ledger_line(record: &ErasureRecord, key: &HmacKey) -> String {
    let line = LedgerLine {
        user_id: record.user_id,
        erased_at: record.erased_at,
        reason: record.reason.clone(),
        mac: to_hex(&ledger_mac(
            key,
            record.user_id,
            record.erased_at,
            &record.reason,
        )),
    };
    // Plain strings, a UUID and a valid time: serialisation cannot fail.
    serde_json::to_string(&line).unwrap_or_default()
}

/// Parses one `export-erasures` line and checks its MAC under `key`
/// (constant time). `None` for anything that is not an authentic line
/// written by [`ledger_line`] with the same key.
#[must_use]
pub fn parse_ledger_line(line: &str, key: &HmacKey) -> Option<ErasureRecord> {
    let parsed: LedgerLine = serde_json::from_str(line).ok()?;
    let tag = from_hex(&parsed.mac)?;
    let fields_user = parsed.user_id.to_string();
    let fields_at = parsed.erased_at.unix_timestamp_nanos().to_string();
    key.verify_fields(
        &[
            LEDGER_MAC_DOMAIN,
            fields_user.as_bytes(),
            fields_at.as_bytes(),
            parsed.reason.as_bytes(),
        ],
        &tag,
    )
    .then_some(ErasureRecord {
        user_id: parsed.user_id,
        erased_at: parsed.erased_at,
        reason: parsed.reason,
    })
}

/// What [`AccountService::reapply_erasure`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapplyOutcome {
    /// The account does not exist: nothing to erase (ledger row ensured).
    AlreadyErased,
    /// The account had come back and was erased again.
    Erased,
    /// The account is the only owner of an organization in the restored
    /// data; nothing changed (transfer or delete the organization, rerun).
    BlockedLastOwner,
}

/// Records an erasure in the ledger (inside the erasure transaction). The
/// first erasure of an account wins (a re-application keeps the original
/// time and reason).
pub(super) async fn record(
    conn: &mut PgConnection,
    user: UserId,
    erased_at: OffsetDateTime,
    reason: &str,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO erasure_ledger (user_id, erased_at, reason) VALUES ($1, $2, $3) \
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user)
    .bind(erased_at)
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(())
}

/// Reason codes accepted from a ledger file (the column's `CHECK`).
fn is_reason_code(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl AccountService {
    /// Ledger entries erased at or after `since`, oldest first, at most
    /// `limit`, continuing after `after` (the last entry of the previous
    /// page) when given (K-108). Export them regularly to storage that is
    /// not restored with the database; overlapping exports are harmless.
    pub async fn export_erasures(
        &self,
        since: OffsetDateTime,
        after: Option<&ErasureRecord>,
        limit: i64,
    ) -> Result<Vec<ErasureRecord>, AuthError> {
        let (after_at, after_user) = match after {
            Some(entry) => (Some(entry.erased_at), Some(entry.user_id)),
            None => (None, None),
        };
        Ok(sqlx::query_as::<_, ErasureRecord>(
            "SELECT user_id, erased_at, reason FROM erasure_ledger \
             WHERE erased_at >= $1 \
               AND ($2::timestamptz IS NULL OR (erased_at, user_id) > ($2, $3)) \
             ORDER BY erased_at, user_id LIMIT $4",
        )
        .bind(since)
        .bind(after_at)
        .bind(after_user)
        .bind(limit.clamp(1, 1_000_000))
        .fetch_all(self.pool())
        .await?)
    }

    /// Re-applies one ledger entry after a restore (K-108). Idempotent.
    pub async fn reapply_erasure(
        &self,
        entry: &ErasureRecord,
    ) -> Result<ReapplyOutcome, AuthError> {
        if !is_reason_code(&entry.reason) {
            return Err(AuthError::internal("invalid erasure reason code"));
        }
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(user) = UserRepository::lock_for_update(tx.conn(), entry.user_id).await? else {
            record(tx.conn(), entry.user_id, entry.erased_at, &entry.reason).await?;
            tx.commit().await?;
            return Ok(ReapplyOutcome::AlreadyErased);
        };
        if !self
            .deps()
            .ownership
            .sole_owner_organizations(tx.conn(), user.id)
            .await?
            .is_empty()
        {
            drop(tx);
            tracing::warn!(user_id = %user.id, "erasure not re-applied: last owner of an organization");
            return Ok(ReapplyOutcome::BlockedLastOwner);
        }
        // The original record (time and reason) is kept.
        record(tx.conn(), user.id, entry.erased_at, &entry.reason).await?;
        // Walk the state machine to `deleted` (each step audited), as the
        // original erasure did; a restored schedule is completed.
        let verified = user.email_verified_at.is_some();
        let path: &[AccountStatus] = match user.status {
            AccountStatus::PendingVerification | AccountStatus::PendingDeletion => &[],
            AccountStatus::Locked => &[AccountStatus::Suspended, AccountStatus::PendingDeletion],
            AccountStatus::Active | AccountStatus::Suspended | AccountStatus::Disabled => {
                &[AccountStatus::PendingDeletion]
            }
            AccountStatus::Deleted => {
                return Err(AuthError::internal("account row in the deleted state"));
            }
        };
        let mut current = user.clone();
        for step in path {
            apply_transition(
                &mut tx,
                &current,
                &StatusChange::new(*step, REAPPLIED_REASON, Actor::System),
                verified,
                now,
                None,
            )
            .await?;
            current.status = *step;
        }
        apply_transition(
            &mut tx,
            &current,
            &StatusChange::new(AccountStatus::Deleted, REAPPLIED_REASON, Actor::System),
            verified,
            now,
            None,
        )
        .await?;
        if let Some(scheduled) = DeletionRepository::find_scheduled(tx.conn(), user.id).await? {
            DeletionRepository::complete(tx.conn(), scheduled.id, now).await?;
        }
        self.finish_erasure(tx, user.id, REAPPLIED_REASON, now)
            .await?;
        Ok(ReapplyOutcome::Erased)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k_108_ledger_line_round_trips_and_is_strict() {
        let line = r#"{"user_id":"01900000-0000-7000-8000-0000000000aa","erased_at":"2026-11-05T10:00:00Z","reason":"grace_period_elapsed"}"#;
        let record: ErasureRecord = serde_json::from_str(line).unwrap();
        assert_eq!(record.reason, "grace_period_elapsed");
        assert_eq!(serde_json::to_string(&record).unwrap(), line);
        for bad in [
            r#"{"user_id":"x","erased_at":"2026-11-05T10:00:00Z","reason":"a"}"#,
            r#"{"user_id":"01900000-0000-7000-8000-0000000000aa","erased_at":"yesterday","reason":"a"}"#,
            r#"{"user_id":"01900000-0000-7000-8000-0000000000aa","erased_at":"2026-11-05T10:00:00Z","reason":"a","email":"x"}"#,
        ] {
            assert!(serde_json::from_str::<ErasureRecord>(bad).is_err(), "{bad}");
        }
    }

    fn key(byte: u8) -> HmacKey {
        authn_crypto::kdf::KeyRing::derive(&[byte; 32])
            .unwrap()
            .key(authn_crypto::kdf::KeyPurpose::ErasureLedger)
            .unwrap()
            .clone()
    }

    #[test]
    fn acc_09_k108_ledger_lines_are_authenticated() {
        let record = ErasureRecord {
            user_id: serde_json::from_str("\"01900000-0000-7000-8000-0000000000aa\"").unwrap(),
            erased_at: OffsetDateTime::from_unix_timestamp(1_793_000_000).unwrap(),
            reason: "grace_period_elapsed".to_owned(),
        };
        let line = ledger_line(&record, &key(1));
        assert_eq!(parse_ledger_line(&line, &key(1)), Some(record.clone()));
        // Another deployment's (or a rotated) key, no MAC, a changed field.
        assert_eq!(parse_ledger_line(&line, &key(2)), None);
        let unsigned = serde_json::to_string(&record).unwrap();
        assert_eq!(parse_ledger_line(&unsigned, &key(1)), None);
        let retargeted = line.replace("0000000000aa", "0000000000ab");
        assert_ne!(retargeted, line);
        assert_eq!(parse_ledger_line(&retargeted, &key(1)), None);
        let rereasoned = line.replace("grace_period_elapsed", "unverified_expired");
        assert_eq!(parse_ledger_line(&rereasoned, &key(1)), None);
        let bad_hex = line.replace("\"mac\":\"", "\"mac\":\"zz");
        assert_eq!(parse_ledger_line(&bad_hex, &key(1)), None);
    }

    #[test]
    fn k_108_reason_codes_match_the_column_check() {
        for ok in ["a", "grace_period_elapsed", "erasure_reapplied", "x1_2"] {
            assert!(is_reason_code(ok), "{ok}");
        }
        for bad in ["", "A", "1a", "a-b", "a b", &"a".repeat(65)] {
            assert!(!is_reason_code(bad), "{bad}");
        }
    }
}
