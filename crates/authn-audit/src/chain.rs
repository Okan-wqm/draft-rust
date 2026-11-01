//! The hash chain (AUD-02).
//!
//! `hash = SHA-256(prev_hash || canonical_json(record))` where `prev_hash` is
//! the 32-byte hash of the previous event (32 zero bytes for the first event,
//! or the hash stored in the latest retention checkpoint after a purge) and
//! `record` is the [`ChainRecord`] below: every stored column of
//! `audit_events` except `seq`, `prev_hash` and `hash`.
//!
//! Personal data is *not* part of the record: users appear as pseudonyms,
//! and IP / user agent are represented by `pii_digest =
//! SHA-256(salt || canonical_json({"ip":…,"user_agent":…}))` whose inputs
//! live in `audit_event_pii` and may be deleted (AUD-05) without touching the
//! chain. Once the salt is gone the digest cannot be brute-forced back to an
//! IP address.

use std::net::IpAddr;

use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

use crate::canonical::{self, CanonicalError, hex};

/// Version of the canonical record layout.
pub const RECORD_VERSION: u8 = 1;

/// `prev_hash` of the very first event.
pub const GENESIS_HASH: [u8; 32] = [0; 32];

/// The chained part of an audit event.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainRecord {
    /// Event id.
    pub id: Uuid,
    /// When it happened (microsecond precision, UTC).
    pub occurred_at: OffsetDateTime,
    /// When it was recorded (microsecond precision, UTC).
    pub recorded_at: OffsetDateTime,
    /// Event kind.
    pub kind: String,
    /// `success` / `failure`.
    pub outcome: String,
    /// Reason code.
    pub reason: Option<String>,
    /// Actor type.
    pub actor_type: String,
    /// Pseudonym of the acting user.
    pub actor_pseudonym: Option<Uuid>,
    /// Service account / API key id.
    pub actor_ref: Option<Uuid>,
    /// Pseudonym of the impersonating admin.
    pub impersonator_pseudonym: Option<Uuid>,
    /// Pseudonym of the subject user.
    pub subject_pseudonym: Option<Uuid>,
    /// Organization.
    pub org_id: Option<Uuid>,
    /// Resource type.
    pub resource_type: Option<String>,
    /// Resource id.
    pub resource_id: Option<String>,
    /// Request id.
    pub request_id: Option<Uuid>,
    /// Sanitized metadata.
    pub metadata: Map<String, Value>,
    /// Digest of the personal data stored outside the chain.
    pub pii_digest: Option<[u8; 32]>,
}

/// Truncates to microseconds and converts to UTC (PostgreSQL `timestamptz`
/// precision), so the value hashed equals the value read back.
#[must_use]
pub fn normalize_timestamp(at: OffsetDateTime) -> OffsetDateTime {
    let utc = at.to_offset(UtcOffset::UTC);
    let micros = utc.microsecond();
    utc.replace_microsecond(micros).unwrap_or(utc)
}

/// RFC 3339 with exactly six fractional digits, `Z` suffix.
pub fn format_timestamp(at: OffsetDateTime) -> Result<String, ChainError> {
    let at = normalize_timestamp(at);
    let year = at.year();
    if !(0..=9999).contains(&year) {
        return Err(ChainError::Timestamp);
    }
    Ok(format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        at.microsecond()
    ))
}

/// Errors building a record's canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// The timestamp cannot be represented.
    #[error("timestamp out of range")]
    Timestamp,
    /// Metadata has no canonical form.
    #[error("metadata is not canonicalizable: {0}")]
    Canonical(#[from] CanonicalError),
}

fn opt_uuid(id: Option<Uuid>) -> Value {
    id.map_or(Value::Null, |u| Value::String(u.hyphenated().to_string()))
}

impl ChainRecord {
    /// The canonical JSON bytes of the record.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let value = json!({
            "v": RECORD_VERSION,
            "id": self.id.hyphenated().to_string(),
            "occurred_at": format_timestamp(self.occurred_at)?,
            "recorded_at": format_timestamp(self.recorded_at)?,
            "kind": self.kind,
            "outcome": self.outcome,
            "reason": self.reason,
            "actor_type": self.actor_type,
            "actor_pseudonym": opt_uuid(self.actor_pseudonym),
            "actor_ref": opt_uuid(self.actor_ref),
            "impersonator_pseudonym": opt_uuid(self.impersonator_pseudonym),
            "subject_pseudonym": opt_uuid(self.subject_pseudonym),
            "org_id": opt_uuid(self.org_id),
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "request_id": opt_uuid(self.request_id),
            "metadata": Value::Object(self.metadata.clone()),
            "pii_digest": self.pii_digest.map(|d| hex(&d)),
        });
        Ok(canonical::to_canonical_vec(&value)?)
    }

    /// `SHA-256(prev_hash || canonical_json(record))`.
    pub fn hash(&self, prev_hash: &[u8; 32]) -> Result<[u8; 32], ChainError> {
        Ok(chain_hash(prev_hash, &self.canonical_bytes()?))
    }
}

/// `SHA-256(prev_hash || canonical)`.
#[must_use]
pub fn chain_hash(prev_hash: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(canonical);
    hasher.finalize().into()
}

/// Digest binding the off-chain personal data of one event:
/// `SHA-256(salt || canonical_json({"ip":…,"user_agent":…}))`.
pub fn pii_digest(
    salt: &[u8],
    ip: Option<IpAddr>,
    user_agent: Option<&str>,
) -> Result<[u8; 32], ChainError> {
    let value = json!({
        "ip": ip.map(|ip| ip.to_string()),
        "user_agent": user_agent,
    });
    let canonical = canonical::to_canonical_vec(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(&canonical);
    Ok(hasher.finalize().into())
}

/// Converts a stored 32-byte hash.
pub fn hash_from_slice(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn record() -> ChainRecord {
        ChainRecord {
            id: Uuid::nil(),
            occurred_at: datetime!(2026-01-01 00:00:00.123456789 UTC),
            recorded_at: datetime!(2026-01-01 01:00:00 +01:00),
            kind: "login.failed".into(),
            outcome: "failure".into(),
            reason: Some("wrong_password".into()),
            actor_type: "anonymous".into(),
            actor_pseudonym: None,
            actor_ref: None,
            impersonator_pseudonym: None,
            subject_pseudonym: Some(Uuid::from_u128(1)),
            org_id: None,
            resource_type: None,
            resource_id: None,
            request_id: None,
            metadata: Map::new(),
            pii_digest: Some([0xab; 32]),
        }
    }

    #[test]
    fn aud_02_timestamps_are_microsecond_utc() {
        let at = datetime!(2026-01-01 03:00:00.123456789 +03:00);
        assert_eq!(format_timestamp(at).unwrap(), "2026-01-01T00:00:00.123456Z");
        assert_eq!(
            format_timestamp(datetime!(2026-01-01 00:00:00 UTC)).unwrap(),
            "2026-01-01T00:00:00.000000Z"
        );
        assert_eq!(
            normalize_timestamp(at),
            datetime!(2026-01-01 00:00:00.123456 UTC)
        );
    }

    #[test]
    fn aud_02_hash_is_sha256_of_prev_hash_and_canonical_json() {
        let r = record();
        let canonical = String::from_utf8(r.canonical_bytes().unwrap()).unwrap();
        assert!(canonical.starts_with(r#"{"actor_pseudonym":null,"actor_ref":null,"actor_type":"anonymous","id":"00000000-0000-0000-0000-000000000000","impersonator_pseudonym":null,"kind":"login.failed","metadata":{},"occurred_at":"2026-01-01T00:00:00.123456Z""#), "{canonical}");
        assert!(canonical.ends_with(r#""recorded_at":"2026-01-01T00:00:00.000000Z","request_id":null,"resource_id":null,"resource_type":null,"subject_pseudonym":"00000000-0000-0000-0000-000000000001","v":1}"#), "{canonical}");
        let prev = [7_u8; 32];
        let mut expected = Sha256::new();
        expected.update(prev);
        expected.update(canonical.as_bytes());
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(r.hash(&prev).unwrap(), expected);
        // Any change in the record or in the previous hash changes the hash.
        let mut other = r.clone();
        other.reason = Some("unknown_account".into());
        assert_ne!(other.hash(&prev).unwrap(), expected);
        assert_ne!(r.hash(&GENESIS_HASH).unwrap(), expected);
    }

    #[test]
    fn aud_05_pii_digest_depends_on_salt_and_content() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let a = pii_digest(&[1; 32], Some(ip), Some("ua")).unwrap();
        assert_eq!(a, pii_digest(&[1; 32], Some(ip), Some("ua")).unwrap());
        assert_ne!(a, pii_digest(&[2; 32], Some(ip), Some("ua")).unwrap());
        assert_ne!(a, pii_digest(&[1; 32], None, Some("ua")).unwrap());
    }
}
