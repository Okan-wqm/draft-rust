//! JWT signing-key lifecycle (CRY-10) on the `signing_keys` table.
//!
//! ```text
//!   create_pending ──► pending ──(activate_after reached)──► active ──(next activation)──► retired
//!        │                │                                    │                               │
//!        │                └────────────── revoke ──────────────┴──────────── revoke ───────────┘
//!        └─ emergency_rotate: revokes the active key and activates a fresh one at once
//! ```
//!
//! * Private keys are Ed25519 seeds sealed with envelope encryption
//!   (CRY-08, AAD = `signing_keys` / `private_key_ciphertext` / key id); the
//!   loaded key is checked against the stored public key.
//! * A new key is published as `pending` for at least the JWKS cache TTL
//!   before it can sign (`crypto.signing_keys.pending_period`); a retired key
//!   stays published until `publish_until` (`retired_retention`, ≥ the
//!   longest token lifetime); a revoked key disappears at once.
//! * Every state change runs in a transaction (savepoint inside a caller's
//!   transaction) holding a transaction-scoped advisory lock, so concurrent
//!   rotations from several instances serialize; the partial unique index
//!   `signing_keys_single_active_idx` additionally guarantees at most one
//!   active key.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use authn_core::config::crypto::SigningKeyConfig;
use authn_core::error::{AuthError, codes};
use authn_core::id::SigningKeyId;
use authn_crypto::CryptoError;
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::jwt::{JwkSet, JwtSigner, JwtVerifier};
use authn_crypto::signing::{
    Ed25519PublicKey, Ed25519SigningKey, SigningKeyStatus, open_private_key, private_key_context,
    seal_private_key,
};
use sqlx::{Connection as _, PgConnection, PgExecutor};
use time::OffsetDateTime;

use crate::error::StoreError;

/// Advisory-lock key serializing lifecycle changes ("authnSKy").
const LIFECYCLE_LOCK: i64 = 0x6175_7468_6e53_4b79;

/// Errors of the signing-key lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum SigningKeyError {
    /// Database failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Sealing / opening the private key failed (wrong KEK, tampering).
    #[error("signing key cryptography failed: {0}")]
    Crypto(#[from] CryptoError),
    /// No active key exists (bootstrap with [`SigningKeyRepository::rotate_if_due`]
    /// or [`SigningKeyRepository::emergency_rotate`]).
    #[error("no active signing key")]
    NoActiveKey,
    /// The key does not exist.
    #[error("signing key not found")]
    NotFound,
    /// The requested transition is not allowed from the key's state.
    #[error("invalid signing key state transition")]
    InvalidTransition,
}

impl From<SigningKeyError> for AuthError {
    fn from(err: SigningKeyError) -> Self {
        match err {
            SigningKeyError::Store(store) => store.into(),
            SigningKeyError::NoActiveKey => {
                AuthError::new(codes::common::SERVICE_UNAVAILABLE).with_source(err)
            }
            SigningKeyError::NotFound => AuthError::new(codes::common::NOT_FOUND).with_source(err),
            SigningKeyError::InvalidTransition => {
                AuthError::new(codes::common::CONFLICT).with_source(err)
            }
            SigningKeyError::Crypto(_) => {
                AuthError::new(codes::common::INTERNAL_ERROR).with_source(err)
            }
        }
    }
}

/// A row of `signing_keys` (without the private key).
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKeyRecord {
    /// Id; its hyphenated form is the JWS `kid`.
    pub id: SigningKeyId,
    /// Lifecycle state.
    pub status: SigningKeyStatus,
    /// Public key.
    pub public_key: Ed25519PublicKey,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Earliest activation.
    pub activate_after: OffsetDateTime,
    /// Activation time.
    pub activated_at: Option<OffsetDateTime>,
    /// Retirement time.
    pub retired_at: Option<OffsetDateTime>,
    /// Leaves the JWKS after this instant (retired keys).
    pub publish_until: Option<OffsetDateTime>,
    /// Revocation time.
    pub revoked_at: Option<OffsetDateTime>,
}

impl fmt::Debug for SigningKeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeyRecord")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("activate_after", &self.activate_after)
            .field("activated_at", &self.activated_at)
            .field("retired_at", &self.retired_at)
            .field("publish_until", &self.publish_until)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

impl SigningKeyRecord {
    /// The JWS `kid`.
    #[must_use]
    pub fn kid(&self) -> String {
        self.id.to_string()
    }

    /// Whether the key belongs in the JWKS at `now`.
    #[must_use]
    pub fn is_publishable(&self, now: OffsetDateTime) -> bool {
        match self.status {
            SigningKeyStatus::Pending | SigningKeyStatus::Active => true,
            SigningKeyStatus::Retired => self.publish_until.is_some_and(|until| until > now),
            SigningKeyStatus::Revoked => false,
        }
    }
}

macro_rules! key_columns {
    () => {
        "id, algorithm, status, public_key, created_at, activate_after, activated_at, \
         retired_at, publish_until, revoked_at"
    };
}

#[derive(sqlx::FromRow)]
struct KeyRow {
    id: SigningKeyId,
    algorithm: String,
    status: String,
    public_key: Vec<u8>,
    created_at: OffsetDateTime,
    activate_after: OffsetDateTime,
    activated_at: Option<OffsetDateTime>,
    retired_at: Option<OffsetDateTime>,
    publish_until: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
}

impl TryFrom<KeyRow> for SigningKeyRecord {
    type Error = StoreError;

    fn try_from(row: KeyRow) -> Result<Self, Self::Error> {
        if row.algorithm != authn_crypto::jwt::ALG {
            return Err(StoreError::Corrupt("unsupported signing key algorithm"));
        }
        Ok(Self {
            id: row.id,
            status: SigningKeyStatus::from_str(&row.status)
                .map_err(|_| StoreError::Corrupt("signing key status"))?,
            public_key: Ed25519PublicKey::from_bytes(&row.public_key)
                .map_err(|_| StoreError::Corrupt("signing key public key"))?,
            created_at: row.created_at,
            activate_after: row.activate_after,
            activated_at: row.activated_at,
            retired_at: row.retired_at,
            publish_until: row.publish_until,
            revoked_at: row.revoked_at,
        })
    }
}

/// What [`SigningKeyRepository::rotate_if_due`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationReport {
    /// No usable key existed: a key was created and activated immediately.
    pub bootstrapped: Option<SigningKeyId>,
    /// A due pending key was activated.
    pub activated: Option<SigningKeyId>,
    /// A new pending key was created (rotation interval reached).
    pub created_pending: Option<SigningKeyId>,
}

fn add(at: OffsetDateTime, by: Duration) -> Result<OffsetDateTime, StoreError> {
    let by =
        time::Duration::try_from(by).map_err(|_| StoreError::Config("duration out of range"))?;
    at.checked_add(by)
        .ok_or(StoreError::Config("timestamp out of range"))
}

async fn lock(conn: &mut PgConnection) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LIFECYCLE_LOCK)
        .execute(conn)
        .await?;
    Ok(())
}

/// Queries and transitions on `signing_keys`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SigningKeyRepository;

impl SigningKeyRepository {
    /// Generates an Ed25519 key, seals its private part and stores it as
    /// `pending`, activatable after `pending_period`.
    pub async fn create_pending(
        conn: &mut PgConnection,
        cipher: &EnvelopeCipher,
        now: OffsetDateTime,
        pending_period: Duration,
    ) -> Result<SigningKeyRecord, SigningKeyError> {
        let mut tx = conn.begin().await.map_err(StoreError::from)?;
        lock(&mut tx).await?;
        let record = insert_key(&mut tx, cipher, now, add(now, pending_period)?).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(record)
    }

    /// Activates the oldest `pending` key whose `activate_after` has passed
    /// and retires the current active key (published until
    /// `now + retired_retention`). Returns the newly active key, if any.
    pub async fn activate_due(
        conn: &mut PgConnection,
        now: OffsetDateTime,
        retired_retention: Duration,
    ) -> Result<Option<SigningKeyRecord>, SigningKeyError> {
        let mut tx = conn.begin().await.map_err(StoreError::from)?;
        lock(&mut tx).await?;
        let due: Option<SigningKeyId> = sqlx::query_scalar(
            "SELECT id FROM signing_keys WHERE status = 'pending' AND activate_after <= $1 \
             ORDER BY activate_after, created_at, id LIMIT 1",
        )
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::from)?;
        let activated = match due {
            Some(id) => Some(activate_locked(&mut tx, id, now, retired_retention).await?),
            None => None,
        };
        tx.commit().await.map_err(StoreError::from)?;
        Ok(activated)
    }

    /// Activates a specific `pending` key now. Unless `ignore_pending_period`
    /// is set, the key must have been pending for its full period (CRY-10:
    /// published before use).
    pub async fn activate(
        conn: &mut PgConnection,
        id: SigningKeyId,
        now: OffsetDateTime,
        retired_retention: Duration,
        ignore_pending_period: bool,
    ) -> Result<SigningKeyRecord, SigningKeyError> {
        let mut tx = conn.begin().await.map_err(StoreError::from)?;
        lock(&mut tx).await?;
        let key = find_locked(&mut tx, id)
            .await?
            .ok_or(SigningKeyError::NotFound)?;
        if key.status != SigningKeyStatus::Pending
            || (!ignore_pending_period && key.activate_after > now)
        {
            return Err(SigningKeyError::InvalidTransition);
        }
        let record = activate_locked(&mut tx, id, now, retired_retention).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(record)
    }

    /// Emergency revocation (CRY-10, ADM-06): the key leaves the JWKS and
    /// every verifier at once. Revoking the active key leaves the system
    /// without a signing key — use [`SigningKeyRepository::emergency_rotate`]
    /// for that case.
    pub async fn revoke(
        conn: &mut PgConnection,
        id: SigningKeyId,
        now: OffsetDateTime,
    ) -> Result<SigningKeyRecord, SigningKeyError> {
        let mut tx = conn.begin().await.map_err(StoreError::from)?;
        lock(&mut tx).await?;
        let record = revoke_locked(&mut tx, id, now).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(record)
    }

    /// Emergency rotation (ADM-06): revokes the active key (if any) and
    /// creates and activates a fresh key in one transaction. Tokens signed
    /// by the revoked key stop verifying immediately.
    pub async fn emergency_rotate(
        conn: &mut PgConnection,
        cipher: &EnvelopeCipher,
        now: OffsetDateTime,
    ) -> Result<SigningKeyRecord, SigningKeyError> {
        let mut tx = conn.begin().await.map_err(StoreError::from)?;
        lock(&mut tx).await?;
        let active: Option<SigningKeyId> =
            sqlx::query_scalar("SELECT id FROM signing_keys WHERE status = 'active'")
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::from)?;
        if let Some(id) = active {
            revoke_locked(&mut tx, id, now).await?;
        }
        let created = insert_key(&mut tx, cipher, now, now).await?;
        let record = activate_locked(&mut tx, created.id, now, Duration::ZERO).await?;
        tx.commit().await.map_err(StoreError::from)?;
        tracing::warn!(kid = %record.id, "emergency signing key rotation");
        Ok(record)
    }

    /// Scheduler entry point (OPS-06), safe to call from every instance:
    /// 1. no active and no pending key → create and activate one at once
    ///    (first start);
    /// 2. activate a due pending key;
    /// 3. the active key is older than `rotation_interval` and nothing is
    ///    pending → create a pending key.
    pub async fn rotate_if_due(
        conn: &mut PgConnection,
        cipher: &EnvelopeCipher,
        now: OffsetDateTime,
        config: &SigningKeyConfig,
    ) -> Result<RotationReport, SigningKeyError> {
        let mut tx = conn.begin().await.map_err(StoreError::from)?;
        lock(&mut tx).await?;
        let mut report = RotationReport::default();

        let (active, pending): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE status = 'active'), \
             count(*) FILTER (WHERE status = 'pending') FROM signing_keys",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::from)?;

        if active == 0 && pending == 0 {
            let created = insert_key(&mut tx, cipher, now, now).await?;
            let record =
                activate_locked(&mut tx, created.id, now, config.retired_retention).await?;
            report.bootstrapped = Some(record.id);
            tx.commit().await.map_err(StoreError::from)?;
            return Ok(report);
        }

        // Without an active key nothing can be signed: promote the oldest
        // pending key even before its period ends (it is already published).
        let due: Option<SigningKeyId> = if active == 0 {
            tracing::warn!("no active signing key; activating the oldest pending key early");
            sqlx::query_scalar(
                "SELECT id FROM signing_keys WHERE status = 'pending' \
                 ORDER BY activate_after, created_at, id LIMIT 1",
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::from)?
        } else {
            sqlx::query_scalar(
                "SELECT id FROM signing_keys WHERE status = 'pending' AND activate_after <= $1 \
                 ORDER BY activate_after, created_at, id LIMIT 1",
            )
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::from)?
        };
        if let Some(id) = due {
            let record = activate_locked(&mut tx, id, now, config.retired_retention).await?;
            report.activated = Some(record.id);
        }

        let still_pending: i64 =
            sqlx::query_scalar("SELECT count(*) FROM signing_keys WHERE status = 'pending'")
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::from)?;
        let active_since: Option<OffsetDateTime> =
            sqlx::query_scalar("SELECT activated_at FROM signing_keys WHERE status = 'active'")
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::from)?
                .flatten();
        let rotation_due = match active_since {
            Some(since) => add(since, config.rotation_interval)? <= now,
            None => false,
        };
        if still_pending == 0 && rotation_due {
            let created =
                insert_key(&mut tx, cipher, now, add(now, config.pending_period)?).await?;
            report.created_pending = Some(created.id);
        }
        tx.commit().await.map_err(StoreError::from)?;
        Ok(report)
    }

    /// A key by id.
    pub async fn find<'e>(
        executor: impl PgExecutor<'e>,
        id: SigningKeyId,
    ) -> Result<Option<SigningKeyRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            key_columns!(),
            " FROM signing_keys WHERE id = $1"
        );
        sqlx::query_as::<_, KeyRow>(sql)
            .bind(id)
            .fetch_optional(executor)
            .await?
            .map(SigningKeyRecord::try_from)
            .transpose()
    }

    /// The active key, if any.
    pub async fn active<'e>(
        executor: impl PgExecutor<'e>,
    ) -> Result<Option<SigningKeyRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            key_columns!(),
            " FROM signing_keys WHERE status = 'active'"
        );
        sqlx::query_as::<_, KeyRow>(sql)
            .fetch_optional(executor)
            .await?
            .map(SigningKeyRecord::try_from)
            .transpose()
    }

    /// Loads and opens the active key as a [`JwtSigner`] (`kid` = key id).
    /// Cache the result and reload on rotation.
    pub async fn load_active_signer<'e>(
        executor: impl PgExecutor<'e>,
        cipher: &EnvelopeCipher,
    ) -> Result<JwtSigner, SigningKeyError> {
        let row: Option<(SigningKeyId, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT id, public_key, private_key_ciphertext FROM signing_keys \
             WHERE status = 'active'",
        )
        .fetch_optional(executor)
        .await
        .map_err(StoreError::from)?;
        let (id, public_key, sealed) = row.ok_or(SigningKeyError::NoActiveKey)?;
        let key = open_private_key(cipher, id, &sealed, &public_key).await?;
        Ok(JwtSigner::new(id.to_string(), key)?)
    }

    /// Keys published in the JWKS at `now`: pending, active and retired keys
    /// whose `publish_until` has not passed; never revoked keys. Ordered by
    /// creation (oldest first).
    pub async fn publishable<'e>(
        executor: impl PgExecutor<'e>,
        now: OffsetDateTime,
    ) -> Result<Vec<SigningKeyRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            key_columns!(),
            " FROM signing_keys WHERE status IN ('pending', 'active') \
             OR (status = 'retired' AND publish_until > $1) ORDER BY created_at, id"
        );
        sqlx::query_as::<_, KeyRow>(sql)
            .bind(now)
            .fetch_all(executor)
            .await?
            .into_iter()
            .map(SigningKeyRecord::try_from)
            .collect()
    }

    /// The JWKS document (SES-09).
    pub async fn jwks<'e>(
        executor: impl PgExecutor<'e>,
        now: OffsetDateTime,
    ) -> Result<JwkSet, StoreError> {
        let keys = Self::publishable(executor, now).await?;
        let pairs: Vec<(String, Ed25519PublicKey)> =
            keys.iter().map(|k| (k.kid(), k.public_key)).collect();
        Ok(JwkSet::from_keys(
            pairs.iter().map(|(kid, key)| (kid.as_str(), key)),
        ))
    }

    /// A verifier trusting exactly the publishable keys (pending keys
    /// included: another instance may already have activated one).
    pub async fn verifier<'e>(
        executor: impl PgExecutor<'e>,
        now: OffsetDateTime,
    ) -> Result<JwtVerifier, StoreError> {
        let keys = Self::publishable(executor, now).await?;
        Ok(JwtVerifier::new(
            keys.into_iter().map(|k| (k.kid(), k.public_key)),
        ))
    }

    /// Every key, newest first (admin listing).
    pub async fn list<'e>(
        executor: impl PgExecutor<'e>,
    ) -> Result<Vec<SigningKeyRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            key_columns!(),
            " FROM signing_keys ORDER BY created_at DESC, id DESC"
        );
        sqlx::query_as::<_, KeyRow>(sql)
            .fetch_all(executor)
            .await?
            .into_iter()
            .map(SigningKeyRecord::try_from)
            .collect()
    }

    /// KEK rotation (`rotate-kek` / `reencrypt`, CRY-08): re-wraps every
    /// non-revoked private key whose envelope does not use the current KEK.
    /// Returns the number of re-wrapped keys.
    pub async fn rewrap_private_keys(
        conn: &mut PgConnection,
        cipher: &EnvelopeCipher,
    ) -> Result<u64, SigningKeyError> {
        let mut tx = conn.begin().await.map_err(StoreError::from)?;
        lock(&mut tx).await?;
        let rows: Vec<(SigningKeyId, Vec<u8>)> = sqlx::query_as(
            "SELECT id, private_key_ciphertext FROM signing_keys WHERE status <> 'revoked' \
             ORDER BY created_at",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::from)?;
        let mut count = 0;
        for (id, sealed) in rows {
            if let Some(rewrapped) = cipher.rewrap(&sealed, &private_key_context(id)?).await? {
                sqlx::query("UPDATE signing_keys SET private_key_ciphertext = $2 WHERE id = $1")
                    .bind(id)
                    .bind(rewrapped)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::from)?;
                count += 1;
            }
        }
        tx.commit().await.map_err(StoreError::from)?;
        Ok(count)
    }
}

async fn insert_key(
    conn: &mut PgConnection,
    cipher: &EnvelopeCipher,
    now: OffsetDateTime,
    activate_after: OffsetDateTime,
) -> Result<SigningKeyRecord, SigningKeyError> {
    let id = SigningKeyId::generate();
    let key = Ed25519SigningKey::generate()?;
    let sealed = seal_private_key(cipher, id, &key).await?;
    let sql = concat!(
        "INSERT INTO signing_keys (id, algorithm, status, public_key, private_key_ciphertext, \
         created_at, activate_after) VALUES ($1, $2, 'pending', $3, $4, $5, $6) RETURNING ",
        key_columns!()
    );
    let row = sqlx::query_as::<_, KeyRow>(sql)
        .bind(id)
        .bind(authn_crypto::jwt::ALG)
        .bind(key.public_key().to_bytes().as_slice())
        .bind(sealed)
        .bind(now)
        .bind(activate_after)
        .fetch_one(conn)
        .await
        .map_err(StoreError::from)?;
    Ok(SigningKeyRecord::try_from(row)?)
}

async fn find_locked(
    conn: &mut PgConnection,
    id: SigningKeyId,
) -> Result<Option<SigningKeyRecord>, StoreError> {
    let sql = concat!(
        "SELECT ",
        key_columns!(),
        " FROM signing_keys WHERE id = $1 FOR UPDATE"
    );
    sqlx::query_as::<_, KeyRow>(sql)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .map(SigningKeyRecord::try_from)
        .transpose()
}

/// Retires the current active key and activates `id` (must be pending).
/// Caller holds the lifecycle lock.
async fn activate_locked(
    conn: &mut PgConnection,
    id: SigningKeyId,
    now: OffsetDateTime,
    retired_retention: Duration,
) -> Result<SigningKeyRecord, SigningKeyError> {
    let publish_until = add(now, retired_retention)?;
    sqlx::query(
        "UPDATE signing_keys SET status = 'retired', retired_at = $1, publish_until = $2 \
         WHERE status = 'active'",
    )
    .bind(now)
    .bind(publish_until)
    .execute(&mut *conn)
    .await
    .map_err(StoreError::from)?;
    let sql = concat!(
        "UPDATE signing_keys SET status = 'active', activated_at = $2 \
         WHERE id = $1 AND status = 'pending' RETURNING ",
        key_columns!()
    );
    let row = sqlx::query_as::<_, KeyRow>(sql)
        .bind(id)
        .bind(now)
        .fetch_optional(&mut *conn)
        .await
        .map_err(StoreError::from)?
        .ok_or(SigningKeyError::InvalidTransition)?;
    Ok(SigningKeyRecord::try_from(row)?)
}

async fn revoke_locked(
    conn: &mut PgConnection,
    id: SigningKeyId,
    now: OffsetDateTime,
) -> Result<SigningKeyRecord, SigningKeyError> {
    let current = find_locked(conn, id)
        .await?
        .ok_or(SigningKeyError::NotFound)?;
    if current.status == SigningKeyStatus::Revoked {
        return Ok(current);
    }
    let sql = concat!(
        "UPDATE signing_keys SET status = 'revoked', revoked_at = $2 WHERE id = $1 RETURNING ",
        key_columns!()
    );
    let row = sqlx::query_as::<_, KeyRow>(sql)
        .bind(id)
        .bind(now)
        .fetch_one(conn)
        .await
        .map_err(StoreError::from)?;
    let record = SigningKeyRecord::try_from(row)?;
    tracing::warn!(kid = %record.id, previous = %current.status, "signing key revoked");
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_10_publishable_states() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let key = Ed25519SigningKey::generate().unwrap();
        let mut record = SigningKeyRecord {
            id: SigningKeyId::generate(),
            status: SigningKeyStatus::Pending,
            public_key: key.public_key(),
            created_at: now,
            activate_after: now,
            activated_at: None,
            retired_at: None,
            publish_until: None,
            revoked_at: None,
        };
        assert!(record.is_publishable(now));
        record.status = SigningKeyStatus::Active;
        assert!(record.is_publishable(now));
        record.status = SigningKeyStatus::Retired;
        record.publish_until = Some(now + time::Duration::seconds(1));
        assert!(record.is_publishable(now));
        assert!(!record.is_publishable(now + time::Duration::seconds(1)));
        record.status = SigningKeyStatus::Revoked;
        assert!(!record.is_publishable(now));
        assert_eq!(record.kid().len(), 36);
    }

    #[test]
    fn cry_10_errors_map_to_safe_codes() {
        assert_eq!(
            AuthError::from(SigningKeyError::NoActiveKey).code(),
            codes::common::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AuthError::from(SigningKeyError::Crypto(CryptoError::Unauthentic)).code(),
            codes::common::INTERNAL_ERROR
        );
        assert!(add(OffsetDateTime::UNIX_EPOCH, Duration::MAX).is_err());
    }
}
