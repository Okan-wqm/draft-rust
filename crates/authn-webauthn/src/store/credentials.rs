//! `webauthn_credentials` (PKY-02, PKY-04, PKY-05).
//!
//! `passkey` holds the serialized `webauthn-rs` credential (public key,
//! signature counter, flags, attestation). It is public data — integrity
//! matters, confidentiality does not — and is only ever written from a
//! credential `webauthn-rs` verified.

use authn_core::error::AuthError;
use authn_core::id::{CredentialId, UserId};
use authn_store::StoreError;
use sqlx::types::Json;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::service::PasskeyUsage;

/// Unique constraint on the authenticator credential id.
pub(crate) const CREDENTIAL_ID_UNIQUE: &str = "webauthn_credentials_credential_id_key";

/// Column list of [`CredentialRow`] (kept `&'static str` for sqlx 0.9).
macro_rules! credential_columns {
    () => {
        "id, user_id, credential_id, passkey, name, aaguid, usage, user_verified, \
         backup_eligible, backup_state, sign_count, transports, attestation_format, created_at, \
         last_used_at, clone_suspected_at, discoverable"
    };
}

/// A row of `webauthn_credentials`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct CredentialRow {
    pub(crate) id: CredentialId,
    pub(crate) user_id: UserId,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) passkey: Json<serde_json::Value>,
    pub(crate) name: String,
    pub(crate) aaguid: Option<Uuid>,
    pub(crate) usage: String,
    pub(crate) user_verified: bool,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
    pub(crate) sign_count: i64,
    pub(crate) transports: Vec<String>,
    pub(crate) attestation_format: Option<String>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) last_used_at: Option<OffsetDateTime>,
    pub(crate) clone_suspected_at: Option<OffsetDateTime>,
    pub(crate) discoverable: Option<bool>,
}

impl CredentialRow {
    /// The stored usage (unknown values are treated as the most
    /// restrictive, second factor only).
    pub(crate) fn usage(&self) -> PasskeyUsage {
        self.usage.parse().unwrap_or(PasskeyUsage::SecondFactor)
    }
}

/// Input of [`insert`].
#[derive(Debug, Clone)]
pub(crate) struct NewCredential<'a> {
    pub(crate) id: CredentialId,
    pub(crate) user_id: UserId,
    pub(crate) credential_id: &'a [u8],
    pub(crate) passkey: serde_json::Value,
    pub(crate) name: &'a str,
    pub(crate) aaguid: Option<Uuid>,
    pub(crate) usage: PasskeyUsage,
    pub(crate) user_verified: bool,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
    pub(crate) sign_count: i64,
    pub(crate) transports: Vec<String>,
    pub(crate) attestation_format: Option<String>,
    pub(crate) discoverable: Option<bool>,
    pub(crate) created_at: OffsetDateTime,
}

/// Inserts a verified credential. A duplicate authenticator credential id
/// fails with `StoreError::UniqueViolation { constraint: CREDENTIAL_ID_UNIQUE }`.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    new: NewCredential<'_>,
) -> Result<CredentialRow, StoreError> {
    let sql = concat!(
        "INSERT INTO webauthn_credentials (id, user_id, credential_id, passkey, name, aaguid, \
         usage, user_verified, backup_eligible, backup_state, sign_count, transports, \
         attestation_format, discoverable, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15) RETURNING ",
        credential_columns!()
    );
    Ok(sqlx::query_as::<_, CredentialRow>(sql)
        .bind(new.id)
        .bind(new.user_id)
        .bind(new.credential_id)
        .bind(Json(new.passkey))
        .bind(new.name)
        .bind(new.aaguid)
        .bind(new.usage.as_str())
        .bind(new.user_verified)
        .bind(new.backup_eligible)
        .bind(new.backup_state)
        .bind(new.sign_count)
        .bind(new.transports)
        .bind(new.attestation_format)
        .bind(new.discoverable)
        .bind(new.created_at)
        .fetch_one(conn)
        .await?)
}

/// Every credential of a user, oldest first.
pub(crate) async fn list_for_user<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
) -> Result<Vec<CredentialRow>, AuthError> {
    let sql = concat!(
        "SELECT ",
        credential_columns!(),
        " FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at, id"
    );
    Ok(sqlx::query_as::<_, CredentialRow>(sql)
        .bind(user)
        .fetch_all(executor)
        .await?)
}

/// Number of credentials of a user, optionally only those usable for
/// passwordless login.
pub(crate) async fn count_for_user<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
    login_capable_only: bool,
) -> Result<u32, AuthError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM webauthn_credentials WHERE user_id = $1 \
         AND (NOT $2 OR usage IN ('passwordless', 'both'))",
    )
    .bind(user)
    .bind(login_capable_only)
    .fetch_one(executor)
    .await?;
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Row-locks the credential with the given authenticator credential id
/// owned by `user` (authentication finish).
pub(crate) async fn lock_by_raw_id(
    conn: &mut PgConnection,
    raw_id: &[u8],
    user: UserId,
) -> Result<Option<CredentialRow>, AuthError> {
    let sql = concat!(
        "SELECT ",
        credential_columns!(),
        " FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2 FOR UPDATE"
    );
    Ok(sqlx::query_as::<_, CredentialRow>(sql)
        .bind(raw_id)
        .bind(user)
        .fetch_optional(conn)
        .await?)
}

/// Values written after a successful assertion.
#[derive(Debug, Clone)]
pub(crate) struct UsageUpdate {
    pub(crate) passkey: serde_json::Value,
    pub(crate) sign_count: i64,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
    pub(crate) used_at: OffsetDateTime,
}

/// Records a successful use. The caller holds the row lock and has checked
/// the counter against the locked row.
pub(crate) async fn record_use(
    conn: &mut PgConnection,
    id: CredentialId,
    update: UsageUpdate,
) -> Result<(), AuthError> {
    sqlx::query(
        "UPDATE webauthn_credentials SET passkey = $2, sign_count = $3, backup_eligible = $4, \
         backup_state = $5, last_used_at = $6 WHERE id = $1",
    )
    .bind(id)
    .bind(Json(update.passkey))
    .bind(update.sign_count)
    .bind(update.backup_eligible)
    .bind(update.backup_state)
    .bind(update.used_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Marks a credential as possibly cloned (PKY-05); keeps the first time.
pub(crate) async fn mark_clone_suspected(
    conn: &mut PgConnection,
    id: CredentialId,
    at: OffsetDateTime,
) -> Result<(), AuthError> {
    sqlx::query(
        "UPDATE webauthn_credentials SET clone_suspected_at = COALESCE(clone_suspected_at, $2) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Renames a credential of `user`; `None` when it does not exist.
pub(crate) async fn rename(
    conn: &mut PgConnection,
    id: CredentialId,
    user: UserId,
    name: &str,
) -> Result<Option<CredentialRow>, AuthError> {
    let sql = concat!(
        "UPDATE webauthn_credentials SET name = $3 WHERE id = $1 AND user_id = $2 RETURNING ",
        credential_columns!()
    );
    Ok(sqlx::query_as::<_, CredentialRow>(sql)
        .bind(id)
        .bind(user)
        .bind(name)
        .fetch_optional(conn)
        .await?)
}

/// Deletes a credential of `user`; whether a row was removed.
pub(crate) async fn delete(
    conn: &mut PgConnection,
    id: CredentialId,
    user: UserId,
) -> Result<bool, AuthError> {
    let result = sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user)
        .execute(conn)
        .await?;
    Ok(result.rows_affected() == 1)
}
