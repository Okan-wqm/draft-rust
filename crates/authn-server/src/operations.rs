//! Operational commands behind the CLI (OPS-01): KEK rotation, signing
//! key rotation, audit chain verification, legacy hash migration and the
//! break-glass admin (ADM-05).

use std::sync::Arc;

use authn_core::domain::{AccountStatus, EmailAddress};
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::{Actor, AuditSink, Clock, SecurityEvent, SecurityEventKind};
use authn_core::secret::SensitiveString;
use authn_crypto::CryptoServices;
use authn_crypto::envelope::{EnvelopeCipher, EnvelopeContext};
use authn_crypto::password::LegacyDigest;
use authn_crypto::token::OpaqueToken;
use authn_store::{NewPasswordHash, NewUser, SigningKeyRepository, UserRepository};
use sqlx::PgPool;
use uuid::Uuid;

/// A sealed column re-wrapped by `rotate-kek` (table, id column, sealed
/// column; AAD = `table/column/<id>`).
struct SealedColumn {
    select: &'static str,
    update: &'static str,
    table: &'static str,
    column: &'static str,
}

/// Every envelope-encrypted column besides signing keys and webhook
/// secrets (which have their own re-wrap functions).
const SEALED_COLUMNS: &[SealedColumn] = &[
    SealedColumn {
        select: "SELECT id, secret_ciphertext FROM mfa_factors WHERE secret_ciphertext IS NOT NULL",
        update: "UPDATE mfa_factors SET secret_ciphertext = $2 WHERE id = $1 AND secret_ciphertext = $3",
        table: "mfa_factors",
        column: "secret_ciphertext",
    },
    SealedColumn {
        select: "SELECT id, successor_ciphertext FROM refresh_tokens WHERE successor_ciphertext IS NOT NULL",
        update: "UPDATE refresh_tokens SET successor_ciphertext = $2 WHERE id = $1 AND successor_ciphertext = $3",
        table: "refresh_tokens",
        column: "successor_ciphertext",
    },
    SealedColumn {
        select: "SELECT id, sealed_payload FROM outbox WHERE sealed_payload IS NOT NULL",
        update: "UPDATE outbox SET sealed_payload = $2 WHERE id = $1 AND sealed_payload = $3",
        table: "outbox",
        column: "sealed_payload",
    },
];

/// Result of a KEK rotation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RewrapReport {
    /// Signing keys re-wrapped.
    pub signing_keys: u64,
    /// Webhook secrets re-wrapped.
    pub webhook_secrets: u64,
    /// Other sealed values re-wrapped.
    pub other: u64,
}

/// `rotate-kek` / `reencrypt` (CRY-08): re-wraps every envelope that does
/// not use the current KEK. Idempotent; concurrent writers are respected
/// (compare-and-set on the old envelope).
pub async fn rotate_kek(pool: &PgPool, cipher: &EnvelopeCipher) -> Result<RewrapReport, AuthError> {
    let mut report = RewrapReport::default();
    let mut conn = pool.acquire().await?;
    report.signing_keys = SigningKeyRepository::rewrap_private_keys(&mut conn, cipher)
        .await
        .map_err(|e| AuthError::internal("signing key re-wrap failed").with_source(e))?;
    drop(conn);
    report.webhook_secrets = authn_audit::webhooks::rewrap_webhook_secrets(pool, cipher).await?;
    for column in SEALED_COLUMNS {
        let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(column.select).fetch_all(pool).await?;
        for (id, sealed) in rows {
            let context =
                EnvelopeContext::new(column.table, column.column, id).map_err(AuthError::from)?;
            if let Some(rewrapped) = cipher
                .rewrap(&sealed, &context)
                .await
                .map_err(AuthError::from)?
            {
                let changed = sqlx::query(column.update)
                    .bind(id)
                    .bind(&rewrapped)
                    .bind(&sealed)
                    .execute(pool)
                    .await?
                    .rows_affected();
                report.other += changed;
            }
        }
    }
    Ok(report)
}

/// `rotate-signing-key` (CRY-10, ADM-06): a pending key (activated after
/// `pending_period`), or — `emergency` — revoke the active key and
/// activate a fresh one at once. Returns the new key id.
pub async fn rotate_signing_key(
    pool: &PgPool,
    crypto: &CryptoServices,
    clock: &dyn Clock,
    config: &authn_core::config::crypto::SigningKeyConfig,
    emergency: bool,
) -> Result<String, AuthError> {
    let mut conn = pool.acquire().await?;
    let record = if emergency {
        SigningKeyRepository::emergency_rotate(&mut conn, &crypto.envelopes, clock.now()).await
    } else {
        SigningKeyRepository::create_pending(
            &mut conn,
            &crypto.envelopes,
            clock.now(),
            config.pending_period,
        )
        .await
    }
    .map_err(|e| AuthError::internal("signing key rotation failed").with_source(e))?;
    Ok(record.id.to_string())
}

/// One line of the legacy hash import (`user_id,algorithm,hex`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyLine {
    /// The account.
    pub user: UserId,
    /// `md5` or `sha1`.
    pub digest: LegacyDigest,
    /// The legacy hex digest.
    pub hex: String,
}

/// Parses the import file; reports the first bad line by number (never
/// its content: it holds password hashes).
pub fn parse_legacy_lines(text: &str) -> Result<Vec<LegacyLine>, String> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let mut parts = line.split(',');
        let (Some(user), Some(algorithm), Some(hex), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("line {number}: expected user_id,algorithm,hash"));
        };
        let user = Uuid::parse_str(user.trim())
            .map(UserId::from_uuid)
            .map_err(|_| format!("line {number}: invalid user id"))?;
        let digest = match algorithm.trim() {
            "md5" => LegacyDigest::Md5,
            "sha1" => LegacyDigest::Sha1,
            _ => return Err(format!("line {number}: algorithm must be md5 or sha1")),
        };
        out.push(LegacyLine {
            user,
            digest,
            hex: hex.trim().to_owned(),
        });
    }
    Ok(out)
}

/// `migrate-legacy-hashes` (CRY-04): wraps each legacy digest in Argon2id
/// (verified and upgraded at the next login). Returns the number of
/// accounts updated; unknown accounts are skipped.
pub async fn migrate_legacy_hashes(
    pool: &PgPool,
    crypto: &CryptoServices,
    clock: &dyn Clock,
    lines: &[LegacyLine],
) -> Result<u64, AuthError> {
    let mut updated = 0;
    for line in lines {
        let record = crypto
            .passwords
            .wrap_legacy_digest(line.digest, &line.hex)
            .await
            .map_err(AuthError::from)?;
        let mut tx = authn_store::begin(pool).await?;
        if UserRepository::lock_for_update(&mut tx, line.user)
            .await?
            .is_none()
        {
            continue;
        }
        UserRepository::set_password(
            &mut tx,
            line.user,
            &NewPasswordHash {
                password_hash: &record.hash,
                algorithm: record.algorithm.as_str(),
                pepper_version: record.pepper_version,
            },
            false,
            clock.now(),
        )
        .await?;
        authn_store::commit(tx).await?;
        updated += 1;
    }
    Ok(updated)
}

/// `create-admin` (ADM-05): an active, verified break-glass platform admin
/// with a strong random password, shown exactly once. The creation is a
/// high-priority audit event.
pub async fn create_break_glass_admin(
    pool: &PgPool,
    crypto: &CryptoServices,
    clock: &dyn Clock,
    audit: &Arc<dyn AuditSink>,
    email: &str,
) -> Result<(UserId, SensitiveString), AuthError> {
    let email = EmailAddress::parse(email).map_err(|_| {
        AuthError::new(authn_core::error::codes::common::VALIDATION_FAILED).with_context("email")
    })?;
    // 256 bits of CSPRNG output, base64url (43 characters).
    let password = OpaqueToken::generate().map_err(AuthError::from)?;
    let secret = authn_core::secret::SecretString::from(password.expose().to_owned());
    let record = crypto
        .passwords
        .hash(&secret)
        .await
        .map_err(AuthError::from)?;
    let now = clock.now();
    let id = UserId::generate();
    let mut tx = authn_store::begin(pool).await?;
    UserRepository::create(
        &mut tx,
        &NewUser {
            id,
            email: email.clone(),
            status: AccountStatus::Active,
            created_at: now,
        },
    )
    .await?;
    UserRepository::mark_email_verified(&mut tx, id, now).await?;
    UserRepository::set_password(
        &mut tx,
        id,
        &NewPasswordHash {
            password_hash: &record.hash,
            algorithm: record.algorithm.as_str(),
            pepper_version: record.pepper_version,
        },
        false,
        now,
    )
    .await?;
    sqlx::query("UPDATE users SET is_platform_admin = true, is_break_glass = true WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let event = SecurityEvent::new(SecurityEventKind::AdminAction, now)
        .with_actor(Actor::System)
        .with_subject(id)
        .with_meta("action", "break_glass_admin_created")
        .with_meta("priority", "high");
    audit.record_in_tx(&mut tx, event).await?;
    authn_store::commit(tx).await?;
    Ok((id, password.into_sensitive()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_04_legacy_import_lines_are_parsed_strictly() {
        let user = Uuid::now_v7();
        let text = format!("# comment\n\n{user},md5,5f4dcc3b5aa765d61d8327deb882cf99\n");
        let lines = parse_legacy_lines(&text).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].digest, LegacyDigest::Md5);
        let err = parse_legacy_lines(&format!("{user},sha256,abc")).unwrap_err();
        assert_eq!(err, "line 1: algorithm must be md5 or sha1");
        let err = parse_legacy_lines("x,md5,secret-hash-value").unwrap_err();
        assert!(!err.contains("secret"), "never echoes the line: {err}");
        assert!(parse_legacy_lines(&format!("{user},md5")).is_err());
    }
}
