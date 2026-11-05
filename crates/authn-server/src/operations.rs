//! Operational commands behind the CLI (OPS-01): KEK rotation, signing
//! key rotation, legacy hash migration and sealing the Apple key. The
//! break-glass admin commands (ADM-05, K-07, K-11) call authn-admin
//! directly (`crate::cli`).

use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::Clock;
use authn_crypto::CryptoServices;
use authn_crypto::envelope::{EnvelopeCipher, EnvelopeContext};
use authn_crypto::password::LegacyDigest;
use authn_store::{NewPasswordHash, SigningKeyRepository, UserRepository};
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
        select: "SELECT id, secret_ciphertext FROM mfa_factors WHERE secret_ciphertext IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
        update: "UPDATE mfa_factors SET secret_ciphertext = $2 WHERE id = $1 AND secret_ciphertext = $3",
        table: "mfa_factors",
        column: "secret_ciphertext",
    },
    SealedColumn {
        select: "SELECT id, successor_ciphertext FROM refresh_tokens WHERE successor_ciphertext IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
        update: "UPDATE refresh_tokens SET successor_ciphertext = $2 WHERE id = $1 AND successor_ciphertext = $3",
        table: "refresh_tokens",
        column: "successor_ciphertext",
    },
    SealedColumn {
        select: "SELECT id, sealed_payload FROM outbox WHERE sealed_payload IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
        update: "UPDATE outbox SET sealed_payload = $2 WHERE id = $1 AND sealed_payload = $3",
        table: "outbox",
        column: "sealed_payload",
    },
    // authn-oidc-client (SOC-08, K-35): stored provider tokens, PKCE
    // verifiers of pending flows, queued token revocations.
    SealedColumn {
        select: "SELECT id, access_token_ciphertext FROM identities WHERE access_token_ciphertext IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
        update: "UPDATE identities SET access_token_ciphertext = $2 WHERE id = $1 AND access_token_ciphertext = $3",
        table: "identities",
        column: "access_token_ciphertext",
    },
    SealedColumn {
        select: "SELECT id, refresh_token_ciphertext FROM identities WHERE refresh_token_ciphertext IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
        update: "UPDATE identities SET refresh_token_ciphertext = $2 WHERE id = $1 AND refresh_token_ciphertext = $3",
        table: "identities",
        column: "refresh_token_ciphertext",
    },
    SealedColumn {
        select: "SELECT id, pkce_verifier_ciphertext FROM oauth_states WHERE pkce_verifier_ciphertext IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
        update: "UPDATE oauth_states SET pkce_verifier_ciphertext = $2 WHERE id = $1 AND pkce_verifier_ciphertext = $3",
        table: "oauth_states",
        column: "pkce_verifier_ciphertext",
    },
    SealedColumn {
        select: "SELECT id, token_ciphertext FROM oauth_token_revocations WHERE id > $1 ORDER BY id LIMIT $2",
        update: "UPDATE oauth_token_revocations SET token_ciphertext = $2 WHERE id = $1 AND token_ciphertext = $3",
        table: "oauth_token_revocations",
        column: "token_ciphertext",
    },
];

/// The `(table, column)` pairs [`rotate_kek`] re-wraps besides signing keys
/// and webhook secrets (tests compare it with the schema: every
/// `*_ciphertext` column must be covered).
#[must_use]
pub fn sealed_columns() -> Vec<(&'static str, &'static str)> {
    SEALED_COLUMNS.iter().map(|c| (c.table, c.column)).collect()
}

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

/// `oidc_client.apple.private_key_ciphertext` after a KEK rotation: the
/// value lives in the configuration, so the command can only print the
/// re-wrapped envelope for the operator to store (it is ciphertext, not a
/// secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppleKeyRewrap {
    /// No envelope-encrypted Apple key is configured.
    NotConfigured,
    /// Already sealed with the current KEK.
    Current,
    /// Sealed with an older KEK: replace the configured value with this.
    Rewrapped(String),
}

/// Re-wraps the configured Apple key envelope (K-34) with the current KEK.
pub async fn rewrap_apple_key(
    config: &authn_core::config::AppConfig,
    cipher: &EnvelopeCipher,
) -> Result<AppleKeyRewrap, AuthError> {
    use authn_core::secret::ExposeSecret;
    use base64::Engine as _;
    let Some(sealed) = config
        .oidc_client
        .apple
        .as_ref()
        .and_then(|apple| apple.private_key_ciphertext.as_ref())
    else {
        return Ok(AppleKeyRewrap::NotConfigured);
    };
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine.decode(sealed.expose_secret().trim()).map_err(|_| {
        AuthError::internal("oidc_client.apple.private_key_ciphertext is not base64")
    })?;
    let context = authn_oidc_client::apple::private_key_context()?;
    Ok(
        match cipher
            .rewrap(&bytes, &context)
            .await
            .map_err(AuthError::from)?
        {
            Some(rewrapped) => AppleKeyRewrap::Rewrapped(engine.encode(rewrapped)),
            None => AppleKeyRewrap::Current,
        },
    )
}

/// Error context of authn-oidc-client's `seal_private_key` for an input
/// that is not a PKCS#8 P-256 key (the CLI reports it as an input error).
pub const NOT_AN_APPLE_KEY: &str = "apple private key is not a PKCS#8 P-256 key";

/// `seal-apple-key` (SOC-07, K-34): validates a PKCS#8 P-256 PEM and seals
/// it for `oidc_client.apple.private_key_ciphertext` (base64). Errors never
/// contain the key.
pub async fn seal_apple_key(cipher: &EnvelopeCipher, pem: &str) -> Result<String, AuthError> {
    use authn_core::secret::ExposeSecret;
    let pem = authn_core::secret::SecretString::from(pem.trim().to_owned());
    let sealed = authn_oidc_client::apple::seal_private_key(cipher, &pem).await?;
    Ok(sealed.expose_secret().to_owned())
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
        // Keyset pages: bounded memory on large tables (outbox), no
        // long-running transaction; every row is compare-and-set, so an
        // interrupted run is simply started again.
        let mut after = Uuid::nil();
        loop {
            let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(column.select)
                .bind(after)
                .bind(REWRAP_PAGE)
                .fetch_all(pool)
                .await?;
            let Some((last, _)) = rows.last() else {
                break;
            };
            after = *last;
            report.other += rewrap_rows(pool, cipher, column, rows).await?;
        }
    }
    Ok(report)
}

/// Rows read per page by [`rotate_kek`].
const REWRAP_PAGE: i64 = 500;

async fn rewrap_rows(
    pool: &PgPool,
    cipher: &EnvelopeCipher,
    column: &SealedColumn,
    rows: Vec<(Uuid, Vec<u8>)>,
) -> Result<u64, AuthError> {
    let mut changed = 0;
    for (id, sealed) in rows {
        let context =
            EnvelopeContext::new(column.table, column.column, id).map_err(AuthError::from)?;
        if let Some(rewrapped) = cipher
            .rewrap(&sealed, &context)
            .await
            .map_err(AuthError::from)?
        {
            changed += sqlx::query(column.update)
                .bind(id)
                .bind(&rewrapped)
                .bind(&sealed)
                .execute(pool)
                .await?
                .rows_affected();
        }
    }
    Ok(changed)
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
