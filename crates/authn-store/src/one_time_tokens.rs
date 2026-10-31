//! Generic one-time token / code repository (`one_time_tokens`).
//!
//! Requirements: ARC-06 (atomic consumption), CRY-06 (256-bit link tokens,
//! only SHA-256 stored), CRY-07 (6-digit codes, keyed hash, attempt limit),
//! TST-02 (race: exactly one concurrent consumer wins).
//!
//! The repository never sees a token or code in clear text: callers pass
//! the [`TokenHash`] computed by `authn_crypto::token::OpaqueToken::hash`
//! (links) or `authn_crypto::otp::OtpHasher::hash` (codes). Each
//! [`TokenPurpose`] belongs to exactly one module
//! (`docs/architecture/contracts.md` §5).
//!
//! Transaction semantics — read carefully:
//!
//! * [`OneTimeTokenRepository::create`] and
//!   [`OneTimeTokenRepository::consume_link`] take `&mut PgConnection` and
//!   run inside the **caller's** transaction (a savepoint when one is open):
//!   if the caller rolls back (e.g. the new password is rejected), the link
//!   stays unconsumed.
//! * [`OneTimeTokenRepository::verify_code`] takes the **pool** and commits
//!   its own transaction. A failed attempt must be counted even when the
//!   caller's business transaction rolls back; otherwise an attacker could
//!   brute-force the 10^6 code space by making every request fail later.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use authn_core::id::{ChallengeId, OneTimeTokenId, UserId};
use authn_crypto::token::TokenHash;
use sqlx::{Connection as _, PgConnection, PgExecutor, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::StoreError;

/// Link or code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// 256-bit token sent as a link; `token_hash = SHA-256(token)`, globally
    /// unique.
    Link,
    /// Short code; `token_hash = HMAC(K_otp, purpose, code)`, looked up only
    /// together with its subject.
    Code,
}

impl TokenKind {
    /// Stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Code => "code",
        }
    }
}

/// Registered `one_time_tokens.purpose` values (contracts §5). Adding one is
/// a contract change (§13) by the owning module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenPurpose {
    /// authn-account: e-mail verification link (ACC-04).
    EmailVerification,
    /// authn-account: e-mail verification code (ACC-04).
    EmailVerificationCode,
    /// authn-account: e-mail change confirmation link (ACC-07).
    EmailChange,
    /// authn-account: e-mail change confirmation code (ACC-07).
    EmailChangeCode,
    /// authn-account: "revert e-mail change" link to the old address (ACC-07).
    EmailChangeRevert,
    /// authn-account: cancel a pending deletion (ACC-09).
    AccountDeletionCancel,
    /// authn-password: reset link (PWD-07).
    PasswordReset,
    /// authn-password: reset code for mobile (PWD-08).
    PasswordResetCode,
    /// authn-session: magic link (SES-18).
    MagicLink,
    /// authn-session: passwordless e-mail login code (SES-19).
    LoginCode,
    /// authn-session: "this was not me" link (RSK-04).
    NotMe,
    /// authn-mfa: e-mail OTP second factor (MFA-05).
    MfaEmailOtp,
    /// authn-mfa: SMS OTP second factor (MFA-06).
    MfaSmsOtp,
    /// authn-mfa: phone number verification (MFA-06).
    PhoneVerification,
    /// authn-org: ownership transfer acceptance (ORG-11).
    OrgOwnershipTransfer,
}

impl TokenPurpose {
    /// Every purpose.
    pub const ALL: &'static [Self] = &[
        Self::EmailVerification,
        Self::EmailVerificationCode,
        Self::EmailChange,
        Self::EmailChangeCode,
        Self::EmailChangeRevert,
        Self::AccountDeletionCancel,
        Self::PasswordReset,
        Self::PasswordResetCode,
        Self::MagicLink,
        Self::LoginCode,
        Self::NotMe,
        Self::MfaEmailOtp,
        Self::MfaSmsOtp,
        Self::PhoneVerification,
        Self::OrgOwnershipTransfer,
    ];

    /// Stored text (also the `purpose` input of `OtpHasher::hash`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::EmailVerificationCode => "email_verification_code",
            Self::EmailChange => "email_change",
            Self::EmailChangeCode => "email_change_code",
            Self::EmailChangeRevert => "email_change_revert",
            Self::AccountDeletionCancel => "account_deletion_cancel",
            Self::PasswordReset => "password_reset",
            Self::PasswordResetCode => "password_reset_code",
            Self::MagicLink => "magic_link",
            Self::LoginCode => "login_code",
            Self::NotMe => "not_me",
            Self::MfaEmailOtp => "mfa_email_otp",
            Self::MfaSmsOtp => "mfa_sms_otp",
            Self::PhoneVerification => "phone_verification",
            Self::OrgOwnershipTransfer => "org_ownership_transfer",
        }
    }

    /// Whether the purpose uses links or codes.
    #[must_use]
    pub const fn kind(self) -> TokenKind {
        match self {
            Self::EmailVerificationCode
            | Self::EmailChangeCode
            | Self::PasswordResetCode
            | Self::LoginCode
            | Self::MfaEmailOtp
            | Self::MfaSmsOtp
            | Self::PhoneVerification => TokenKind::Code,
            Self::EmailVerification
            | Self::EmailChange
            | Self::EmailChangeRevert
            | Self::AccountDeletionCancel
            | Self::PasswordReset
            | Self::MagicLink
            | Self::NotMe
            | Self::OrgOwnershipTransfer => TokenKind::Link,
        }
    }
}

impl fmt::Display for TokenPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TokenPurpose {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or(StoreError::Corrupt("unknown one-time token purpose"))
    }
}

/// Who a token belongs to: a user, a pending authentication challenge, or
/// both. Codes are looked up by the challenge when one is set, otherwise by
/// the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenSubject {
    user_id: Option<UserId>,
    challenge_id: Option<ChallengeId>,
}

impl TokenSubject {
    /// A token of `user`.
    #[must_use]
    pub const fn user(user: UserId) -> Self {
        Self {
            user_id: Some(user),
            challenge_id: None,
        }
    }

    /// A token bound to a pending challenge (e.g. SES-19 login code).
    #[must_use]
    pub const fn challenge(challenge: ChallengeId) -> Self {
        Self {
            user_id: None,
            challenge_id: Some(challenge),
        }
    }

    /// A token of `user` bound to `challenge`.
    #[must_use]
    pub const fn user_and_challenge(user: UserId, challenge: ChallengeId) -> Self {
        Self {
            user_id: Some(user),
            challenge_id: Some(challenge),
        }
    }

    /// The user, if any.
    #[must_use]
    pub const fn user_id(&self) -> Option<UserId> {
        self.user_id
    }

    /// The challenge, if any.
    #[must_use]
    pub const fn challenge_id(&self) -> Option<ChallengeId> {
        self.challenge_id
    }

    /// Advisory-lock key serializing creation per (subject, purpose).
    fn lock_key(&self, purpose: TokenPurpose) -> String {
        match (self.challenge_id, self.user_id) {
            (Some(c), _) => format!("authn:ott:c:{c}:{purpose}"),
            (None, Some(u)) => format!("authn:ott:u:{u}:{purpose}"),
            (None, None) => format!("authn:ott:none:{purpose}"),
        }
    }
}

/// Input of [`OneTimeTokenRepository::create`].
#[derive(Debug, Clone)]
pub struct NewOneTimeToken<'a> {
    /// New id (UUIDv7).
    pub id: OneTimeTokenId,
    /// Purpose (determines link vs. code).
    pub purpose: TokenPurpose,
    /// Storage hash of the token / code.
    pub token_hash: TokenHash,
    /// Owner.
    pub subject: TokenSubject,
    /// Shared id of a link and a code issued together; consuming one revokes
    /// the others.
    pub group_id: Option<Uuid>,
    /// Purpose-specific target (e.g. the new address of an e-mail change).
    pub target: Option<&'a str>,
    /// Allowed verification attempts for codes (1..=100); ignored semantics
    /// for links (stored as given).
    pub max_attempts: u32,
    /// Additional non-secret data (JSON object).
    pub metadata: serde_json::Value,
    /// Requesting IP.
    pub created_ip: Option<IpAddr>,
    /// Creation time (injected clock).
    pub created_at: OffsetDateTime,
    /// Expiry (must be after `created_at`).
    pub expires_at: OffsetDateTime,
}

/// A stored token (the hash itself is never returned).
#[derive(Clone, PartialEq, Eq)]
pub struct OneTimeTokenRecord {
    /// Id.
    pub id: OneTimeTokenId,
    /// Purpose.
    pub purpose: TokenPurpose,
    /// Link or code.
    pub kind: TokenKind,
    /// Owning user.
    pub user_id: Option<UserId>,
    /// Owning challenge.
    pub challenge_id: Option<ChallengeId>,
    /// Group of tokens issued together.
    pub group_id: Option<Uuid>,
    /// Purpose-specific target (personal data: masked in `Debug`).
    pub target: Option<String>,
    /// Failed + successful verification attempts (codes).
    pub attempts: u32,
    /// Attempt limit.
    pub max_attempts: u32,
    /// Additional data.
    pub metadata: serde_json::Value,
    /// Requesting IP (personal data: masked in `Debug`).
    pub created_ip: Option<IpAddr>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Consumption time.
    pub consumed_at: Option<OffsetDateTime>,
    /// Revocation time.
    pub revoked_at: Option<OffsetDateTime>,
}

impl fmt::Debug for OneTimeTokenRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimeTokenRecord")
            .field("id", &self.id)
            .field("purpose", &self.purpose)
            .field("user_id", &self.user_id)
            .field("challenge_id", &self.challenge_id)
            .field(
                "target",
                &self.target.as_ref().map(|_| authn_core::secret::REDACTED),
            )
            .field("attempts", &self.attempts)
            .field("max_attempts", &self.max_attempts)
            .field(
                "created_ip",
                &self.created_ip.map(authn_core::redact::mask_ip),
            )
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .field("revoked_at", &self.revoked_at)
            .finish_non_exhaustive()
    }
}

/// Outcome of [`OneTimeTokenRepository::verify_code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeVerification {
    /// Correct code; the token is now consumed (and its group revoked).
    Verified(Box<OneTimeTokenRecord>),
    /// Wrong code; the attempt was counted.
    Invalid {
        /// Attempts left before lockout.
        remaining_attempts: u32,
    },
    /// The attempt limit is reached; the code was revoked (MFA-03: emit a
    /// security event).
    LockedOut,
    /// No active code for this subject and purpose (none issued, expired,
    /// consumed or revoked).
    NotFound,
}

macro_rules! token_columns {
    () => {
        "id, purpose, kind, user_id, challenge_id, group_id, target, attempts, max_attempts, \
         metadata, created_ip, created_at, expires_at, consumed_at, revoked_at"
    };
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: OneTimeTokenId,
    purpose: String,
    kind: String,
    user_id: Option<UserId>,
    challenge_id: Option<ChallengeId>,
    group_id: Option<Uuid>,
    target: Option<String>,
    attempts: i32,
    max_attempts: i32,
    metadata: serde_json::Value,
    created_ip: Option<IpAddr>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    consumed_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
}

impl TryFrom<TokenRow> for OneTimeTokenRecord {
    type Error = StoreError;

    fn try_from(row: TokenRow) -> Result<Self, Self::Error> {
        let purpose = TokenPurpose::from_str(&row.purpose)?;
        let kind = purpose.kind();
        if kind.as_str() != row.kind {
            return Err(StoreError::Corrupt(
                "one-time token kind does not match purpose",
            ));
        }
        Ok(Self {
            id: row.id,
            purpose,
            kind,
            user_id: row.user_id,
            challenge_id: row.challenge_id,
            group_id: row.group_id,
            target: row.target,
            attempts: u32::try_from(row.attempts).map_err(|_| StoreError::Corrupt("attempts"))?,
            max_attempts: u32::try_from(row.max_attempts)
                .map_err(|_| StoreError::Corrupt("max_attempts"))?,
            metadata: row.metadata,
            created_ip: row.created_ip,
            created_at: row.created_at,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
            revoked_at: row.revoked_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct CodeRow {
    #[sqlx(flatten)]
    token: TokenRow,
    token_hash: Vec<u8>,
}

/// Queries on `one_time_tokens`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OneTimeTokenRepository;

impl OneTimeTokenRepository {
    /// Inserts a token. With `invalidate_previous`, every active token of the
    /// same subject and purpose is revoked first (PWD-07: "a new request
    /// invalidates previous tokens"); concurrent creations for the same
    /// subject and purpose are serialized with a transaction-scoped advisory
    /// lock, so at most one stays active.
    pub async fn create(
        conn: &mut PgConnection,
        new: &NewOneTimeToken<'_>,
        invalidate_previous: bool,
    ) -> Result<OneTimeTokenRecord, StoreError> {
        validate_new(new)?;
        let max_attempts =
            i32::try_from(new.max_attempts).map_err(|_| StoreError::Corrupt("max_attempts"))?;
        let mut tx = conn.begin().await?;
        if invalidate_previous {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(new.subject.lock_key(new.purpose))
                .execute(&mut *tx)
                .await?;
            revoke_active(&mut tx, new.subject, new.purpose, new.created_at).await?;
        }
        let sql = concat!(
            "INSERT INTO one_time_tokens (id, purpose, kind, token_hash, user_id, challenge_id, \
             group_id, target, max_attempts, metadata, created_ip, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING ",
            token_columns!()
        );
        let row = sqlx::query_as::<_, TokenRow>(sql)
            .bind(new.id)
            .bind(new.purpose.as_str())
            .bind(new.purpose.kind().as_str())
            .bind(new.token_hash.as_bytes().as_slice())
            .bind(new.subject.user_id)
            .bind(new.subject.challenge_id)
            .bind(new.group_id)
            .bind(new.target)
            .bind(max_attempts)
            .bind(&new.metadata)
            .bind(new.created_ip)
            .bind(new.created_at)
            .bind(new.expires_at)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        row.try_into()
    }

    /// Looks up an active link without consuming it (e.g. to render the
    /// confirmation page of a magic link, SES-18).
    pub async fn find_active_link<'e>(
        executor: impl PgExecutor<'e>,
        purpose: TokenPurpose,
        token_hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<Option<OneTimeTokenRecord>, StoreError> {
        if purpose.kind() != TokenKind::Link {
            return Ok(None);
        }
        let sql = concat!(
            "SELECT ",
            token_columns!(),
            " FROM one_time_tokens WHERE token_hash = $1 AND purpose = $2 AND kind = 'link' \
             AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $3"
        );
        sqlx::query_as::<_, TokenRow>(sql)
            .bind(token_hash.as_bytes().as_slice())
            .bind(purpose.as_str())
            .bind(now)
            .fetch_optional(executor)
            .await?
            .map(OneTimeTokenRecord::try_from)
            .transpose()
    }

    /// Atomically consumes an active link (ARC-06): a single
    /// `UPDATE … WHERE consumed_at IS NULL AND revoked_at IS NULL AND
    /// expires_at > $now RETURNING`. Of any number of concurrent callers at
    /// most one gets `Some`. The purpose must match (a reset token cannot be
    /// used as a verification token). Other tokens of the same group are
    /// revoked in the same transaction.
    pub async fn consume_link(
        conn: &mut PgConnection,
        purpose: TokenPurpose,
        token_hash: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<Option<OneTimeTokenRecord>, StoreError> {
        if purpose.kind() != TokenKind::Link {
            return Ok(None);
        }
        let mut tx = conn.begin().await?;
        let sql = concat!(
            "UPDATE one_time_tokens SET consumed_at = $3 \
             WHERE token_hash = $1 AND purpose = $2 AND kind = 'link' \
             AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $3 RETURNING ",
            token_columns!()
        );
        let row = sqlx::query_as::<_, TokenRow>(sql)
            .bind(token_hash.as_bytes().as_slice())
            .bind(purpose.as_str())
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let record = OneTimeTokenRecord::try_from(row)?;
        if let Some(group) = record.group_id {
            revoke_group_except(&mut tx, group, record.id, now).await?;
        }
        tx.commit().await?;
        Ok(Some(record))
    }

    /// Verifies a code with attempt counting and lockout (CRY-07, MFA-03).
    ///
    /// Runs in its **own** committed transaction (see the module docs): the
    /// newest active code of `subject` + `purpose` is row-locked
    /// (`FOR UPDATE`), the candidate hash is compared in constant time, and
    /// the attempt counter, consumption or lockout is written before
    /// commit. Concurrent verifications of the same code serialize on the
    /// row lock: exactly one succeeds.
    pub async fn verify_code(
        pool: &PgPool,
        purpose: TokenPurpose,
        subject: TokenSubject,
        candidate: &TokenHash,
        now: OffsetDateTime,
    ) -> Result<CodeVerification, StoreError> {
        if purpose.kind() != TokenKind::Code {
            return Ok(CodeVerification::NotFound);
        }
        let mut tx = pool.begin().await?;
        let row = match (subject.challenge_id, subject.user_id) {
            (Some(challenge), _) => {
                let sql = concat!(
                    "SELECT ",
                    token_columns!(),
                    ", token_hash FROM one_time_tokens WHERE challenge_id = $1 AND purpose = $2 \
                     AND kind = 'code' AND consumed_at IS NULL AND revoked_at IS NULL \
                     AND expires_at > $3 ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE"
                );
                sqlx::query_as::<_, CodeRow>(sql)
                    .bind(challenge)
                    .bind(purpose.as_str())
                    .bind(now)
                    .fetch_optional(&mut *tx)
                    .await?
            }
            (None, Some(user)) => {
                let sql = concat!(
                    "SELECT ",
                    token_columns!(),
                    ", token_hash FROM one_time_tokens WHERE user_id = $1 AND purpose = $2 \
                     AND kind = 'code' AND consumed_at IS NULL AND revoked_at IS NULL \
                     AND expires_at > $3 ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE"
                );
                sqlx::query_as::<_, CodeRow>(sql)
                    .bind(user)
                    .bind(purpose.as_str())
                    .bind(now)
                    .fetch_optional(&mut *tx)
                    .await?
            }
            (None, None) => None,
        };
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(CodeVerification::NotFound);
        };
        let stored = TokenHash::from_slice(&row.token_hash)
            .map_err(|_| StoreError::Corrupt("token_hash length"))?;
        let record = OneTimeTokenRecord::try_from(row.token)?;

        if record.attempts >= record.max_attempts {
            // Defensive: a code at its limit should already be revoked.
            revoke_by_id(&mut tx, record.id, now).await?;
            tx.commit().await?;
            return Ok(CodeVerification::LockedOut);
        }

        // Constant-time comparison (CRY-12) on the hash, in Rust, after the
        // row lock is held.
        let outcome = if stored == *candidate {
            let sql = concat!(
                "UPDATE one_time_tokens SET attempts = attempts + 1, consumed_at = $2 \
                 WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL RETURNING ",
                token_columns!()
            );
            let row = sqlx::query_as::<_, TokenRow>(sql)
                .bind(record.id)
                .bind(now)
                .fetch_one(&mut *tx)
                .await?;
            let consumed = OneTimeTokenRecord::try_from(row)?;
            if let Some(group) = consumed.group_id {
                revoke_group_except(&mut tx, group, consumed.id, now).await?;
            }
            CodeVerification::Verified(Box::new(consumed))
        } else {
            let (attempts, max_attempts, revoked): (i32, i32, bool) = sqlx::query_as(
                "UPDATE one_time_tokens SET attempts = attempts + 1, \
                 revoked_at = CASE WHEN attempts + 1 >= max_attempts THEN $2 ELSE NULL END \
                 WHERE id = $1 RETURNING attempts, max_attempts, revoked_at IS NOT NULL",
            )
            .bind(record.id)
            .bind(now)
            .fetch_one(&mut *tx)
            .await?;
            if revoked {
                CodeVerification::LockedOut
            } else {
                CodeVerification::Invalid {
                    remaining_attempts: u32::try_from(max_attempts.saturating_sub(attempts))
                        .unwrap_or(0),
                }
            }
        };
        tx.commit().await?;
        Ok(outcome)
    }

    /// Revokes every active token of `subject` for `purpose` (e.g. after a
    /// successful password reset). Returns the number of revoked tokens.
    pub async fn revoke_active(
        conn: &mut PgConnection,
        subject: TokenSubject,
        purpose: TokenPurpose,
        now: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        revoke_active(conn, subject, purpose, now).await
    }

    /// Revokes every active token of `user` for any of `purposes`.
    pub async fn revoke_for_user(
        conn: &mut PgConnection,
        user: UserId,
        purposes: &[TokenPurpose],
        now: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let purposes: Vec<&str> = purposes.iter().map(|p| p.as_str()).collect();
        let result = sqlx::query(
            "UPDATE one_time_tokens SET revoked_at = $3 WHERE user_id = $1 \
             AND purpose = ANY($2) AND consumed_at IS NULL AND revoked_at IS NULL",
        )
        .bind(user)
        .bind(&purposes)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }

    /// Revokes every active token of a group.
    pub async fn revoke_group(
        conn: &mut PgConnection,
        group: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "UPDATE one_time_tokens SET revoked_at = $2 WHERE group_id = $1 \
             AND consumed_at IS NULL AND revoked_at IS NULL",
        )
        .bind(group)
        .bind(now)
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }

    /// Finds a token by id (administrative / diagnostic use).
    pub async fn find_by_id<'e>(
        executor: impl PgExecutor<'e>,
        id: OneTimeTokenId,
    ) -> Result<Option<OneTimeTokenRecord>, StoreError> {
        let sql = concat!(
            "SELECT ",
            token_columns!(),
            " FROM one_time_tokens WHERE id = $1"
        );
        sqlx::query_as::<_, TokenRow>(sql)
            .bind(id)
            .fetch_optional(executor)
            .await?
            .map(OneTimeTokenRecord::try_from)
            .transpose()
    }

    /// Deletes up to `limit` tokens that expired before `before` (cleanup
    /// job, OPS-06). Returns the number of deleted rows.
    pub async fn delete_expired(
        conn: &mut PgConnection,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "DELETE FROM one_time_tokens WHERE id IN (SELECT id FROM one_time_tokens \
             WHERE expires_at < $1 ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(before)
        .bind(i64::from(limit))
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }
}

fn validate_new(new: &NewOneTimeToken<'_>) -> Result<(), StoreError> {
    if new.subject.user_id.is_none() && new.subject.challenge_id.is_none() {
        return Err(StoreError::CheckViolation {
            constraint: "one_time_tokens_owner_check".to_owned(),
        });
    }
    if new.expires_at <= new.created_at {
        return Err(StoreError::CheckViolation {
            constraint: "one_time_tokens_expiry_check".to_owned(),
        });
    }
    if !(1..=100).contains(&new.max_attempts) {
        return Err(StoreError::CheckViolation {
            constraint: "one_time_tokens_attempts_check".to_owned(),
        });
    }
    if !new.metadata.is_object() {
        return Err(StoreError::CheckViolation {
            constraint: "one_time_tokens_metadata_check".to_owned(),
        });
    }
    if new.target.is_some_and(|t| t.chars().count() > 320) {
        return Err(StoreError::CheckViolation {
            constraint: "one_time_tokens_target_check".to_owned(),
        });
    }
    Ok(())
}

async fn revoke_active(
    conn: &mut PgConnection,
    subject: TokenSubject,
    purpose: TokenPurpose,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let result = match (subject.challenge_id, subject.user_id) {
        (Some(challenge), _) => {
            sqlx::query(
                "UPDATE one_time_tokens SET revoked_at = $3 WHERE challenge_id = $1 \
                 AND purpose = $2 AND consumed_at IS NULL AND revoked_at IS NULL",
            )
            .bind(challenge)
            .bind(purpose.as_str())
            .bind(now)
            .execute(conn)
            .await?
        }
        (None, Some(user)) => {
            sqlx::query(
                "UPDATE one_time_tokens SET revoked_at = $3 WHERE user_id = $1 \
                 AND purpose = $2 AND consumed_at IS NULL AND revoked_at IS NULL",
            )
            .bind(user)
            .bind(purpose.as_str())
            .bind(now)
            .execute(conn)
            .await?
        }
        (None, None) => return Ok(0),
    };
    Ok(result.rows_affected())
}

async fn revoke_group_except(
    conn: &mut PgConnection,
    group: Uuid,
    keep: OneTimeTokenId,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "UPDATE one_time_tokens SET revoked_at = $3 WHERE group_id = $1 AND id <> $2 \
         AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(keep)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

async fn revoke_by_id(
    conn: &mut PgConnection,
    id: OneTimeTokenId,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE one_time_tokens SET revoked_at = $2 WHERE id = $1 \
         AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_06_purposes_round_trip_and_match_the_contract() {
        let codes = [
            "email_verification_code",
            "email_change_code",
            "password_reset_code",
            "login_code",
            "mfa_email_otp",
            "mfa_sms_otp",
            "phone_verification",
        ];
        for purpose in TokenPurpose::ALL {
            assert_eq!(purpose.as_str().parse::<TokenPurpose>().unwrap(), *purpose);
            assert_eq!(purpose.to_string(), purpose.as_str());
            let expected = if codes.contains(&purpose.as_str()) {
                TokenKind::Code
            } else {
                TokenKind::Link
            };
            assert_eq!(purpose.kind(), expected, "{purpose}");
        }
        assert_eq!(TokenPurpose::ALL.len(), 15);
        assert!("unknown".parse::<TokenPurpose>().is_err());
    }

    #[test]
    fn arc_06_lock_keys_distinguish_subjects_and_purposes() {
        let user = UserId::generate();
        let challenge = ChallengeId::generate();
        let a = TokenSubject::user(user).lock_key(TokenPurpose::PasswordReset);
        let b = TokenSubject::user(user).lock_key(TokenPurpose::PasswordResetCode);
        let c = TokenSubject::challenge(challenge).lock_key(TokenPurpose::LoginCode);
        let d = TokenSubject::user_and_challenge(user, challenge).lock_key(TokenPurpose::LoginCode);
        assert_ne!(a, b);
        assert_eq!(c, d, "lookups by challenge share the lock");
    }
}
