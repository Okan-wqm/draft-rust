//! SQL for this crate's tables (`identities`, `oauth_states`, migration
//! `0007`, `2100`–`2102`; `oauth_token_revocations`, `2102`). Runtime
//! queries with `&'static str` SQL; values are always bind parameters.

use authn_core::domain::ClientKind;
use authn_core::id::{IdentityId, OAuthStateId, SessionId, UserId};
use authn_store::StoreError;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;

/// `oauth_states.flow` of a browser login.
pub const FLOW_LOGIN: &str = "login";
/// `oauth_states.flow` of a browser identity link.
pub const FLOW_LINK: &str = "link";
/// `oauth_states.flow` of a native nonce.
pub const FLOW_NATIVE_NONCE: &str = "native_nonce";

/// Name of the `(provider, subject)` unique constraint.
pub const PROVIDER_SUBJECT_KEY: &str = "identities_provider_subject_key";
/// Name of the `(user_id, provider)` unique constraint.
pub const USER_PROVIDER_KEY: &str = "identities_user_provider_key";

/// Input of [`insert_state`].
#[derive(Debug)]
pub struct NewState<'a> {
    pub id: OAuthStateId,
    pub provider: &'a str,
    pub flow: &'static str,
    pub state_hash: &'a [u8; 32],
    pub nonce_hash: &'a [u8; 32],
    pub pkce_verifier_ciphertext: Option<&'a [u8]>,
    pub user_id: Option<UserId>,
    pub return_to: Option<&'a str>,
    pub client_kind: ClientKind,
    pub binding_hash: Option<&'a [u8; 32]>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    /// "Remember me" of a web login (SES-06, K-32).
    pub remember_me: bool,
    /// "Not my device" of a web login (SES-07, K-32).
    pub shared_device: bool,
    /// Session that started a link flow (K-03).
    pub session_id: Option<SessionId>,
}

/// A consumed `oauth_states` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StateRow {
    pub id: OAuthStateId,
    pub provider: String,
    pub flow: String,
    pub nonce_hash: Vec<u8>,
    pub pkce_verifier_ciphertext: Option<Vec<u8>>,
    pub user_id: Option<UserId>,
    pub return_to: Option<String>,
    pub binding_hash: Option<Vec<u8>>,
    pub remember_me: bool,
    pub shared_device: bool,
    pub session_id: Option<SessionId>,
}

/// Inserts an authorization state / native nonce.
pub async fn insert_state(
    executor: impl PgExecutor<'_>,
    new: &NewState<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO oauth_states (id, provider, flow, state_hash, nonce_hash, \
         pkce_verifier_ciphertext, user_id, return_to, client_kind, binding_hash, created_at, \
         expires_at, remember_me, shared_device, session_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(new.id)
    .bind(new.provider)
    .bind(new.flow)
    .bind(&new.state_hash[..])
    .bind(&new.nonce_hash[..])
    .bind(new.pkce_verifier_ciphertext)
    .bind(new.user_id)
    .bind(new.return_to)
    .bind(new.client_kind)
    .bind(new.binding_hash.map(|h| &h[..]))
    .bind(new.created_at)
    .bind(new.expires_at)
    .bind(new.remember_me)
    .bind(new.shared_device)
    .bind(new.session_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Atomically consumes a live browser state (single use, SOC-02): exactly
/// one of several concurrent callbacks gets the row.
pub async fn consume_web_state(
    executor: impl PgExecutor<'_>,
    state_hash: &[u8; 32],
    now: OffsetDateTime,
) -> Result<Option<StateRow>, StoreError> {
    let sql = const_format_returning::CONSUME_WEB;
    Ok(sqlx::query_as::<_, StateRow>(sql)
        .bind(&state_hash[..])
        .bind(now)
        .fetch_optional(executor)
        .await?)
}

/// Atomically consumes a live native nonce of `provider` (SOC-04).
pub async fn consume_native_nonce(
    executor: impl PgExecutor<'_>,
    nonce_hash: &[u8; 32],
    provider: &str,
    now: OffsetDateTime,
) -> Result<Option<StateRow>, StoreError> {
    let sql = const_format_returning::CONSUME_NONCE;
    Ok(sqlx::query_as::<_, StateRow>(sql)
        .bind(&nonce_hash[..])
        .bind(now)
        .bind(provider)
        .fetch_optional(executor)
        .await?)
}

/// `concat!`-built statements (sqlx 0.9 needs `&'static str`).
mod const_format_returning {
    macro_rules! returning {
        () => {
            " RETURNING id, provider, flow, nonce_hash, pkce_verifier_ciphertext, user_id, \
             return_to, binding_hash, remember_me, shared_device, session_id"
        };
    }
    pub(super) const CONSUME_WEB: &str = concat!(
        "UPDATE oauth_states SET consumed_at = $2 WHERE state_hash = $1 \
         AND flow IN ('login', 'link') AND consumed_at IS NULL AND expires_at > $2",
        returning!()
    );
    pub(super) const CONSUME_NONCE: &str = concat!(
        "UPDATE oauth_states SET consumed_at = $2 WHERE nonce_hash = $1 \
         AND flow = 'native_nonce' AND provider = $3 AND consumed_at IS NULL AND expires_at > $2",
        returning!()
    );
}

/// Deletes up to `limit` expired states; returns how many.
pub async fn purge_expired_states(
    executor: impl PgExecutor<'_>,
    now: OffsetDateTime,
    limit: i64,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        "DELETE FROM oauth_states WHERE id IN (SELECT id FROM oauth_states \
         WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2)",
    )
    .bind(now)
    .bind(limit)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// A row of `identities`.
#[derive(Clone, sqlx::FromRow)]
pub struct IdentityRow {
    pub id: IdentityId,
    pub user_id: UserId,
    pub provider: String,
    pub subject: String,
    pub issuer: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub access_token_ciphertext: Option<Vec<u8>>,
    pub refresh_token_ciphertext: Option<Vec<u8>>,
    pub token_expires_at: Option<OffsetDateTime>,
    pub token_client_id: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for IdentityRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityRow")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("provider", &self.provider)
            .field(
                "access_token_stored",
                &self.access_token_ciphertext.is_some(),
            )
            .field(
                "refresh_token_stored",
                &self.refresh_token_ciphertext.is_some(),
            )
            .finish_non_exhaustive()
    }
}

macro_rules! identity_columns {
    () => {
        "id, user_id, provider, subject, issuer, email, email_verified, display_name, \
         access_token_ciphertext, refresh_token_ciphertext, token_expires_at, token_client_id, \
         created_at, last_login_at"
    };
}

/// The identity `(provider, subject)`, if linked.
pub async fn find_identity(
    executor: impl PgExecutor<'_>,
    provider: &str,
    subject: &str,
) -> Result<Option<IdentityRow>, StoreError> {
    let sql = concat!(
        "SELECT ",
        identity_columns!(),
        " FROM identities WHERE provider = $1 AND subject = $2"
    );
    Ok(sqlx::query_as::<_, IdentityRow>(sql)
        .bind(provider)
        .bind(subject)
        .fetch_optional(executor)
        .await?)
}

/// The identity `id`, row-locked (`FOR UPDATE`) for the caller's
/// transaction: concurrent sign-ins replacing its tokens are serialized
/// (K-59: each replaced token is seen, and queued, exactly once).
pub async fn lock_identity(
    conn: &mut PgConnection,
    id: IdentityId,
) -> Result<Option<IdentityRow>, StoreError> {
    let sql = concat!(
        "SELECT ",
        identity_columns!(),
        " FROM identities WHERE id = $1 FOR UPDATE"
    );
    Ok(sqlx::query_as::<_, IdentityRow>(sql)
        .bind(id)
        .fetch_optional(conn)
        .await?)
}

/// The user's identities, oldest first.
pub async fn identities_of(
    executor: impl PgExecutor<'_>,
    user: UserId,
) -> Result<Vec<IdentityRow>, StoreError> {
    let sql = concat!(
        "SELECT ",
        identity_columns!(),
        " FROM identities WHERE user_id = $1 ORDER BY created_at, id"
    );
    Ok(sqlx::query_as::<_, IdentityRow>(sql)
        .bind(user)
        .fetch_all(executor)
        .await?)
}

/// Number of identities linked to `user`.
pub async fn count_identities(
    executor: impl PgExecutor<'_>,
    user: UserId,
) -> Result<i64, StoreError> {
    Ok(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identities WHERE user_id = $1")
            .bind(user)
            .fetch_one(executor)
            .await?,
    )
}

/// Input of [`insert_identity`].
#[derive(Debug)]
pub struct NewIdentity<'a> {
    pub id: IdentityId,
    pub user_id: UserId,
    pub provider: &'a str,
    pub subject: &'a str,
    pub issuer: Option<&'a str>,
    pub email: Option<&'a str>,
    pub email_verified: bool,
    pub display_name: Option<&'a str>,
    pub now: OffsetDateTime,
}

/// Links an identity. Unique violations: [`PROVIDER_SUBJECT_KEY`],
/// [`USER_PROVIDER_KEY`].
pub async fn insert_identity(
    conn: &mut PgConnection,
    new: &NewIdentity<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, subject, issuer, email, email_verified, \
         display_name, created_at, last_login_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9)",
    )
    .bind(new.id)
    .bind(new.user_id)
    .bind(new.provider)
    .bind(new.subject)
    .bind(new.issuer)
    .bind(new.email)
    .bind(new.email_verified)
    .bind(new.display_name)
    .bind(new.now)
    .execute(conn)
    .await?;
    Ok(())
}

/// Refreshes the provider-asserted attributes after a login. A display
/// name is only replaced by a new one (Apple sends the name once).
pub async fn touch_identity(
    conn: &mut PgConnection,
    id: IdentityId,
    email: Option<&str>,
    email_verified: bool,
    display_name: Option<&str>,
    now: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE identities SET email = $2, email_verified = $3, \
         display_name = COALESCE($4, display_name), last_login_at = $5 WHERE id = $1",
    )
    .bind(id)
    .bind(email)
    .bind(email_verified)
    .bind(display_name)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

/// Sealed provider tokens of an identity (SOC-08); `None` columns are
/// cleared.
#[derive(Debug, Default)]
pub struct SealedTokens<'a> {
    pub access: Option<&'a [u8]>,
    pub refresh: Option<&'a [u8]>,
    pub expires_at: Option<OffsetDateTime>,
    /// Client id the tokens were issued to (K-35: revocation presents it).
    pub client_id: Option<&'a str>,
}

/// Stores (or clears) the sealed provider tokens (SOC-08).
pub async fn set_tokens(
    conn: &mut PgConnection,
    id: IdentityId,
    tokens: &SealedTokens<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE identities SET access_token_ciphertext = $2, refresh_token_ciphertext = $3, \
         token_expires_at = $4, token_client_id = $5 WHERE id = $1",
    )
    .bind(id)
    .bind(tokens.access)
    .bind(tokens.refresh)
    .bind(tokens.expires_at)
    .bind(tokens.client_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// Unlinks one of `user`'s identities; returns whether a row was deleted.
pub async fn delete_identity(
    conn: &mut PgConnection,
    id: IdentityId,
    user: UserId,
) -> Result<bool, StoreError> {
    let result = sqlx::query("DELETE FROM identities WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user)
        .execute(conn)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// A queued provider-token revocation (K-35).
#[derive(Clone, sqlx::FromRow)]
pub struct RevocationRow {
    pub id: sqlx::types::Uuid,
    pub provider: String,
    pub client_id: String,
    pub token_ciphertext: Vec<u8>,
    pub token_type_hint: String,
    pub attempts: i32,
}

impl std::fmt::Debug for RevocationRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationRow")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

/// Input of [`enqueue_revocation`].
#[derive(Debug)]
pub struct NewRevocation<'a> {
    pub id: sqlx::types::Uuid,
    pub provider: &'a str,
    pub client_id: &'a str,
    pub token_ciphertext: &'a [u8],
    pub token_type_hint: &'static str,
    pub now: OffsetDateTime,
}

/// Queues a token revocation (caller's transaction).
pub async fn enqueue_revocation(
    conn: &mut PgConnection,
    new: &NewRevocation<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO oauth_token_revocations (id, provider, client_id, token_ciphertext, \
         token_type_hint, attempts, next_attempt_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, 0, $6, $6)",
    )
    .bind(new.id)
    .bind(new.provider)
    .bind(new.client_id)
    .bind(new.token_ciphertext)
    .bind(new.token_type_hint)
    .bind(new.now)
    .execute(conn)
    .await?;
    Ok(())
}

/// Claims the next due revocation (multi-instance safe): its attempt
/// counter is raised and it is leased until `lease_until`, in one
/// statement, so the HTTP call runs without holding a lock or a
/// transaction.
pub async fn claim_revocation(
    executor: impl PgExecutor<'_>,
    now: OffsetDateTime,
    lease_until: OffsetDateTime,
) -> Result<Option<RevocationRow>, StoreError> {
    Ok(sqlx::query_as::<_, RevocationRow>(
        "UPDATE oauth_token_revocations SET attempts = attempts + 1, next_attempt_at = $2 \
         WHERE id = (SELECT id FROM oauth_token_revocations WHERE next_attempt_at <= $1 \
           ORDER BY next_attempt_at, id LIMIT 1 FOR UPDATE SKIP LOCKED) \
         RETURNING id, provider, client_id, token_ciphertext, token_type_hint, attempts",
    )
    .bind(now)
    .bind(lease_until)
    .fetch_optional(executor)
    .await?)
}

/// Removes a revocation (done or given up).
pub async fn delete_revocation(
    executor: impl PgExecutor<'_>,
    id: sqlx::types::Uuid,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM oauth_token_revocations WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Schedules the next attempt of a revocation.
pub async fn reschedule_revocation(
    executor: impl PgExecutor<'_>,
    id: sqlx::types::Uuid,
    next_attempt_at: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE oauth_token_revocations SET next_attempt_at = $2 WHERE id = $1")
        .bind(id)
        .bind(next_attempt_at)
        .execute(executor)
        .await?;
    Ok(())
}
