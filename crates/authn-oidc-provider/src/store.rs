//! SQL of the provider tables (migration `3000`). Runtime queries with
//! static SQL text and bind parameters only (contracts §11).

use authn_core::id::{SessionId, UserId};
use sqlx::{FromRow, PgConnection, PgExecutor};
use time::OffsetDateTime;
use uuid::Uuid;

/// Grant type wire values.
pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
/// Refresh token grant.
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";

/// A client registration row (OIDP-01). `secret_hash` is the SHA-256 of
/// the client secret; it never leaves this crate and is not in `Debug`.
#[derive(Clone, FromRow)]
pub struct ClientRow {
    /// Internal id.
    pub id: Uuid,
    /// Public client identifier.
    pub client_id: String,
    /// Display name (shown on the consent screen).
    pub name: String,
    /// `confidential` or `public`.
    pub client_type: String,
    /// `web` or `native`.
    pub application_type: String,
    pub(crate) secret_hash: Option<Vec<u8>>,
    /// Last secret rotation.
    pub secret_rotated_at: Option<OffsetDateTime>,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Scopes the client may request.
    pub allowed_scopes: Vec<String>,
    /// Grant types the client may use.
    pub allowed_grant_types: Vec<String>,
    /// Resource indicators the client may request.
    pub allowed_resources: Vec<String>,
    /// First-party client: no consent screen.
    pub skip_consent: bool,
    /// Disabled clients can neither authorize nor use tokens.
    pub disabled: bool,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last change.
    pub updated_at: OffsetDateTime,
}

impl std::fmt::Debug for ClientRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRow")
            .field("client_id", &self.client_id)
            .field("client_type", &self.client_type)
            .field("disabled", &self.disabled)
            .finish_non_exhaustive()
    }
}

impl ClientRow {
    /// Whether the client holds a secret.
    #[must_use]
    pub fn is_confidential(&self) -> bool {
        self.client_type == "confidential"
    }

    /// Whether the client may use `grant`.
    #[must_use]
    pub fn allows_grant(&self, grant: &str) -> bool {
        self.allowed_grant_types.iter().any(|g| g == grant)
    }
}

macro_rules! client_columns {
    () => {
        "id, client_id, name, client_type, application_type, secret_hash, \
         secret_rotated_at, redirect_uris, allowed_scopes, allowed_grant_types, \
         allowed_resources, skip_consent, disabled, created_at, updated_at"
    };
}

/// Inserts a client.
pub(crate) async fn insert_client(
    conn: &mut PgConnection,
    row: &ClientRow,
) -> Result<(), sqlx::Error> {
    sqlx::query(concat!(
        "INSERT INTO oidc_clients (",
        client_columns!(),
        ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
    ))
    .bind(row.id)
    .bind(&row.client_id)
    .bind(&row.name)
    .bind(&row.client_type)
    .bind(&row.application_type)
    .bind(&row.secret_hash)
    .bind(row.secret_rotated_at)
    .bind(&row.redirect_uris)
    .bind(&row.allowed_scopes)
    .bind(&row.allowed_grant_types)
    .bind(&row.allowed_resources)
    .bind(row.skip_consent)
    .bind(row.disabled)
    .bind(row.created_at)
    .bind(row.updated_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Updates the mutable fields of a client.
pub(crate) async fn update_client(
    conn: &mut PgConnection,
    row: &ClientRow,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oidc_clients SET name = $2, redirect_uris = $3, allowed_scopes = $4, \
         allowed_grant_types = $5, allowed_resources = $6, skip_consent = $7, disabled = $8, \
         updated_at = $9 WHERE id = $1",
    )
    .bind(row.id)
    .bind(&row.name)
    .bind(&row.redirect_uris)
    .bind(&row.allowed_scopes)
    .bind(&row.allowed_grant_types)
    .bind(&row.allowed_resources)
    .bind(row.skip_consent)
    .bind(row.disabled)
    .bind(row.updated_at)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Replaces the secret hash.
pub(crate) async fn set_client_secret(
    conn: &mut PgConnection,
    id: Uuid,
    hash: &[u8; 32],
    now: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oidc_clients SET secret_hash = $2, secret_rotated_at = $3, updated_at = $3 \
         WHERE id = $1 AND client_type = 'confidential'",
    )
    .bind(id)
    .bind(hash.as_slice())
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Deletes a client (grants, codes, tokens, consents cascade).
pub(crate) async fn delete_client(conn: &mut PgConnection, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
        .bind(id)
        .execute(conn)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// A client by its public identifier.
pub(crate) async fn find_client<'e>(
    executor: impl PgExecutor<'e>,
    client_id: &str,
) -> Result<Option<ClientRow>, sqlx::Error> {
    sqlx::query_as::<_, ClientRow>(concat!(
        "SELECT ",
        client_columns!(),
        " FROM oidc_clients WHERE client_id = $1"
    ))
    .bind(client_id)
    .fetch_optional(executor)
    .await
}

/// A client by its internal id.
pub(crate) async fn find_client_by_pk<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<Option<ClientRow>, sqlx::Error> {
    sqlx::query_as::<_, ClientRow>(concat!(
        "SELECT ",
        client_columns!(),
        " FROM oidc_clients WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await
}

/// Every client, newest first (bounded).
pub(crate) async fn list_clients<'e>(
    executor: impl PgExecutor<'e>,
    limit: i64,
) -> Result<Vec<ClientRow>, sqlx::Error> {
    sqlx::query_as::<_, ClientRow>(concat!(
        "SELECT ",
        client_columns!(),
        " FROM oidc_clients ORDER BY created_at DESC, id DESC LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(executor)
    .await
}

// --- interactions -----------------------------------------------------------

/// A pending authorization request.
#[derive(Debug, Clone, FromRow)]
pub struct InteractionRow {
    /// Id (shown to the front end).
    pub id: Uuid,
    /// Client (internal id).
    pub client_id: Uuid,
    pub(crate) browser_hash: Vec<u8>,
    /// Validated redirect URI (as requested).
    pub redirect_uri: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Requested resources.
    pub resources: Vec<String>,
    /// `state`.
    pub state: Option<String>,
    /// `nonce`.
    pub nonce: Option<String>,
    /// `S256` challenge.
    pub code_challenge: String,
    /// `prompt=login`.
    pub prompt_login: bool,
    /// `prompt=consent`.
    pub prompt_consent: bool,
    /// `max_age` seconds.
    pub max_age: Option<i64>,
    /// Requested `acr_values`.
    pub acr_values: Vec<String>,
    /// Creation.
    pub created_at: OffsetDateTime,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Completion (consent given or denied).
    pub completed_at: Option<OffsetDateTime>,
}

/// Inserts an interaction.
pub(crate) async fn insert_interaction<'e>(
    executor: impl PgExecutor<'e>,
    row: &InteractionRow,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oidc_interactions (id, client_id, browser_hash, redirect_uri, scopes, \
         resources, state, nonce, code_challenge, prompt_login, prompt_consent, max_age, \
         acr_values, created_at, expires_at, completed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(row.id)
    .bind(row.client_id)
    .bind(&row.browser_hash)
    .bind(&row.redirect_uri)
    .bind(&row.scopes)
    .bind(&row.resources)
    .bind(&row.state)
    .bind(&row.nonce)
    .bind(&row.code_challenge)
    .bind(row.prompt_login)
    .bind(row.prompt_consent)
    .bind(row.max_age)
    .bind(&row.acr_values)
    .bind(row.created_at)
    .bind(row.expires_at)
    .bind(row.completed_at)
    .execute(executor)
    .await?;
    Ok(())
}

const INTERACTION_SELECT: &str = "SELECT id, client_id, browser_hash, redirect_uri, scopes, \
     resources, state, nonce, code_challenge, prompt_login, prompt_consent, max_age, \
     acr_values, created_at, expires_at, completed_at FROM oidc_interactions WHERE id = $1";

/// An open (not completed, not expired) interaction.
pub(crate) async fn find_open_interaction<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
    now: OffsetDateTime,
) -> Result<Option<InteractionRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, InteractionRow>(INTERACTION_SELECT)
        .bind(id)
        .fetch_optional(executor)
        .await?;
    Ok(row.filter(|r| r.completed_at.is_none() && r.expires_at > now))
}

/// Atomically completes an open interaction; `false` when it was already
/// completed or expired (single use).
pub(crate) async fn complete_interaction(
    conn: &mut PgConnection,
    id: Uuid,
    now: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oidc_interactions SET completed_at = $2 \
         WHERE id = $1 AND completed_at IS NULL AND expires_at > $2",
    )
    .bind(id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

// --- consents ----------------------------------------------------------------

/// The scopes and resources `user` approved for the client, if any.
pub(crate) async fn consented<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
    client: Uuid,
) -> Result<Option<(Vec<String>, Vec<String>)>, sqlx::Error> {
    sqlx::query_as::<_, (Vec<String>, Vec<String>)>(
        "SELECT scopes, resources FROM oidc_consents WHERE user_id = $1 AND client_id = $2",
    )
    .bind(user)
    .bind(client)
    .fetch_optional(executor)
    .await
}

/// Records consent to `(scopes, resources)` (union with earlier ones).
pub(crate) async fn upsert_consent(
    conn: &mut PgConnection,
    user: UserId,
    client: Uuid,
    approved: (&[String], &[String]),
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    let (scopes, resources) = approved;
    sqlx::query(
        "INSERT INTO oidc_consents (user_id, client_id, scopes, resources, granted_at, \
         updated_at) VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (user_id, client_id) DO UPDATE \
         SET scopes = ARRAY(SELECT DISTINCT unnest(oidc_consents.scopes || EXCLUDED.scopes) \
         ORDER BY 1), resources = ARRAY(SELECT DISTINCT unnest(oidc_consents.resources || \
         EXCLUDED.resources) ORDER BY 1), updated_at = EXCLUDED.updated_at",
    )
    .bind(user)
    .bind(client)
    .bind(scopes)
    .bind(resources)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

/// A consent of the user, for listing.
#[derive(Debug, Clone, FromRow)]
pub struct ConsentRow {
    /// Public client id.
    pub client_id: String,
    /// Client name.
    pub client_name: String,
    /// Approved scopes.
    pub scopes: Vec<String>,
    /// Approved resources (RFC 8707 token audiences).
    pub resources: Vec<String>,
    /// First approval.
    pub granted_at: OffsetDateTime,
    /// Last change.
    pub updated_at: OffsetDateTime,
}

/// The user's consents.
pub(crate) async fn list_consents<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
) -> Result<Vec<ConsentRow>, sqlx::Error> {
    sqlx::query_as::<_, ConsentRow>(
        "SELECT c.client_id, c.name AS client_name, o.scopes, o.resources, o.granted_at, \
         o.updated_at \
         FROM oidc_consents o JOIN oidc_clients c ON c.id = o.client_id \
         WHERE o.user_id = $1 ORDER BY o.granted_at, c.client_id LIMIT 500",
    )
    .bind(user)
    .fetch_all(executor)
    .await
}

/// Deletes a consent.
pub(crate) async fn delete_consent(
    conn: &mut PgConnection,
    user: UserId,
    client: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM oidc_consents WHERE user_id = $1 AND client_id = $2")
        .bind(user)
        .bind(client)
        .execute(conn)
        .await?;
    Ok(result.rows_affected() == 1)
}

// --- grants ------------------------------------------------------------------

/// A grant: one authorization of a client by a user in a session.
#[derive(Debug, Clone, FromRow)]
pub struct GrantRow {
    /// Id.
    pub id: Uuid,
    /// Client (internal id).
    pub client_id: Uuid,
    /// User.
    pub user_id: UserId,
    /// Session the user authorized in.
    pub session_id: SessionId,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Granted resources.
    pub resources: Vec<String>,
    /// `nonce` of the authorization request.
    pub nonce: Option<String>,
    /// Authentication time.
    pub auth_time: OffsetDateTime,
    /// RFC 8176 methods (wire values).
    pub amr: Vec<String>,
    /// `acr`.
    pub acr: Option<String>,
    /// Creation.
    pub created_at: OffsetDateTime,
    /// Absolute expiry.
    pub expires_at: OffsetDateTime,
    /// Revocation.
    pub revoked_at: Option<OffsetDateTime>,
}

/// Inserts a grant.
pub(crate) async fn insert_grant(
    conn: &mut PgConnection,
    row: &GrantRow,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oidc_grants (id, client_id, user_id, session_id, scopes, resources, nonce, \
         auth_time, amr, acr, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(row.id)
    .bind(row.client_id)
    .bind(row.user_id)
    .bind(row.session_id)
    .bind(&row.scopes)
    .bind(&row.resources)
    .bind(&row.nonce)
    .bind(row.auth_time)
    .bind(&row.amr)
    .bind(&row.acr)
    .bind(row.created_at)
    .bind(row.expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// A grant by id.
pub(crate) async fn find_grant<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<Option<GrantRow>, sqlx::Error> {
    sqlx::query_as::<_, GrantRow>(
        "SELECT id, client_id, user_id, session_id, scopes, resources, nonce, auth_time, amr, \
         acr, created_at, expires_at, revoked_at FROM oidc_grants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(executor)
    .await
}

/// Revokes a grant (idempotent).
pub(crate) async fn revoke_grant(
    conn: &mut PgConnection,
    id: Uuid,
    reason: &str,
    now: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oidc_grants SET revoked_at = $2, revoked_reason = $3 \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Revokes every grant of `user` for `client`.
pub(crate) async fn revoke_user_client_grants(
    conn: &mut PgConnection,
    user: UserId,
    client: Uuid,
    reason: &str,
    now: OffsetDateTime,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oidc_grants SET revoked_at = $3, revoked_reason = $4 \
         WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL",
    )
    .bind(user)
    .bind(client)
    .bind(now)
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

/// Revokes every grant of a client.
pub(crate) async fn revoke_client_grants(
    conn: &mut PgConnection,
    client: Uuid,
    reason: &str,
    now: OffsetDateTime,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oidc_grants SET revoked_at = $2, revoked_reason = $3 \
         WHERE client_id = $1 AND revoked_at IS NULL",
    )
    .bind(client)
    .bind(now)
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}

// --- authorization codes -------------------------------------------------------

/// An authorization code (hash only).
#[derive(Debug, Clone, FromRow)]
pub struct CodeRow {
    /// Id.
    pub id: Uuid,
    /// The grant the code creates tokens for.
    pub grant_id: Uuid,
    /// Redirect URI of the authorization request.
    pub redirect_uri: String,
    /// `S256` challenge.
    pub code_challenge: String,
    /// Creation.
    pub created_at: OffsetDateTime,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Redemption (or a failed PKCE check).
    pub consumed_at: Option<OffsetDateTime>,
}

/// Inserts a code.
pub(crate) async fn insert_code(
    conn: &mut PgConnection,
    row: &CodeRow,
    hash: &[u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oidc_authorization_codes (id, code_hash, grant_id, redirect_uri, \
         code_challenge, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(row.id)
    .bind(hash.as_slice())
    .bind(row.grant_id)
    .bind(&row.redirect_uri)
    .bind(&row.code_challenge)
    .bind(row.created_at)
    .bind(row.expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Locks the code with `hash` for the exchange.
pub(crate) async fn lock_code(
    conn: &mut PgConnection,
    hash: &[u8; 32],
) -> Result<Option<CodeRow>, sqlx::Error> {
    sqlx::query_as::<_, CodeRow>(
        "SELECT id, grant_id, redirect_uri, code_challenge, created_at, expires_at, consumed_at \
         FROM oidc_authorization_codes WHERE code_hash = $1 FOR UPDATE",
    )
    .bind(hash.as_slice())
    .fetch_optional(conn)
    .await
}

/// Marks a locked code consumed.
pub(crate) async fn consume_code(
    conn: &mut PgConnection,
    id: Uuid,
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE oidc_authorization_codes SET consumed_at = $2 WHERE id = $1")
        .bind(id)
        .bind(now)
        .execute(conn)
        .await?;
    Ok(())
}

// --- refresh tokens ------------------------------------------------------------

/// A refresh token (hash only).
#[derive(Debug, Clone, FromRow)]
pub struct RefreshRow {
    /// Id.
    pub id: Uuid,
    /// Grant.
    pub grant_id: Uuid,
    /// Idle expiry.
    pub expires_at: OffsetDateTime,
    /// Rotation time.
    pub consumed_at: Option<OffsetDateTime>,
}

/// Inserts a refresh token.
pub(crate) async fn insert_refresh(
    conn: &mut PgConnection,
    id: Uuid,
    grant: Uuid,
    hash: &[u8; 32],
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oidc_refresh_tokens (id, grant_id, token_hash, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(grant)
    .bind(hash.as_slice())
    .bind(now)
    .bind(expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Locks the refresh token with `hash`.
pub(crate) async fn lock_refresh(
    conn: &mut PgConnection,
    hash: &[u8; 32],
) -> Result<Option<RefreshRow>, sqlx::Error> {
    sqlx::query_as::<_, RefreshRow>(
        "SELECT id, grant_id, expires_at, consumed_at FROM oidc_refresh_tokens \
         WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(hash.as_slice())
    .fetch_optional(conn)
    .await
}

/// A refresh token by hash, without locking (introspection, revocation).
pub(crate) async fn find_refresh<'e>(
    executor: impl PgExecutor<'e>,
    hash: &[u8; 32],
) -> Result<Option<RefreshRow>, sqlx::Error> {
    sqlx::query_as::<_, RefreshRow>(
        "SELECT id, grant_id, expires_at, consumed_at FROM oidc_refresh_tokens \
         WHERE token_hash = $1",
    )
    .bind(hash.as_slice())
    .fetch_optional(executor)
    .await
}

/// Marks a refresh token rotated.
pub(crate) async fn consume_refresh(
    conn: &mut PgConnection,
    id: Uuid,
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE oidc_refresh_tokens SET consumed_at = $2 WHERE id = $1")
        .bind(id)
        .bind(now)
        .execute(conn)
        .await?;
    Ok(())
}

// --- access tokens -------------------------------------------------------------

/// Records an issued access token.
pub(crate) async fn insert_access_token(
    conn: &mut PgConnection,
    jti: Uuid,
    grant: Uuid,
    expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO oidc_access_tokens (jti, grant_id, expires_at) VALUES ($1, $2, $3)")
        .bind(jti)
        .bind(grant)
        .bind(expires_at)
        .execute(conn)
        .await?;
    Ok(())
}

/// An access token record.
#[derive(Debug, Clone, FromRow)]
pub struct AccessTokenRow {
    /// The grant.
    pub grant_id: Uuid,
    /// Expiry.
    pub expires_at: OffsetDateTime,
    /// Revocation (RFC 7009).
    pub revoked_at: Option<OffsetDateTime>,
}

/// An access token record by `jti`.
pub(crate) async fn find_access_token<'e>(
    executor: impl PgExecutor<'e>,
    jti: Uuid,
) -> Result<Option<AccessTokenRow>, sqlx::Error> {
    sqlx::query_as::<_, AccessTokenRow>(
        "SELECT grant_id, expires_at, revoked_at FROM oidc_access_tokens WHERE jti = $1",
    )
    .bind(jti)
    .fetch_optional(executor)
    .await
}

/// Revokes one access token.
pub(crate) async fn revoke_access_token(
    conn: &mut PgConnection,
    jti: Uuid,
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE oidc_access_tokens SET revoked_at = $2 WHERE jti = $1 AND revoked_at IS NULL",
    )
    .bind(jti)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

// --- maintenance ---------------------------------------------------------------

/// Deletes up to `limit` expired rows of each table. Grants are deleted
/// once expired or revoked for longer than `retention` (codes and tokens
/// cascade).
pub(crate) async fn purge_expired(
    conn: &mut PgConnection,
    now: OffsetDateTime,
    retention_before: OffsetDateTime,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let mut total = 0;
    for sql in [
        "DELETE FROM oidc_interactions WHERE id IN (SELECT id FROM oidc_interactions \
         WHERE expires_at < $2 LIMIT $3 FOR UPDATE SKIP LOCKED) AND $1 = $1",
        "DELETE FROM oidc_access_tokens WHERE jti IN (SELECT jti FROM oidc_access_tokens \
         WHERE expires_at < $1 LIMIT $3 FOR UPDATE SKIP LOCKED) AND $2 = $2",
        "DELETE FROM oidc_grants WHERE id IN (SELECT id FROM oidc_grants \
         WHERE expires_at < $2 OR revoked_at < $2 LIMIT $3 FOR UPDATE SKIP LOCKED) AND $1 = $1",
    ] {
        let result = sqlx::query(sql)
            .bind(now)
            .bind(retention_before)
            .bind(limit)
            .execute(&mut *conn)
            .await?;
        total += result.rows_affected();
    }
    Ok(total)
}
