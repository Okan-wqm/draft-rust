//! `webauthn_user_handles` (PKY-03): one random, e-mail independent user
//! handle per user.
//!
//! The handle is what authenticators store as `user.id` and return as
//! `userHandle` in discoverable logins. It is 16 bytes from the operating
//! system CSPRNG — never derived from the user id or e-mail — so a passkey
//! reveals nothing about the account and handles cannot be enumerated.

use authn_core::error::AuthError;
use authn_core::id::UserId;
use sqlx::{PgConnection, PgExecutor};
use time::OffsetDateTime;

/// Length of generated handles (`webauthn-rs` uses a 16-byte UUID).
pub(crate) const HANDLE_LEN: usize = 16;

/// Returns the user's handle, creating it on first use. Concurrent first
/// uses agree on one handle (`ON CONFLICT DO NOTHING` + re-read).
pub(crate) async fn get_or_create(
    conn: &mut PgConnection,
    user: UserId,
    now: OffsetDateTime,
) -> Result<[u8; HANDLE_LEN], AuthError> {
    if let Some(existing) = find(&mut *conn, user).await? {
        return Ok(existing);
    }
    let candidate = authn_crypto::random::bytes::<HANDLE_LEN>()?;
    sqlx::query(
        "INSERT INTO webauthn_user_handles (user_id, user_handle, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user)
    .bind(candidate.as_slice())
    .bind(now)
    .execute(&mut *conn)
    .await
    .map_err(authn_store::StoreError::from)?;
    find(&mut *conn, user)
        .await?
        .ok_or_else(|| AuthError::internal("user handle missing after insert"))
}

/// The user's handle, if one was created.
pub(crate) async fn find<'e>(
    executor: impl PgExecutor<'e>,
    user: UserId,
) -> Result<Option<[u8; HANDLE_LEN]>, AuthError> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT user_handle FROM webauthn_user_handles WHERE user_id = $1")
            .bind(user)
            .fetch_optional(executor)
            .await?;
    row.map(|(bytes,)| {
        <[u8; HANDLE_LEN]>::try_from(bytes.as_slice())
            .map_err(|_| AuthError::internal("stored user handle has an unexpected length"))
    })
    .transpose()
}

/// The user owning a handle (discoverable login).
pub(crate) async fn find_user<'e>(
    executor: impl PgExecutor<'e>,
    handle: &[u8],
) -> Result<Option<UserId>, AuthError> {
    let row: Option<(UserId,)> =
        sqlx::query_as("SELECT user_id FROM webauthn_user_handles WHERE user_handle = $1")
            .bind(handle)
            .fetch_optional(executor)
            .await?;
    Ok(row.map(|(user,)| user))
}
