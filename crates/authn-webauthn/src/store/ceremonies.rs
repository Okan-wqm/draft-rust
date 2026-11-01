//! `webauthn_ceremonies` (PKY-01): server-side ceremony state.
//!
//! * The `webauthn-rs` state (it contains the challenge) never leaves the
//!   server; the client only receives the ceremony id (and, for
//!   authentication, a 256-bit binding token whose SHA-256 is stored).
//! * A ceremony is consumed by exactly one atomic
//!   `UPDATE … WHERE consumed_at IS NULL AND expires_at > $now … RETURNING`
//!   that also requires every binding (kind, purpose, user, session, login
//!   challenge, binding hash) to match. Unknown, expired, replayed and
//!   swapped ceremonies are therefore indistinguishable `None`s, and two
//!   concurrent finishes cannot both obtain the state.
//! * Consumption is committed on its own, *before* the response is
//!   verified: a failed verification burns the challenge (no retries
//!   against the same challenge).

use authn_core::error::AuthError;
use authn_core::id::{CeremonyId, ChallengeId, SessionId, UserId};
use sqlx::PgConnection;
use sqlx::types::Json;
use time::OffsetDateTime;

/// `webauthn_ceremonies.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CeremonyKind {
    Registration,
    Authentication,
    DiscoverableAuthentication,
}

impl CeremonyKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Authentication => "authentication",
            Self::DiscoverableAuthentication => "discoverable_authentication",
        }
    }
}

/// `webauthn_ceremonies.purpose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CeremonyPurpose {
    Register,
    Login,
    SecondFactor,
    StepUp,
}

impl CeremonyPurpose {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Login => "login",
            Self::SecondFactor => "second_factor",
            Self::StepUp => "step_up",
        }
    }
}

/// Everything a ceremony is bound to. The same value is used to create and
/// to consume a ceremony; any difference makes consumption fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CeremonyBinding {
    pub(crate) kind: CeremonyKind,
    pub(crate) purpose: CeremonyPurpose,
    pub(crate) user_id: Option<UserId>,
    pub(crate) session_id: Option<SessionId>,
    pub(crate) challenge_id: Option<ChallengeId>,
    /// SHA-256 of the client binding token (authentication ceremonies).
    pub(crate) binding_hash: Option<[u8; 32]>,
}

/// Stores a new ceremony.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    id: CeremonyId,
    binding: &CeremonyBinding,
    state: serde_json::Value,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), authn_store::StoreError> {
    sqlx::query(
        "INSERT INTO webauthn_ceremonies (id, kind, purpose, user_id, session_id, challenge_id, \
         state, binding_hash, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(binding.kind.as_str())
    .bind(binding.purpose.as_str())
    .bind(binding.user_id)
    .bind(binding.session_id)
    .bind(binding.challenge_id)
    .bind(Json(state))
    .bind(binding.binding_hash.as_ref().map(<[u8; 32]>::as_slice))
    .bind(created_at)
    .bind(expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Atomically consumes a live ceremony with exactly this binding and
/// returns its state; `None` for unknown, expired, consumed or differently
/// bound ceremonies.
pub(crate) async fn consume(
    conn: &mut PgConnection,
    id: CeremonyId,
    binding: &CeremonyBinding,
    now: OffsetDateTime,
) -> Result<Option<serde_json::Value>, AuthError> {
    let row: Option<(Json<serde_json::Value>,)> = sqlx::query_as(
        "UPDATE webauthn_ceremonies SET consumed_at = $9 \
         WHERE id = $1 AND kind = $2 AND purpose = $3 \
           AND user_id IS NOT DISTINCT FROM $4 \
           AND session_id IS NOT DISTINCT FROM $5 \
           AND challenge_id IS NOT DISTINCT FROM $6 \
           AND binding_hash IS NOT DISTINCT FROM $7 \
           AND consumed_at IS NULL AND expires_at > $8 \
         RETURNING state",
    )
    .bind(id)
    .bind(binding.kind.as_str())
    .bind(binding.purpose.as_str())
    .bind(binding.user_id)
    .bind(binding.session_id)
    .bind(binding.challenge_id)
    .bind(binding.binding_hash.as_ref().map(<[u8; 32]>::as_slice))
    .bind(now)
    .bind(now)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(Json(state),)| state))
}

/// Deletes ceremonies that expired before `before` (consumed or not).
pub(crate) async fn purge_expired(
    conn: &mut PgConnection,
    before: OffsetDateTime,
    batch: i64,
) -> Result<u64, AuthError> {
    let result = sqlx::query(
        "DELETE FROM webauthn_ceremonies WHERE id IN \
         (SELECT id FROM webauthn_ceremonies WHERE expires_at < $1 LIMIT $2 \
          FOR UPDATE SKIP LOCKED)",
    )
    .bind(before)
    .bind(batch)
    .execute(conn)
    .await?;
    Ok(result.rows_affected())
}
