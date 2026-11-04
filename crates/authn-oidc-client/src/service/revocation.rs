//! Provider token revocation (K-35, SOC-07, SOC-08, ACC-09).
//!
//! Apple requires apps that offer account deletion to revoke the user's
//! Sign in with Apple tokens. This crate therefore keeps the Apple
//! **refresh token** of an identity — envelope encrypted, AAD =
//! `identities` / `refresh_token_ciphertext` / row id, exactly like the
//! SOC-08 token storage — when `oidc_client.apple.revoke_tokens_on_deletion`
//! is on (default), even with `store_provider_tokens` off.
//!
//! When the identity goes away the token is moved, re-sealed for its new
//! row (AAD = `oauth_token_revocations` / `token_ciphertext` / row id), into
//! a revocation queue **in the same transaction**:
//!
//! * account erasure — [`ProviderTokenErasureHook`], registered by the
//!   server with `AccountService::register_erasure_hook` and run inside
//!   the erasure transaction before the cascade deletes `identities`;
//! * unlinking the identity (`DELETE /v1/me/identities/{id}`).
//!
//! [`OidcClientService::process_token_revocations`] (background job) calls
//! the provider's revocation endpoint (`POST /auth/revoke` with an ES256
//! client secret for the token's client id). A failure never blocks the
//! deletion: the row is retried with exponential backoff
//! ([`revocation_backoff`]) and given up after [`MAX_REVOCATION_ATTEMPTS`];
//! the final outcome — revoked or abandoned — is audited (`identity.unlinked`
//! with `step = provider_token_revocation`, `Actor::System`). The queue row
//! holds no user id and is deleted at the end either way. A token that can
//! no longer be decrypted (KEK removed, corrupt row) is audited and
//! dropped instead of blocking anything.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_account::AccountErasureHook;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::{Actor, AuditSink, Clock, SecurityEvent, SecurityEventKind};
use authn_crypto::envelope::{EnvelopeCipher, EnvelopeContext};
use secrecy::zeroize::Zeroizing;
use sqlx::PgConnection;
use time::OffsetDateTime;

use super::OidcClientService;
use crate::outbound;
use crate::store::{self, IdentityRow, NewRevocation, RevocationRow};

/// Attempts before a revocation is given up (and audited as failed): with
/// the backoff below, about 32 hours of provider outage are bridged.
pub const MAX_REVOCATION_ATTEMPTS: i32 = 14;
/// Wait after the first failed attempt; doubles per attempt.
pub const REVOCATION_BACKOFF_BASE: Duration = Duration::from_secs(60);
/// Longest wait between two attempts.
pub const REVOCATION_BACKOFF_MAX: Duration = Duration::from_secs(6 * 3600);
/// A claimed row is not handed to another instance for this long (covers
/// the provider call's timeout).
const REVOCATION_LEASE: Duration = Duration::from_secs(120);
/// Storage id of Sign in with Apple identities.
const APPLE: &str = "apple";

/// Wait before attempt `attempts + 1` after `attempts` failures (≥ 1).
#[must_use]
pub fn revocation_backoff(attempts: i32) -> Duration {
    let exponent = u32::try_from(attempts.saturating_sub(1))
        .unwrap_or(0)
        .min(16);
    REVOCATION_BACKOFF_BASE
        .saturating_mul(1_u32 << exponent)
        .min(REVOCATION_BACKOFF_MAX)
}

/// What one run of [`OidcClientService::process_token_revocations`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RevocationReport {
    /// Revoked at the provider (or already invalid there).
    pub revoked: u64,
    /// Failed, retried later.
    pub retried: u64,
    /// Failed for the last time (or undecryptable): dropped, audited.
    pub abandoned: u64,
}

fn after(now: OffsetDateTime, wait: Duration) -> OffsetDateTime {
    time::Duration::try_from(wait)
        .ok()
        .and_then(|w| now.checked_add(w))
        .unwrap_or(now)
}

fn revocation_event(now: OffsetDateTime, provider: &str) -> SecurityEvent {
    SecurityEvent::new(SecurityEventKind::IdentityUnlinked, now)
        .with_actor(Actor::System)
        .with_meta("step", "provider_token_revocation")
        .with_meta("provider", provider.to_owned())
}

/// Moves the stored (Apple) refresh token of `row` into the revocation
/// queue, re-sealed for the queue row, in the caller's transaction.
/// Returns whether a revocation was queued. Soft failures (the token
/// cannot be decrypted) are audited and skipped; only database errors fail.
pub(crate) async fn queue_identity_revocation(
    conn: &mut PgConnection,
    envelopes: &EnvelopeCipher,
    audit: &dyn AuditSink,
    now: OffsetDateTime,
    user: UserId,
    row: &IdentityRow,
) -> Result<bool, AuthError> {
    let (Some(sealed), Some(client_id)) = (
        row.refresh_token_ciphertext.as_deref(),
        row.token_client_id.as_deref(),
    ) else {
        return Ok(false);
    };
    if row.provider != APPLE {
        return Ok(false);
    }
    let id = sqlx::types::Uuid::now_v7();
    let resealed = async {
        let token = envelopes
            .open(
                sealed,
                &EnvelopeContext::new("identities", "refresh_token_ciphertext", row.id)?,
            )
            .await?;
        envelopes
            .seal(
                token.expose(),
                &EnvelopeContext::new("oauth_token_revocations", "token_ciphertext", id)?,
            )
            .await
    }
    .await;
    let Ok(resealed) = resealed else {
        {
            tracing::warn!(identity = %row.id, "stored provider token unreadable; not revoked");
            crate::metrics::token_revocation(&row.provider, "unreadable");
            let event = revocation_event(now, &row.provider)
                .with_subject(user)
                .with_resource("identity", row.id)
                .failed("provider_token_unreadable");
            audit.record_in_tx(&mut *conn, event).await?;
            return Ok(false);
        }
    };
    store::enqueue_revocation(
        &mut *conn,
        &NewRevocation {
            id,
            provider: &row.provider,
            client_id,
            token_ciphertext: &resealed,
            token_type_hint: "refresh_token",
            now,
        },
    )
    .await?;
    Ok(true)
}

/// Queues the revocation of every stored Apple token of a user who is
/// being erased (ACC-09). Register with
/// `AccountService::register_erasure_hook(Arc::new(oidc.erasure_hook()))`.
/// Holds only the envelope cipher, the audit sink and the clock (no
/// reference back to the account service: no cycle).
#[derive(Clone)]
pub struct ProviderTokenErasureHook {
    envelopes: EnvelopeCipher,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ProviderTokenErasureHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderTokenErasureHook")
    }
}

#[async_trait]
impl AccountErasureHook for ProviderTokenErasureHook {
    async fn before_erasure_in_tx(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<(), AuthError> {
        let now = self.clock.now();
        for row in store::identities_of(&mut *conn, user).await? {
            queue_identity_revocation(
                &mut *conn,
                &self.envelopes,
                self.audit.as_ref(),
                now,
                user,
                &row,
            )
            .await?;
        }
        Ok(())
    }
}

/// Result of one provider call.
enum Attempt {
    /// Revoked (or the provider no longer knows the token).
    Done(&'static str),
    /// Try again later.
    Retry,
    /// Can never succeed (undecryptable): drop now.
    Abandon,
}

impl OidcClientService {
    /// The erasure hook of this crate (K-35); see [`ProviderTokenErasureHook`].
    #[must_use]
    pub fn erasure_hook(&self) -> ProviderTokenErasureHook {
        ProviderTokenErasureHook {
            envelopes: self.deps().envelopes.clone(),
            audit: Arc::clone(&self.deps().audit),
            clock: Arc::clone(&self.deps().clock),
        }
    }

    /// Calls the provider's revocation endpoint for up to `limit` due
    /// queued tokens (OPS-06 background job, e.g. every minute; safe on
    /// several instances: each row is leased by one `UPDATE … SKIP LOCKED`
    /// and no database connection is held during the HTTP call).
    pub async fn process_token_revocations(
        &self,
        limit: u32,
    ) -> Result<RevocationReport, AuthError> {
        let mut report = RevocationReport::default();
        for _ in 0..limit {
            let now = self.now();
            let Some(row) =
                store::claim_revocation(&self.deps().pool, now, after(now, REVOCATION_LEASE))
                    .await?
            else {
                break;
            };
            let attempt = self.revoke_once(&row).await;
            let now = self.now();
            match attempt {
                Attempt::Done(outcome) => {
                    store::delete_revocation(&self.deps().pool, row.id).await?;
                    crate::metrics::token_revocation(&row.provider, outcome);
                    self.audit_revocation(
                        revocation_event(now, &row.provider)
                            .with_meta("outcome", outcome)
                            .with_meta("attempts", row.attempts),
                    )
                    .await;
                    report.revoked += 1;
                }
                Attempt::Retry if row.attempts < MAX_REVOCATION_ATTEMPTS => {
                    let next = after(now, revocation_backoff(row.attempts));
                    store::reschedule_revocation(&self.deps().pool, row.id, next).await?;
                    crate::metrics::token_revocation(&row.provider, "retry");
                    report.retried += 1;
                }
                Attempt::Retry | Attempt::Abandon => {
                    store::delete_revocation(&self.deps().pool, row.id).await?;
                    crate::metrics::token_revocation(&row.provider, "abandoned");
                    tracing::error!(
                        provider = row.provider.as_str(),
                        attempts = row.attempts,
                        "provider token revocation given up"
                    );
                    self.audit_revocation(
                        revocation_event(now, &row.provider)
                            .with_meta("attempts", row.attempts)
                            .failed("provider_token_revocation_failed"),
                    )
                    .await;
                    report.abandoned += 1;
                }
            }
        }
        Ok(report)
    }

    async fn audit_revocation(&self, event: SecurityEvent) {
        if let Err(err) = self.deps().audit.record(event).await {
            tracing::warn!(
                code = err.code().code(),
                "failed to audit a provider token revocation"
            );
        }
    }

    async fn revoke_once(&self, row: &RevocationRow) -> Attempt {
        let token =
            match EnvelopeContext::new("oauth_token_revocations", "token_ciphertext", row.id) {
                Ok(context) => {
                    self.deps()
                        .envelopes
                        .open(&row.token_ciphertext, &context)
                        .await
                }
                Err(e) => Err(e),
            };
        let Ok(token) = token else {
            tracing::warn!(provider = row.provider.as_str(), "queued token unreadable");
            return Attempt::Abandon;
        };
        let Ok(token) = std::str::from_utf8(token.expose()).map(|t| Zeroizing::new(t.to_owned()))
        else {
            return Attempt::Abandon;
        };
        let Some(provider) = self.provider_by_storage_id(&row.provider).cloned() else {
            tracing::warn!(
                provider = row.provider.as_str(),
                "token revocation for a provider that is not configured"
            );
            return Attempt::Retry;
        };
        let Ok(endpoints) = self.endpoints(&provider).await else {
            return Attempt::Retry;
        };
        let Some(url) = endpoints.revocation.clone() else {
            return Attempt::Retry;
        };
        let Ok(secret) = self.client_secret(&provider, &row.client_id) else {
            return Attempt::Retry;
        };
        let form: Vec<(&str, &str)> = vec![
            ("client_id", row.client_id.as_str()),
            ("client_secret", secret.expose()),
            ("token", token.as_str()),
            ("token_type_hint", row.token_type_hint.as_str()),
        ];
        let Ok(response) = outbound::post_form(
            self.deps().http.as_ref(),
            url,
            endpoints.target,
            &form,
            None,
        )
        .await
        else {
            return Attempt::Retry;
        };
        if response.status.is_success() {
            return Attempt::Done("revoked");
        }
        // RFC 7009 / Apple: `invalid_grant` = the token is not (or no
        // longer) valid — nothing left to revoke.
        let invalid_grant = response.status.as_u16() == 400
            && serde_json::from_slice::<serde_json::Value>(&response.body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
                .is_some_and(|e| e == "invalid_grant");
        if invalid_grant {
            return Attempt::Done("already_invalid");
        }
        tracing::warn!(
            provider = row.provider.as_str(),
            status = response.status.as_u16(),
            "provider token revocation failed"
        );
        Attempt::Retry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_07_revocation_backoff_is_exponential_and_bounded() {
        assert_eq!(revocation_backoff(1), Duration::from_secs(60));
        assert_eq!(revocation_backoff(2), Duration::from_secs(120));
        assert_eq!(revocation_backoff(9), Duration::from_secs(60 * 256));
        assert_eq!(revocation_backoff(10), REVOCATION_BACKOFF_MAX);
        assert_eq!(revocation_backoff(i32::MAX), REVOCATION_BACKOFF_MAX);
        assert_eq!(revocation_backoff(0), REVOCATION_BACKOFF_BASE);
    }
}
