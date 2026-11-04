//! Background maintenance jobs (OPS-06). `authn-server` schedules them;
//! each processes at most `max` items per call, one short transaction per
//! item, and is safe on several instances (`FOR UPDATE SKIP LOCKED`).
//!
//! | Job | Requirement |
//! |-----|-------------|
//! | [`AccountService::purge_unverified_accounts`] | ACC-05 (registrations and never-verified accounts, default after 7 days) |
//! | [`AccountService::purge_due_deletions`] | ACC-09 (end of grace period) |
//! | [`AccountService::release_expired_locks`] | ACC-06 (`locked` → `active`) |
//! | [`AccountService::purge_expired_reservations`] | ACC-07 (address reservations) |

use authn_core::domain::AccountStatus;
use authn_core::error::AuthError;
use authn_core::ports::Actor;
use authn_store::{UserClaim, UserRepository};

use super::AccountService;
use crate::lifecycle::{StatusChange, apply_transition};
use crate::registration_store::RegistrationRepository;
use crate::repo::{ReservationRepository, SharedReads};

impl AccountService {
    /// ACC-05: deletes expired registrations (at most `max`), then accounts
    /// that never verified their address within
    /// `account.unverified_purge_after` and have no live registration left.
    /// Returns the number of accounts deleted. Accounts that are the only
    /// owner of an organization are kept (and logged) — an organization must
    /// never lose its last owner.
    pub async fn purge_unverified_accounts(&self, max: u32) -> Result<u64, AuthError> {
        {
            let mut conn = self.pool().acquire().await?;
            RegistrationRepository::delete_expired(&mut conn, self.now(), max).await?;
        }
        let mut purged = 0;
        let mut skip = Vec::new();
        let ttl = time::Duration::try_from(self.config().unverified_purge_after)
            .map_err(|_| AuthError::internal("account.unverified_purge_after out of range"))?;
        for _ in 0..max {
            let now = self.now();
            let Some(created_before) = now.checked_sub(ttl) else {
                break;
            };
            let mut tx = self.begin().await?;
            let Some(user_id) =
                SharedReads::claim_expired_unverified(tx.conn(), created_before, now, &skip)
                    .await?
            else {
                break;
            };
            let Some(user) = UserRepository::lock_for_update(tx.conn(), user_id).await? else {
                continue;
            };
            if !self
                .deps()
                .ownership
                .sole_owner_organizations(tx.conn(), user.id)
                .await?
                .is_empty()
            {
                tracing::warn!(user_id = %user.id, "unverified account kept: last owner of an organization");
                skip.push(user.id.as_uuid());
                continue;
            }
            apply_transition(
                &mut tx,
                &user,
                &StatusChange::new(AccountStatus::Deleted, "unverified_expired", Actor::System),
                false,
                now,
                None,
            )
            .await?;
            self.finish_erasure(tx, user.id, "unverified_expired", now)
                .await?;
            purged += 1;
        }
        Ok(purged)
    }

    /// ACC-06: ends temporary locks whose `locked_until` has passed
    /// (`locked` → `active`, audited). Returns the number unlocked.
    pub async fn release_expired_locks(&self, max: u32) -> Result<u64, AuthError> {
        let mut released = 0;
        let mut skip = Vec::new();
        for _ in 0..max {
            let now = self.now();
            let mut tx = self.begin().await?;
            // Row-locked by the claim itself (`FOR UPDATE SKIP LOCKED`).
            let Some(user) =
                UserRepository::claim_next(tx.conn(), UserClaim::LockExpiredAt(now), &skip).await?
            else {
                break;
            };
            let change = StatusChange::new(AccountStatus::Active, "lock_expired", Actor::System);
            let verified = user.email_verified_at.is_some();
            match apply_transition(&mut tx, &user, &change, verified, now, None).await {
                Ok(_) => {
                    tx.commit().await?;
                    released += 1;
                }
                Err(err) => {
                    // Only reachable with inconsistent data (locked without
                    // a verified address); leave it for an administrator.
                    tracing::error!(user_id = %user.id, error = %err, "expired lock not released");
                    skip.push(user.id);
                }
            }
        }
        Ok(released)
    }

    /// ACC-07: deletes address reservations whose revert period ended.
    pub async fn purge_expired_reservations(&self, max: u32) -> Result<u64, AuthError> {
        let mut conn = self.pool().acquire().await?;
        Ok(ReservationRepository::delete_expired(&mut conn, self.now(), max).await?)
    }
}
