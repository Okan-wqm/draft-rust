//! Cleanup job (OPS-06): ended sessions, old challenges and grace-window
//! successors. Safe on several instances (`FOR UPDATE SKIP LOCKED`).

use std::time::Duration;

use authn_core::error::AuthError;

use super::SessionService;
use crate::store::{challenges, refresh, sessions};

/// How long ended sessions stay (session list history, investigations).
pub const ENDED_SESSION_RETENTION: Duration = Duration::from_secs(30 * 86_400);
/// How long ended challenges stay.
pub const CHALLENGE_RETENTION: Duration = Duration::from_secs(86_400);

/// What [`SessionService::purge_expired`] removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Sessions (with their refresh-token families) deleted.
    pub sessions: u64,
    /// Challenges deleted.
    pub challenges: u64,
    /// Sealed grace-window successors wiped.
    pub successors: u64,
}

impl SessionService {
    /// Deletes up to `limit` sessions that ended more than 30 days ago,
    /// challenges that ended more than a day ago, and wipes sealed refresh
    /// successors whose grace window is over.
    pub async fn purge_expired(&self, limit: i64) -> Result<PurgeReport, AuthError> {
        let now = self.now();
        let grace = self.settings().session.refresh_reuse_grace;
        let mut tx = self.begin().await?;
        let successors = refresh::wipe_successors(
            &mut tx,
            now - time::Duration::try_from(grace).unwrap_or_default(),
        )
        .await?;
        let session_cutoff =
            now - time::Duration::try_from(ENDED_SESSION_RETENTION).unwrap_or_default();
        let sessions = sessions::purge_ended(&mut tx, session_cutoff, limit).await?;
        let challenge_cutoff =
            now - time::Duration::try_from(CHALLENGE_RETENTION).unwrap_or_default();
        let challenges = challenges::purge(&mut tx, challenge_cutoff, limit).await?;
        authn_store::commit(tx).await?;
        Ok(PurgeReport {
            sessions,
            challenges,
            successors,
        })
    }
}
