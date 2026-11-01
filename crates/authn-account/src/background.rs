//! Bounded background execution of the account-specific part of
//! enumeration-sensitive requests (ACC-02, ACC-04, ACC-07).
//!
//! Registration, "resend verification" and e-mail change requests answer
//! the caller **before** looking at whether an address is registered: the
//! synchronous part (rate limits, CAPTCHA, validation, password policy and
//! the Argon2 hash) is identical for every address, and everything that
//! depends on the account runs here. The HTTP response therefore cannot
//! differ in status, body or timing between existing and new addresses.
//!
//! Jobs are tracked (graceful shutdown waits for them, OPS-07), at most
//! [`MAX_CONCURRENT_JOBS`] run at once and at most [`MAX_PENDING_JOBS`] may
//! wait. When the queue is full the request fails with
//! `service_unavailable` — a decision taken before any account lookup, so it
//! reveals nothing either.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use authn_core::error::{AuthError, codes};
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;

/// Jobs executing concurrently.
pub const MAX_CONCURRENT_JOBS: usize = 16;
/// Jobs admitted (running + waiting) before new requests are refused.
pub const MAX_PENDING_JOBS: usize = 4096;

/// The job runner. Cheap to clone.
#[derive(Clone)]
pub(crate) struct BackgroundJobs {
    tracker: TaskTracker,
    permits: Arc<Semaphore>,
    pending: Arc<AtomicUsize>,
}

impl BackgroundJobs {
    pub(crate) fn new() -> Self {
        Self {
            tracker: TaskTracker::new(),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_JOBS)),
            pending: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Admits and starts a job; `service_unavailable` when the queue is
    /// full. Errors of the job are logged (they cannot reach the caller).
    pub(crate) fn spawn<F>(&self, name: &'static str, job: F) -> Result<(), AuthError>
    where
        F: Future<Output = Result<(), AuthError>> + Send + 'static,
    {
        let admitted = self
            .pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_PENDING_JOBS).then_some(n + 1)
            })
            .is_ok();
        if !admitted {
            tracing::warn!(job = name, "account job queue full; request refused");
            return Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE));
        }
        let permits = Arc::clone(&self.permits);
        // Released on drop: also when the job panics or is cancelled, so a
        // failing job can never leak a slot and end in a permanent `503`.
        let slot = PendingSlot(Arc::clone(&self.pending));
        self.tracker.spawn(async move {
            let _slot = slot;
            let result = match permits.acquire_owned().await {
                Ok(_permit) => job.await,
                Err(_) => Err(AuthError::internal("job semaphore closed")),
            };
            if let Err(err) = result {
                tracing::error!(job = name, error = %err, "account background job failed");
            }
        });
        Ok(())
    }

    /// Waits until every job started so far has finished.
    pub(crate) async fn drain(&self) {
        self.tracker.close();
        self.tracker.wait().await;
        self.tracker.reopen();
    }

    /// Jobs admitted and not finished.
    pub(crate) fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }
}

/// One admitted job; gives its slot back when dropped.
struct PendingSlot(Arc<AtomicUsize>);

impl Drop for PendingSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acc_02_panicking_job_releases_its_queue_slot() {
        let jobs = BackgroundJobs::new();
        jobs.spawn("panics", async {
            if jobs_should_panic() {
                panic!("job failure");
            }
            Ok(())
        })
        .unwrap();
        jobs.spawn("fails", async { Err(AuthError::internal("job failure")) })
            .unwrap();
        jobs.spawn("succeeds", async { Ok(()) }).unwrap();
        jobs.drain().await;
        assert_eq!(jobs.pending(), 0, "every slot is returned");
    }

    fn jobs_should_panic() -> bool {
        true
    }

    #[tokio::test]
    async fn acc_02_full_queue_is_refused_before_any_work() {
        let jobs = BackgroundJobs::new();
        jobs.pending.store(MAX_PENDING_JOBS, Ordering::Release);
        let err = jobs.spawn("refused", async { Ok(()) }).unwrap_err();
        assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
        assert_eq!(jobs.pending(), MAX_PENDING_JOBS);
    }
}
