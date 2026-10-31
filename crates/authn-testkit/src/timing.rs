//! Timing comparison for account-enumeration tests (TST-02, CRY-05, ACC-02,
//! PWD-07).
//!
//! Wall-clock measurements are noisy, so the helper interleaves the two
//! operations (ABAB / BABA), discards warm-up runs, compares medians and
//! asserts a *relative* tolerance. Use generous tolerances (e.g. 0.3) and
//! enough samples (≥ 20); the goal is to catch gross differences such as
//! skipping the Argon2 computation for unknown users.

use std::future::Future;
use std::time::{Duration, Instant};

/// Result of [`compare_timings`].
#[derive(Debug, Clone)]
pub struct TimingReport {
    /// Samples per side.
    pub samples: usize,
    /// Median duration of operation A.
    pub median_a: Duration,
    /// Median duration of operation B.
    pub median_b: Duration,
}

impl TimingReport {
    /// `|median_a - median_b| / max(median_a, median_b)` in `0.0..=1.0`.
    #[must_use]
    pub fn relative_difference(&self) -> f64 {
        let a = self.median_a.as_secs_f64();
        let b = self.median_b.as_secs_f64();
        let max = a.max(b);
        if max == 0.0 { 0.0 } else { (a - b).abs() / max }
    }

    /// Panics unless the medians differ by at most `tolerance` (relative).
    pub fn assert_indistinguishable(&self, tolerance: f64) {
        let diff = self.relative_difference();
        assert!(
            diff <= tolerance,
            "timing difference {:.1}% exceeds {:.1}% (A median {:?}, B median {:?}, {} samples)",
            diff * 100.0,
            tolerance * 100.0,
            self.median_a,
            self.median_b,
            self.samples
        );
    }
}

/// Measures two async operations alternately and reports their medians.
pub async fn compare_timings<FA, FutA, FB, FutB>(
    samples: usize,
    mut a: FA,
    mut b: FB,
) -> TimingReport
where
    FA: FnMut() -> FutA,
    FutA: Future<Output = ()>,
    FB: FnMut() -> FutB,
    FutB: Future<Output = ()>,
{
    assert!(samples >= 5, "use at least 5 samples");
    for _ in 0..3 {
        a().await;
        b().await;
    }
    let mut times_a = Vec::with_capacity(samples);
    let mut times_b = Vec::with_capacity(samples);
    for i in 0..samples {
        if i % 2 == 0 {
            times_a.push(measure(&mut a).await);
            times_b.push(measure(&mut b).await);
        } else {
            times_b.push(measure(&mut b).await);
            times_a.push(measure(&mut a).await);
        }
    }
    TimingReport {
        samples,
        median_a: median(&mut times_a),
        median_b: median(&mut times_b),
    }
}

async fn measure<F, Fut>(f: &mut F) -> Duration
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let start = Instant::now();
    f().await;
    start.elapsed()
}

fn median(values: &mut [Duration]) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tst_02_equal_operations_are_indistinguishable() {
        let report = compare_timings(
            11,
            || tokio::time::sleep(Duration::from_millis(5)),
            || tokio::time::sleep(Duration::from_millis(5)),
        )
        .await;
        report.assert_indistinguishable(0.8);
    }

    #[tokio::test]
    async fn tst_02_gross_difference_is_detected() {
        let report = compare_timings(
            7,
            || tokio::time::sleep(Duration::from_millis(1)),
            || tokio::time::sleep(Duration::from_millis(40)),
        )
        .await;
        assert!(report.relative_difference() > 0.5, "{report:?}");
        let result = std::panic::catch_unwind(|| report.assert_indistinguishable(0.3));
        assert!(result.is_err());
    }
}
