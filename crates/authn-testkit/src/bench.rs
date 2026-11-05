//! Measurement helpers for the performance programme (K-70): latency
//! statistics, a dependency-free micro-benchmark runner and an SQL
//! statement counter.
//!
//! * [`Stats`] — latency samples → mean / p50 / p95 / p99 / max.
//! * [`bench_sync`], [`bench_async`] — warm-up, then timed iterations;
//!   used by the `harness = false` bench targets (`cargo bench`). With
//!   [`BenchMode::Smoke`] (any run without `--bench`, i.e. `cargo test
//!   --benches`) each case runs a handful of times only: the target then
//!   proves that every hot path still works, it does not measure.
//! * [`count_queries`] — counts the SQL statements sqlx executes while a
//!   future runs (the `sqlx::query` tracing events of the future's own
//!   task). A structural, noise-free regression guard: "an authenticated
//!   `GET` costs N round trips" does not depend on the machine.
//!
//! No external benchmarking crate is used on purpose: the harness needs no
//! new dependency (LIC-01) and the same statistics serve the load test.

use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// Latency samples.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    samples: Vec<Duration>,
}

/// Summary of [`Stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Number of samples.
    pub count: usize,
    /// Arithmetic mean.
    pub mean: Duration,
    /// Smallest sample.
    pub min: Duration,
    /// Median.
    pub p50: Duration,
    /// 95th percentile (nearest rank).
    pub p95: Duration,
    /// 99th percentile (nearest rank).
    pub p99: Duration,
    /// Largest sample.
    pub max: Duration,
}

impl Stats {
    /// Empty statistics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a sample.
    pub fn push(&mut self, sample: Duration) {
        self.samples.push(sample);
    }

    /// Merges another set of samples.
    pub fn extend(&mut self, other: Stats) {
        self.samples.extend(other.samples);
    }

    /// Number of samples.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether there are no samples.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The summary; `None` without samples.
    #[must_use]
    pub fn summary(&self) -> Option<Summary> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let total: Duration = sorted.iter().sum();
        let count = sorted.len();
        Some(Summary {
            count,
            mean: total / u32::try_from(count).unwrap_or(u32::MAX),
            min: sorted[0],
            p50: percentile(&sorted, 50),
            p95: percentile(&sorted, 95),
            p99: percentile(&sorted, 99),
            max: sorted[count - 1],
        })
    }
}

/// Nearest-rank percentile (`percent` in 1..=100) of an ascending,
/// non-empty slice: the smallest sample with at least `percent` % of the
/// samples at or below it (integer arithmetic, no float rounding).
#[must_use]
pub fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    assert!(!sorted.is_empty(), "percentile of no samples");
    let rank = (percent.min(100) * sorted.len()).div_ceil(100);
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Formats a duration with a unit suited to its size (`812ns`, `41.3µs`,
/// `2.41ms`, `1.20s`).
#[must_use]
pub fn fmt_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{:.1}µs", ns as f64 / 1e3)
    } else if ns < 1_000_000_000 {
        format!("{:.2}ms", ns as f64 / 1e6)
    } else {
        format!("{:.2}s", ns as f64 / 1e9)
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "n={:<6} mean={:>9} p50={:>9} p95={:>9} p99={:>9} max={:>9}",
            self.count,
            fmt_duration(self.mean),
            fmt_duration(self.p50),
            fmt_duration(self.p95),
            fmt_duration(self.p99),
            fmt_duration(self.max),
        )
    }
}

/// How a bench target runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchMode {
    /// `cargo bench`: warm-up plus the requested iterations.
    Measure,
    /// `cargo test --benches` (no `--bench` argument): two iterations per
    /// case, nothing printed but the case names — a functional smoke test.
    Smoke,
}

impl BenchMode {
    /// [`BenchMode::Measure`] when the process got `--bench` (what `cargo
    /// bench` passes), [`BenchMode::Smoke`] otherwise.
    #[must_use]
    pub fn from_args() -> Self {
        if std::env::args().any(|a| a == "--bench") {
            Self::Measure
        } else {
            Self::Smoke
        }
    }

    /// The iteration count: `requested` (overridable with
    /// `AUTHN_BENCH_ITERS`) when measuring, 2 for a smoke run.
    #[must_use]
    pub fn iterations(self, requested: usize) -> usize {
        match self {
            Self::Smoke => 2,
            Self::Measure => std::env::var("AUTHN_BENCH_ITERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(requested)
                .max(1),
        }
    }

    /// Warm-up iterations (none for a smoke run).
    #[must_use]
    pub fn warmup(self, iterations: usize) -> usize {
        match self {
            Self::Smoke => 0,
            Self::Measure => (iterations / 10).clamp(1, 200),
        }
    }

    /// Optional case-name filter: the first free argument (`cargo bench --
    /// jwt`).
    #[must_use]
    pub fn filter() -> Option<String> {
        std::env::args()
            .skip(1)
            .find(|a| !a.starts_with('-'))
            .filter(|a| !a.is_empty())
    }
}

/// Whether a case named `name` runs under the command-line filter.
#[must_use]
pub fn selected(name: &str) -> bool {
    BenchMode::filter().is_none_or(|f| name.contains(&f))
}

// Printing the results is the purpose of a bench target.
#[allow(clippy::print_stdout)]
fn report(name: &str, mode: BenchMode, stats: &Stats) -> Option<Summary> {
    let summary = stats.summary()?;
    match mode {
        BenchMode::Measure => println!("{name:<44} {summary}"),
        BenchMode::Smoke => println!("{name:<44} ok (smoke)"),
    }
    Some(summary)
}

/// Runs `f` `iterations` times after a warm-up and prints the summary.
/// `None` when the case is filtered out.
pub fn bench_sync<T>(
    name: &str,
    mode: BenchMode,
    iterations: usize,
    mut f: impl FnMut() -> T,
) -> Option<Summary> {
    if !selected(name) {
        return None;
    }
    let iterations = mode.iterations(iterations);
    for _ in 0..mode.warmup(iterations) {
        std::hint::black_box(f());
    }
    let mut stats = Stats::new();
    for _ in 0..iterations {
        let start = Instant::now();
        std::hint::black_box(f());
        stats.push(start.elapsed());
    }
    report(name, mode, &stats)
}

/// [`bench_sync`] for an async operation; `f` builds a fresh future per
/// iteration (only its `.await` is timed).
pub async fn bench_async<T, F, Fut>(
    name: &str,
    mode: BenchMode,
    iterations: usize,
    mut f: F,
) -> Option<Summary>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = T>,
{
    if !selected(name) {
        return None;
    }
    let iterations = mode.iterations(iterations);
    for _ in 0..mode.warmup(iterations) {
        std::hint::black_box(f().await);
    }
    let mut stats = Stats::new();
    for _ in 0..iterations {
        let fut = f();
        let start = Instant::now();
        std::hint::black_box(fut.await);
        stats.push(start.elapsed());
    }
    report(name, mode, &stats)
}

/// Prints an already collected set of samples like the runners do.
pub fn print_stats(name: &str, mode: BenchMode, stats: &Stats) -> Option<Summary> {
    report(name, mode, stats)
}

/// The SQL statements a future executed, in order (sqlx's one-line
/// summaries, e.g. `SELECT s.id, s.user_id, …`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryLog {
    /// Statement summaries.
    pub statements: Vec<String>,
}

impl QueryLog {
    /// Number of statements (round trips to PostgreSQL).
    #[must_use]
    pub fn count(&self) -> usize {
        self.statements.len()
    }

    /// Statements that are not transaction control (`BEGIN`, `COMMIT`,
    /// `ROLLBACK`, savepoints).
    #[must_use]
    pub fn data_statements(&self) -> usize {
        self.statements
            .iter()
            .filter(|s| !is_transaction_control(s))
            .count()
    }
}

impl fmt::Display for QueryLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.statements.iter().enumerate() {
            writeln!(f, "  {:>2}. {s}", i + 1)?;
        }
        Ok(())
    }
}

fn is_transaction_control(statement: &str) -> bool {
    let upper = statement.trim_start().to_ascii_uppercase();
    ["BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE"]
        .iter()
        .any(|kw| upper.starts_with(kw))
}

/// Runs `fut` and returns its output with the SQL statements sqlx executed
/// **on that future's task** (spawned tasks are not followed). The counter
/// is installed as the future's own `tracing` dispatcher, so it works on
/// any runtime flavour and does not see other tests' statements.
pub async fn count_queries<F: Future>(fut: F) -> (F::Output, QueryLog) {
    let log = Arc::new(Mutex::new(Vec::new()));
    // `tracing-core` decides with the *global* dispatcher alone while at
    // most one dispatcher is registered (`has_just_one`). In a test binary
    // without a global subscriber, a callsite first hit by another test
    // thread while this counter is the only registered dispatcher is
    // therefore cached as `never`, and its statements vanish from the count
    // when tests run in parallel. With the global test subscriber installed
    // there are always at least two, so every interest includes the counter.
    crate::init_tracing();
    let counter = tracing::Dispatch::new(QueryCounter { log: log.clone() });
    let output = fut.with_subscriber(counter).await;
    let statements = std::mem::take(&mut *log.lock().unwrap());
    (output, QueryLog { statements })
}

const SQLX_QUERY_TARGET: &str = "sqlx::query";

/// A minimal subscriber that records `sqlx::query` events and nothing else.
struct QueryCounter {
    log: Arc<Mutex<Vec<String>>>,
}

struct SummaryVisitor(Option<String>);

impl Visit for SummaryVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "summary" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "summary" && self.0.is_none() {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl Subscriber for QueryCounter {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // `tracing::enabled!` (which sqlx asks first) is a *hint* callsite,
        // not an event: accept everything but spans.
        !metadata.is_span() && metadata.target() == SQLX_QUERY_TARGET
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != SQLX_QUERY_TARGET {
            return;
        }
        let mut visitor = SummaryVisitor(None);
        event.record(&mut visitor);
        let summary = visitor.0.unwrap_or_else(|| "<statement>".to_owned());
        self.log.lock().unwrap().push(summary);
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn tst_01_percentiles_use_nearest_rank() {
        let mut stats = Stats::new();
        for v in 1..=100 {
            stats.push(ms(v));
        }
        let s = stats.summary().unwrap();
        assert_eq!(s.count, 100);
        assert_eq!(s.p50, ms(50));
        assert_eq!(s.p95, ms(95));
        assert_eq!(s.p99, ms(99));
        assert_eq!(s.max, ms(100));
        assert_eq!(s.min, ms(1));
        assert!(Stats::new().summary().is_none());
        let mut one = Stats::new();
        one.push(ms(7));
        assert_eq!(one.summary().unwrap().p99, ms(7));
    }

    #[test]
    fn tst_01_transaction_control_is_not_a_data_statement() {
        let log = QueryLog {
            statements: vec![
                "BEGIN".into(),
                "SELECT 1".into(),
                "commit".into(),
                "INSERT INTO t …".into(),
            ],
        };
        assert_eq!(log.count(), 4);
        assert_eq!(log.data_statements(), 2);
    }

    #[test]
    fn tst_01_duration_formatting() {
        assert_eq!(fmt_duration(Duration::from_nanos(812)), "812ns");
        assert_eq!(fmt_duration(Duration::from_nanos(41_300)), "41.3µs");
        assert_eq!(fmt_duration(Duration::from_micros(2_410)), "2.41ms");
        assert_eq!(fmt_duration(Duration::from_millis(1_200)), "1.20s");
    }

    #[sqlx::test(migrations = false)]
    async fn tst_01_query_counter_sees_only_its_own_statements(pool: sqlx::PgPool) {
        let ((), log) = count_queries(async {
            sqlx::query("SELECT 1").execute(&pool).await.unwrap();
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SELECT 2").execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        })
        .await;
        // Not counted: outside the measured future.
        sqlx::query("SELECT 3").execute(&pool).await.unwrap();
        assert_eq!(log.data_statements(), 2, "{log}");
        assert!(log.statements.iter().any(|s| s.starts_with("SELECT 1")));
        assert!(log.statements.iter().any(|s| s.starts_with("SELECT 2")));
        assert!(!log.statements.iter().any(|s| s.starts_with("SELECT 3")));
    }
}
