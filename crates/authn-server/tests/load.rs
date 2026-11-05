#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)] // integration-test crate
//! Load test harness (K-70): many concurrent callers drive the **real**
//! router (every middleware) against the real PostgreSQL, production
//! shape (PostgreSQL rate limiter, production Argon2id, real clock).
//! Reports p50 / p95 / p99 and throughput per scenario.
//!
//! Ignored by default (it takes about a minute and wants a quiet machine);
//! run it in release mode:
//!
//! ```bash
//! cargo test -p authn-server --release --test load -- --ignored --nocapture
//! AUTHN_LOAD_SECS=20 AUTHN_LOAD_CONCURRENCY=128 AUTHN_LOAD_POOL=32 \
//!   cargo test -p authn-server --release --test load -- --ignored --nocapture
//! ```
//!
//! | Variable | Default | Meaning |
//! |----------|---------|---------|
//! | `AUTHN_LOAD_SECS` | 8 | Duration of each scenario |
//! | `AUTHN_LOAD_CONCURRENCY` | 64 | Concurrent callers |
//! | `AUTHN_LOAD_POOL` | 20 | `database.max_connections` (the default) |
//! | `AUTHN_LOAD_SCENARIOS` | all | Comma-separated subset (`get_time,get_me,refresh,introspect,login`) |
//! | `AUTHN_LOAD_RATE_LIMIT` | `postgres` | Rate-limit backend: `postgres`, `redis` (needs `--features redis`; `AUTHN_LOAD_REDIS_URL`, default `redis://localhost:6379`) or `memory` (single instance only) |
//!
//! Requests go through `tower::ServiceExt::oneshot` in process: the
//! numbers include routing, every middleware, handlers, serialization and
//! PostgreSQL, but not TCP / TLS / HTTP parsing (hyper). Every request
//! comes from a different client IP, as production traffic from many
//! clients would; one IP would only measure the per-IP rate limit. Logins
//! come from the user's own `/24` (a known network after the first login,
//! RSK-02), so they complete without a risk challenge, as most real
//! logins do. A login answered with a challenge counts as an error.
//! Results and their caveats: `docs/operations/performance.md`.

mod common;
mod perf;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use authn_testkit::bench::{Stats, fmt_duration};
use authn_testkit::http::TestRequest;
use common::App;
use perf::{ScratchDatabase, Tokens, client_ip};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

static NEXT_IP: AtomicUsize = AtomicUsize::new(100_000);

fn next_ip() -> std::net::IpAddr {
    client_ip(NEXT_IP.fetch_add(1, Ordering::Relaxed))
}

/// Per-worker state of a scenario.
enum Work {
    Get { path: &'static str, access: String },
    Refresh { refresh: String },
    Introspect { key: String, access: String },
    Login { user: usize },
}

impl Work {
    fn request(&self) -> TestRequest {
        match self {
            Self::Get { path, access } => perf::bearer_get(path, access, next_ip()),
            Self::Refresh { refresh } => perf::refresh_request(refresh, next_ip()),
            Self::Introspect { key, access } => perf::introspect_request(key, access, next_ip()),
            Self::Login { user } => perf::native_login_request(
                *user,
                perf::user_ip(*user, NEXT_IP.fetch_add(1, Ordering::Relaxed)),
            ),
        }
    }
}

struct Outcome {
    stats: Stats,
    errors: usize,
    first_error: Option<String>,
}

/// Runs `workers` callers for `duration`; each repeats its request.
async fn drive(app: Arc<App>, mut workers: Vec<Work>, duration: Duration) -> (Outcome, Duration) {
    let started = Instant::now();
    let deadline = started + duration;
    let mut handles = Vec::with_capacity(workers.len());
    for mut work in workers.drain(..) {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            let mut out = Outcome {
                stats: Stats::new(),
                errors: 0,
                first_error: None,
            };
            while Instant::now() < deadline {
                let request = work.request();
                let start = Instant::now();
                let response = app.send(request).await;
                let elapsed = start.elapsed();
                let completed = response.status.is_success()
                    && !(matches!(work, Work::Login { .. })
                        && response.json::<serde_json::Value>()["status"] != "authenticated");
                if completed {
                    out.stats.push(elapsed);
                    if let Work::Refresh { refresh } = &mut work {
                        *refresh = Tokens::from_body(&response.json()).refresh;
                    }
                } else {
                    out.errors += 1;
                    out.first_error
                        .get_or_insert_with(|| format!("{} {}", response.status, response.text()));
                    if matches!(work, Work::Refresh { .. }) {
                        break; // the chain is broken
                    }
                }
            }
            out
        }));
    }
    let mut total = Outcome {
        stats: Stats::new(),
        errors: 0,
        first_error: None,
    };
    for handle in handles {
        let out = handle.await.unwrap();
        total.stats.extend(out.stats);
        total.errors += out.errors;
        if total.first_error.is_none() {
            total.first_error = out.first_error;
        }
    }
    (total, started.elapsed())
}

fn report(name: &str, outcome: &Outcome, elapsed: Duration) {
    let summary = outcome.stats.summary().expect("no successful request");
    let rps = outcome.stats.len() as f64 / elapsed.as_secs_f64();
    println!(
        "{name:<34} {:>8.0} req/s  p50={:>9} p95={:>9} p99={:>9} max={:>9}  ok={} errors={}",
        rps,
        fmt_duration(summary.p50),
        fmt_duration(summary.p95),
        fmt_duration(summary.p99),
        fmt_duration(summary.max),
        outcome.stats.len(),
        outcome.errors,
    );
    if let Some(err) = &outcome.first_error {
        println!("  first error: {err}");
    }
}

#[test]
#[ignore = "load test: run explicitly in release mode (see the module docs)"]
fn k_70_load_login_refresh_and_authenticated_get() {
    let secs = env_usize("AUTHN_LOAD_SECS", 8);
    let concurrency = env_usize("AUTHN_LOAD_CONCURRENCY", 64).max(1);
    let pool_size = u32::try_from(env_usize("AUTHN_LOAD_POOL", 20)).unwrap();
    let selected = std::env::var("AUTHN_LOAD_SCENARIOS").unwrap_or_default();
    let wanted = |s: &str| selected.is_empty() || selected.split(',').any(|x| x == s);
    let duration = Duration::from_secs(secs as u64);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        authn_core::tls::install_crypto_provider();
        let db = ScratchDatabase::create().await;
        let backend = std::env::var("AUTHN_LOAD_RATE_LIMIT").unwrap_or_else(|_| "postgres".into());
        let app = Arc::new(
            perf::production_app_with(db.pool(pool_size).await, true, |c| {
                use authn_core::config::protect::RateLimitBackend;
                c.protect.rate_limit.backend = match backend.as_str() {
                    "memory" => RateLimitBackend::Memory,
                    "redis" => {
                        c.protect.rate_limit.redis_url =
                            Some(authn_core::secret::SecretString::from(
                                std::env::var("AUTHN_LOAD_REDIS_URL")
                                    .unwrap_or_else(|_| "redis://localhost:6379".into()),
                            ));
                        RateLimitBackend::Redis
                    }
                    _ => RateLimitBackend::Postgres,
                };
            })
            .await,
        );
        let users = concurrency.min(64);
        let ids = perf::users(&app, users).await;
        println!(
            "load: {} CPUs, concurrency {concurrency}, pool {pool_size}, {secs}s per scenario, \
             {users} users, production Argon2id, rate limit {:?}",
            std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
            app.services.config.protect.rate_limit.backend,
        );

        // Fixtures: one native session per worker (sessions are spread
        // over the users; each worker gets its own refresh chain).
        let mut sessions = Vec::with_capacity(concurrency);
        for w in 0..concurrency {
            sessions.push(perf::native_login(&app, w % users).await);
        }
        let mut failures = Vec::new();
        let mut run = |name: &'static str, outcome: Outcome, elapsed: Duration| {
            report(name, &outcome, elapsed);
            if outcome.errors > 0 {
                failures.push(name);
            }
        };

        for (key, path) in [("get_time", "/v1/time"), ("get_me", "/v1/me")] {
            if wanted(key) {
                let workers = sessions
                    .iter()
                    .map(|t| Work::Get {
                        path,
                        access: t.access.clone(),
                    })
                    .collect();
                let (o, e) = drive(app.clone(), workers, duration).await;
                run(
                    if key == "get_time" {
                        "GET /v1/time (bearer)"
                    } else {
                        "GET /v1/me (bearer)"
                    },
                    o,
                    e,
                );
            }
        }
        if wanted("introspect") {
            let (org, key) = perf::org_with_api_key(&app, ids[0]).await;
            let owner = perf::native_login(&app, 0).await;
            let org_tokens = perf::switch_org(&app, &owner, org, next_ip()).await;
            let workers = (0..concurrency)
                .map(|_| Work::Introspect {
                    key: key.clone(),
                    access: org_tokens.access.clone(),
                })
                .collect();
            let (o, e) = drive(app.clone(), workers, duration).await;
            run("POST /v1/token/introspect", o, e);
        }
        if wanted("refresh") {
            let workers = sessions
                .iter()
                .map(|t| Work::Refresh {
                    refresh: t.refresh.clone(),
                })
                .collect();
            let (o, e) = drive(app.clone(), workers, duration).await;
            run("POST /v1/token/refresh", o, e);
        }
        if wanted("login") {
            let workers = (0..concurrency)
                .map(|w| Work::Login { user: w % users })
                .collect();
            let (o, e) = drive(app.clone(), workers, duration).await;
            run("POST /v1/login/password (native)", o, e);
        }

        app.pool.close().await;
        drop(app);
        db.drop_database().await;
        assert!(failures.is_empty(), "scenarios with errors: {failures:?}");
    });
}
