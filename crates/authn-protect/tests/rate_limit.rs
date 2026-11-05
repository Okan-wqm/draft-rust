#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! PostgreSQL (and, with `--features redis`, Redis) rate limiters against
//! real servers (PRT-01, PRT-02, PRT-04).

use std::sync::Arc;
use std::time::Duration;

use authn_core::ports::{
    Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimitStep, RateLimiter,
};
use authn_crypto::kdf::KeyRing;
use authn_protect::KeyHasher;
use authn_protect::rate_limit::PostgresRateLimiter;
use authn_testkit::FakeClock;
use sqlx::PgPool;

fn hasher() -> KeyHasher {
    KeyHasher::new(&KeyRing::derive(&[3_u8; 32]).unwrap()).unwrap()
}

fn pg(pool: &PgPool) -> (Arc<FakeClock>, PostgresRateLimiter) {
    let clock = Arc::new(FakeClock::new());
    (
        clock.clone(),
        PostgresRateLimiter::new(pool.clone(), clock, hasher()),
    )
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_01_postgres_limiter_enforces_burst_and_recovers(pool: PgPool) {
    let (clock, limiter) = pg(&pool);
    let key = RateLimitKey::account("login", "alice@example.com");
    let policy = RateLimitPolicy::new(5, Duration::from_secs(50));
    for remaining in (0..5).rev() {
        assert_eq!(
            limiter.check(&key, policy, 1).await.unwrap(),
            RateLimitDecision::allow(remaining)
        );
    }
    let denied = limiter.check(&key, policy, 1).await.unwrap();
    assert_eq!(denied, RateLimitDecision::deny(Duration::from_secs(10)));
    assert_eq!(limiter.peek(&key, policy).await.unwrap(), denied);
    clock.advance(Duration::from_secs(4));
    assert_eq!(
        limiter.check(&key, policy, 1).await.unwrap(),
        RateLimitDecision::deny(Duration::from_secs(6)),
        "denials never consume, so the wait only shrinks with time"
    );
    clock.advance(Duration::from_secs(6));
    assert!(limiter.check(&key, policy, 1).await.unwrap().allowed);
    // Multi-unit costs.
    clock.advance(Duration::from_secs(50));
    assert_eq!(
        limiter.check(&key, policy, 3).await.unwrap(),
        RateLimitDecision::allow(2)
    );
    assert!(!limiter.check(&key, policy, 3).await.unwrap().allowed);
    assert!(
        !limiter.check(&key, policy, 6).await.unwrap().allowed,
        "cost above limit"
    );
    limiter.reset(&key).await.unwrap();
    assert_eq!(
        limiter.peek(&key, policy).await.unwrap(),
        RateLimitDecision::allow(4)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_01_postgres_limiter_is_race_safe(pool: PgPool) {
    let (_clock, limiter) = pg(&pool);
    let limiter = Arc::new(limiter);
    let key = RateLimitKey::ip("login", "198.51.100.20".parse().unwrap());
    let policy = RateLimitPolicy::new(10, Duration::from_secs(900));
    let mut tasks = Vec::new();
    for _ in 0..60 {
        let limiter = limiter.clone();
        let key = key.clone();
        tasks.push(tokio::spawn(async move {
            limiter.check(&key, policy, 1).await.unwrap().allowed
        }));
    }
    let mut allowed = 0;
    for task in tasks {
        allowed += usize::from(task.await.unwrap());
    }
    assert_eq!(
        allowed, 10,
        "exactly the burst is admitted under concurrency"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_02_postgres_stores_only_keyed_hashes(pool: PgPool) {
    let (_clock, limiter) = pg(&pool);
    let policy = RateLimitPolicy::new(3, Duration::from_secs(60));
    limiter
        .check(
            &RateLimitKey::account("login", "victim@example.com"),
            policy,
            1,
        )
        .await
        .unwrap();
    limiter
        .check(
            &RateLimitKey::ip("login", "203.0.113.77".parse().unwrap()),
            policy,
            1,
        )
        .await
        .unwrap();
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT key_hash FROM rate_limit_buckets")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for (hash,) in rows {
        assert_eq!(hash.len(), 32);
        let text = String::from_utf8_lossy(&hash);
        assert!(!text.contains("victim") && !text.contains("203.0.113"));
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_01_postgres_purge_removes_only_expired_buckets(pool: PgPool) {
    let (clock, limiter) = pg(&pool);
    let short = RateLimitPolicy::new(1, Duration::from_secs(10));
    let long = RateLimitPolicy::new(1, Duration::from_secs(3600));
    limiter
        .check(&RateLimitKey::global("a"), short, 1)
        .await
        .unwrap();
    limiter
        .check(&RateLimitKey::global("b"), long, 1)
        .await
        .unwrap();
    clock.advance(Duration::from_secs(11));
    assert_eq!(limiter.purge_expired(1000).await.unwrap(), 1);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM rate_limit_buckets")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 1);
    // The surviving bucket still limits.
    assert!(
        !limiter
            .check(&RateLimitKey::global("b"), long, 1)
            .await
            .unwrap()
            .allowed
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_04_postgres_and_memory_backends_agree(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let pg = PostgresRateLimiter::new(pool.clone(), clock.clone(), hasher());
    let mem = authn_protect::rate_limit::MemoryRateLimiter::new(clock.clone(), hasher());
    let policy = RateLimitPolicy::new(7, Duration::from_millis(7_777));
    let key = RateLimitKey::endpoint("agree");
    for step in 0..40_u64 {
        clock.advance(Duration::from_millis((step * 397) % 1_500));
        let cost = u32::try_from(step % 3).unwrap() + 1;
        let a = pg.check(&key, policy, cost).await.unwrap();
        let b = mem.check(&key, policy, cost).await.unwrap();
        assert_eq!(a, b, "step {step}");
        let _ = clock.now();
    }
}

/// The login chain of K-128 (per-IP limit, soft-lock peek, CAPTCHA and
/// soft-lock budgets) plus a never-admissible step, run on `limiter` with
/// the given gates.
async fn login_chain(
    limiter: &dyn RateLimiter,
    identifier: &str,
    lock_gates: bool,
) -> Vec<RateLimitDecision> {
    let ip = RateLimitKey::ip("login", "198.51.100.30".parse().unwrap());
    let lock = RateLimitKey::account("login_soft_lock", identifier);
    let captcha = RateLimitKey::account("login_failures_captcha", identifier);
    let budget = RateLimitKey::account("login_failures_lock", identifier);
    limiter
        .check_chain(&[
            RateLimitStep::check(&ip, RateLimitPolicy::new(20, Duration::from_secs(60))),
            RateLimitStep::peek(&lock, RateLimitPolicy::new(1, Duration::from_secs(600)))
                .stop_if_denied(lock_gates),
            RateLimitStep::check(&captcha, RateLimitPolicy::new(3, Duration::from_secs(90))),
            RateLimitStep::check(&budget, RateLimitPolicy::new(5, Duration::from_secs(300))),
        ])
        .await
        .unwrap()
}

/// K-128: a chain on PostgreSQL (one statement) decides exactly like the
/// single calls it replaces (the memory backend runs the port's default:
/// one call after another), including the steps a denial skips, rejected
/// policies and a key repeated within one chain.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_01_k_128_postgres_chain_decides_like_single_calls(pool: PgPool) {
    let clock = Arc::new(FakeClock::new());
    let pg = PostgresRateLimiter::new(pool.clone(), clock.clone(), hasher());
    let mem = authn_protect::rate_limit::MemoryRateLimiter::new(clock.clone(), hasher());
    for round in 0..40_u64 {
        clock.advance(Duration::from_millis((round * 7_919) % 20_000));
        if round == 20 {
            // Engage the soft lock (the peek step then denies).
            let lock = RateLimitKey::account("login_soft_lock", "victim");
            let policy = RateLimitPolicy::new(1, Duration::from_secs(600));
            assert!(pg.check(&lock, policy, 1).await.unwrap().allowed);
            assert!(mem.check(&lock, policy, 1).await.unwrap().allowed);
        }
        let gates = round % 3 != 0;
        let a = login_chain(&pg, "victim", gates).await;
        let b = login_chain(&mem, "victim", gates).await;
        assert_eq!(a, b, "round {round}");
    }
    // Rejected policies (limit 0) decide without storage; a gating one ends
    // the chain, a non-gating one does not.
    let k1 = RateLimitKey::global("k128-a");
    let k2 = RateLimitKey::global("k128-b");
    let zero = RateLimitPolicy::new(0, Duration::from_secs(1));
    let one = RateLimitPolicy::new(1, Duration::from_secs(60));
    for limiter in [&pg as &dyn RateLimiter, &mem] {
        let d = limiter
            .check_chain(&[
                RateLimitStep::check(&k1, zero),
                RateLimitStep::check(&k2, one),
            ])
            .await
            .unwrap();
        assert_eq!(d.len(), 1);
        assert!(!d[0].allowed);
        let d = limiter
            .check_chain(&[
                RateLimitStep::check(&k1, zero).stop_if_denied(false),
                RateLimitStep::check(&k2, one),
            ])
            .await
            .unwrap();
        assert_eq!(d.len(), 2);
        assert!(!d[0].allowed && d[1].allowed);
    }
    // A key repeated within one chain (falls back to single statements).
    let d = pg
        .check_chain(&[
            RateLimitStep::check(&k2, one),
            RateLimitStep::peek(&k2, one),
        ])
        .await
        .unwrap();
    assert_eq!(d.len(), 1, "the first check is denied: the key is used up");
    clock.advance(Duration::from_secs(60));
    let d = pg
        .check_chain(&[
            RateLimitStep::check(&k2, one).stop_if_denied(false),
            RateLimitStep::peek(&k2, one),
        ])
        .await
        .unwrap();
    assert!(d[0].allowed && !d[1].allowed, "{d:?}");
}

/// K-128: steps after a denial that ends the chain consume nothing.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_01_k_128_chain_consumes_nothing_after_a_stopping_denial(pool: PgPool) {
    let (_clock, limiter) = pg(&pool);
    let gate = RateLimitKey::global("k128-gate");
    let after = RateLimitKey::global("k128-after");
    let one = RateLimitPolicy::new(1, Duration::from_secs(600));
    let five = RateLimitPolicy::new(5, Duration::from_secs(600));
    for _ in 0..4 {
        limiter
            .check_chain(&[
                RateLimitStep::check(&gate, one),
                RateLimitStep::check(&after, five),
            ])
            .await
            .unwrap();
    }
    assert_eq!(
        limiter.peek(&after, five).await.unwrap(),
        RateLimitDecision::allow(3),
        "only the first chain passed the gate"
    );
}

/// K-128: concurrent chains never admit more than a policy allows — two
/// requests cannot both take the last unit — and a step guarded by a
/// denied one is consumed exactly once per admitted chain.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_01_k_128_postgres_chain_is_race_safe(pool: PgPool) {
    let (_clock, limiter) = pg(&pool);
    let limiter = Arc::new(limiter);
    let shared = RateLimitKey::account("login_failures_lock", "target");
    let follow = RateLimitKey::account("login_failures_captcha", "target");
    let policy = RateLimitPolicy::new(10, Duration::from_secs(900));
    let wide = RateLimitPolicy::new(1000, Duration::from_secs(900));
    let mut tasks = Vec::new();
    for i in 0..60_u8 {
        let limiter = limiter.clone();
        let (shared, follow) = (shared.clone(), follow.clone());
        tasks.push(tokio::spawn(async move {
            let ip = RateLimitKey::ip("login", std::net::IpAddr::from([198, 51, 100, i]));
            let d = limiter
                .check_chain(&[
                    RateLimitStep::check(&ip, wide),
                    RateLimitStep::check(&shared, policy),
                    RateLimitStep::check(&follow, wide),
                ])
                .await
                .unwrap();
            usize::from(d.get(1).is_some_and(|d| d.allowed))
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        admitted += task.await.unwrap();
    }
    assert_eq!(
        admitted, 10,
        "exactly the burst is admitted under concurrency"
    );
    assert_eq!(
        limiter.peek(&follow, wide).await.unwrap(),
        RateLimitDecision::allow(1000 - 10 - 1),
        "the guarded step ran once per admitted chain"
    );

    // The last slot: two concurrent chains, one unit left.
    let last = RateLimitKey::global("k128-last");
    let one = RateLimitPolicy::new(1, Duration::from_secs(900));
    let steps = [RateLimitStep::check(&last, one)];
    let (a, b) = tokio::join!(limiter.check_chain(&steps), limiter.check_chain(&steps));
    let passed = [a.unwrap(), b.unwrap()]
        .iter()
        .filter(|d| d[0].allowed)
        .count();
    assert_eq!(passed, 1);
}

/// K-128: a chain, several peeks and several resets are one statement
/// each on PostgreSQL.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_01_k_128_postgres_batches_are_one_statement(pool: PgPool) {
    let (_clock, limiter) = pg(&pool);
    let (chain, log) = authn_testkit::bench::count_queries(login_chain(&limiter, "x", true)).await;
    assert_eq!(chain.len(), 4);
    assert_eq!(log.count(), 1, "{log}");
    let a = RateLimitKey::account("login_failures_captcha", "x");
    let b = RateLimitKey::account("login_failures_lock", "x");
    let policy = RateLimitPolicy::new(3, Duration::from_secs(90));
    let five = RateLimitPolicy::new(5, Duration::from_secs(300));
    let (peeks, log) =
        authn_testkit::bench::count_queries(limiter.peek_many(&[(&a, policy), (&b, five)])).await;
    assert_eq!(
        peeks.unwrap(),
        vec![RateLimitDecision::allow(1), RateLimitDecision::allow(3)]
    );
    assert_eq!(log.count(), 1, "{log}");
    let (reset, log) = authn_testkit::bench::count_queries(limiter.reset_many(&[&a, &b])).await;
    reset.unwrap();
    assert_eq!(log.count(), 1, "{log}");
    assert_eq!(
        limiter
            .peek_many(&[(&a, policy), (&b, five)])
            .await
            .unwrap(),
        vec![RateLimitDecision::allow(2), RateLimitDecision::allow(4)]
    );
}

#[cfg(feature = "redis")]
mod redis_backend {
    use authn_core::secret::SecretString;
    use authn_protect::rate_limit::RedisRateLimiter;

    use super::*;

    /// Skips (with a visible note) when no Redis is reachable: the backend
    /// is optional and CI's coverage job runs without a Redis service.
    #[allow(clippy::print_stderr)]
    async fn connect(clock: Arc<FakeClock>) -> Option<RedisRateLimiter> {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        match RedisRateLimiter::connect(&SecretString::from(url), clock, hasher()).await {
            Ok(limiter) => Some(limiter),
            Err(err) => {
                // Redis is an optional backend; CI's test job provides it.
                eprintln!("skipping redis test: {err}");
                None
            }
        }
    }

    fn unique(name: &str) -> String {
        format!("{name}-{}", uuid::Uuid::now_v7())
    }

    #[tokio::test]
    async fn prt_01_redis_limiter_enforces_burst_and_recovers() {
        let clock = Arc::new(FakeClock::new());
        let Some(limiter) = connect(clock.clone()).await else {
            return;
        };
        let key = RateLimitKey::account("login", &unique("alice"));
        let policy = RateLimitPolicy::new(4, Duration::from_secs(40));
        for remaining in (0..4).rev() {
            assert_eq!(
                limiter.check(&key, policy, 1).await.unwrap(),
                RateLimitDecision::allow(remaining)
            );
        }
        let denied = limiter.check(&key, policy, 1).await.unwrap();
        assert_eq!(denied, RateLimitDecision::deny(Duration::from_secs(10)));
        assert_eq!(limiter.peek(&key, policy).await.unwrap(), denied);
        clock.advance(Duration::from_secs(10));
        assert!(limiter.check(&key, policy, 1).await.unwrap().allowed);
        limiter.reset(&key).await.unwrap();
        assert_eq!(
            limiter.peek(&key, policy).await.unwrap(),
            RateLimitDecision::allow(3)
        );
        limiter.quit().await.unwrap();
    }

    #[tokio::test]
    async fn prt_01_redis_limiter_is_race_safe() {
        let clock = Arc::new(FakeClock::new());
        let Some(limiter) = connect(clock).await else {
            return;
        };
        let limiter = Arc::new(limiter);
        let key = RateLimitKey::account("login", &unique("race"));
        let policy = RateLimitPolicy::new(10, Duration::from_secs(600));
        let mut tasks = Vec::new();
        for _ in 0..80 {
            let limiter = limiter.clone();
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                limiter.check(&key, policy, 1).await.unwrap().allowed
            }));
        }
        let mut allowed = 0;
        for task in tasks {
            allowed += usize::from(task.await.unwrap());
        }
        assert_eq!(allowed, 10);
    }

    /// K-128: the Redis chain (independent steps sent concurrently) and
    /// multi-key peeks / resets decide like the memory backend.
    #[tokio::test]
    async fn prt_01_k_128_redis_chain_decides_like_single_calls() {
        let clock = Arc::new(FakeClock::new());
        let Some(redis) = connect(clock.clone()).await else {
            return;
        };
        let mem = authn_protect::rate_limit::MemoryRateLimiter::new(clock.clone(), hasher());
        let identifier = unique("victim");
        for round in 0..30_u64 {
            clock.advance(Duration::from_millis((round * 7_919) % 20_000));
            let gates = round % 3 != 0;
            let a = login_chain(&redis, &identifier, gates).await;
            let b = login_chain(&mem, &identifier, gates).await;
            assert_eq!(a, b, "round {round}");
        }
        let a = RateLimitKey::account("login_failures_captcha", &identifier);
        let b = RateLimitKey::account("login_failures_lock", &identifier);
        let policy = RateLimitPolicy::new(3, Duration::from_secs(90));
        assert_eq!(
            redis
                .peek_many(&[(&a, policy), (&b, policy)])
                .await
                .unwrap(),
            mem.peek_many(&[(&a, policy), (&b, policy)]).await.unwrap()
        );
        redis.reset_many(&[&a, &b]).await.unwrap();
        assert_eq!(
            redis
                .peek_many(&[(&a, policy), (&b, policy)])
                .await
                .unwrap(),
            vec![RateLimitDecision::allow(2), RateLimitDecision::allow(2)]
        );
        redis.quit().await.unwrap();
    }

    #[tokio::test]
    async fn prt_01_redis_unreachable_fails_with_service_unavailable() {
        let clock = Arc::new(FakeClock::new());
        let err = tokio::time::timeout(
            Duration::from_secs(20),
            RedisRateLimiter::connect(
                &SecretString::from("redis://127.0.0.1:1".to_owned()),
                clock,
                hasher(),
            ),
        )
        .await
        .expect("connect gives up")
        .unwrap_err();
        assert_eq!(
            err.code(),
            authn_core::error::codes::common::SERVICE_UNAVAILABLE
        );
        assert!(!format!("{err:?}").contains("127.0.0.1:1"));
    }
}
