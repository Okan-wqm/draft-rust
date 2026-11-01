#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! PostgreSQL (and, with `--features redis`, Redis) rate limiters against
//! real servers (PRT-01, PRT-02, PRT-04).

use std::sync::Arc;
use std::time::Duration;

use authn_core::ports::{Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
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
