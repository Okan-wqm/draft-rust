#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Login throttling, CAPTCHA escalation and the soft lock (PRT-02, PRT-03,
//! PRT-04) with PostgreSQL.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::protect::ProtectConfig;
use authn_core::domain::{AccountStatus, EmailAddress, Locale, LoginMethod};
use authn_core::error::AuthError;
use authn_core::error::codes;
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Clock, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter, SecurityEventKind,
};
use authn_crypto::kdf::KeyRing;
use authn_protect::KeyHasher;
use authn_protect::captcha::CaptchaService;
use authn_protect::login::{LoginAttempt, LoginProtection};
use authn_protect::rate_limit::MemoryRateLimiter;
use authn_protect::risk::{DeviceObservation, RiskStore};
use authn_store::{NewUser, UserRepository};
use authn_testkit::TestPorts;
use sqlx::PgPool;

const KNOWN_DEVICE: &str = "known-device-0000000001";
const ATTACKER_DEVICE: &str = "attacker-device-00000001";

struct Fixture {
    ports: TestPorts,
    limiter: Arc<dyn RateLimiter>,
    protection: LoginProtection,
    store: RiskStore,
    pool: PgPool,
}

fn config() -> ProtectConfig {
    let mut config = ProtectConfig::default();
    config.rate_limit.login_per_ip = RateLimitPolicy::new(1000, Duration::from_secs(900));
    config.rate_limit.login_per_account_captcha = RateLimitPolicy::new(3, Duration::from_secs(900));
    config.rate_limit.login_per_account_soft_lock =
        RateLimitPolicy::new(5, Duration::from_secs(3600));
    config.rate_limit.soft_lock_duration = Duration::from_secs(3600);
    config
}

fn fixture(pool: &PgPool, config: &ProtectConfig) -> Fixture {
    fixture_with(pool, config, |limiter| limiter)
}

fn fixture_with(
    pool: &PgPool,
    config: &ProtectConfig,
    wrap: impl FnOnce(Arc<dyn RateLimiter>) -> Arc<dyn RateLimiter>,
) -> Fixture {
    let ports = TestPorts::new();
    let hasher = KeyHasher::new(&KeyRing::derive(&[5_u8; 32]).unwrap()).unwrap();
    let limiter: Arc<dyn RateLimiter> = wrap(Arc::new(MemoryRateLimiter::new(
        ports.clock.clone(),
        hasher.clone(),
    )));
    let captcha = CaptchaService::new(
        ports.captcha.clone(),
        limiter.clone(),
        ports.audit.clone(),
        ports.clock.clone(),
        &config.captcha,
    );
    let store = RiskStore::new(pool.clone(), hasher);
    let protection = LoginProtection::new(
        pool.clone(),
        ports.clock.clone(),
        limiter.clone(),
        ports.audit.clone(),
        captcha,
        store.clone(),
        config,
    );
    Fixture {
        ports,
        limiter,
        protection,
        store,
        pool: pool.clone(),
    }
}

fn ctx(ip: &str, device: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::system(Locale::En);
    ctx.client_ip = ip.parse().unwrap();
    ctx.device_id = device.map(str::to_owned);
    ctx
}

fn attempt<'a>(identifier: &'a str, user: Option<UserId>) -> LoginAttempt<'a> {
    LoginAttempt {
        identifier,
        user_id: user,
        method: LoginMethod::Password,
        trusted_device: false,
        captcha_response: None,
    }
}

async fn create_user(f: &Fixture, email: &str) -> UserId {
    let mut conn = f.pool.acquire().await.unwrap();
    let user = UserRepository::create(
        &mut conn,
        &NewUser {
            id: UserId::generate(),
            email: EmailAddress::parse(email).unwrap(),
            status: AccountStatus::Active,
            created_at: f.ports.clock.now(),
        },
    )
    .await
    .unwrap();
    user.id
}

async fn remember_device(f: &Fixture, user: UserId, device: &str) {
    let mut tx = f.pool.begin().await.unwrap();
    f.store
        .record(
            &mut tx,
            user,
            &DeviceObservation {
                device_id: Some(device.to_owned()),
                device_name: "Firefox on Linux".to_owned(),
                ip: "198.51.100.10".parse().unwrap(),
                country: None,
                latitude: None,
                longitude: None,
                at: f.ports.clock.now(),
                approximate_location: None,
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_02_login_attempts_per_ip_are_limited_with_retry_after(pool: PgPool) {
    let mut config = config();
    config.rate_limit.login_per_ip = RateLimitPolicy::new(3, Duration::from_secs(900));
    let f = fixture(&pool, &config);
    let ctx = ctx("203.0.113.50", None);
    for method in [
        LoginMethod::Password,
        LoginMethod::Passkey,
        LoginMethod::MagicLink,
    ] {
        let mut a = attempt("a@example.com", None);
        a.method = method;
        f.protection.check_attempt(&a, &ctx).await.unwrap();
    }
    let err = f
        .protection
        .check_attempt(&attempt("b@example.com", None), &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    assert_eq!(err.retry_after(), Some(Duration::from_secs(300)));
    assert_eq!(
        f.ports
            .audit
            .of_kind(SecurityEventKind::RateLimitTriggered)
            .len(),
        1
    );
    // Another IP is unaffected.
    f.protection
        .check_attempt(
            &attempt("b@example.com", None),
            &self::ctx("203.0.113.51", None),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_02_captcha_is_required_after_identifier_failures(pool: PgPool) {
    let f = fixture(&pool, &config());
    let user = create_user(&f, "alice@example.com").await;
    let ctx = ctx("203.0.113.60", Some(ATTACKER_DEVICE));
    for (identifier, user) in [
        ("alice@example.com", Some(user)),
        ("nobody@example.com", None),
    ] {
        for _ in 0..3 {
            f.protection
                .check_attempt(&attempt(identifier, user), &ctx)
                .await
                .unwrap();
            f.protection
                .record_failure(&attempt(identifier, user), &ctx)
                .await
                .unwrap();
        }
        let err = f
            .protection
            .check_attempt(&attempt(identifier, user), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::protect::CAPTCHA_REQUIRED, "{identifier}");
        assert_eq!(err.details().unwrap()["challenge"]["type"], "widget");
        let mut wrong = attempt(identifier, user);
        wrong.captcha_response = Some("wrong");
        assert_eq!(
            f.protection
                .check_attempt(&wrong, &ctx)
                .await
                .unwrap_err()
                .code(),
            codes::protect::CAPTCHA_FAILED
        );
        let mut solved = attempt(identifier, user);
        solved.captcha_response = Some("pass");
        f.protection.check_attempt(&solved, &ctx).await.unwrap();
    }
    // A successful login clears the escalation.
    f.protection
        .record_success(&attempt("alice@example.com", Some(user)), &ctx)
        .await
        .unwrap();
    f.protection
        .check_attempt(&attempt("alice@example.com", Some(user)), &ctx)
        .await
        .unwrap();
}

/// Fails password attempts (solving the CAPTCHA once it is demanded) until
/// the soft lock engages: 5 failures, the 6th attempt is blocked.
async fn lock(f: &Fixture, identifier: &str, user: Option<UserId>) {
    let ctx = ctx("203.0.113.70", Some(ATTACKER_DEVICE));
    for i in 0..6 {
        let mut a = attempt(identifier, user);
        a.captcha_response = Some("pass");
        match f.protection.check_attempt(&a, &ctx).await {
            Ok(()) => {
                assert!(i < 5, "attempt {i} was not blocked");
                f.protection.record_failure(&a, &ctx).await.unwrap();
            }
            Err(err) => {
                assert_eq!(i, 5, "attempt {i}: {err:?}");
                assert_eq!(err.code(), codes::protect::LOGIN_TEMPORARILY_BLOCKED);
                assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
            }
        }
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_03_soft_lock_blocks_only_untrusted_password_attempts(pool: PgPool) {
    let f = fixture(&pool, &config());
    let user = create_user(&f, "victim@example.com").await;
    remember_device(&f, user, KNOWN_DEVICE).await;
    lock(&f, "victim@example.com", Some(user)).await;

    // Attacker (unknown device): blocked, with Retry-After.
    let err = f
        .protection
        .check_attempt(
            &attempt("victim@example.com", Some(user)),
            &ctx("203.0.113.71", Some(ATTACKER_DEVICE)),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::protect::LOGIN_TEMPORARILY_BLOCKED);
    assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    // Without any device id: blocked as well.
    assert!(
        f.protection
            .check_attempt(
                &attempt("victim@example.com", Some(user)),
                &ctx("203.0.113.71", None)
            )
            .await
            .is_err()
    );

    // The owner's known device, a trusted-device token and passkeys pass —
    // no CAPTCHA is forced on trusted devices either.
    f.protection
        .check_attempt(
            &attempt("victim@example.com", Some(user)),
            &ctx("198.51.100.10", Some(KNOWN_DEVICE)),
        )
        .await
        .unwrap();
    let mut trusted = attempt("victim@example.com", Some(user));
    trusted.trusted_device = true;
    f.protection
        .check_attempt(&trusted, &ctx("192.0.2.1", None))
        .await
        .unwrap();
    let mut passkey = attempt("victim@example.com", Some(user));
    passkey.method = LoginMethod::Passkey;
    f.protection
        .check_attempt(&passkey, &ctx("203.0.113.71", Some(ATTACKER_DEVICE)))
        .await
        .unwrap();
    // The known device of *another* user does not help the attacker.
    let attacker = create_user(&f, "attacker@example.com").await;
    remember_device(&f, attacker, ATTACKER_DEVICE).await;
    assert!(
        f.protection
            .check_attempt(
                &attempt("victim@example.com", Some(user)),
                &ctx("203.0.113.71", Some(ATTACKER_DEVICE)),
            )
            .await
            .is_err()
    );
    // Password reset and other actions use separate keys: unaffected.
    assert!(
        f.limiter
            .check(
                &RateLimitKey::account("password_reset", "victim@example.com"),
                RateLimitPolicy::new(3, Duration::from_secs(3600)),
                1
            )
            .await
            .unwrap()
            .allowed
    );

    // Bookkeeping: audit once, lock row for the existing account.
    let events = f.ports.audit.of_kind(SecurityEventKind::SoftLockEngaged);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].subject_user, Some(user));
    let until = f.protection.locked_until(user).await.unwrap().unwrap();
    assert_eq!(until, f.ports.clock.now() + Duration::from_secs(3600));

    // The lock expires by itself…
    f.ports.clock.advance(Duration::from_secs(3600));
    let mut solved = attempt("victim@example.com", Some(user));
    solved.captcha_response = Some("pass");
    f.protection
        .check_attempt(&solved, &ctx("203.0.113.71", Some(ATTACKER_DEVICE)))
        .await
        .unwrap();
    assert_eq!(f.protection.purge_expired().await.unwrap(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_03_admin_unlock_lifts_the_soft_lock(pool: PgPool) {
    let f = fixture(&pool, &config());
    let user = create_user(&f, "carol@example.com").await;
    lock(&f, "carol@example.com", Some(user)).await;
    assert!(
        f.protection
            .soft_lock_remaining("carol@example.com")
            .await
            .unwrap()
            .is_some()
    );
    f.protection
        .unlock(user, "carol@example.com")
        .await
        .unwrap();
    assert!(
        f.protection
            .soft_lock_remaining("carol@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(f.protection.locked_until(user).await.unwrap().is_none());
    f.protection
        .check_attempt(
            &attempt("carol@example.com", Some(user)),
            &ctx("203.0.113.71", Some(ATTACKER_DEVICE)),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_03_lock_response_does_not_reveal_account_existence(pool: PgPool) {
    let f = fixture(&pool, &config());
    let user = create_user(&f, "exists@example.com").await;
    lock(&f, "exists@example.com", Some(user)).await;
    lock(&f, "ghost@example.com", None).await;
    let ctx = ctx("203.0.113.72", Some(ATTACKER_DEVICE));

    let existing = f
        .protection
        .check_attempt(&attempt("exists@example.com", Some(user)), &ctx)
        .await
        .unwrap_err();
    let unknown = f
        .protection
        .check_attempt(&attempt("ghost@example.com", None), &ctx)
        .await
        .unwrap_err();
    assert_eq!(existing.code(), unknown.code());
    assert_eq!(existing.retry_after(), unknown.retry_after());
    let render = |e: &authn_core::AuthError| {
        let response = e.render(Locale::En, None);
        (
            response.status(),
            response.headers().get("retry-after").cloned(),
        )
    };
    assert_eq!(render(&existing), render(&unknown));
    assert_eq!(existing.details(), unknown.details());

    // Equal work on both paths (one indexed lookup each, no early exit).
    let report = authn_testkit::timing::compare_timings(
        30,
        || async {
            let _ = f
                .protection
                .check_attempt(&attempt("exists@example.com", Some(user)), &ctx)
                .await;
        },
        || async {
            let _ = f
                .protection
                .check_attempt(&attempt("ghost@example.com", None), &ctx)
                .await;
        },
    )
    .await;
    report.assert_indistinguishable(0.5);
}

/// Regression (security review): the per-identifier budgets used to be
/// *peeked* before verification and *counted* only after a failure, so every
/// attempt already in flight passed the check. N concurrent guesses got N
/// password verifications without CAPTCHA or soft lock.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_02_concurrent_attempts_cannot_outrun_the_failure_counters(pool: PgPool) {
    let f = fixture(&pool, &config()); // CAPTCHA after 3, soft lock after 5
    let ctx = ctx("203.0.113.80", Some(ATTACKER_DEVICE));
    let target = "target@example.com";

    // Ten guesses in flight at once, none of them has failed yet.
    let guess = attempt(target, None);
    let results =
        futures::future::join_all((0..10).map(|_| f.protection.check_attempt(&guess, &ctx))).await;
    let passed = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(passed, 3, "only the CAPTCHA-free budget may pass");
    for err in results.iter().filter_map(|r| r.as_ref().err()) {
        assert_eq!(err.code(), codes::protect::CAPTCHA_REQUIRED);
    }

    // With CAPTCHAs solved, the soft-lock budget still bounds what is in
    // flight: 5 - 3 = 2 more, then the lock engages (audited once).
    let mut solved = attempt(target, None);
    solved.captcha_response = Some("pass");
    let results =
        futures::future::join_all((0..10).map(|_| f.protection.check_attempt(&solved, &ctx))).await;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 2);
    for err in results.iter().filter_map(|r| r.as_ref().err()) {
        assert_eq!(err.code(), codes::protect::LOGIN_TEMPORARILY_BLOCKED);
        assert!(err.retry_after().is_some());
    }
    assert_eq!(
        f.ports
            .audit
            .of_kind(SecurityEventKind::SoftLockEngaged)
            .len(),
        1
    );

    // A success gives the reserved budget back (no lock yet for alice).
    let user = create_user(&f, "alice@example.com").await;
    for _ in 0..3 {
        let a = attempt("alice@example.com", Some(user));
        f.protection.check_attempt(&a, &ctx).await.unwrap();
        f.protection.record_success(&a, &ctx).await.unwrap();
    }
    f.protection
        .check_attempt(&attempt("alice@example.com", Some(user)), &ctx)
        .await
        .unwrap();
}

/// Counts limiter operations (work done per request).
struct CountingLimiter {
    inner: Arc<dyn RateLimiter>,
    ops: AtomicUsize,
}

#[async_trait]
impl RateLimiter for CountingLimiter {
    async fn check(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
    ) -> Result<RateLimitDecision, AuthError> {
        self.ops.fetch_add(1, Ordering::SeqCst);
        self.inner.check(key, policy, cost).await
    }

    async fn peek(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> Result<RateLimitDecision, AuthError> {
        self.ops.fetch_add(1, Ordering::SeqCst);
        self.inner.peek(key, policy).await
    }

    async fn reset(&self, key: &RateLimitKey) -> Result<(), AuthError> {
        self.ops.fetch_add(1, Ordering::SeqCst);
        self.inner.reset(key).await
    }
}

/// Regression (security review): `record_failure` did one more limiter
/// write (the per-user velocity counter) when the identifier matched an
/// account — a timing difference on the failed-login path (SES-01).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_03_failure_path_does_the_same_work_for_unknown_accounts(pool: PgPool) {
    let counter = Arc::new(std::sync::Mutex::new(None::<Arc<CountingLimiter>>));
    let slot = counter.clone();
    let f = fixture_with(&pool, &config(), move |inner| {
        let counting = Arc::new(CountingLimiter {
            inner,
            ops: AtomicUsize::new(0),
        });
        *slot.lock().unwrap() = Some(counting.clone());
        counting
    });
    let counting = counter.lock().unwrap().clone().unwrap();
    let user = create_user(&f, "exists@example.com").await;
    let ctx = ctx("203.0.113.81", Some(ATTACKER_DEVICE));

    let mut ops = Vec::new();
    for (identifier, user) in [
        ("exists@example.com", Some(user)),
        ("ghost@example.com", None),
    ] {
        let a = attempt(identifier, user);
        let before = counting.ops.load(Ordering::SeqCst);
        f.protection.check_attempt(&a, &ctx).await.unwrap();
        let checked = counting.ops.load(Ordering::SeqCst);
        f.protection.record_failure(&a, &ctx).await.unwrap();
        let failed = counting.ops.load(Ordering::SeqCst);
        ops.push((checked - before, failed - checked));
    }
    assert_eq!(ops[0], ops[1], "limiter work differs: {ops:?}");
    assert_eq!(ops[0].1, 2, "per-user and per-IP velocity counters");
}
