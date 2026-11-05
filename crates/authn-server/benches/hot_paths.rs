#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    missing_docs
)] // bench target
//! Hot-path latency benchmarks (K-70), single caller, release profile:
//!
//! ```bash
//! cargo bench -p authn-server --bench hot_paths              # everything
//! cargo bench -p authn-server --bench hot_paths -- jwt/      # a filter
//! cargo bench -p authn-server --features redis --bench hot_paths   # + Redis
//! AUTHN_BENCH_ITERS=500 cargo bench -p authn-server --bench hot_paths
//! ```
//!
//! Without `--bench` (`cargo test -p authn-server --benches`) every case
//! runs twice as a functional smoke test and nothing is measured.
//!
//! Cases: JWT EdDSA sign / verify (pure and through the signing-key
//! cache), the per-request session check (bearer, cookie), rate-limit
//! decisions (memory, PostgreSQL, Redis), Argon2id at the OWASP parameter
//! sets, and full HTTP requests through the real router and every
//! middleware: cheap authenticated `GET`, `GET /v1/me`, refresh rotation,
//! introspection, native password login (production Argon2id) and passkey
//! login (assertion verification). Needs PostgreSQL (`DATABASE_URL`); a
//! scratch database is created and dropped. Results and their caveats:
//! `docs/operations/performance.md`.

#[path = "../tests/common/mod.rs"]
mod common;
#[path = "../tests/perf/mod.rs"]
mod perf;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use authn_core::config::crypto::Argon2Config;
use authn_core::ports::{Clock, RateLimitKey, RateLimitPolicy, RateLimiter, SystemClock};
use authn_core::secret::SecretString;
use authn_crypto::jwt::{JwtSigner, JwtValidation, JwtVerifier, TYP_ACCESS_TOKEN};
use authn_crypto::password::PasswordHasher;
use authn_crypto::signing::Ed25519SigningKey;
use authn_session::AccessTokenClaims;
use authn_testkit::bench::{BenchMode, bench_async, bench_sync};
use axum::http::StatusCode;
use common::{App, PASSWORD};
use perf::{ScratchDatabase, Tokens, client_ip};

/// Next distinct client IP (rate-limit buckets are per IP).
static NEXT_IP: AtomicUsize = AtomicUsize::new(10_000);

fn next_ip() -> std::net::IpAddr {
    client_ip(NEXT_IP.fetch_add(1, Ordering::Relaxed))
}

fn main() {
    let mode = BenchMode::from_args();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(run(mode));
}

async fn run(mode: BenchMode) {
    authn_core::tls::install_crypto_provider();
    if mode == BenchMode::Measure {
        println!(
            "hot_paths: {} CPUs, single caller; release profile",
            std::thread::available_parallelism().map_or(0, std::num::NonZero::get)
        );
    }
    jwt(mode);
    argon2(mode).await;

    let db = ScratchDatabase::create().await;
    {
        let pool = db.pool(20).await;
        let app = perf::production_app(pool, true).await;
        // perf0..3: native logins; perf4: passkey (its first web login
        // must not look like a new device of a known user, RSK-03).
        perf::users(&app, 5).await;
        session_and_http(mode, &app).await;
        rate_limits(mode, &app).await;
        #[cfg(feature = "passkey")]
        passkey(mode, &app).await;
        app.pool.close().await;
    }
    db.drop_database().await;
}

/// Pure JWT cost: EdDSA signature + strict JSON parsing + claim checks.
fn jwt(mode: BenchMode) {
    let key = Ed25519SigningKey::generate().unwrap();
    let verifier = JwtVerifier::new([("k1".to_owned(), key.public_key())]);
    let signer = JwtSigner::new("k1", key).unwrap();
    let now = time::OffsetDateTime::now_utc();
    let claims = AccessTokenClaims {
        iss: "https://auth.test.example".into(),
        sub: uuid::Uuid::now_v7().to_string(),
        aud: vec!["https://auth.test.example".into()],
        exp: now.unix_timestamp() + 900,
        iat: now.unix_timestamp(),
        nbf: now.unix_timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        sid: uuid::Uuid::now_v7().to_string(),
        auth_time: now.unix_timestamp(),
        amr: vec![authn_core::domain::AuthMethodRef::Pwd],
        acr: None,
        org_id: None,
        scope: String::new(),
        client_id: "first-party".into(),
        act: None,
        read_only: None,
    };
    let token = signer.sign(TYP_ACCESS_TOKEN, &claims).unwrap();
    let validation =
        JwtValidation::access_token("https://auth.test.example", "https://auth.test.example")
            .with_max_lifetime(Duration::from_secs(900));
    bench_sync("jwt/sign_access_token", mode, 5_000, || {
        signer.sign(TYP_ACCESS_TOKEN, &claims).unwrap()
    });
    bench_sync("jwt/verify_access_token", mode, 5_000, || {
        verifier
            .verify::<AccessTokenClaims>(&token, &validation, now)
            .unwrap()
    });
}

/// Argon2id hash / verify at the OWASP Password Storage Cheat Sheet
/// parameter sets (all equivalent in strength by OWASP's reckoning) and
/// the RFC 9106 second recommendation. The project default (CRY-01) is
/// `m=19456 KiB, t=2, p=1`.
async fn argon2(mode: BenchMode) {
    let sets: [(u32, u32, u32, &str); 6] = [
        (19_456, 2, 1, "default/owasp-2"),
        (47_104, 1, 1, "owasp-1"),
        (12_288, 3, 1, "owasp-3"),
        (9_216, 4, 1, "owasp-4"),
        (7_168, 5, 1, "owasp-5"),
        (65_536, 3, 4, "rfc9106-2"),
    ];
    let password = SecretString::from(PASSWORD.to_owned());
    for (memory_kib, iterations, parallelism, label) in sets {
        let mut config = authn_testkit::config::test_config().crypto;
        config.argon2 = Argon2Config {
            memory_kib,
            iterations,
            parallelism,
        };
        let hasher = PasswordHasher::from_config(&config).await.unwrap();
        let record = hasher.hash(&password).await.unwrap();
        let stored = authn_crypto::password::StoredPasswordHash::new(
            &record.hash,
            record.algorithm.as_str(),
            record.pepper_version,
        );
        let name = format!("argon2/verify m={memory_kib} t={iterations} p={parallelism} ({label})");
        bench_async(&name, mode, 30, || hasher.verify(&password, Some(&stored))).await;
        if label.starts_with("default") {
            argon2_throughput(
                mode,
                &hasher,
                &password,
                &stored,
                config.max_concurrent_hashes,
            )
            .await;
        }
    }
}

/// The login ceiling of one instance: verifications per second with every
/// hashing permit busy (`crypto.max_concurrent_hashes`, ARC-12).
async fn argon2_throughput(
    mode: BenchMode,
    hasher: &PasswordHasher,
    password: &SecretString,
    stored: &authn_crypto::password::StoredPasswordHash,
    permits: u32,
) {
    if !authn_testkit::bench::selected("argon2/throughput") {
        return;
    }
    let total = mode.iterations(120);
    let start = std::time::Instant::now();
    let jobs = (0..total).map(|_| hasher.verify(password, Some(stored)));
    for outcome in futures::future::join_all(jobs).await {
        assert!(outcome.unwrap().is_valid());
    }
    let elapsed = start.elapsed();
    if mode == BenchMode::Measure {
        println!(
            "{:<44} {:.1} verifications/s ({total} with {permits} permits in {})",
            "argon2/throughput (default, all permits busy)",
            total as f64 / elapsed.as_secs_f64(),
            authn_testkit::bench::fmt_duration(elapsed),
        );
    }
}

async fn login(app: &App, user: usize) -> Tokens {
    let n = NEXT_IP.fetch_add(1, Ordering::Relaxed);
    let r = app
        .send(perf::native_login_request(user, perf::user_ip(user, n)))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let body: serde_json::Value = r.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    Tokens::from_body(&body)
}

async fn session_and_http(mode: BenchMode, app: &App) {
    let tokens = login(app, 0).await;
    let sessions = app.services.sessions.clone();

    bench_async(
        "session/verify_access_token (key cache)",
        mode,
        5_000,
        || {
            let sessions = sessions.clone();
            let token = tokens.access.clone();
            async move { sessions.verify_access_token(&token).await.unwrap() }
        },
    )
    .await;
    bench_async(
        "session/authenticate_bearer (verify + DB)",
        mode,
        3_000,
        || {
            let sessions = sessions.clone();
            let token = tokens.access.clone();
            async move { sessions.authenticate_bearer(&token).await.unwrap() }
        },
    )
    .await;

    bench_async("http/GET /v1/time (bearer)", mode, 3_000, || {
        let request = perf::bearer_get("/v1/time", &tokens.access, next_ip());
        async move { app.send(request).await.assert_status(StatusCode::OK).status }
    })
    .await;
    bench_async("http/GET /v1/me (bearer)", mode, 2_000, || {
        let request = perf::bearer_get("/v1/me", &tokens.access, next_ip());
        async move { app.send(request).await.assert_status(StatusCode::OK).status }
    })
    .await;

    // Refresh rotation: every iteration consumes the previous token.
    let current = Arc::new(std::sync::Mutex::new(login(app, 1).await.refresh));
    bench_async(
        "http/POST /v1/token/refresh (rotation)",
        mode,
        1_000,
        || {
            let refresh = current.lock().unwrap().clone();
            let current = current.clone();
            let request = perf::refresh_request(&refresh, next_ip());
            async move {
                let r = app.send(request).await;
                assert_eq!(r.status, StatusCode::OK, "{}", r.text());
                *current.lock().unwrap() = Tokens::from_body(&r.json()).refresh;
            }
        },
    )
    .await;

    // Introspection of an organization token with an API key.
    let owner = app.services.pool.clone();
    let owner_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM users WHERE email_normalized = 'perf2@example.com'")
            .fetch_one(&owner)
            .await
            .unwrap();
    let (org, key) = perf::org_with_api_key(app, authn_core::id::UserId::from_uuid(owner_id)).await;
    let org_tokens = perf::switch_org(app, &login(app, 2).await, org, next_ip()).await;
    bench_async(
        "http/POST /v1/token/introspect (active)",
        mode,
        2_000,
        || {
            let request = perf::introspect_request(&key, &org_tokens.access, next_ip());
            async move { app.send(request).await.assert_status(StatusCode::OK).status }
        },
    )
    .await;

    // Native password login with the production Argon2id parameters.
    let user = AtomicUsize::new(0);
    bench_async(
        "http/POST /v1/login/password (native, argon2 default)",
        mode,
        100,
        || {
            let u = user.fetch_add(1, Ordering::Relaxed) % 4;
            let n = NEXT_IP.fetch_add(1, Ordering::Relaxed);
            let request = perf::native_login_request(u, perf::user_ip(u, n));
            async move {
                let r = app.send(request).await;
                assert_eq!(r.status, StatusCode::OK, "{}", r.text());
                assert_eq!(r.json::<serde_json::Value>()["status"], "authenticated");
            }
        },
    )
    .await;
}

async fn rate_limits(mode: BenchMode, app: &App) {
    let policy = RateLimitPolicy::new(1_000_000_000, Duration::from_secs(60));
    let hasher = authn_protect::keys::KeyHasher::new(&app.services.crypto.keys).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let memory: Arc<dyn RateLimiter> = Arc::new(authn_protect::rate_limit::MemoryRateLimiter::new(
        clock.clone(),
        hasher.clone(),
    ));
    let postgres: Arc<dyn RateLimiter> =
        Arc::new(authn_protect::rate_limit::PostgresRateLimiter::new(
            app.pool.clone(),
            clock.clone(),
            hasher.clone(),
        ));
    let mut backends = vec![("memory", memory), ("postgres", postgres)];
    #[cfg(feature = "redis")]
    {
        let url = std::env::var("AUTHN_BENCH_REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_owned());
        match authn_protect::rate_limit::RedisRateLimiter::connect(
            &SecretString::from(url),
            clock.clone(),
            hasher.clone(),
        )
        .await
        {
            Ok(redis) => backends.push(("redis", Arc::new(redis))),
            Err(err) => println!("ratelimit/redis skipped: {err}"),
        }
    }
    for (name, limiter) in backends {
        let hot = RateLimitKey::ip("bench_hot", client_ip(1));
        bench_async(
            &format!("ratelimit/{name} (one hot key)"),
            mode,
            3_000,
            || {
                let limiter = limiter.clone();
                let key = hot.clone();
                async move { limiter.check(&key, policy, 1).await.unwrap() }
            },
        )
        .await;
        bench_async(
            &format!("ratelimit/{name} (new key each)"),
            mode,
            3_000,
            || {
                let limiter = limiter.clone();
                let key = RateLimitKey::ip("bench_new", next_ip());
                async move { limiter.check(&key, policy, 1).await.unwrap() }
            },
        )
        .await;
    }
}

#[cfg(feature = "passkey")]
async fn passkey(mode: BenchMode, app: &App) {
    use common::{Browser, ORIGIN};
    use serde_json::{Value, json};
    use url::Url;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs_proto::{
        AllowCredentials, CreationChallengeResponse, RequestChallengeResponse,
    };

    let mut browser = app.browser();
    let body = browser.login(app, "perf4@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    let r = browser
        .send(
            app,
            browser.post("/v1/me/passkeys/registration/options", &json!({})),
        )
        .await;
    let start: Value = r.json();
    let ccr: CreationChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    let mut key = SoftPasskey::new(true);
    let credential = key
        .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
        .unwrap();
    let raw_id = credential.raw_id.clone();
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/me/passkeys/registration/verify",
                &json!({"ceremony_id": start["ceremony_id"], "credential": credential}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let (handle,): (Vec<u8>,) = sqlx::query_as(
        "SELECT h.user_handle FROM webauthn_user_handles h JOIN users u ON u.id = h.user_id \
         WHERE u.email_normalized = 'perf4@example.com'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();

    // Ceremonies and client-side signatures are prepared up front, in
    // order (the signature counter must increase); only the server's
    // verification request is timed.
    let count = mode.iterations(200) + mode.warmup(mode.iterations(200));
    let mut prepared = std::collections::VecDeque::with_capacity(count);
    for _ in 0..count {
        // One client IP per simulated browser (per-IP limits, PRT-01).
        let ip = next_ip();
        let mut other = Browser::default();
        let r = other.send(app, other.get("/v1/csrf").peer_ip(ip)).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let r = other
            .send(
                app,
                other
                    .post("/v1/login/passkey/options", &json!({}))
                    .peer_ip(ip),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        let options: Value = r.json();
        let mut rcr: RequestChallengeResponse =
            serde_json::from_value(options["options"].clone()).unwrap();
        rcr.public_key.allow_credentials = vec![AllowCredentials {
            type_: "public-key".to_owned(),
            id: raw_id.clone(),
            transports: None,
        }];
        let mut assertion = key
            .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
            .unwrap();
        assertion.response.user_handle = Some(handle.clone());
        let request = other
            .post(
                "/v1/login/passkey",
                &json!({"ceremony_id": options["ceremony_id"], "credential": assertion}),
            )
            .peer_ip(ip);
        prepared.push_back(request);
    }
    let prepared = std::sync::Mutex::new(prepared);
    let web_session = std::sync::Mutex::new(None::<Browser>);
    bench_async(
        "http/POST /v1/login/passkey (assertion verify)",
        mode,
        200,
        || {
            let request = prepared.lock().unwrap().pop_front().unwrap();
            let web_session = &web_session;
            async move {
                let r = app.send(request).await;
                assert_eq!(r.status, StatusCode::OK, "{}", r.text());
                let mut b = Browser::default();
                b.absorb(&r);
                *web_session.lock().unwrap() = Some(b);
            }
        },
    )
    .await;

    // The per-request cookie session check (web).
    let Some(browser) = web_session.lock().unwrap().clone() else {
        return; // the passkey case was filtered out: no web session
    };
    bench_async("http/GET /v1/time (session cookie)", mode, 3_000, || {
        let request = browser.get("/v1/time").peer_ip(next_ip());
        async move { app.send(request).await.assert_status(StatusCode::OK).status }
    })
    .await;
}
