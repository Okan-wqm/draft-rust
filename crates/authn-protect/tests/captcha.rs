#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! CAPTCHA verifiers against PostgreSQL and a mock provider (PRT-05).

use std::sync::Arc;
use std::time::Duration;

use authn_core::config::protect::{CaptchaConfig, OutboundHttpConfig};
use authn_core::ports::{
    CaptchaChallenge, CaptchaContext, CaptchaProvider, CaptchaVerdict, CaptchaVerifier,
    RateLimitPolicy,
};
use authn_crypto::kdf::KeyRing;
use authn_protect::captcha::{
    CaptchaService, ProofOfWorkCaptcha, SiteVerifyCaptcha, build_captcha_verifier, solve,
};
use authn_protect::outbound::{SsrfSafeHttpClient, StaticResolver};
use authn_testkit::TestPorts;
use authn_testkit::http::{TestRequest, with_request_context};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::StatusCode;
use sqlx::PgPool;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DIFFICULTY: u8 = 8;

fn keys() -> KeyRing {
    KeyRing::derive(&[9_u8; 32]).unwrap()
}

fn pow(pool: &PgPool, ports: &TestPorts) -> ProofOfWorkCaptcha {
    ProofOfWorkCaptcha::new(
        pool.clone(),
        ports.clock.clone(),
        &keys(),
        DIFFICULTY,
        Duration::from_secs(300),
    )
    .unwrap()
}

fn ctx(action: &'static str) -> CaptchaContext {
    CaptchaContext {
        action,
        ip: "198.51.100.8".parse().unwrap(),
    }
}

async fn issue(verifier: &ProofOfWorkCaptcha, action: &'static str) -> String {
    match verifier.issue_challenge(&ctx(action)).await.unwrap() {
        CaptchaChallenge::ProofOfWork {
            challenge,
            difficulty,
            ..
        } => {
            assert_eq!(difficulty, DIFFICULTY);
            challenge
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_05_pow_solution_passes_exactly_once(pool: PgPool) {
    let ports = TestPorts::new();
    let verifier = pow(&pool, &ports);
    let challenge = issue(&verifier, "login").await;
    // Issuance stores nothing (no table flooding through the endpoint).
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM captcha_pow_challenges")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    let response = solve(&challenge, DIFFICULTY);
    assert_eq!(
        verifier.verify(&response, &ctx("login")).await.unwrap(),
        CaptchaVerdict::Passed
    );
    assert_eq!(
        verifier.verify(&response, &ctx("login")).await.unwrap(),
        CaptchaVerdict::Failed,
        "replay"
    );
    // A different solution of the same challenge is a replay too.
    let other = solve_skipping(&challenge, &response);
    assert_eq!(
        verifier.verify(&other, &ctx("login")).await.unwrap(),
        CaptchaVerdict::Failed
    );
}

fn solve_skipping(challenge: &str, first: &str) -> String {
    let first_solution: u64 = first.rsplit_once(':').unwrap().1.parse().unwrap();
    let mut n = first_solution + 1;
    loop {
        let candidate = format!("{challenge}:{n}");
        let digest = authn_crypto::sha256(candidate.as_bytes());
        if authn_protect::captcha::leading_zero_bits(&digest) >= u32::from(DIFFICULTY) {
            return candidate;
        }
        n += 1;
    }
}

/// Regression (security review): the purge job deleted a consumed
/// challenge's single-use record as soon as *its* clock passed the expiry.
/// Another instance whose clock lags behind still accepts the challenge and
/// then finds no record — the spent solution could be replayed.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_05_pow_purge_does_not_reopen_replays_across_clock_skew(pool: PgPool) {
    let lagging = TestPorts::new();
    let ahead = TestPorts::new();
    let behind_verifier = pow(&pool, &lagging);
    let ahead_verifier = pow(&pool, &ahead);
    let challenge = issue(&behind_verifier, "login").await;
    let response = solve(&challenge, DIFFICULTY);
    assert_eq!(
        behind_verifier
            .verify(&response, &ctx("login"))
            .await
            .unwrap(),
        CaptchaVerdict::Passed
    );
    // The other instance's clock is 5 minutes ahead: for it the challenge
    // (TTL 300 s) has expired, and its purge job runs.
    ahead.clock.advance(Duration::from_secs(300));
    lagging.clock.advance(Duration::from_secs(299));
    assert_eq!(ahead_verifier.purge_expired().await.unwrap(), 0);
    // The lagging instance still considers the challenge valid: the replay
    // must fail because the single-use record is still there.
    assert_eq!(
        behind_verifier
            .verify(&response, &ctx("login"))
            .await
            .unwrap(),
        CaptchaVerdict::Failed,
        "replay after purge"
    );
    // Records are removed once the grace has passed everywhere.
    ahead
        .clock
        .advance(authn_protect::captcha::PURGE_GRACE + Duration::from_secs(1));
    assert_eq!(ahead_verifier.purge_expired().await.unwrap(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_05_pow_concurrent_double_spend_passes_once(pool: PgPool) {
    let ports = TestPorts::new();
    let verifier = Arc::new(pow(&pool, &ports));
    let challenge = issue(&verifier, "register").await;
    let response = solve(&challenge, DIFFICULTY);
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let verifier = verifier.clone();
        let response = response.clone();
        tasks.push(tokio::spawn(async move {
            verifier.verify(&response, &ctx("register")).await.unwrap()
        }));
    }
    let mut passed = 0;
    for task in tasks {
        if task.await.unwrap() == CaptchaVerdict::Passed {
            passed += 1;
        }
    }
    assert_eq!(passed, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_05_pow_rejects_forgery_wrong_action_expiry_and_lazy_work(pool: PgPool) {
    let ports = TestPorts::new();
    let verifier = pow(&pool, &ports);

    // Wrong action: a login challenge cannot unlock registration.
    let challenge = issue(&verifier, "login").await;
    let response = solve(&challenge, DIFFICULTY);
    assert_eq!(
        verifier.verify(&response, &ctx("register")).await.unwrap(),
        CaptchaVerdict::Failed
    );

    // Forged: lower the difficulty inside the payload (MAC no longer matches).
    let (payload_b64, tag_b64) = challenge.split_once('.').unwrap();
    let mut payload = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    payload[33] = 1;
    let forged = format!("{}.{tag_b64}", URL_SAFE_NO_PAD.encode(&payload));
    assert_eq!(
        verifier
            .verify(&solve(&forged, 1), &ctx("login"))
            .await
            .unwrap(),
        CaptchaVerdict::Failed
    );
    // Challenge signed with another key.
    let foreign = ProofOfWorkCaptcha::new(
        pool.clone(),
        ports.clock.clone(),
        &KeyRing::derive(&[1_u8; 32]).unwrap(),
        DIFFICULTY,
        Duration::from_secs(300),
    )
    .unwrap();
    let foreign_challenge = issue(&foreign, "login").await;
    assert_eq!(
        verifier
            .verify(&solve(&foreign_challenge, DIFFICULTY), &ctx("login"))
            .await
            .unwrap(),
        CaptchaVerdict::Failed
    );

    // Insufficient work: a solution that does not meet the difficulty.
    let challenge = issue(&verifier, "login").await;
    let lazy = (0..10_000_u32)
        .map(|n| format!("{challenge}:{n}"))
        .find(|c| {
            authn_protect::captcha::leading_zero_bits(&authn_crypto::sha256(c.as_bytes()))
                < u32::from(DIFFICULTY)
        })
        .unwrap();
    assert_eq!(
        verifier.verify(&lazy, &ctx("login")).await.unwrap(),
        CaptchaVerdict::Failed
    );

    // Expired.
    let challenge = issue(&verifier, "login").await;
    let response = solve(&challenge, DIFFICULTY);
    ports.clock.advance(Duration::from_secs(301));
    assert_eq!(
        verifier.verify(&response, &ctx("login")).await.unwrap(),
        CaptchaVerdict::Failed
    );

    // Malformed input never errors.
    for junk in [
        "",
        ":",
        "a:b",
        "....:1",
        "x.y:1",
        &format!("{challenge}:"),
        &format!("{challenge}: 1"),
        &format!("{challenge}:{}", "9".repeat(65)),
        &"a".repeat(10_000),
        "ünïcödé:1",
    ] {
        assert_eq!(
            verifier.verify(junk, &ctx("login")).await.unwrap(),
            CaptchaVerdict::Failed,
            "{junk}"
        );
    }
    assert_eq!(verifier.purge_expired().await.unwrap(), 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_05_challenge_endpoint_serves_pow_challenges(pool: PgPool) {
    let ports = TestPorts::new();
    let config = CaptchaConfig {
        provider: CaptchaProvider::ProofOfWork,
        pow_difficulty: DIFFICULTY,
        challenge_per_ip: RateLimitPolicy::new(3, Duration::from_secs(60)),
        ..CaptchaConfig::default()
    };
    let verifier = build_captcha_verifier(
        &config,
        ports.http.clone(),
        pool.clone(),
        ports.clock.clone(),
        &keys(),
    )
    .unwrap();
    let service = CaptchaService::new(
        verifier.clone(),
        ports.rate_limiter.clone(),
        ports.audit.clone(),
        ports.clock.clone(),
        &config,
    );
    let app = with_request_context(authn_protect::router().with_state(service));

    let res = TestRequest::get("/v1/captcha/challenge?action=login")
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: serde_json::Value = res.json();
    assert_eq!(body["type"], "proof_of_work");
    assert_eq!(body["difficulty"], 8);
    assert_eq!(body["expires_at"], "2026-01-01T00:05:00Z");
    let challenge = body["challenge"].as_str().unwrap();
    assert_eq!(
        verifier
            .verify(&solve(challenge, DIFFICULTY), &ctx("login"))
            .await
            .unwrap(),
        CaptchaVerdict::Passed
    );

    TestRequest::get("/v1/captcha/challenge?action=drop_tables")
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    TestRequest::get("/v1/captcha/challenge")
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    TestRequest::get("/v1/captcha/challenge?action=login")
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    TestRequest::get("/v1/captcha/challenge?action=login")
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    let res = TestRequest::get("/v1/captcha/challenge?action=login")
        .send(&app)
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(res.header("retry-after").is_some());
}

#[tokio::test]
async fn prt_05_turnstile_through_the_ssrf_safe_client() {
    let provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string_contains("response=good"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"success": true, "action": "login"})),
        )
        .mount(&provider)
        .await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string_contains("response=used"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"success": false, "error-codes": ["timeout-or-duplicate"]}),
        ))
        .mount(&provider)
        .await;
    let http = Arc::new(
        SsrfSafeHttpClient::with_resolver(
            &OutboundHttpConfig::default(),
            Arc::new(StaticResolver::new()),
        )
        .unwrap(),
    );
    let verify_url = format!("{}/siteverify", provider.uri());
    let make = |url: &str| {
        SiteVerifyCaptcha::new(
            CaptchaProvider::Turnstile,
            "0x4AAAA".to_owned(),
            authn_core::secret::SecretString::from("0x4AAAA-secret".to_owned()),
            Some(url),
            http.clone(),
        )
        .unwrap()
    };
    let verifier = make(&verify_url);
    assert_eq!(
        verifier.verify("good", &ctx("login")).await.unwrap(),
        CaptchaVerdict::Passed
    );
    assert_eq!(
        verifier.verify("used", &ctx("login")).await.unwrap(),
        CaptchaVerdict::Failed
    );
    // Provider unreachable (closed port) → Unavailable, never Passed.
    let down = make("http://127.0.0.1:1/siteverify");
    assert_eq!(
        down.verify("good", &ctx("login")).await.unwrap(),
        CaptchaVerdict::Unavailable
    );
}
