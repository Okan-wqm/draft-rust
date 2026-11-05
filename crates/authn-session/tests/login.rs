#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Login flows over HTTP (SES-01, SES-02, SES-18 … SES-22, RSK-03, RSK-04,
//! MFA-09): the real session router behind the authentication middleware,
//! the real wave-A services and PostgreSQL.

mod common;

use std::time::Duration;

use authn_core::domain::{AccountStatus, AuthMethodRef, EmailAddress, FactorKind};
use authn_core::id::UserId;
use authn_core::ports::{NotificationKind, RiskAssessment, RiskLevel, RiskReason};
use authn_core::secret::SecretString;
use authn_session::cookies::{CHALLENGE_COOKIE, PRE_SESSION_COOKIE, SESSION_COOKIE};
use authn_store::{NewUser, UserRepository};
use authn_testkit::http::{TestRequest, TestResponse};
use axum::http::StatusCode;
use common::browser::{Browser, native, native_challenge, status_of};
use common::{Harness, ORIGIN, PASSWORD, empty_policy};
use serde_json::{Value, json};
use sqlx::PgPool;

const WRONG: &str = "definitely not the password 99";

fn password_body(email: &str, password: &str) -> Value {
    json!({ "email": email, "password": password })
}

async fn web_password_login(h: &Harness, browser: &mut Browser, email: &str) -> TestResponse {
    browser
        .send(
            h,
            browser.post("/v1/login/password", &password_body(email, PASSWORD)),
        )
        .await
}

/// `GET /v1/me` with the browser's session.
async fn me_status(h: &Harness, browser: &Browser) -> StatusCode {
    h.send(browser.get("/v1/me")).await.status
}

async fn unverified_user(h: &Harness, email: &str, with_password: bool) -> UserId {
    let id = UserId::generate();
    let mut conn = h.pool.acquire().await.unwrap();
    UserRepository::create(
        &mut conn,
        &NewUser {
            id,
            email: EmailAddress::parse(email).unwrap(),
            status: AccountStatus::PendingVerification,
            created_at: h.now(),
        },
    )
    .await
    .unwrap();
    if with_password {
        let record = h
            .crypto
            .passwords
            .hash(&SecretString::from(PASSWORD.to_owned()))
            .await
            .unwrap();
        UserRepository::set_password(
            &mut conn,
            id,
            &authn_store::NewPasswordHash {
                password_hash: &record.hash,
                algorithm: record.algorithm.as_str(),
                pepper_version: record.pepper_version,
            },
            false,
            h.now(),
        )
        .await
        .unwrap();
    }
    id
}

async fn set_status(h: &Harness, user: UserId, status: &str) {
    sqlx::query("UPDATE users SET status = $2 WHERE id = $1")
        .bind(user)
        .bind(status)
        .execute(&h.pool)
        .await
        .unwrap();
}

async fn set_must_change(h: &Harness, user: UserId) {
    sqlx::query("UPDATE password_credentials SET must_change = true WHERE user_id = $1")
        .bind(user)
        .execute(&h.pool)
        .await
        .unwrap();
}

fn medium_risk() -> RiskAssessment {
    RiskAssessment {
        level: RiskLevel::Medium,
        reasons: vec![RiskReason::NewNetwork],
    }
}

fn high_risk() -> RiskAssessment {
    RiskAssessment {
        level: RiskLevel::High,
        reasons: vec![RiskReason::ImpossibleTravel],
    }
}

fn magic_link_token(h: &Harness) -> String {
    h.ports
        .notifier
        .recorded()
        .into_iter()
        .rev()
        .find_map(|n| match n.kind {
            NotificationKind::MagicLink { token, .. } => Some(token.expose().to_owned()),
            _ => None,
        })
        .expect("a magic link was sent")
}

fn login_code(h: &Harness) -> String {
    h.ports
        .notifier
        .recorded()
        .into_iter()
        .rev()
        .find_map(|n| match n.kind {
            NotificationKind::LoginCode { code, .. } => Some(code.expose().to_owned()),
            _ => None,
        })
        .expect("a login code was sent")
}

fn count_kind(h: &Harness, template: &str) -> usize {
    h.ports.notifier.with_template(template).len()
}

async fn active_sessions(h: &Harness, user: UserId) -> i64 {
    h.count(
        "SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL",
        user.as_uuid(),
    )
    .await
}

// ---------------------------------------------------------------------------
// SES-01 password login
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_web_password_login_sets_a_session_cookie(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mut browser = Browser::new(&h);
    let response = web_password_login(&h, &mut browser, "Alice@Example.com").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["status"], "authenticated");
    assert_eq!(body["user_id"], json!(alice));
    assert_eq!(body["amr"], json!(["pwd"]));
    assert!(body.get("access_token").is_none(), "web gets no tokens");
    assert!(browser.has(SESSION_COOKIE));
    assert!(
        !browser.has(PRE_SESSION_COOKIE),
        "pre-session cookie cleared"
    );
    assert_eq!(response.header("cache-control"), Some("no-store"));
    assert_eq!(me_status(&h, &browser).await, StatusCode::OK);
    // login.succeeded is audited with the method.
    assert!(
        !h.ports
            .audit
            .of_kind(authn_core::ports::SecurityEventKind::LoginSucceeded)
            .is_empty()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_native_password_login_returns_tokens(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let response = h
        .send(native(
            "/v1/login/password",
            &password_body("alice@example.com", PASSWORD),
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["client_kind"], "native");
    let access = body["access_token"].as_str().unwrap();
    assert!(body["refresh_token"].as_str().is_some());
    assert!(response.set_cookies().is_empty(), "native gets no cookies");
    h.send(TestRequest::get("/v1/me").bearer(access))
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_every_credential_failure_is_identical(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    unverified_user(&h, "placeholder@example.com", false).await;
    let cases = [
        ("alice@example.com", WRONG),
        ("nobody@example.com", PASSWORD),
        ("not an address", PASSWORD),
        ("placeholder@example.com", PASSWORD),
    ];
    let mut bodies = Vec::new();
    for (email, password) in cases {
        let mut browser = Browser::new(&h);
        let response = browser
            .send(
                &h,
                browser.post("/v1/login/password", &password_body(email, password)),
            )
            .await;
        let error = response.assert_error(StatusCode::UNAUTHORIZED, "invalid_credentials");
        assert!(!browser.has(SESSION_COOKIE));
        let mut body: Value = response.json();
        body["error"]["request_id"] = Value::Null;
        bodies.push((body, error.code));
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_unknown_account_takes_as_long_as_a_wrong_password(pool: PgPool) {
    // Budgets high enough that every sample reaches the password check.
    let h = Harness::with(pool, |c| {
        c.protect.rate_limit.login_per_account_captcha =
            authn_core::ports::RateLimitPolicy::new(1000, Duration::from_secs(900));
        c.protect.rate_limit.login_per_account_soft_lock =
            authn_core::ports::RateLimitPolicy::new(1000, Duration::from_secs(900));
        c.protect.rate_limit.login_per_ip =
            authn_core::ports::RateLimitPolicy::new(1000, Duration::from_secs(900));
    })
    .await;
    h.user("alice@example.com").await;
    let report = authn_testkit::timing::compare_timings_repeated(
        3,
        41,
        0.35,
        || async {
            let b = Browser::new(&h);
            h.send(b.post(
                "/v1/login/password",
                &password_body("alice@example.com", WRONG),
            ))
            .await;
        },
        || async {
            let b = Browser::new(&h);
            h.send(b.post(
                "/v1/login/password",
                &password_body("nobody@example.com", WRONG),
            ))
            .await;
        },
    )
    .await;
    report.assert_indistinguishable(0.35);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_account_status_is_revealed_only_after_a_correct_password(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    set_status(&h, alice, "suspended").await;
    let mut browser = Browser::new(&h);
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/password",
                &password_body("alice@example.com", WRONG),
            ),
        )
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_credentials");
    let response = web_password_login(&h, &mut browser, "alice@example.com").await;
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "{}",
        response.text()
    );
    assert_eq!(response.error().code, "account_suspended");
    assert!(!browser.has(SESSION_COOKIE));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_web_login_requires_the_login_csrf_proof(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    // No pre-session cookie / token.
    h.send(
        TestRequest::post("/v1/login/password")
            .json(&password_body("alice@example.com", PASSWORD))
            .header("origin", ORIGIN),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    // Cross-site origin with an otherwise valid proof.
    let browser = Browser::new(&h);
    let mut request = TestRequest::post("/v1/login/password")
        .json(&password_body("alice@example.com", PASSWORD))
        .header("origin", "https://evil.example")
        .header("x-csrf-token", &browser.csrf);
    for (name, value) in &browser.cookies {
        request = request.cookie(name, value);
    }
    h.send(request)
        .await
        .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_repeated_failures_escalate_to_captcha(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let budget = h.config.protect.rate_limit.login_per_account_captcha.limit;
    for _ in 0..budget {
        let b = Browser::new(&h);
        h.send(b.post(
            "/v1/login/password",
            &password_body("alice@example.com", WRONG),
        ))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_credentials");
    }
    let mut b = Browser::new(&h);
    let response = b
        .send(
            &h,
            b.post(
                "/v1/login/password",
                &password_body("alice@example.com", PASSWORD),
            ),
        )
        .await;
    assert_eq!(
        response.error().code,
        "captcha_required",
        "{}",
        response.text()
    );
    // The same escalation for an address without an account (no oracle).
    for _ in 0..budget {
        let b = Browser::new(&h);
        h.send(b.post(
            "/v1/login/password",
            &password_body("ghost@example.com", WRONG),
        ))
        .await;
    }
    let b = Browser::new(&h);
    let ghost = h
        .send(b.post(
            "/v1/login/password",
            &password_body("ghost@example.com", WRONG),
        ))
        .await;
    assert_eq!(ghost.error().code, "captcha_required");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_concurrent_guesses_cannot_outrun_the_captcha_budget(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let budget = h.config.protect.rate_limit.login_per_account_captcha.limit as usize;
    let attempts = budget + 6;
    let futures = (0..attempts).map(|_| {
        let b = Browser::new(&h);
        h.send(b.post(
            "/v1/login/password",
            &password_body("alice@example.com", WRONG),
        ))
    });
    let responses = futures::future::join_all(futures).await;
    let verified = responses
        .iter()
        .filter(|r| r.status == StatusCode::UNAUTHORIZED)
        .count();
    assert!(
        verified <= budget,
        "{verified} password checks for a budget of {budget}"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_successful_login_refunds_the_failure_budget(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let budget = h.config.protect.rate_limit.login_per_account_captcha.limit;
    for round in 0..3 {
        for _ in 0..budget - 1 {
            let b = Browser::new(&h);
            h.send(b.post(
                "/v1/login/password",
                &password_body("alice@example.com", WRONG),
            ))
            .await;
        }
        let mut b = Browser::new(&h);
        web_password_login(&h, &mut b, "alice@example.com")
            .await
            .assert_status(StatusCode::OK);
        assert!(b.has(SESSION_COOKIE), "round {round}");
    }
}

// ---------------------------------------------------------------------------
// SES-02 MFA challenge
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_totp_user_gets_a_challenge_then_a_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let mut browser = Browser::new(&h);
    let response = web_password_login(&h, &mut browser, "alice@example.com").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["status"], "challenge_required");
    assert_eq!(body["required_actions"], json!(["verify_mfa"]));
    assert!(
        body["allowed_factors"]
            .as_array()
            .unwrap()
            .contains(&json!("totp"))
    );
    assert!(
        body.get("challenge_token").is_none(),
        "web: token only in cookie"
    );
    assert!(browser.has(CHALLENGE_COOKIE));
    assert!(
        !browser.has(SESSION_COOKIE),
        "no session before the second factor"
    );
    assert_eq!(me_status(&h, &browser).await, StatusCode::UNAUTHORIZED);

    let code = h.totp_code(&secret);
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": code}),
            ),
        )
        .await;
    done.assert_status(StatusCode::OK);
    let body: Value = done.json();
    assert_eq!(body["status"], "authenticated");
    assert_eq!(body["amr"], json!(["pwd", "otp", "mfa"]));
    assert!(browser.has(SESSION_COOKIE));
    assert!(!browser.has(CHALLENGE_COOKIE), "challenge cookie cleared");
    assert_eq!(me_status(&h, &browser).await, StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_native_challenge_with_recovery_code(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    h.enroll_totp(alice).await;
    let codes = h
        .mfa
        .regenerate_recovery_codes(&h.ctx(), &h.fresh(alice))
        .await
        .unwrap();
    let response = h
        .send(native(
            "/v1/login/password",
            &password_body("alice@example.com", PASSWORD),
        ))
        .await;
    let body: Value = response.json();
    assert_eq!(body["status"], "challenge_required");
    let token = body["challenge_token"].as_str().unwrap().to_owned();
    let recovery = codes.codes[0].as_str().to_owned();
    let done = h
        .send(native_challenge(
            "/v1/login/challenge/verify",
            &json!({"method": "recovery_code", "code": recovery}),
            &token,
        ))
        .await;
    done.assert_status(StatusCode::OK);
    let body: Value = done.json();
    assert_eq!(body["status"], "authenticated");
    assert!(body["access_token"].as_str().is_some());
    assert!(body["amr"].as_array().unwrap().contains(&json!("mfa")));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_a_factor_outside_allowed_factors_is_refused_before_verification(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let codes = h
        .mfa
        .regenerate_recovery_codes(&h.ctx(), &h.fresh(alice))
        .await
        .unwrap();
    // The organization allows TOTP only.
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let mut policy = empty_policy();
    policy.allowed_mfa_factors = Some(vec![FactorKind::Totp]);
    h.set_policy(owner, org, policy).await;

    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(body["allowed_factors"], json!(["totp"]));
    // A valid recovery code is still refused (and not consumed).
    let recovery = codes.codes[0].as_str().to_owned();
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "recovery_code", "code": recovery}),
            ),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    let status = h.mfa.recovery_codes_status(&h.fresh(alice)).await.unwrap();
    assert_eq!(
        status.remaining, 10,
        "the recovery code was never evaluated"
    );
    // SMS was never enrolled nor allowed.
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "sms", "code": "123456"}),
            ),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    // The allowed factor works.
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret)}),
            ),
        )
        .await;
    assert_eq!(status_of(&done), "authenticated", "{}", done.text());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_challenge_is_single_use(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let response = h
        .send(native(
            "/v1/login/password",
            &password_body("alice@example.com", PASSWORD),
        ))
        .await;
    let token = response.json::<Value>()["challenge_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let code = h.totp_code(&secret);
    h.send(native_challenge(
        "/v1/login/challenge/verify",
        &json!({"method": "totp", "code": code}),
        &token,
    ))
    .await
    .assert_status(StatusCode::OK);
    h.advance(Duration::from_secs(30));
    let code = h.totp_code(&secret);
    h.send(native_challenge(
        "/v1/login/challenge/verify",
        &json!({"method": "totp", "code": code}),
        &token,
    ))
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "challenge_invalid");
    assert_eq!(active_sessions(&h, alice).await, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_wrong_codes_burn_the_challenge(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let response = h
        .send(native(
            "/v1/login/password",
            &password_body("alice@example.com", PASSWORD),
        ))
        .await;
    let token = response.json::<Value>()["challenge_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let max = h.config.session.challenge_max_attempts;
    let mut last = None;
    for _ in 0..max {
        let r = h
            .send(native_challenge(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": "000000"}),
                &token,
            ))
            .await;
        last = Some(r.error().code);
    }
    // The last failure burns the challenge (or the MFA lock kicks in).
    let last = last.unwrap();
    assert!(
        ["challenge_invalid", "too_many_attempts"].contains(&last.as_str()),
        "{last}"
    );
    let r = h
        .send(native_challenge(
            "/v1/login/challenge/verify",
            &json!({"method": "totp", "code": h.totp_code(&secret)}),
            &token,
        ))
        .await;
    assert_ne!(
        r.status,
        StatusCode::OK,
        "a burnt challenge never completes"
    );
    assert_eq!(active_sessions(&h, alice).await, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_challenge_is_bound_to_the_client_kind_and_device(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let mut browser = Browser::new(&h);
    web_password_login(&h, &mut browser, "alice@example.com").await;
    let token = browser.cookies[CHALLENGE_COOKIE].clone();
    // The web challenge presented by a native client.
    h.send(native_challenge(
        "/v1/login/challenge/verify",
        &json!({"method": "totp", "code": h.totp_code(&secret)}),
        &token,
    ))
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "challenge_invalid");
    // The same cookie from another device.
    let mut thief = Browser::new(&h);
    thief.cookies.insert(CHALLENGE_COOKIE.into(), token);
    thief
        .send(
            &h,
            thief.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret)}),
            ),
        )
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "challenge_invalid");
    // The original browser still completes it.
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret)}),
            ),
        )
        .await;
    assert_eq!(status_of(&done), "authenticated", "{}", done.text());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_02_suspension_during_the_challenge_stops_the_login(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let mut browser = Browser::new(&h);
    web_password_login(&h, &mut browser, "alice@example.com").await;
    set_status(&h, alice, "suspended").await;
    let r = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret)}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    assert!(!browser.has(SESSION_COOKIE));
}

// ---------------------------------------------------------------------------
// MFA-09 trusted devices
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_trusted_device_skips_the_second_factor(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let mut browser = Browser::new(&h);
    web_password_login(&h, &mut browser, "alice@example.com").await;
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret), "trust_device": true}),
            ),
        )
        .await;
    assert_eq!(status_of(&done), "authenticated");
    assert!(browser.has(authn_mfa::TRUSTED_DEVICE_COOKIE));

    // Next login from the same browser: no challenge.
    browser.start_over(&h);
    let again = web_password_login(&h, &mut browser, "alice@example.com").await;
    assert_eq!(status_of(&again), "authenticated", "{}", again.text());
    // A browser without the token still gets the challenge.
    let mut other = Browser::new(&h);
    let r = web_password_login(&h, &mut other, "alice@example.com").await;
    assert_eq!(status_of(&r), "challenge_required");
    // A token of another user is worthless.
    let bob = h.user("bob@example.com").await;
    h.enroll_totp(bob).await;
    let mut stolen = Browser::new(&h);
    stolen.cookies.insert(
        authn_mfa::TRUSTED_DEVICE_COOKIE.into(),
        browser.cookies[authn_mfa::TRUSTED_DEVICE_COOKIE].clone(),
    );
    let r = web_password_login(&h, &mut stolen, "bob@example.com").await;
    assert_eq!(status_of(&r), "challenge_required");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_trusted_device_is_ignored_when_risk_demands_mfa(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let mut browser = Browser::new(&h);
    web_password_login(&h, &mut browser, "alice@example.com").await;
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret), "trust_device": true}),
            ),
        )
        .await;
    browser.start_over(&h);
    h.ports.risk.set(medium_risk());
    let r = web_password_login(&h, &mut browser, "alice@example.com").await;
    assert_eq!(status_of(&r), "challenge_required", "{}", r.text());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_organization_can_forbid_trusted_devices(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let mut policy = empty_policy();
    policy.trusted_devices_allowed = false;
    h.set_policy(owner, org, policy).await;
    let mut browser = Browser::new(&h);
    web_password_login(&h, &mut browser, "alice@example.com").await;
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret), "trust_device": true}),
            ),
        )
        .await;
    assert!(!browser.has(authn_mfa::TRUSTED_DEVICE_COOKIE));
}

// ---------------------------------------------------------------------------
// SES-22 required actions
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_22_must_change_password_is_a_required_action(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    set_must_change(&h, alice).await;
    let mut browser = Browser::new(&h);
    let r = web_password_login(&h, &mut browser, "alice@example.com").await;
    let body: Value = r.json();
    assert_eq!(body["status"], "challenge_required");
    // The old password alone never sets the new one: mailbox proof first.
    assert_eq!(
        body["required_actions"],
        json!(["verify_mfa", "change_password"])
    );
    assert_eq!(body["allowed_factors"], json!(["email"]));
    assert!(!browser.has(SESSION_COOKIE));
    let body = confirm_by_email(&h, &mut browser).await;
    assert_eq!(
        body["required_actions"],
        json!(["change_password"]),
        "{body}"
    );
    // The new password must satisfy the policy.
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/step",
                &json!({"step": "change_password", "new_password": PASSWORD}),
            ),
        )
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "password_unchanged");
    let new_password = "a fresh and long passphrase 2026";
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/step",
                &json!({"step": "change_password", "new_password": new_password}),
            ),
        )
        .await;
    assert_eq!(status_of(&done), "authenticated", "{}", done.text());
    // The old password is gone, the new one works without a challenge.
    let mut b2 = Browser::new(&h);
    b2.send(
        &h,
        b2.post(
            "/v1/login/password",
            &password_body("alice@example.com", PASSWORD),
        ),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "invalid_credentials");
    let r = b2
        .send(
            &h,
            b2.post(
                "/v1/login/password",
                &password_body("alice@example.com", new_password),
            ),
        )
        .await;
    assert_eq!(status_of(&r), "authenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_22_required_actions_wait_for_the_second_factor(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    set_must_change(&h, alice).await;
    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(
        body["required_actions"],
        json!(["verify_mfa", "change_password"])
    );
    // Password alone cannot change the password.
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/step",
                &json!({"step": "change_password", "new_password": "a fresh and long passphrase 2026"}),
            ),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    let r = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret)}),
            ),
        )
        .await;
    let body: Value = r.json();
    assert_eq!(body["status"], "challenge_required");
    assert_eq!(body["required_actions"], json!(["change_password"]));
    assert!(!browser.has(SESSION_COOKIE));
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/step",
                &json!({"step": "change_password", "new_password": "a fresh and long passphrase 2026"}),
            ),
        )
        .await;
    let body: Value = done.json();
    assert_eq!(body["status"], "authenticated");
    assert_eq!(body["amr"], json!(["pwd", "otp", "mfa"]));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_22_new_terms_must_be_accepted(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    // Alice accepted the previous version.
    let old = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO terms_versions (id, document, version, url, published_at) \
         VALUES ($1, 'terms_of_service', '2025-01', 'https://example.com/tos', $2)",
    )
    .bind(old)
    .bind(h.now() - time::Duration::days(300))
    .execute(&h.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO consents (id, user_id, terms_version_id, accepted_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(alice)
    .bind(old)
    .bind(h.now() - time::Duration::days(300))
    .execute(&h.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO terms_versions (id, document, version, url, published_at, requires_reacceptance) \
         VALUES ($1, 'terms_of_service', '2026-11', 'https://example.com/tos', $2, true)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(h.now() - time::Duration::hours(1))
    .execute(&h.pool)
    .await
    .unwrap();
    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(body["required_actions"], json!(["accept_terms"]));
    // Accepting another version does not count.
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/step",
                &json!({"step": "accept_terms", "accepted": [{"document": "terms_of_service", "version": "1999"}]}),
            ),
        )
        .await;
    assert!(!browser.has(SESSION_COOKIE));
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/step",
                &json!({"step": "accept_terms", "accepted": [{"document": "terms_of_service", "version": "2026-11"}]}),
            ),
        )
        .await;
    assert_eq!(status_of(&done), "authenticated", "{}", done.text());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_22_organization_mfa_requirement_forces_enrollment(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let mut policy = empty_policy();
    policy.mfa_required = true;
    h.set_policy(owner, org, policy).await;
    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(body["required_actions"], json!(["enroll_mfa"]));
    let started = browser
        .send(
            &h,
            browser.post("/v1/login/challenge/step", &json!({"step": "enroll_totp"})),
        )
        .await;
    let started: Value = started.json();
    assert_eq!(started["status"], "challenge_required", "{started}");
    let secret =
        authn_crypto::totp::TotpSecret::from_base32(started["data"]["secret"].as_str().unwrap())
            .unwrap();
    let factor_id = started["data"]["factor"]["id"].clone();
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/step",
                &json!({"step": "confirm_enrollment", "factor_id": factor_id, "code": h.totp_code(&secret)}),
            ),
        )
        .await;
    let body: Value = done.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    assert!(body["amr"].as_array().unwrap().contains(&json!("mfa")));
    assert_eq!(
        body["data"]["recovery_codes"]["codes"]
            .as_array()
            .unwrap()
            .len(),
        10,
        "first factor returns recovery codes once"
    );
    // Confirming a factor that was not started in this login is refused.
    let mut b2 = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut b2, "alice@example.com")
        .await
        .json();
    assert_eq!(body["required_actions"], json!(["verify_mfa"]));
}

// ---------------------------------------------------------------------------
// RSK-03 risk reactions, RSK-04 new device + "this wasn't me"
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_03_high_risk_is_blocked_after_the_password_and_the_user_is_told(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    h.ports.risk.set(high_risk());
    let mut browser = Browser::new(&h);
    // A wrong password still answers invalid_credentials (no risk oracle).
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/password",
                &password_body("alice@example.com", WRONG),
            ),
        )
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_credentials");
    let r = web_password_login(&h, &mut browser, "alice@example.com").await;
    assert_eq!(r.error().code, "suspicious_login_blocked", "{}", r.text());
    assert!(!browser.has(SESSION_COOKIE));
    assert_eq!(count_kind(&h, "suspicious_login_blocked"), 1);
    assert_eq!(active_sessions(&h, alice).await, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_03_medium_risk_without_mfa_requires_an_email_confirmation(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    h.ports.risk.set(medium_risk());
    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(body["required_actions"], json!(["verify_mfa"]));
    assert_eq!(body["allowed_factors"], json!(["email"]));
    // The enrolled-factor e-mail path is not this step.
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/send-code",
                &json!({"channel": "email"}),
            ),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    let sent = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/send-code",
                &json!({"channel": "email_confirmation"}),
            ),
        )
        .await;
    sent.assert_status(StatusCode::ACCEPTED);
    assert_eq!(sent.json::<Value>()["destination"], "a***@example.com");
    let wrong = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "email_confirmation", "code": "000000"}),
            ),
        )
        .await;
    wrong.assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    let code = login_code(&h);
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "email_confirmation", "code": code}),
            ),
        )
        .await;
    let body: Value = done.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    assert!(
        !body["amr"].as_array().unwrap().contains(&json!("mfa")),
        "a mailbox confirmation is not an enrolled second factor"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_03_medium_risk_with_mfa_asks_for_the_factor(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    h.enroll_totp(alice).await;
    let _ = owner;
    h.ports.risk.set(medium_risk());
    let r = h
        .send(native(
            "/v1/login/password",
            &password_body("alice@example.com", PASSWORD),
        ))
        .await;
    let body: Value = r.json();
    assert_eq!(body["required_actions"], json!(["verify_mfa"]));
    assert!(
        body["allowed_factors"]
            .as_array()
            .unwrap()
            .contains(&json!("totp"))
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_03_risk_applies_to_federated_logins(pool: PgPool) {
    use authn_core::ports::{LoginOutcome, PrimaryAuthentication, SessionIssuer};
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    h.ports.risk.set(high_risk());
    let result = h
        .service
        .complete_primary_authentication(
            &h.ctx(),
            PrimaryAuthentication {
                user_id: alice,
                method: authn_core::domain::LoginMethod::Social,
                amr: vec![AuthMethodRef::Fed],
                client: authn_core::domain::ClientKind::Native,
                remember_me: false,
                shared_device: false,
                requested_org: None,
                provider_asserted_mfa: false,
            },
        )
        .await;
    assert_eq!(
        result.unwrap_err().code().code(),
        "suspicious_login_blocked"
    );
    h.ports.risk.set(medium_risk());
    let outcome = h
        .service
        .complete_primary_authentication(
            &h.ctx(),
            PrimaryAuthentication {
                user_id: alice,
                method: authn_core::domain::LoginMethod::Social,
                amr: vec![AuthMethodRef::Fed],
                client: authn_core::domain::ClientKind::Native,
                remember_me: false,
                shared_device: false,
                requested_org: None,
                provider_asserted_mfa: false,
            },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, LoginOutcome::ChallengeRequired(_)));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_04_new_device_login_is_notified_and_not_me_secures_the_account(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    // First login builds the history (no notice).
    let mut laptop = Browser::with_device(&h, "laptop-device-0000001");
    web_password_login(&h, &mut laptop, "alice@example.com").await;
    assert_eq!(count_kind(&h, "new_device_login"), 0);
    // Same device again: still quiet.
    laptop.start_over(&h);
    web_password_login(&h, &mut laptop, "alice@example.com").await;
    assert_eq!(count_kind(&h, "new_device_login"), 0);
    // A new device: notice with a "this wasn't me" link.
    let mut phone = Browser::with_device(&h, "phone-device-00000002");
    web_password_login(&h, &mut phone, "alice@example.com").await;
    let token = h
        .ports
        .notifier
        .recorded()
        .into_iter()
        .find_map(|n| match n.kind {
            NotificationKind::NewDeviceLogin { not_me_token, .. } => {
                Some(not_me_token.expose().to_owned())
            }
            _ => None,
        })
        .expect("new-device notice");
    assert!(active_sessions(&h, alice).await >= 2);

    let r = h
        .send(TestRequest::post("/v1/login/not-me").json(&json!({"token": token})))
        .await;
    r.assert_status(StatusCode::OK);
    assert!(r.json::<Value>()["sessions_revoked"].as_u64().unwrap() >= 2);
    assert_eq!(active_sessions(&h, alice).await, 0);
    assert_eq!(me_status(&h, &laptop).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me_status(&h, &phone).await, StatusCode::UNAUTHORIZED);
    // Password change is forced (PWD-12, after a mailbox proof) and a
    // reset link is mailed.
    let mut b = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut b, "alice@example.com")
        .await
        .json();
    assert_eq!(
        body["required_actions"],
        json!(["verify_mfa", "change_password"])
    );
    h.service.drain_background_jobs().await;
    // The link is single-use.
    h.send(TestRequest::post("/v1/login/not-me").json(&json!({"token": token})))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

// ---------------------------------------------------------------------------
// SES-18 magic link
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_18_magic_link_signs_in_on_the_requesting_browser(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mut browser = Browser::new(&h);
    let r = browser
        .send(
            &h,
            browser.post(
                "/v1/login/magic-link",
                &json!({"email": "alice@example.com"}),
            ),
        )
        .await;
    r.assert_status(StatusCode::ACCEPTED);
    assert!(browser.has(authn_session::login::MAGIC_LINK_BINDING_COOKIE));
    h.service.drain_background_jobs().await;
    let token = magic_link_token(&h);
    // Never consumed by GET (link previews).
    let get = h
        .send(TestRequest::get(&format!(
            "/v1/login/magic-link/verify?token={token}"
        )))
        .await;
    assert_eq!(get.status, StatusCode::METHOD_NOT_ALLOWED);
    let done = browser
        .send(
            &h,
            browser.post("/v1/login/magic-link/verify", &json!({"token": token})),
        )
        .await;
    let body: Value = done.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(body["user_id"], json!(alice));
    assert_eq!(body["amr"], json!(["email"]));
    assert!(!browser.has(authn_session::login::MAGIC_LINK_BINDING_COOKIE));
    // Single use.
    let mut again = Browser::new(&h);
    again
        .send(
            &h,
            again.post(
                "/v1/login/magic-link/verify",
                &json!({"token": token, "confirm_other_device": true}),
            ),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_18_unknown_addresses_get_the_same_answer_and_no_mail(pool: PgPool) {
    // Every sample comes from one IP: only the per-IP limit is raised.
    let h = Harness::with(pool, |c| {
        c.protect.rate_limit.login_per_ip =
            authn_core::ports::RateLimitPolicy::new(1000, Duration::from_secs(900));
    })
    .await;
    h.user("alice@example.com").await;
    let mut known = Browser::new(&h);
    let a = known
        .send(
            &h,
            known.post(
                "/v1/login/magic-link",
                &json!({"email": "alice@example.com"}),
            ),
        )
        .await;
    let mut unknown = Browser::new(&h);
    let b = unknown
        .send(
            &h,
            unknown.post(
                "/v1/login/magic-link",
                &json!({"email": "nobody@example.com"}),
            ),
        )
        .await;
    assert_eq!(a.status, b.status);
    assert_eq!(a.json::<Value>(), b.json::<Value>());
    assert_eq!(a.set_cookies().len(), b.set_cookies().len());
    h.service.drain_background_jobs().await;
    assert_eq!(count_kind(&h, "magic_link"), 1);
    // A fresh address per sample: the per-address limit (5 per hour) must
    // not turn the comparison into one of two `429` answers.
    const SAMPLES: usize = 31;
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    // Enough fresh addresses for up to three rounds (warm-up included).
    for i in 0..3 * (SAMPLES + 3) {
        let email = format!("member{i}@example.com");
        h.user(&email).await;
        known.push(email);
        unknown.push(format!("stranger{i}@example.com"));
    }
    let known = std::sync::Mutex::new(known);
    let unknown = std::sync::Mutex::new(unknown);
    let harness = &h;
    let request = move |email: String| async move {
        let b = Browser::new(harness);
        let r = harness
            .send(b.post("/v1/login/magic-link", &json!({"email": email})))
            .await;
        r.assert_status(StatusCode::ACCEPTED);
    };
    let report = authn_testkit::timing::compare_timings_repeated(
        3,
        SAMPLES,
        0.35,
        || request(known.lock().unwrap().pop().unwrap()),
        || request(unknown.lock().unwrap().pop().unwrap()),
    )
    .await;
    report.assert_indistinguishable(0.35);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_18_another_device_needs_an_explicit_confirmation(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let mut requester = Browser::new(&h);
    requester
        .send(
            &h,
            requester.post(
                "/v1/login/magic-link",
                &json!({"email": "alice@example.com", "remember_me": true}),
            ),
        )
        .await;
    h.service.drain_background_jobs().await;
    let token = magic_link_token(&h);
    let mut other = Browser::new(&h);
    other
        .send(
            &h,
            other.post("/v1/login/magic-link/verify", &json!({"token": token})),
        )
        .await
        .assert_error(StatusCode::CONFLICT, "magic_link_confirmation_required");
    assert!(!other.has(SESSION_COOKIE));
    let done = other
        .send(
            &h,
            other.post(
                "/v1/login/magic-link/verify",
                &json!({"token": token, "confirm_other_device": true}),
            ),
        )
        .await;
    assert_eq!(status_of(&done), "authenticated", "{}", done.text());
    // No "remember me" on a device that did not ask for it.
    let cookie = authn_session_cookie_line(&done);
    assert!(!cookie.contains("Max-Age"), "{cookie}");
}

fn authn_session_cookie_line(response: &TestResponse) -> String {
    response
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{SESSION_COOKIE}=")))
        .unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_18_magic_link_on_an_unverified_placeholder_drops_unproven_credentials(pool: PgPool) {
    // ADR 0002: someone registered the victim's address with their own
    // password; the mailbox owner signs in with a magic link.
    let h = Harness::new(pool).await;
    let victim = unverified_user(&h, "victim@example.com", true).await;
    let mut browser = Browser::new(&h);
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/magic-link",
                &json!({"email": "victim@example.com"}),
            ),
        )
        .await;
    h.service.drain_background_jobs().await;
    let token = magic_link_token(&h);
    let done = browser
        .send(
            &h,
            browser.post("/v1/login/magic-link/verify", &json!({"token": token})),
        )
        .await;
    assert_eq!(status_of(&done), "authenticated", "{}", done.text());
    let record = UserRepository::find_by_id(&h.pool, victim)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, AccountStatus::Active);
    assert!(record.email_verified_at.is_some());
    // The attacker's password no longer works.
    assert!(
        UserRepository::find_password(&h.pool, victim)
            .await
            .unwrap()
            .is_none()
    );
    let mut attacker = Browser::new(&h);
    attacker
        .send(
            &h,
            attacker.post(
                "/v1/login/password",
                &password_body("victim@example.com", PASSWORD),
            ),
        )
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_credentials");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_18_expired_links_are_refused(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let mut browser = Browser::new(&h);
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/magic-link",
                &json!({"email": "alice@example.com"}),
            ),
        )
        .await;
    h.service.drain_background_jobs().await;
    let token = magic_link_token(&h);
    h.advance(h.config.session.magic_link_ttl + Duration::from_secs(1));
    browser
        .send(
            &h,
            browser.post("/v1/login/magic-link/verify", &json!({"token": token})),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_18_magic_link_still_requires_the_second_factor(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let mut browser = Browser::new(&h);
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/magic-link",
                &json!({"email": "alice@example.com"}),
            ),
        )
        .await;
    h.service.drain_background_jobs().await;
    let token = magic_link_token(&h);
    let r = browser
        .send(
            &h,
            browser.post("/v1/login/magic-link/verify", &json!({"token": token})),
        )
        .await;
    assert_eq!(status_of(&r), "challenge_required");
    let done = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret)}),
            ),
        )
        .await;
    let body: Value = done.json();
    assert_eq!(body["amr"], json!(["email", "otp", "mfa"]));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_18_requests_are_rate_limited_per_address(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let mut last = StatusCode::OK;
    for _ in 0..6 {
        let b = Browser::new(&h);
        last = h
            .send(b.post(
                "/v1/login/magic-link",
                &json!({"email": "alice@example.com"}),
            ))
            .await
            .status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

// ---------------------------------------------------------------------------
// SES-19 e-mail code
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_19_email_code_login_web_and_native(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mut browser = Browser::new(&h);
    let r = browser
        .send(
            &h,
            browser.post(
                "/v1/login/email-code",
                &json!({"email": "alice@example.com"}),
            ),
        )
        .await;
    r.assert_status(StatusCode::ACCEPTED);
    assert!(browser.has(CHALLENGE_COOKIE));
    h.service.drain_background_jobs().await;
    let code = login_code(&h);
    let done = browser
        .send(
            &h,
            browser.post("/v1/login/email-code/verify", &json!({"code": code})),
        )
        .await;
    let body: Value = done.json();
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(body["user_id"], json!(alice));

    let r = h
        .send(native(
            "/v1/login/email-code",
            &json!({"email": "alice@example.com"}),
        ))
        .await;
    let token = r.json::<Value>()["token"].as_str().unwrap().to_owned();
    h.service.drain_background_jobs().await;
    let code = login_code(&h);
    let done = h
        .send(native_challenge(
            "/v1/login/email-code/verify",
            &json!({"code": code}),
            &token,
        ))
        .await;
    assert!(done.json::<Value>()["access_token"].as_str().is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_19_failures_are_uniform_and_attempts_are_limited(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    // Unknown address: same start answer, and a verify answers invalid_code.
    let r = h
        .send(native(
            "/v1/login/email-code",
            &json!({"email": "nobody@example.com"}),
        ))
        .await;
    r.assert_status(StatusCode::ACCEPTED);
    let ghost = r.json::<Value>()["token"].as_str().unwrap().to_owned();
    h.service.drain_background_jobs().await;
    assert_eq!(count_kind(&h, "login_code"), 0);
    h.send(native_challenge(
        "/v1/login/email-code/verify",
        &json!({"code": "123456"}),
        &ghost,
    ))
    .await
    .assert_error(StatusCode::BAD_REQUEST, "invalid_code");

    let r = h
        .send(native(
            "/v1/login/email-code",
            &json!({"email": "alice@example.com"}),
        ))
        .await;
    let token = r.json::<Value>()["token"].as_str().unwrap().to_owned();
    h.service.drain_background_jobs().await;
    let code = login_code(&h);
    let wrong = if code == "000000" { "111111" } else { "000000" };
    for _ in 0..h.config.session.email_code_max_attempts {
        h.send(native_challenge(
            "/v1/login/email-code/verify",
            &json!({"code": wrong}),
            &token,
        ))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    }
    // The right code no longer works once the attempts are used up.
    h.send(native_challenge(
        "/v1/login/email-code/verify",
        &json!({"code": code}),
        &token,
    ))
    .await
    .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_19_code_is_bound_to_the_requesting_device(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let mut browser = Browser::new(&h);
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/email-code",
                &json!({"email": "alice@example.com"}),
            ),
        )
        .await;
    h.service.drain_background_jobs().await;
    let code = login_code(&h);
    let mut thief = Browser::new(&h);
    thief.cookies.insert(
        CHALLENGE_COOKIE.into(),
        browser.cookies[CHALLENGE_COOKIE].clone(),
    );
    thief
        .send(
            &h,
            thief.post("/v1/login/email-code/verify", &json!({"code": code})),
        )
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    let _ = browser.device.len();
}

// ---------------------------------------------------------------------------
// SES-21 organization policy for every method
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_21_organization_login_methods_apply_to_passwordless_logins(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let mut policy = empty_policy();
    policy.allowed_login_methods = Some(vec![authn_core::domain::LoginMethod::Passkey]);
    h.set_policy(owner, org, policy).await;
    let mut browser = Browser::new(&h);
    let r = browser
        .send(
            &h,
            browser.post(
                "/v1/login/password",
                &json!({"email": "alice@example.com", "password": PASSWORD, "org_id": org}),
            ),
        )
        .await;
    r.assert_error(StatusCode::FORBIDDEN, "login_method_not_allowed");
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/magic-link",
                &json!({"email": "alice@example.com", "org_id": org}),
            ),
        )
        .await;
    h.service.drain_background_jobs().await;
    let token = magic_link_token(&h);
    browser
        .send(
            &h,
            browser.post("/v1/login/magic-link/verify", &json!({"token": token})),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "login_method_not_allowed");
    // The refused link was not consumed by the refusal... but it cannot be
    // used for that organization either.
    assert!(!browser.has(SESSION_COOKIE));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_captcha_escalated_answers_take_the_same_time(pool: PgPool) {
    // Only the per-IP limit is raised (every sample comes from one IP); the
    // per-identifier CAPTCHA budget keeps its default so it escalates.
    let h = Harness::with(pool, |c| {
        c.protect.rate_limit.login_per_ip =
            authn_core::ports::RateLimitPolicy::new(1000, Duration::from_secs(900));
    })
    .await;
    h.user("alice@example.com").await;
    let budget = h.config.protect.rate_limit.login_per_account_captcha.limit;
    for email in ["alice@example.com", "nobody@example.com"] {
        for _ in 0..budget {
            let b = Browser::new(&h);
            h.send(b.post("/v1/login/password", &password_body(email, WRONG)))
                .await;
        }
    }
    let report = authn_testkit::timing::compare_timings_repeated(
        3,
        41,
        0.35,
        || async {
            let b = Browser::new(&h);
            let r = h
                .send(b.post(
                    "/v1/login/password",
                    &password_body("alice@example.com", WRONG),
                ))
                .await;
            assert_eq!(r.error().code, "captcha_required");
        },
        || async {
            let b = Browser::new(&h);
            let r = h
                .send(b.post(
                    "/v1/login/password",
                    &password_body("nobody@example.com", WRONG),
                ))
                .await;
            assert_eq!(r.error().code, "captcha_required");
        },
    )
    .await;
    report.assert_indistinguishable(0.35);
}

// ---------------------------------------------------------------------------
// Security review regressions
// ---------------------------------------------------------------------------

/// Sends the e-mailed confirmation code of the current `verify_mfa` step.
async fn confirm_by_email(h: &Harness, browser: &mut Browser) -> Value {
    browser
        .send(
            h,
            browser.post(
                "/v1/login/challenge/send-code",
                &json!({"channel": "email_confirmation"}),
            ),
        )
        .await
        .assert_status(StatusCode::ACCEPTED);
    let code = login_code(h);
    browser
        .send(
            h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "email_confirmation", "code": code}),
            ),
        )
        .await
        .json()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_22_policy_enrollment_needs_an_existing_factor_first(pool: PgPool) {
    // Alice protects her account with TOTP; her organization later permits
    // only e-mail factors. A stolen password must not be able to enroll a
    // permitted factor (and get an `mfa` session) without her TOTP.
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let mut policy = empty_policy();
    policy.mfa_required = true;
    policy.allowed_mfa_factors = Some(vec![FactorKind::Email]);
    h.set_policy(owner, org, policy).await;
    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(
        body["required_actions"],
        json!(["verify_mfa", "enroll_mfa"]),
        "{body}"
    );
    assert!(
        body["allowed_factors"]
            .as_array()
            .unwrap()
            .contains(&json!("totp")),
        "{body}"
    );
    browser
        .send(
            &h,
            browser.post("/v1/login/challenge/step", &json!({"step": "enroll_email"})),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    let r = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": h.totp_code(&secret)}),
            ),
        )
        .await;
    let body: Value = r.json();
    assert_eq!(body["status"], "challenge_required", "{body}");
    assert_eq!(body["required_actions"], json!(["enroll_mfa"]));
    assert_eq!(body["allowed_factors"], json!(["email"]));
    let started = browser
        .send(
            &h,
            browser.post("/v1/login/challenge/step", &json!({"step": "enroll_email"})),
        )
        .await;
    assert_eq!(
        status_of(&started),
        "challenge_required",
        "{}",
        started.text()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_03_medium_risk_enrollment_needs_the_email_confirmation_first(pool: PgPool) {
    // RSK-03: medium risk without an enrolled factor demands an e-mail
    // confirmation; a pending policy enrollment must not replace it.
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let mut policy = empty_policy();
    policy.mfa_required = true;
    h.set_policy(owner, org, policy).await;
    h.ports.risk.set(medium_risk());
    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(
        body["required_actions"],
        json!(["verify_mfa", "enroll_mfa"]),
        "{body}"
    );
    assert_eq!(body["allowed_factors"], json!(["email"]));
    browser
        .send(
            &h,
            browser.post("/v1/login/challenge/step", &json!({"step": "enroll_totp"})),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    let body = confirm_by_email(&h, &mut browser).await;
    assert_eq!(body["status"], "challenge_required", "{body}");
    assert_eq!(body["required_actions"], json!(["enroll_mfa"]));
    assert!(
        body["allowed_factors"]
            .as_array()
            .unwrap()
            .contains(&json!("totp")),
        "{body}"
    );
    let started = browser
        .send(
            &h,
            browser.post("/v1/login/challenge/step", &json!({"step": "enroll_totp"})),
        )
        .await;
    assert_eq!(
        status_of(&started),
        "challenge_required",
        "{}",
        started.text()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_04_not_me_locks_out_whoever_knows_the_old_password(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mut laptop = Browser::with_device(&h, "laptop-device-0000001");
    web_password_login(&h, &mut laptop, "alice@example.com").await;
    // The attacker signs in from a new device with the stolen password.
    let mut attacker = Browser::with_device(&h, "attacker-device-00001");
    web_password_login(&h, &mut attacker, "alice@example.com").await;
    let token = h
        .ports
        .notifier
        .recorded()
        .into_iter()
        .find_map(|n| match n.kind {
            NotificationKind::NewDeviceLogin { not_me_token, .. } => {
                Some(not_me_token.expose().to_owned())
            }
            _ => None,
        })
        .expect("new-device notice");
    h.send(TestRequest::post("/v1/login/not-me").json(&json!({"token": token})))
        .await
        .assert_status(StatusCode::OK);
    h.service.drain_background_jobs().await;
    // The attacker comes back with the same password: it must not be enough
    // to set a new one (and take the account over again).
    attacker.start_over(&h);
    let body: Value = web_password_login(&h, &mut attacker, "alice@example.com")
        .await
        .json();
    assert_eq!(
        body["required_actions"],
        json!(["verify_mfa", "change_password"]),
        "{body}"
    );
    assert_eq!(body["allowed_factors"], json!(["email"]));
    attacker
        .send(
            &h,
            attacker.post(
                "/v1/login/challenge/step",
                &json!({"step": "change_password", "new_password": "attacker owns this now 2026"}),
            ),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "challenge_step_not_allowed");
    assert_eq!(active_sessions(&h, alice).await, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_06_login_auto_joins_verified_domain_organizations(pool: PgPool) {
    // contracts §15.7: verified-domain auto-join after every login.
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    sqlx::query(
        "INSERT INTO org_domains (id, org_id, domain, verification_value, status, auto_join, verified_at) \
         VALUES ($1, $2, 'acme.example', 'verification-value-0001', 'verified', true, now())",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(org)
    .execute(&h.pool)
    .await
    .unwrap();
    let dev = h.user("dev@acme.example").await;
    let mut browser = Browser::new(&h);
    let r = web_password_login(&h, &mut browser, "dev@acme.example").await;
    assert_eq!(status_of(&r), "authenticated", "{}", r.text());
    let members: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memberships WHERE org_id = $1 AND user_id = $2 AND status = 'active'",
    )
    .bind(org)
    .bind(dev)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(members, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_19_wrong_code_takes_as_long_for_unknown_addresses(pool: PgPool) {
    // A wrong code for an existing account must not answer measurably later
    // than one for a challenge token that never had an account behind it.
    let h = Harness::with(pool, |c| {
        c.protect.rate_limit.login_per_ip =
            authn_core::ports::RateLimitPolicy::new(1000, Duration::from_secs(900));
    })
    .await;
    let mut real = Vec::new();
    let mut ghost = Vec::new();
    // Tokens for up to three rounds of 41 samples (warm-up included).
    for i in 0..3 * 44 {
        let email = format!("user{i}@example.com");
        h.user(&email).await;
        for (address, out) in [
            (email, &mut real),
            (format!("nobody{i}@example.com"), &mut ghost),
        ] {
            let r = h
                .send(native("/v1/login/email-code", &json!({"email": address})))
                .await;
            r.assert_status(StatusCode::ACCEPTED);
            out.push(r.json::<Value>()["token"].as_str().unwrap().to_owned());
        }
    }
    h.service.drain_background_jobs().await;
    let real = std::sync::Mutex::new(real);
    let ghost = std::sync::Mutex::new(ghost);
    let wrong = |token: String| {
        native_challenge(
            "/v1/login/email-code/verify",
            &json!({"code": "000000"}),
            &token,
        )
    };
    let report = authn_testkit::timing::compare_timings_repeated(
        3,
        41,
        0.35,
        || async {
            let token = real.lock().unwrap().pop().unwrap();
            h.send(wrong(token)).await;
        },
        || async {
            let token = ghost.lock().unwrap().pop().unwrap();
            h.send(wrong(token)).await;
        },
    )
    .await;
    report.assert_indistinguishable(0.35);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_04_browser_without_device_cookie_is_a_new_device(pool: PgPool) {
    // An attacker's fresh browser carries no device cookie at all; the
    // session gets a new device id and the owner must be told.
    let h = Harness::new(pool).await;
    h.user("alice@example.com").await;
    let mut laptop = Browser::with_device(&h, "laptop-device-0000001");
    let r = web_password_login(&h, &mut laptop, "alice@example.com").await;
    assert_eq!(status_of(&r), "authenticated");
    assert_eq!(count_kind(&h, "new_device_login"), 0);
    let mut fresh = Browser::without_device(&h);
    let r = web_password_login(&h, &mut fresh, "alice@example.com").await;
    assert_eq!(status_of(&r), "authenticated", "{}", r.text());
    assert_eq!(count_kind(&h, "new_device_login"), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_01_concurrent_logins_never_starve_the_connection_pool(pool: PgPool) {
    // The test pool has 5 connections. A login that held its transaction
    // while waiting for a second connection (account, MFA, risk, signing
    // key) deadlocked here until the 30 s acquire timeout (500).
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let started = std::time::Instant::now();
    let logins = (0..12).map(|i| {
        let body = password_body("alice@example.com", PASSWORD);
        let request = if i % 2 == 0 {
            native("/v1/login/password", &body)
        } else {
            Browser::new(&h).post("/v1/login/password", &body)
        };
        h.send(request)
    });
    let responses = futures::future::join_all(logins).await;
    for r in &responses {
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    }
    // Every challenge completes concurrently as well.
    let completions = responses.iter().filter_map(|r| {
        let token = r.json::<Value>()["challenge_token"].as_str()?.to_owned();
        Some(h.send(native_challenge(
            "/v1/login/challenge/verify",
            &json!({"method": "recovery_code", "code": "unused-code"}),
            &token,
        )))
    });
    for r in futures::future::join_all(completions).await {
        assert!(!r.status.is_server_error(), "{}", r.text());
    }
    let _ = secret;
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "logins stalled for {:?}",
        started.elapsed()
    );
}

/// The `mfa_factors` recorded for a session (K-78).
async fn session_factors(h: &Harness, user: UserId) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT mfa_factors::text[] FROM sessions WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user)
    .fetch_one(&h.pool)
    .await
    .unwrap()
}

/// K-78 regression: the e-mailed confirmation of a risky login (RSK-03)
/// adds `email` to `amr`, but it is no second factor. A session that got
/// `mfa` from a TOTP step-up must not enter an organization that only
/// allows the e-mail factor because the risk confirmation's `email` sits in
/// its `amr` (before K-78 the factor was read from `amr`).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_78_risk_confirmation_never_counts_as_an_allowed_second_factor(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    h.ports.risk.set(medium_risk());

    // Password + risk confirmation e-mail: amr [pwd, email], no factor.
    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(body["allowed_factors"], json!(["email"]));
    browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/send-code",
                &json!({"channel": "email_confirmation"}),
            ),
        )
        .await
        .assert_status(StatusCode::ACCEPTED);
    let code = login_code(&h);
    let done: Value = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "email_confirmation", "code": code}),
            ),
        )
        .await
        .json();
    assert_eq!(done["status"], "authenticated", "{done}");
    assert_eq!(done["amr"], json!(["pwd", "email"]));
    assert!(session_factors(&h, alice).await.is_empty());

    // A TOTP step-up: now `mfa`, produced by the TOTP.
    let secret = h.enroll_totp(alice).await;
    let code = h.totp_code(&secret);
    let stepped = browser
        .send(
            &h,
            browser.post("/v1/reauth", &json!({ "method": "totp", "code": code })),
        )
        .await;
    stepped.assert_status(StatusCode::OK);
    let amr = stepped.json::<Value>()["amr"].clone();
    assert!(amr.as_array().unwrap().contains(&json!("mfa")), "{amr}");
    assert!(amr.as_array().unwrap().contains(&json!("email")), "{amr}");
    assert_eq!(session_factors(&h, alice).await, vec!["totp".to_owned()]);

    // The organization only allows the e-mail factor.
    let mut policy = empty_policy();
    policy.mfa_required = true;
    policy.allowed_mfa_factors = Some(vec![FactorKind::Email]);
    h.set_policy(owner, org, policy).await;
    browser
        .send(
            &h,
            browser.post("/v1/session/org", &json!({ "org_id": org })),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "org_policy_mfa_required");

    // An organization allowing the TOTP that produced `mfa` is fine.
    let mut policy = empty_policy();
    policy.mfa_required = true;
    policy.allowed_mfa_factors = Some(vec![FactorKind::Totp]);
    h.set_policy(owner, org, policy).await;
    browser
        .send(
            &h,
            browser.post("/v1/session/org", &json!({ "org_id": org })),
        )
        .await
        .assert_status(StatusCode::OK);
}

/// K-78: the second factor verified at login is recorded for the session
/// and is what organization policies see.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_78_verified_login_factor_is_recorded_for_the_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let secret = h.enroll_totp(alice).await;
    let mut browser = Browser::new(&h);
    let body: Value = web_password_login(&h, &mut browser, "alice@example.com")
        .await
        .json();
    assert_eq!(body["required_actions"], json!(["verify_mfa"]));
    let code = h.totp_code(&secret);
    let done: Value = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({"method": "totp", "code": code}),
            ),
        )
        .await
        .json();
    assert_eq!(done["amr"], json!(["pwd", "otp", "mfa"]));
    assert_eq!(session_factors(&h, alice).await, vec!["totp".to_owned()]);

    let mut policy = empty_policy();
    policy.mfa_required = true;
    policy.allowed_mfa_factors = Some(vec![FactorKind::RecoveryCode]);
    h.set_policy(owner, org, policy).await;
    browser
        .send(
            &h,
            browser.post("/v1/session/org", &json!({ "org_id": org })),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "org_policy_mfa_required");
}
