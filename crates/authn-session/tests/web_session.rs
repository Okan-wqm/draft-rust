#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Web sessions: cookies, CSRF, fixation, lifetimes, concurrency limit
//! (SES-03, SES-04, SES-06, SES-07, SES-14).

mod common;

use std::time::Duration;

use authn_core::domain::{AuthMethodRef, LoginMethod};
use authn_core::ports::{RevocationReason, SecurityEventKind};
use authn_session::cookies::{PRE_SESSION_COOKIE, SESSION_COOKIE};
use authn_session::response::credentials_response;
use authn_session::{ChallengeKind, IssuedCredentials, NewChallenge};
use authn_testkit::http::TestRequest;
use common::{Harness, ORIGIN, cookie_value, set_cookie, web_of};
use http::StatusCode;
use http_body_util::BodyExt;
use sqlx::PgPool;

async fn probe_user(h: &Harness, request: TestRequest) -> serde_json::Value {
    let res = h.send(request).await;
    res.assert_status(StatusCode::OK);
    res.json()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_03_session_cookie_is_host_prefixed_http_only_secure_lax(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let established = h.establish(h.request(user, h.web_channel())).await;
    let record = established.session.clone();
    let response = credentials_response(&record, established.credentials, h.now());
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let session = set_cookie(&cookies, SESSION_COOKIE).unwrap();
    for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
        assert!(session.contains(attribute), "{session}");
    }
    assert!(!session.contains("Domain"), "{session}");
    assert!(
        !session.contains("Max-Age"),
        "browser-session cookie without remember-me"
    );
    // The login-CSRF pre-session ends with the login.
    assert!(
        set_cookie(&cookies, PRE_SESSION_COOKIE)
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["csrf_token"].is_string());
    assert!(body.get("access_token").is_none());
    // The session token never appears in a body.
    assert!(!body.to_string().contains(&cookie_value(session)));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_06_remember_me_cookie_is_persistent_until_the_absolute_expiry(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let mut request = h.request(user, h.web_channel());
    request.remember_me = true;
    let established = h.establish(request).await;
    let lifetime = established.session.absolute_expires_at - established.session.created_at;
    assert_eq!(lifetime, time::Duration::days(30));
    assert_eq!(
        established.session.idle_expires_at - established.session.created_at,
        time::Duration::days(14)
    );
    let IssuedCredentials::Web { persistent_for, .. } = &established.credentials else {
        panic!()
    };
    assert_eq!(*persistent_for, Some(Duration::from_secs(30 * 86_400)));
    let response = credentials_response(&established.session, established.credentials, h.now());
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.ends_with("; Max-Age=2592000"), "{cookie}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_07_not_my_device_is_a_short_browser_session_even_with_remember_me(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let mut request = h.request(user, h.web_channel());
    request.remember_me = true;
    request.shared_device = true;
    let established = h.establish(request).await;
    let s = &established.session;
    assert!(s.shared_device && !s.remember_me);
    assert_eq!(
        s.absolute_expires_at - s.created_at,
        time::Duration::hours(4)
    );
    assert_eq!(
        s.idle_expires_at - s.created_at,
        time::Duration::minutes(30)
    );
    let IssuedCredentials::Web { persistent_for, .. } = &established.credentials else {
        panic!()
    };
    assert_eq!(*persistent_for, None, "browser-session cookie only");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_03_cookie_authenticates_and_every_login_gets_a_fresh_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let attacker = h.user("mallory@example.com").await;
    // Fixation attempt: the attacker plants their own valid session cookie
    // in the victim's browser; the victim's login never reuses it.
    let planted = h.web_login(attacker).await;
    let login = h.web_login(user).await;
    assert_ne!(login.cookie, planted.cookie);
    assert_ne!(login.session_id, planted.session_id);
    let body = probe_user(&h, h.web_get("/v1/probe", &login)).await;
    assert_eq!(body["user_id"], user.to_string());
    assert_eq!(body["session_id"], login.session_id.to_string());
    // Garbage and unknown cookies authenticate nobody.
    for bad in ["x", "AAAA", &"A".repeat(43)] {
        let body = probe_user(
            &h,
            TestRequest::get("/v1/probe").cookie(SESSION_COOKIE, bad),
        )
        .await;
        assert_eq!(body["authenticated"], false, "{bad}");
    }
    // Cookie tossing: two different session cookies are refused.
    let body = probe_user(
        &h,
        TestRequest::get("/v1/probe")
            .cookie(SESSION_COOKIE, &login.cookie)
            .cookie(SESSION_COOKIE, &planted.cookie),
    )
    .await;
    assert_eq!(body["authenticated"], false);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_04_state_changing_cookie_requests_need_origin_and_csrf_token(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    // Correct origin + token.
    h.send(h.web_post("/v1/probe", &login))
        .await
        .assert_status(StatusCode::OK);
    // Missing token.
    h.send(
        TestRequest::post("/v1/probe")
            .cookie(SESSION_COOKIE, &login.cookie)
            .header("origin", ORIGIN),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    // Wrong token (another session's).
    let other = h.web_login(h.user("bob@example.com").await).await;
    h.send(
        TestRequest::post("/v1/probe")
            .cookie(SESSION_COOKIE, &login.cookie)
            .header("origin", ORIGIN)
            .header("x-csrf-token", &other.csrf),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    // Cross-origin with a valid token (e.g. leaked): still refused.
    for origin in [
        "https://evil.example",
        "null",
        "https://auth.test.example.evil.example",
    ] {
        h.send(
            TestRequest::post("/v1/probe")
                .cookie(SESSION_COOKIE, &login.cookie)
                .header("origin", origin)
                .header("x-csrf-token", &login.csrf),
        )
        .await
        .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    }
    // No Origin: only same-origin fetch metadata is accepted.
    h.send(
        TestRequest::post("/v1/probe")
            .cookie(SESSION_COOKIE, &login.cookie)
            .header("sec-fetch-site", "cross-site")
            .header("x-csrf-token", &login.csrf),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    h.send(
        TestRequest::post("/v1/probe")
            .cookie(SESSION_COOKIE, &login.cookie)
            .header("sec-fetch-site", "same-origin")
            .header("x-csrf-token", &login.csrf),
    )
    .await
    .assert_status(StatusCode::OK);
    // Safe methods need no token.
    h.send(h.web_get("/v1/probe", &login))
        .await
        .assert_status(StatusCode::OK);
    // Bearer requests ignore cookies entirely (no CSRF exposure).
    let res = h
        .send(
            TestRequest::post("/v1/probe")
                .cookie(SESSION_COOKIE, &login.cookie)
                .header("authorization", "Basic Zm9vOmJhcg=="),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<serde_json::Value>()["authenticated"], false);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_04_login_csrf_pre_session_token(pool: PgPool) {
    let h = Harness::new(pool).await;
    // GET /v1/csrf without a session: pre-session cookie + token.
    let res = h.send(TestRequest::get("/v1/csrf")).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["kind"], "pre_session");
    let cookies = res.set_cookies();
    let line = set_cookie(&cookies, PRE_SESSION_COOKIE).unwrap();
    assert!(
        line.contains("SameSite=Strict") && line.contains("HttpOnly") && line.contains("Secure")
    );
    let secret = cookie_value(line);
    let token = body["csrf_token"].as_str().unwrap().to_owned();
    // The same pre-session keeps its token.
    let again: serde_json::Value = h
        .send(TestRequest::get("/v1/csrf").cookie(PRE_SESSION_COOKIE, &secret))
        .await
        .json();
    assert_eq!(again["csrf_token"], token.as_str());

    let headers = |origin: &str, cookie: Option<&str>, token: Option<&str>| {
        let mut map = http::HeaderMap::new();
        map.insert("origin", origin.parse().unwrap());
        if let Some(cookie) = cookie {
            map.insert(
                "cookie",
                format!("{PRE_SESSION_COOKIE}={cookie}").parse().unwrap(),
            );
        }
        if let Some(token) = token {
            map.insert("x-csrf-token", token.parse().unwrap());
        }
        map
    };
    assert!(
        h.service
            .verify_login_csrf(&headers(ORIGIN, Some(&secret), Some(&token)))
            .is_ok()
    );
    // An attacker page cannot read the token and cannot forge the origin.
    let fail = |map| {
        h.service
            .verify_login_csrf(&map)
            .unwrap_err()
            .code()
            .code()
            .to_owned()
    };
    assert_eq!(fail(headers(ORIGIN, Some(&secret), None)), "csrf_failed");
    assert_eq!(fail(headers(ORIGIN, None, Some(&token))), "csrf_failed");
    assert_eq!(
        fail(headers("https://evil.example", Some(&secret), Some(&token))),
        "csrf_failed"
    );
    // The attacker's own pre-session token does not match the victim's
    // cookie.
    let attacker: serde_json::Value = h.send(TestRequest::get("/v1/csrf")).await.json();
    assert_eq!(
        fail(headers(
            ORIGIN,
            Some(&secret),
            attacker["csrf_token"].as_str()
        )),
        "csrf_failed"
    );

    // With a session, /v1/csrf returns the session token.
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    let body: serde_json::Value = h.send(h.web_get("/v1/csrf", &login)).await.json();
    assert_eq!(body["kind"], "session");
    assert_eq!(body["csrf_token"], login.csrf.as_str());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_06_idle_expiry_and_absolute_expiry_with_fake_clock(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    let (_, _, absolute) = common::session_row(&h.pool, login.session_id).await;
    // Activity every 90 minutes keeps the 2h idle window open…
    for _ in 0..7 {
        h.advance(Duration::from_secs(90 * 60));
        let body = probe_user(&h, h.web_get("/v1/probe", &login)).await;
        assert_eq!(body["authenticated"], true);
        let (_, idle, abs) = common::session_row(&h.pool, login.session_id).await;
        assert!(idle <= abs, "idle never beyond absolute");
        assert_eq!(abs, absolute, "absolute expiry is never extended (SES-06)");
    }
    // …but never past the 12h absolute expiry.
    h.advance(Duration::from_secs(90 * 60));
    let body = probe_user(&h, h.web_get("/v1/probe", &login)).await;
    assert_eq!(body["authenticated"], false);

    // Idle: 2h without activity ends a session.
    let login = h.web_login(user).await;
    h.advance(Duration::from_secs(2 * 3600 + 1));
    let body = probe_user(&h, h.web_get("/v1/probe", &login)).await;
    assert_eq!(body["authenticated"], false);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_06_touch_writes_are_throttled(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    let (_, idle_before, _) = common::session_row(&h.pool, login.session_id).await;
    h.advance(Duration::from_secs(30));
    probe_user(&h, h.web_get("/v1/probe", &login)).await;
    let (_, idle_after, _) = common::session_row(&h.pool, login.session_id).await;
    assert_eq!(idle_before, idle_after, "within touch_interval: no write");
    h.advance(Duration::from_secs(60));
    probe_user(&h, h.web_get("/v1/probe", &login)).await;
    let (_, idle_later, _) = common::session_row(&h.pool, login.session_id).await;
    assert!(idle_later > idle_before);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_06_suspended_owner_never_authenticates(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user)
        .execute(&h.pool)
        .await
        .unwrap();
    let body = probe_user(&h, h.web_get("/v1/probe", &login)).await;
    assert_eq!(body["authenticated"], false);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_14_concurrent_session_limit_evicts_the_oldest(pool: PgPool) {
    let h = Harness::with(pool, |c| c.session.max_concurrent_sessions = Some(2)).await;
    let user = h.user("alice@example.com").await;
    let first = h.web_login(user).await;
    h.advance(Duration::from_secs(1));
    let second = h.native_login(user).await;
    h.advance(Duration::from_secs(1));
    let third = h.establish(h.request(user, h.web_channel())).await;
    assert_eq!(third.evicted, vec![first.session_id]);
    let third = web_of(third);
    assert_eq!(
        h.revoked_reason(first.session_id).await.as_deref(),
        Some("concurrent_limit")
    );
    assert_eq!(h.revoked_reason(second.session_id).await, None);
    let body = probe_user(&h, h.web_get("/v1/probe", &first)).await;
    assert_eq!(body["authenticated"], false);
    let body = probe_user(&h, h.web_get("/v1/probe", &third)).await;
    assert_eq!(body["authenticated"], true);
    // Concurrent logins never leave more than the limit alive.
    let mut handles = Vec::new();
    for _ in 0..6 {
        let h2 = h.service.clone();
        let request = h.request(user, h.web_channel());
        let ctx = h.ctx();
        handles.push(tokio::spawn(async move {
            let mut tx = h2.begin().await.unwrap();
            h2.establish(&mut tx, &ctx, request).await.unwrap();
            tx.commit().await.unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    let live = h
        .count(
            "SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL",
            user.as_uuid(),
        )
        .await;
    assert_eq!(live, 2);
    assert!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::SessionRevoked)
            .iter()
            .any(|e| e.metadata["reason"] == RevocationReason::ConcurrentLimit.as_str())
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_03_login_challenge_is_single_use_bounded_and_bound_to_the_device(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let device = "device-0123456789abcdef";
    let ctx = h.ctx_from("203.0.113.10".parse().unwrap(), Some(device));
    let mut tx = h.service.begin().await.unwrap();
    let issued = h
        .service
        .create_challenge(
            &mut tx,
            &ctx,
            NewChallenge {
                kind: ChallengeKind::Login,
                user_id: user,
                client_kind: authn_core::domain::ClientKind::Web,
                primary_method: Some(LoginMethod::Password),
                amr: vec![AuthMethodRef::Pwd],
                first_factor_at: Some(h.now()),
                allowed_factors: vec![authn_core::domain::FactorKind::Totp],
                required_actions: vec![authn_core::ports::RequiredAction::VerifyMfa],
                remember_me: false,
                shared_device: false,
                requested_org: None,
                risk_level: None,
                session_id: None,
                metadata: serde_json::Map::new(),
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let token = issued.token.expose().to_owned();
    let open = |ctx: authn_core::http::RequestContext, token: String| {
        let service = h.service.clone();
        async move {
            let mut tx = service.begin().await.unwrap();
            let result = service
                .open_challenge(
                    &mut tx,
                    &ctx,
                    &token,
                    ChallengeKind::Login,
                    authn_core::domain::ClientKind::Web,
                )
                .await;
            (tx, result)
        }
    };
    // Another device cannot use it.
    let other = h.ctx_from(
        "203.0.113.10".parse().unwrap(),
        Some("device-ffffffffffffffff"),
    );
    let (_, result) = open(other, token.clone()).await;
    assert_eq!(result.unwrap_err().code().code(), "challenge_invalid");
    // Wrong client kind.
    let mut tx = h.service.begin().await.unwrap();
    let err = h
        .service
        .open_challenge(
            &mut tx,
            &ctx,
            &token,
            ChallengeKind::Login,
            authn_core::domain::ClientKind::Native,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "challenge_invalid");
    drop(tx);
    // Attempts are bounded; failures persist outside the caller's tx.
    assert_eq!(
        h.service
            .record_challenge_failure(issued.challenge.id)
            .await
            .unwrap(),
        4
    );
    // Consumption is single use.
    let (mut tx, state) = open(ctx.clone(), token.clone()).await;
    let state = state.unwrap();
    assert_eq!(state.attempts, 1);
    assert!(state.allows_factor(authn_core::domain::FactorKind::Totp));
    assert!(!state.allows_factor(authn_core::domain::FactorKind::Sms));
    h.service
        .consume_challenge(&mut tx, state.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let (_, again) = open(ctx.clone(), token.clone()).await;
    assert_eq!(again.unwrap_err().code().code(), "challenge_invalid");
    // Expiry (5 minutes) for a fresh one.
    let mut tx = h.service.begin().await.unwrap();
    let second = h
        .service
        .create_challenge(
            &mut tx,
            &ctx,
            NewChallenge {
                kind: ChallengeKind::Login,
                user_id: user,
                client_kind: authn_core::domain::ClientKind::Web,
                primary_method: Some(LoginMethod::Password),
                amr: vec![AuthMethodRef::Pwd],
                first_factor_at: None,
                allowed_factors: vec![],
                required_actions: vec![authn_core::ports::RequiredAction::AcceptTerms],
                remember_me: false,
                shared_device: false,
                requested_org: None,
                risk_level: None,
                session_id: None,
                metadata: serde_json::Map::new(),
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Exhausting the attempts burns it.
    for _ in 0..5 {
        h.service
            .record_challenge_failure(second.challenge.id)
            .await
            .unwrap();
    }
    let (_, burnt) = open(ctx.clone(), second.token.expose().to_owned()).await;
    assert_eq!(burnt.unwrap_err().code().code(), "challenge_invalid");
    h.advance(Duration::from_secs(301));
    let (_, expired) = open(ctx, token).await;
    assert!(expired.is_err());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_04_signed_in_browser_proves_login_csrf_with_its_session_token(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    // A state-changing request with a valid session cookie passed the
    // middleware's CSRF check: its CurrentSession says so.
    let service = h.service.clone();
    let app = authn_testkit::http::with_request_context(
        axum::Router::new()
            .route(
                "/v1/login-probe",
                axum::routing::post(
                    |axum::extract::State(service): axum::extract::State<
                        authn_session::SessionService,
                    >,
                     headers: http::HeaderMap,
                     current: Option<authn_session::CurrentSession>| async move {
                        let ok = service
                            .verify_login_csrf_request(&headers, current.as_ref())
                            .is_ok();
                        axum::Json(serde_json::json!({ "ok": ok }))
                    },
                ),
            )
            .with_state(service.clone())
            .layer(axum::middleware::from_fn_with_state(
                service,
                authn_session::authenticate,
            )),
    );
    let res = h.web_post("/v1/login-probe", &login).send(&app).await;
    assert_eq!(res.json::<serde_json::Value>()["ok"], true);
    // Without a session the pre-session token is required.
    let res = TestRequest::post("/v1/login-probe")
        .header("origin", ORIGIN)
        .send(&app)
        .await;
    assert_eq!(res.json::<serde_json::Value>()["ok"], false);
    // A session cookie without the CSRF token never reaches the handler.
    TestRequest::post("/v1/login-probe")
        .cookie(SESSION_COOKIE, &login.cookie)
        .header("origin", ORIGIN)
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
}

// --- security review regressions -------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_03_challenge_failure_never_waits_forever_on_the_callers_lock(pool: PgPool) {
    // Misuse guard of the challenge API: counting a failure while the
    // caller still holds `open_challenge`'s row lock fails within the lock
    // timeout instead of parking a pool connection forever.
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let (id, token) = h.pending_challenge(user, ChallengeKind::Login, None).await;
    let mut held = h.service.begin().await.unwrap();
    h.service
        .open_challenge(
            &mut held,
            &h.ctx(),
            &token,
            ChallengeKind::Login,
            authn_core::domain::ClientKind::Web,
        )
        .await
        .unwrap();
    let outcome = tokio::time::timeout(
        authn_session::service::CHALLENGE_LOCK_TIMEOUT + Duration::from_secs(10),
        h.service.record_challenge_failure(id),
    )
    .await
    .expect("record_challenge_failure blocked on the caller's own row lock");
    assert!(outcome.is_err());
    // The documented order: end the opening transaction first.
    drop(held);
    assert_eq!(h.service.record_challenge_failure(id).await.unwrap(), 4);
}
