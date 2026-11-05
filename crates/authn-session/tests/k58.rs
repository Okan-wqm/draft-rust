#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-58 regressions: the risks the session core used to accept.
//!
//! * Pool pattern: no flow holds one pooled connection while waiting for
//!   another (SES-05, OPS).
//! * Concurrent privilege changes of a native session never turn the
//!   client's newest refresh token into a "replay" (SES-05, SES-13,
//!   SES-17).
//! * Signing-key changes reach every instance at once (CRY-10, SES-09).

mod common;

use std::time::Duration;

use authn_store::SigningKeyRepository;
use authn_testkit::http::TestRequest;
use common::{Harness, PASSWORD};
use http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// A pool with a single connection: a flow that waits for a second pooled
/// connection while holding the first one stalls until the acquire
/// timeout and fails.
async fn single_connection_pool(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap()
}

/// Past the signing-key cache lifetime (30 s): the next token issuance
/// has to reload the keys.
const PAST_KEY_CACHE: Duration = Duration::from_secs(31);

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_k58_native_flows_never_wait_for_a_second_pooled_connection(pool: PgPool) {
    let small = single_connection_pool(&pool).await;
    let h = Harness::new(small).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;

    // Password login (native) with a cold key cache.
    h.advance(PAST_KEY_CACHE);
    let res = h
        .send(common::browser::native(
            "/v1/login/password",
            &json!({ "email": "alice@example.com", "password": PASSWORD }),
        ))
        .await;
    let (_, refresh) = tokens(&res);

    // Refresh after the key cache expired: the reload must not need a
    // second connection while the rotation transaction is open.
    h.advance(PAST_KEY_CACHE);
    let (access, _) = tokens(&self::refresh(&h, &refresh).await);

    // Organization switch (server-side rotation) with a cold cache.
    h.advance(PAST_KEY_CACHE);
    let res = h
        .send(
            TestRequest::post("/v1/session/org")
                .bearer(&access)
                .json(&json!({ "org_id": org })),
        )
        .await;
    let (access, _) = tokens(&res);

    // Step-up (server-side rotation) with a cold cache.
    h.advance(PAST_KEY_CACHE);
    let (access, refresh) = tokens(&step_up(&h, &access).await);

    // Listing and logging out.
    h.send(TestRequest::get("/v1/me/sessions").bearer(&access))
        .await
        .assert_status(StatusCode::OK);
    h.send(TestRequest::post("/v1/logout/all").bearer(&access))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    h.send(TestRequest::post("/v1/token/refresh").json(&json!({ "refresh_token": refresh })))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_03_k58_web_flows_never_wait_for_a_second_pooled_connection(pool: PgPool) {
    let small = single_connection_pool(&pool).await;
    let h = Harness::new(small).await;
    let alice = h.user("alice@example.com").await;
    let secret = h.enroll_totp(alice).await;
    let mut browser = common::browser::Browser::new(&h);
    let res = browser
        .send(
            &h,
            browser.post(
                "/v1/login/password",
                &json!({ "email": "alice@example.com", "password": PASSWORD }),
            ),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(
        common::browser::status_of(&res),
        "challenge_required",
        "{}",
        res.text()
    );
    let code = h.totp_code(&secret);
    let res = browser
        .send(
            &h,
            browser.post(
                "/v1/login/challenge/verify",
                &json!({ "method": "totp", "code": code }),
            ),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(
        common::browser::status_of(&res),
        "authenticated",
        "{}",
        res.text()
    );
    let login = h.web_login(alice).await;
    h.send(h.web_get("/v1/me", &login))
        .await
        .assert_status(StatusCode::OK);
    h.send(h.web_post("/v1/me/sessions/revoke-others", &login))
        .await
        .assert_status(StatusCode::OK);
    h.send(h.web_post("/v1/logout", &login))
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

// --- concurrent privilege changes (refresh "reuse" false positive) --------

async fn step_up(h: &Harness, access: &str) -> authn_testkit::http::TestResponse {
    h.send(
        TestRequest::post("/v1/reauth")
            .bearer(access)
            .json(&json!({ "method": "password", "password": PASSWORD })),
    )
    .await
}

async fn refresh(h: &Harness, token: &str) -> authn_testkit::http::TestResponse {
    h.send(TestRequest::post("/v1/token/refresh").json(&json!({ "refresh_token": token })))
        .await
}

fn tokens(res: &authn_testkit::http::TestResponse) -> (String, String) {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body: Value = res.json();
    (
        body["access_token"].as_str().unwrap().to_owned(),
        body["refresh_token"].as_str().unwrap().to_owned(),
    )
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_k58_overtaken_privilege_change_is_refused_not_a_replay(pool: PgPool) {
    // Two privilege changes started with the same access token: the first
    // rotates the native credentials; the second (overtaken) one used to
    // rotate again, retiring the refresh token the first response had just
    // handed out — the client then presented it, it looked like a replay
    // and the whole session was revoked.
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    h.advance(Duration::from_secs(60));
    let (_, first_refresh) = tokens(&step_up(&h, &login.access).await);
    // The overtaken change: refused, nothing rotated.
    step_up(&h, &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    // The client keeps the first response's refresh token: still valid.
    let (access, _) = tokens(&refresh(&h, &first_refresh).await);
    h.send(TestRequest::get("/v1/me").bearer(&access))
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(h.revoked_reason(login.session_id).await, None);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_13_k58_concurrent_privilege_changes_keep_the_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    h.advance(Duration::from_secs(60));
    let (first, second) = futures::join!(step_up(&h, &login.access), step_up(&h, &login.access));
    // Exactly one change wins; the other is told to retry (401), not
    // treated as a replay.
    let winners: Vec<_> = [&first, &second]
        .into_iter()
        .filter(|r| r.status == StatusCode::OK)
        .collect();
    assert_eq!(winners.len(), 1, "{} / {}", first.text(), second.text());
    for r in [&first, &second] {
        if r.status != StatusCode::OK {
            r.assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
        }
    }
    // Whichever response the client stored last, the session survives:
    // the loser carried no tokens, the winner's refresh token is live.
    let (_, winner_refresh) = tokens(winners[0]);
    tokens(&refresh(&h, &winner_refresh).await);
    assert_eq!(h.revoked_reason(login.session_id).await, None);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_k58_org_switch_overtaken_by_a_step_up_is_refused(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let user = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, user).await;
    let login = h.native_login(user).await;
    h.advance(Duration::from_secs(60));
    let (_, stepped_refresh) = tokens(&step_up(&h, &login.access).await);
    h.send(
        TestRequest::post("/v1/session/org")
            .bearer(&login.access)
            .json(&json!({ "org_id": org })),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    tokens(&refresh(&h, &stepped_refresh).await);
    assert_eq!(h.revoked_reason(login.session_id).await, None);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_k58_privilege_change_after_a_refresh_with_the_old_access_token_is_refused(
    pool: PgPool,
) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    h.advance(Duration::from_secs(60));
    // A refresh and a step-up race; the refresh wins.
    let (new_access, new_refresh) = tokens(&refresh(&h, &login.refresh).await);
    step_up(&h, &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    // The refreshed credentials keep working, and the retry with the new
    // access token succeeds.
    tokens(&step_up(&h, &new_access).await);
    // Reuse detection is unchanged: the retired token is still a replay.
    refresh(&h, &new_refresh)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
    assert_eq!(
        h.revoked_reason(login.session_id).await.as_deref(),
        Some("refresh_token_reuse")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_k58_grace_window_covers_a_refresh_racing_a_privilege_change(pool: PgPool) {
    let h = Harness::with(pool, |c| {
        c.session.refresh_reuse_grace = Duration::from_secs(10);
    })
    .await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    h.advance(Duration::from_secs(60));
    // The step-up wins; the client's concurrent refresh still carries the
    // token the step-up retired.
    let (_, stepped_refresh) = tokens(&step_up(&h, &login.access).await);
    let (_, raced_refresh) = tokens(&refresh(&h, &login.refresh).await);
    assert_eq!(raced_refresh, stepped_refresh, "the same successor");
    assert_eq!(h.revoked_reason(login.session_id).await, None);
    tokens(&refresh(&h, &stepped_refresh).await);
}

// --- signing-key changes reach every instance -----------------------------

async fn probe(h: &Harness, access: &str) -> StatusCode {
    h.send(TestRequest::get("/v1/probe").bearer(access))
        .await
        .status
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_09_k58_emergency_rotation_reaches_other_instances_at_once(pool: PgPool) {
    // Instance A issues; instances B (listening) and C (not listening)
    // verify. The CLI rotates the key directly in the database: no
    // in-process invalidation anywhere.
    let a = Harness::new(pool.clone()).await;
    let b = Harness::new(pool.clone()).await;
    let c = Harness::new(pool.clone()).await;
    let (shutdown, stop) = tokio::sync::oneshot::channel::<()>();
    let listener = {
        let service = b.service.clone();
        tokio::spawn(async move {
            service
                .run_signing_key_listener(async move {
                    let _ = stop.await;
                })
                .await;
        })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !b.service.signing_key_listener_connected() {
        assert!(
            std::time::Instant::now() < deadline,
            "listener never connected"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let user = a.user("alice@example.com").await;
    let login = a.native_login(user).await;
    // Both verifying instances cache the current key.
    assert_eq!(probe(&b, &login.access).await, StatusCode::OK);
    assert_eq!(probe(&c, &login.access).await, StatusCode::OK);

    let mut conn = pool.acquire().await.unwrap();
    SigningKeyRepository::emergency_rotate(&mut conn, &a.crypto.envelopes, a.now())
        .await
        .unwrap();
    drop(conn);

    // B drops its cache on the notification: the revoked key's tokens fail
    // within the notification latency (not after the 30 s cache lifetime).
    let started = std::time::Instant::now();
    loop {
        if probe(&b, &login.access).await == StatusCode::UNAUTHORIZED {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the listening instance still accepts the revoked key"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Without the listener the old behaviour remains: the revoked key keeps
    // verifying until the cache expires (here: the fake clock never moves).
    assert_eq!(probe(&c, &login.access).await, StatusCode::OK);

    shutdown.send(()).unwrap();
    listener.await.unwrap();
    assert!(!b.service.signing_key_listener_connected());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn cry_10_k58_every_signing_key_change_notifies(pool: PgPool) {
    let h = Harness::new(pool.clone()).await;
    let mut listener = sqlx::postgres::PgListener::connect_with(&pool)
        .await
        .unwrap();
    listener
        .listen(authn_session::SIGNING_KEYS_CHANNEL)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    SigningKeyRepository::emergency_rotate(&mut conn, &h.crypto.envelopes, h.now())
        .await
        .unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("no notification after a key change")
        .unwrap();
    assert_eq!(notification.channel(), authn_session::SIGNING_KEYS_CHANNEL);
    assert_eq!(notification.payload(), "", "no key material in the payload");
    // A rolled-back change notifies nobody.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE signing_keys SET status = status")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.recv())
            .await
            .is_err()
    );
}

/// Measurement (not a gate): the per-request cost of the bearer session
/// check (K-58). `cargo test -p authn-session --test k58 -- --ignored
/// --nocapture k58_measure`.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
#[ignore = "measurement"]
async fn ses_08_k58_measure_bearer_session_check(pool: PgPool) {
    const N: u32 = 3000;
    for check in [false, true, false, true] {
        let h = Harness::with(pool.clone(), |c| {
            c.session.access_token_session_check = check;
        })
        .await;
        let user = h
            .user(&format!("m{}@example.com", uuid::Uuid::new_v4().simple()))
            .await;
        let login = h.native_login(user).await;
        for _ in 0..200 {
            h.service.authenticate_bearer(&login.access).await.unwrap();
        }
        let started = std::time::Instant::now();
        for _ in 0..N {
            h.service.authenticate_bearer(&login.access).await.unwrap();
        }
        let per = started.elapsed() / N;
        eprintln!("session_check={check}: {per:?} per bearer authentication");
    }
}

// --- wave 4B audit regressions ----------------------------------------------

fn impersonation_request(
    admin: authn_core::id::UserId,
    target: authn_core::id::UserId,
) -> authn_core::ports::ImpersonationRequest {
    authn_core::ports::ImpersonationRequest {
        admin_user_id: admin,
        target_user_id: target,
        read_only: true,
        ttl: Duration::from_secs(15 * 60),
        reason: "Support ticket 4711".into(),
    }
}

/// Pool pattern (audit finding): starting an impersonation read the target's
/// profile (notification language / name) through a second pooled
/// connection while the transaction held the target's row lock.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_k58_impersonation_never_waits_for_a_second_pooled_connection(pool: PgPool) {
    use authn_core::domain::ClientKind;
    use authn_core::ports::SessionIssuer;
    let small = single_connection_pool(&pool).await;
    let h = Harness::new(small).await;
    let admin = h.user("admin@example.com").await;
    h.make_admin(admin).await;
    let admin_session = h.establish(h.request(admin, h.web_channel())).await;
    let target = h.user("alice@example.com").await;
    let issuer: &dyn SessionIssuer = &h.service;
    for client in [ClientKind::Web, ClientKind::Native] {
        let issued = issuer
            .start_impersonation_with(
                &h.ctx(),
                impersonation_request(admin, target),
                client,
                Some(admin_session.session.id),
            )
            .await
            .unwrap_or_else(|e| panic!("{client:?}: {e}"));
        assert_eq!(issued.user_id, target);
    }
}

/// `password_changed` (audit finding): a login started with the old
/// password — e.g. by whoever made the user change it — must not be
/// completable after the change. Only a pending login whose own outstanding
/// step *is* the password change survives (SES-22: that step revokes with
/// this reason from inside the login; it cannot be completed after another
/// change, as `apply_required_password_change` needs the flag that any
/// change clears).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_k58_password_change_closes_pending_logins_started_before_it(pool: PgPool) {
    use authn_core::domain::{AuthMethodRef, ClientKind, LoginMethod};
    use authn_core::ports::{RequiredAction, RevocationReason, RevokeOptions, SessionRevoker};
    use authn_session::ChallengeKind;
    let h = Harness::new(pool).await;
    let h = &h;
    let user = h.user("alice@example.com").await;
    let (_, mfa_pending) = h.pending_challenge(user, ChallengeKind::Login, None).await;
    let in_flight = |action: RequiredAction| async move {
        let mut tx = h.service.begin().await.unwrap();
        let issued = h
            .service
            .create_challenge(
                &mut tx,
                &h.ctx(),
                authn_session::NewChallenge {
                    kind: ChallengeKind::Login,
                    user_id: user,
                    client_kind: ClientKind::Web,
                    primary_method: Some(LoginMethod::Password),
                    amr: vec![AuthMethodRef::Pwd],
                    first_factor_at: Some(h.now()),
                    allowed_factors: Vec::new(),
                    required_actions: vec![action],
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
        issued.token.expose().to_owned()
    };
    let changing = in_flight(RequiredAction::ChangePassword).await;
    let verifying = in_flight(RequiredAction::VerifyEmail).await;
    let mut tx = h.service.begin().await.unwrap();
    h.revoker
        .revoke_all_for_user(
            &mut tx,
            user,
            RevocationReason::PasswordChanged,
            RevokeOptions::default(),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        !h.challenge_open(&mfa_pending, ChallengeKind::Login).await,
        "a login started with the old password survived the password change"
    );
    assert!(h.challenge_open(&changing, ChallengeKind::Login).await);
    assert!(h.challenge_open(&verifying, ChallengeKind::Login).await);
}

/// Listener robustness (audit): after its connection is killed the
/// listener subscribes again, and a rotation made afterwards still reaches
/// the instance at once.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_09_k58_listener_survives_a_killed_connection(pool: PgPool) {
    let a = Harness::new(pool.clone()).await;
    let b = Harness::new(pool.clone()).await;
    let (shutdown, stop) = tokio::sync::oneshot::channel::<()>();
    let listener = {
        let service = b.service.clone();
        tokio::spawn(async move {
            service
                .run_signing_key_listener(async move {
                    let _ = stop.await;
                })
                .await;
        })
    };
    let wait_connected = || async {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !b.service.signing_key_listener_connected() {
            assert!(
                std::time::Instant::now() < deadline,
                "listener not connected"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    wait_connected().await;
    let killed: Vec<bool> = sqlx::query_scalar(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = current_database() AND query ILIKE 'LISTEN%'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(killed.iter().any(|k| *k), "no listener backend found");
    // Give the listener time to notice, then wait until it is back.
    tokio::time::sleep(Duration::from_millis(300)).await;
    wait_connected().await;
    let listening: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity \
         WHERE datname = current_database() AND query ILIKE 'LISTEN%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(listening >= 1, "the listener did not subscribe again");

    let user = a.user("alice@example.com").await;
    let login = a.native_login(user).await;
    assert_eq!(probe(&b, &login.access).await, StatusCode::OK);
    let mut conn = pool.acquire().await.unwrap();
    SigningKeyRepository::emergency_rotate(&mut conn, &a.crypto.envelopes, a.now())
        .await
        .unwrap();
    drop(conn);
    let started = std::time::Instant::now();
    while probe(&b, &login.access).await != StatusCode::UNAUTHORIZED {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "rotation after a reconnection went unnoticed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    shutdown.send(()).unwrap();
    listener.await.unwrap();
}

/// "Which factor produced `mfa`" (audit item): an organization that only
/// allows some second factors must not be entered with a session whose
/// `mfa` came from another one (login without the organization, then
/// `POST /v1/session/org`). K-78: the factor is read from the session's
/// recorded `mfa_factors`, not from `amr`; a session without a recorded
/// allowed factor is refused (step-up with an allowed factor).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_17_k58_org_switch_enforces_the_allowed_second_factors(pool: PgPool) {
    use authn_core::domain::{AuthMethodRef, FactorKind, LoginMethod};
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    h.add_member(org, alice).await;
    let mut policy = common::empty_policy();
    policy.mfa_required = true;
    policy.allowed_mfa_factors = Some(vec![FactorKind::Totp]);
    h.set_policy(owner, org, policy).await;
    let switch = |login: &common::WebLogin| {
        h.web_post("/v1/session/org", login)
            .json(&json!({ "org_id": org }))
    };
    let login_with = |method: LoginMethod, amr: Vec<AuthMethodRef>, factors: Vec<FactorKind>| {
        let mut request = h.request(alice, h.web_channel());
        request.method = method;
        request.amr = amr;
        request.mfa_factors = factors;
        request
    };
    use AuthMethodRef::{Email, Fed, Kba, Mfa, Otp, Pwd, Sms};
    for (method, amr, factors) in [
        (
            LoginMethod::Password,
            vec![Pwd, Sms, Mfa],
            vec![FactorKind::Sms],
        ),
        (
            LoginMethod::Password,
            vec![Pwd, Kba, Mfa],
            vec![FactorKind::RecoveryCode],
        ),
        (
            LoginMethod::Social,
            vec![Fed, Email, Mfa],
            vec![FactorKind::Email],
        ),
        // `otp` in `amr` without a recorded TOTP (e.g. the e-mail code
        // login's own reference, or a session from before K-78): refused.
        (LoginMethod::EmailCode, vec![Email, Otp, Mfa], vec![]),
        (LoginMethod::Password, vec![Pwd, Otp, Mfa], vec![]),
    ] {
        let login = common::web_of(h.establish(login_with(method, amr, factors)).await);
        h.send(switch(&login))
            .await
            .assert_error(StatusCode::FORBIDDEN, "org_policy_mfa_required");
    }
    for (method, amr) in [
        (LoginMethod::Password, vec![Pwd, Otp, Mfa]),
        // K-78: an e-mail code login + TOTP is now told apart.
        (LoginMethod::EmailCode, vec![Email, Otp, Mfa]),
    ] {
        let login = common::web_of(
            h.establish(login_with(method, amr, vec![FactorKind::Totp]))
                .await,
        );
        h.send(switch(&login)).await.assert_status(StatusCode::OK);
    }
}
