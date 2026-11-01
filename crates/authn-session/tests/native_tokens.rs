#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Native tokens: access-token claims and verification, refresh rotation,
//! reuse detection, grace window, JWKS (SES-05, SES-06, SES-08, SES-09).

mod common;

use std::time::Duration;

use authn_core::ports::SecurityEventKind;
use authn_crypto::jwt::TYP_ACCESS_TOKEN;
use authn_crypto::signing::Ed25519SigningKey;
use authn_store::SigningKeyRepository;
use authn_testkit::http::{TestRequest, TestResponse};
use common::{Harness, NativeLogin, jwt_payload};
use http::StatusCode;
use sqlx::PgPool;

async fn refresh(h: &Harness, token: &str) -> TestResponse {
    h.send(
        TestRequest::post("/v1/token/refresh").json(&serde_json::json!({ "refresh_token": token })),
    )
    .await
}

async fn probe(h: &Harness, access: &str) -> TestResponse {
    h.send(TestRequest::get("/v1/probe").bearer(access)).await
}

fn b64(value: &serde_json::Value) -> String {
    data_encoding::BASE64URL_NOPAD.encode(&serde_json::to_vec(value).unwrap())
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_08_access_token_claims_follow_rfc_9068_without_personal_data(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice.personal@example.com").await;
    let login = h.native_login(user).await;
    let header = {
        let raw = login.access.split('.').next().unwrap();
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(raw.as_bytes())
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    };
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "at+jwt");
    assert!(header["kid"].is_string());
    let claims = jwt_payload(&login.access);
    for claim in [
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "sid",
        "auth_time",
        "amr",
        "scope",
        "client_id",
    ] {
        assert!(claims.get(claim).is_some(), "missing {claim}: {claims}");
    }
    assert_eq!(claims["iss"], "https://auth.test.example");
    assert_eq!(claims["sub"], user.to_string());
    assert_eq!(claims["sid"], login.session_id.to_string());
    assert_eq!(claims["aud"], serde_json::json!(["rust-authentication"]));
    assert_eq!(claims["amr"], serde_json::json!(["pwd"]));
    assert_eq!(claims["scope"], "api");
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        600,
        "10 minute access tokens"
    );
    assert!(claims.get("act").is_none());
    let text = claims.to_string();
    assert!(
        !text.contains("alice") && !text.contains("example.com"),
        "no PII: {text}"
    );
    // The token authenticates through the middleware.
    let res = probe(&h, &login.access).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["user_id"], user.to_string());
    assert_eq!(body["session_id"], login.session_id.to_string());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_08_tampered_and_foreign_tokens_are_rejected_by_the_middleware(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    let signer = SigningKeyRepository::load_active_signer(&h.pool, &h.crypto.envelopes)
        .await
        .unwrap();
    let claims = jwt_payload(&login.access);
    let sign = |claims: &serde_json::Value| signer.sign(TYP_ACCESS_TOKEN, claims).unwrap();
    let with = |key: &str, value: serde_json::Value| {
        let mut c = claims.clone();
        c[key] = value;
        c
    };
    let parts: Vec<&str> = login.access.split('.').collect();
    let other_user = h.user("bob@example.com").await;
    let mut cases: Vec<(&str, String)> = vec![
        (
            "payload swapped, signature kept",
            format!(
                "{}.{}.{}",
                parts[0],
                b64(&with("sub", other_user.to_string().into())),
                parts[2]
            ),
        ),
        (
            "alg none",
            format!(
                "{}.{}.",
                b64(&serde_json::json!({"alg": "none", "typ": "at+jwt", "kid": signer.kid()})),
                parts[1]
            ),
        ),
        (
            "alg HS256",
            format!(
                "{}.{}.{}",
                b64(&serde_json::json!({"alg": "HS256", "typ": "at+jwt", "kid": signer.kid()})),
                parts[1],
                parts[2]
            ),
        ),
        (
            "wrong audience",
            sign(&with("aud", serde_json::json!(["other-api"]))),
        ),
        (
            "wrong issuer",
            sign(&with("iss", "https://evil.example".into())),
        ),
        (
            "lifetime too long",
            sign(&with(
                "exp",
                (claims["iat"].as_i64().unwrap() + 3600).into(),
            )),
        ),
        (
            "not yet valid",
            sign(&with(
                "nbf",
                (claims["iat"].as_i64().unwrap() + 3600).into(),
            )),
        ),
        (
            "unknown session",
            sign(&with("sid", uuid::Uuid::now_v7().to_string().into())),
        ),
        (
            "other owner",
            sign(&with("sub", other_user.to_string().into())),
        ),
        ("garbage", "not-a-jwt".to_owned()),
    ];
    // A key that is not in the JWKS (unknown kid) and a known kid with a
    // foreign key (bad signature).
    let foreign = authn_crypto::jwt::JwtSigner::new(
        "00000000-0000-7000-8000-000000000000",
        Ed25519SigningKey::generate().unwrap(),
    )
    .unwrap();
    cases.push((
        "unknown kid",
        foreign.sign(TYP_ACCESS_TOKEN, &claims).unwrap(),
    ));
    let impostor =
        authn_crypto::jwt::JwtSigner::new(signer.kid(), Ed25519SigningKey::generate().unwrap())
            .unwrap();
    cases.push((
        "known kid, foreign key",
        impostor.sign(TYP_ACCESS_TOKEN, &claims).unwrap(),
    ));
    cases.push(("wrong typ", signer.sign("JWT", &claims).unwrap()));
    for (name, token) in cases {
        let res = probe(&h, &token).await;
        res.assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
        assert_eq!(
            res.header("www-authenticate"),
            Some("Bearer error=\"invalid_token\""),
            "{name}"
        );
    }
    // Expiry (with the 30 s leeway).
    probe(&h, &login.access).await.assert_status(StatusCode::OK);
    h.advance(Duration::from_secs(600 + 31));
    probe(&h, &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_revoked_session_rejects_its_access_tokens_at_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    probe(&h, &login.access).await.assert_status(StatusCode::OK);
    h.send(TestRequest::post("/v1/logout").bearer(&login.access))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    probe(&h, &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    refresh(&h, &login.refresh)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_without_session_check_revocation_waits_for_expiry(pool: PgPool) {
    let h = Harness::with(pool, |c| c.session.access_token_session_check = false).await;
    let user = h.user("alice@example.com").await;
    h.make_admin(user).await;
    let login = h.native_login(user).await;
    let mut tx = h.service.begin().await.unwrap();
    authn_core::ports::SessionRevoker::revoke_session(
        &h.revoker,
        &mut tx,
        login.session_id,
        authn_core::ports::RevocationReason::AdminAction,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // Documented trade-off: still accepted until it expires…
    let res = probe(&h, &login.access).await;
    res.assert_status(StatusCode::OK);
    // …but never with platform-admin rights.
    assert_eq!(res.json::<serde_json::Value>()["is_platform_admin"], false);
    h.advance(Duration::from_secs(631));
    probe(&h, &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_refresh_rotates_and_replay_revokes_the_family(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    let res = refresh(&h, &login.refresh).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let first: serde_json::Value = res.json();
    let second_refresh = first["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(second_refresh, login.refresh);
    assert_eq!(first["token_type"], "Bearer");
    assert_eq!(first["expires_in"], 600);
    let access = first["access_token"].as_str().unwrap().to_owned();
    probe(&h, &access).await.assert_status(StatusCode::OK);
    // Normal use continues.
    let third: serde_json::Value = refresh(&h, &second_refresh).await.json();
    let third_refresh = third["refresh_token"].as_str().unwrap().to_owned();

    // An attacker replays the first (already rotated) token: uniform error,
    // the whole family dies, a security event is recorded.
    refresh(&h, &login.refresh)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
    assert_eq!(
        h.revoked_reason(login.session_id).await.as_deref(),
        Some("refresh_token_reuse")
    );
    refresh(&h, &third_refresh)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
    probe(&h, third["access_token"].as_str().unwrap())
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let events = h
        .ports
        .audit
        .of_kind(SecurityEventKind::RefreshTokenReuseDetected);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].subject_user, Some(user));
    let live = h
        .count(
            "SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL",
            login.session_id.as_uuid(),
        )
        .await;
    assert_eq!(live, 0);
    // Unknown and malformed tokens: the same answer.
    for bad in ["", "x", &"A".repeat(43)] {
        refresh(&h, bad)
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_concurrent_refresh_of_one_token_is_a_replay(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    let ctx = h.ctx();
    let attempts: Vec<_> = (0..4)
        .map(|_| {
            let service = h.service.clone();
            let ctx = ctx.clone();
            let token = login.refresh.clone();
            tokio::spawn(async move { service.refresh(&ctx, &token).await })
        })
        .collect();
    let mut ok = 0;
    for attempt in attempts {
        match attempt.await.unwrap() {
            Ok(_) => ok += 1,
            Err(err) => assert_eq!(err.code().code(), "invalid_refresh_token"),
        }
    }
    assert_eq!(ok, 1, "exactly one rotation wins");
    // Without a grace window the losers are replays: the family is revoked.
    assert_eq!(
        h.revoked_reason(login.session_id).await.as_deref(),
        Some("refresh_token_reuse")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_grace_window_returns_the_same_successor_only(pool: PgPool) {
    let h = Harness::with(pool, |c| {
        c.session.refresh_reuse_grace = Duration::from_secs(10);
    })
    .await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    let first: serde_json::Value = refresh(&h, &login.refresh).await.json();
    // A retry (lost response) within the window gets the same successor.
    h.advance(Duration::from_secs(5));
    let retry: serde_json::Value = refresh(&h, &login.refresh).await.json();
    assert_eq!(retry["refresh_token"], first["refresh_token"]);
    let live = h
        .count(
            "SELECT count(*) FROM refresh_tokens WHERE session_id = $1 \
             AND used_at IS NULL AND revoked_at IS NULL",
            login.session_id.as_uuid(),
        )
        .await;
    assert_eq!(live, 1, "never two live tokens");
    // Once the successor is used, the old token is a replay again.
    let next: serde_json::Value = refresh(&h, first["refresh_token"].as_str().unwrap())
        .await
        .json();
    assert!(next["refresh_token"].is_string());
    refresh(&h, &login.refresh)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
    assert_eq!(
        h.revoked_reason(login.session_id).await.as_deref(),
        Some("refresh_token_reuse")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_05_grace_window_closes(pool: PgPool) {
    let h = Harness::with(pool, |c| {
        c.session.refresh_reuse_grace = Duration::from_secs(10);
    })
    .await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    refresh(&h, &login.refresh)
        .await
        .assert_status(StatusCode::OK);
    h.advance(Duration::from_secs(11));
    refresh(&h, &login.refresh)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
    assert_eq!(
        h.revoked_reason(login.session_id).await.as_deref(),
        Some("refresh_token_reuse")
    );
    // The sealed successor is wiped by the cleanup job.
    let report = h.service.purge_expired(100).await.unwrap();
    assert_eq!(
        h.count(
            "SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND successor_ciphertext IS NOT NULL",
            login.session_id.as_uuid(),
        )
        .await,
        0
    );
    let _ = report;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_06_refresh_never_extends_the_absolute_expiry(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let NativeLogin {
        refresh: mut token,
        session_id,
        ..
    } = h.native_login(user).await;
    let (_, _, absolute) = common::session_row(&h.pool, session_id).await;
    assert_eq!(absolute - h.now(), time::Duration::days(90));
    // Refresh every 29 days (inside the 30-day idle window).
    for _ in 0..3 {
        h.advance(Duration::from_secs(29 * 86_400));
        let body: serde_json::Value = refresh(&h, &token).await.json();
        token = body["refresh_token"].as_str().unwrap().to_owned();
        let expires: time::OffsetDateTime = time::OffsetDateTime::parse(
            body["refresh_token_expires_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(expires <= absolute);
        let (_, _, abs) = common::session_row(&h.pool, session_id).await;
        assert_eq!(abs, absolute);
    }
    h.advance(Duration::from_secs(3 * 86_400 + 1));
    refresh(&h, &token)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_06_refresh_idle_timeout(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    h.advance(Duration::from_secs(30 * 86_400 + 1));
    refresh(&h, &login.refresh)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "invalid_refresh_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_09_jwks_publishes_public_keys_with_cache_headers(pool: PgPool) {
    let h = Harness::new(pool).await;
    let res = h.send(TestRequest::get("/.well-known/jwks.json")).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("public, max-age=3600"));
    let body: serde_json::Value = res.json();
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["use"], "sig");
    for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
        assert!(key.get(private).is_none(), "private member {private}");
    }
    // The key verifies issued tokens offline (resource servers).
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    let header = login.access.split('.').next().unwrap();
    let header: serde_json::Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(header.as_bytes())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["kid"], key["kid"]);
    let x = data_encoding::BASE64URL_NOPAD
        .decode(key["x"].as_str().unwrap().as_bytes())
        .unwrap();
    let public = authn_crypto::signing::Ed25519PublicKey::from_bytes(&x).unwrap();
    let verifier =
        authn_crypto::jwt::JwtVerifier::new([(key["kid"].as_str().unwrap().to_owned(), public)]);
    let validation = authn_crypto::jwt::JwtValidation::access_token(
        "https://auth.test.example",
        "rust-authentication",
    );
    verifier
        .verify::<serde_json::Value>(&login.access, &validation, h.now())
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_09_rotated_keys_keep_verifying_and_revoked_keys_stop(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.native_login(user).await;
    let mut conn = h.pool.acquire().await.unwrap();
    let new_key = SigningKeyRepository::emergency_rotate(&mut conn, &h.crypto.envelopes, h.now())
        .await
        .unwrap();
    drop(conn);
    h.service.invalidate_signing_keys();
    // Emergency rotation revoked the old key: its tokens fail at once.
    probe(&h, &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    // New tokens use the new key.
    let fresh = h.native_login(user).await;
    let header = fresh.access.split('.').next().unwrap();
    let header: serde_json::Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(header.as_bytes())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["kid"], new_key.kid());
    probe(&h, &fresh.access).await.assert_status(StatusCode::OK);
}
