#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Token introspection for resource servers (SES-10, RFC 7662).

mod common;

use authn_core::id::OrgId;
use authn_testkit::http::{TestRequest, TestResponse};
use common::{Harness, NativeLogin};
use http::StatusCode;
use sqlx::PgPool;

async fn introspect(h: &Harness, key: Option<&str>, token: &str) -> TestResponse {
    let mut request = TestRequest::post("/v1/token/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("token={token}&token_type_hint=access_token"));
    if let Some(key) = key {
        request = request.bearer(key);
    }
    h.send(request).await
}

async fn org_login(h: &Harness, user: authn_core::id::UserId, org: OrgId) -> NativeLogin {
    let mut request = h.request(user, authn_session::ClientChannel::Native);
    request.org = Some(h.verified_org(user, org).await);
    common::native_of(h.establish(request).await)
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_10_introspection_requires_api_key_client_authentication(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    let login = org_login(&h, owner, org).await;
    introspect(&h, None, &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    // A user's own access token is not a client credential.
    introspect(&h, Some(&login.access), &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    introspect(&h, Some("ak_test_invalid_key"), &login.access)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_10_active_token_of_the_clients_organization(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    let key = h.api_key(owner, org).await;
    let login = org_login(&h, owner, org).await;
    let res = introspect(&h, Some(&key), &login.access).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: serde_json::Value = res.json();
    assert_eq!(body["active"], true);
    assert_eq!(body["sub"], owner.to_string());
    assert_eq!(body["sid"], login.session_id.to_string());
    assert_eq!(body["org_id"], org.to_string());
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "api");
    assert!(body["exp"].is_i64() && body["iat"].is_i64());
    assert!(!body.to_string().contains("owner@example.com"), "no PII");
    // JSON bodies are accepted too; X-API-Key works as well.
    let res = h
        .send(
            TestRequest::post("/v1/token/introspect")
                .header("x-api-key", &key)
                .json(&serde_json::json!({ "token": login.access })),
        )
        .await;
    assert_eq!(res.json::<serde_json::Value>()["active"], true);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_10_revoked_expired_and_foreign_tokens_are_inactive(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    let other_owner = h.user("other@example.com").await;
    let other_org = h.org(other_owner, "globex").await;
    let key = h.api_key(owner, org).await;
    let inactive = serde_json::json!({ "active": false });

    // Another tenant's token: indistinguishable from an invalid one.
    let foreign = org_login(&h, other_owner, other_org).await;
    assert_eq!(
        introspect(&h, Some(&key), &foreign.access)
            .await
            .json::<serde_json::Value>(),
        inactive
    );
    // A personal token (no active organization).
    let personal = h.native_login(owner).await;
    assert_eq!(
        introspect(&h, Some(&key), &personal.access)
            .await
            .json::<serde_json::Value>(),
        inactive
    );
    // Garbage, refresh tokens.
    assert_eq!(
        introspect(&h, Some(&key), "garbage")
            .await
            .json::<serde_json::Value>(),
        inactive
    );
    assert_eq!(
        introspect(&h, Some(&key), &personal.refresh)
            .await
            .json::<serde_json::Value>(),
        inactive
    );

    // Revoked session: inactive at once, even though the JWT is still valid.
    let login = org_login(&h, owner, org).await;
    assert_eq!(
        introspect(&h, Some(&key), &login.access)
            .await
            .json::<serde_json::Value>()["active"],
        true
    );
    h.send(TestRequest::post("/v1/logout").bearer(&login.access))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        introspect(&h, Some(&key), &login.access)
            .await
            .json::<serde_json::Value>(),
        inactive
    );

    // Expired.
    let login = org_login(&h, owner, org).await;
    h.advance(std::time::Duration::from_secs(700));
    let key_still_valid = introspect(&h, Some(&key), &login.access).await;
    assert_eq!(key_still_valid.json::<serde_json::Value>(), inactive);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_10_introspection_is_rate_limited_per_client(pool: PgPool) {
    let h = Harness::with(pool, |c| {
        c.session.introspection_per_client =
            authn_core::ports::RateLimitPolicy::new(2, std::time::Duration::from_secs(60));
    })
    .await;
    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    let key = h.api_key(owner, org).await;
    for _ in 0..2 {
        introspect(&h, Some(&key), "x")
            .await
            .assert_status(StatusCode::OK);
    }
    introspect(&h, Some(&key), "x")
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_10_api_keys_authenticate_only_on_organization_routes(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    let key = h.api_key(owner, org).await;
    // On an organization route the key is a principal…
    let body: serde_json::Value = h
        .send(TestRequest::get(&format!("/v1/orgs/{org}/probe")).bearer(&key))
        .await
        .json();
    assert_eq!(body["authenticated"], true);
    // …elsewhere it grants nothing (and the session cookie is not consulted
    // either).
    let login = h.web_login(owner).await;
    let body: serde_json::Value = h
        .send(
            TestRequest::get("/v1/probe")
                .bearer(&key)
                .cookie(authn_session::cookies::SESSION_COOKIE, &login.cookie),
        )
        .await
        .json();
    assert_eq!(body["authenticated"], false);
    h.send(TestRequest::get("/v1/me").bearer(&key))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    // Ambiguous credentials are refused.
    h.send(
        TestRequest::get(&format!("/v1/orgs/{org}/probe"))
            .bearer(&key)
            .header("x-api-key", &key),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_10_empty_oversized_and_refresh_hinted_tokens_are_inactive(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let org = h.org(owner, "acme").await;
    let key = h.api_key(owner, org).await;
    let login = org_login(&h, owner, org).await;
    let inactive = serde_json::json!({ "active": false });
    let send = |body: String| {
        let request = TestRequest::post("/v1/token/introspect")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .bearer(&key);
        h.send(request)
    };
    // The same access token is active with the access hint …
    let active: serde_json::Value = send(format!("token={}", login.access)).await.json();
    assert_eq!(active["active"], true);
    // … but refresh tokens are never introspected, and empty or oversized
    // input is answered without any lookup.
    for body in [
        format!("token={}&token_type_hint=refresh_token", login.access),
        format!("token={}&token_type_hint=refresh_token", login.refresh),
        "token=".to_owned(),
        format!("token={}", "a".repeat(20_000)),
    ] {
        let response = send(body).await;
        response.assert_status(StatusCode::OK);
        assert_eq!(response.json::<serde_json::Value>(), inactive);
    }
}
