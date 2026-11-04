#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Browser flow (SOC-01, SOC-02, SOC-03, SOC-07) against fake providers.

mod common;

use authn_core::domain::{AccountStatus, AuthMethodRef, ClientKind, LoginMethod};
use authn_core::ports::SecurityEventKind;
use authn_oidc_client::OidcClientService;
use authn_store::UserRepository;
use authn_testkit::http::TestRequest;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(authn_crypto::sha256(verifier.as_bytes()))
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_google_web_login_creates_verified_account_and_logs_in(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", Some("/dashboard?tab=1")).await;

    // Authorization request: code + PKCE S256 + state + nonce, redirect_uri
    // from the public base URL.
    assert_eq!(started.location.path(), "/google/authorize");
    assert_eq!(started.param("response_type"), "code");
    assert_eq!(started.param("client_id"), GOOGLE_WEB);
    assert_eq!(started.param("code_challenge_method"), "S256");
    assert_eq!(
        started.param("redirect_uri"),
        "https://auth.test.example/v1/oauth/google/callback"
    );
    assert_eq!(started.param("scope"), "openid email profile");
    assert_eq!(started.param("state").len(), 43);
    assert_eq!(started.param("nonce").len(), 43);
    assert_ne!(started.param("state"), started.param("nonce"));
    for attr in [
        "HttpOnly",
        "Secure",
        "Path=/",
        "SameSite=None",
        "Max-Age=600",
    ] {
        assert!(started.set_cookie.contains(attr), "{}", started.set_cookie);
    }

    // Nothing secret is stored in clear.
    let (state_hash, verifier_ct, return_to): (Vec<u8>, Vec<u8>, String) =
        sqlx::query_as("SELECT state_hash, pkce_verifier_ciphertext, return_to FROM oauth_states")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        state_hash,
        authn_crypto::sha256(started.param("state").as_bytes())
    );
    assert_eq!(return_to, "https://auth.test.example/dashboard?tab=1");
    assert!(
        !verifier_ct
            .windows(10)
            .any(|w| started.param("state").as_bytes().starts_with(w))
    );

    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_WEB,
        "google-sub-1",
        "AUTO",
        "new.user@example.com",
    );
    h.token_for("/google", &started, &claims).await;
    let res = h.callback("google", &started).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json::<Value>()["status"], "authenticated");

    // PKCE: the verifier sent to the token endpoint hashes to the challenge.
    let token_requests = h.idp.requests_to("/google/token").await;
    assert_eq!(token_requests.len(), 1);
    let form = form_of(&token_requests[0]);
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "the-code");
    assert_eq!(form["client_id"], GOOGLE_WEB);
    assert_eq!(form["client_secret"], "google-web-client-secret");
    assert_eq!(
        s256(&form["code_verifier"]),
        started.param("code_challenge")
    );
    assert_eq!(form["redirect_uri"], started.param("redirect_uri"));

    // Account: active, verified, identity linked.
    let user = h.identity_owner("google", "google-sub-1").await.unwrap();
    let record = UserRepository::find_by_id(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, AccountStatus::Active);
    assert!(record.is_email_verified());
    assert_eq!(record.email.as_deref(), Some("new.user@example.com"));

    // The login went through the SessionIssuer port as a social login.
    let logins = h.ports.session_issuer.logins();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].user_id, user);
    assert_eq!(logins[0].method, LoginMethod::Social);
    assert_eq!(logins[0].amr, vec![AuthMethodRef::Fed]);
    assert_eq!(logins[0].client, ClientKind::Web);
    assert!(!logins[0].provider_asserted_mfa);

    let kinds: Vec<_> = h.ports.audit.recorded().iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&SecurityEventKind::AccountRegistered));
    assert!(kinds.contains(&SecurityEventKind::IdentityLinked));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_state_replay_is_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", None).await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_WEB,
        "s1",
        "AUTO",
        "a@example.com",
    );
    h.token_for("/google", &started, &claims).await;
    h.token_for("/google", &started, &claims).await;
    assert_eq!(h.callback("google", &started).await.status, StatusCode::OK);
    let replay = h.callback("google", &started).await;
    replay.assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
    assert_eq!(h.ports.session_issuer.logins().len(), 1);
    // The second code was never exchanged.
    assert_eq!(h.idp.requests_to("/google/token").await.len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_concurrent_callbacks_consume_the_state_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", None).await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_WEB,
        "s1",
        "AUTO",
        "a@example.com",
    );
    for _ in 0..4 {
        h.token_for("/google", &started, &claims).await;
    }
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let app = h.app();
        let state = started.param("state");
        let binding = started.binding.clone();
        tasks.push(tokio::spawn(async move {
            TestRequest::get(&format!("/v1/oauth/google/callback?code=c&state={state}"))
                .cookie("__Host-authn_oauth", &binding)
                .send(&app)
                .await
                .status
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_callback_from_another_browser_is_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    // The attacker starts a flow and lures the victim to the callback URL
    // with the attacker's state and code (login CSRF).
    let attacker = h.start("google", None).await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_WEB,
        "attacker",
        "AUTO",
        "atk@example.com",
    );
    h.token_for("/google", &attacker, &claims).await;
    let state = attacker.param("state");
    let no_cookie = TestRequest::get(&format!("/v1/oauth/google/callback?code=c&state={state}"))
        .send(&h.app())
        .await;
    no_cookie.assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");

    let victim = h.start("google", None).await;
    let other_browser = TestRequest::get(&format!(
        "/v1/oauth/google/callback?code=c&state={}",
        victim.param("state")
    ))
    .cookie("__Host-authn_oauth", &attacker.binding)
    .send(&h.app())
    .await;
    other_browser.assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
    assert!(h.ports.session_issuer.logins().is_empty());
    assert!(h.idp.requests_to("/google/token").await.is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_state_of_another_provider_is_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", None).await;
    let res = h.callback("apple", &started).await;
    res.assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
    // ...and the state is burnt.
    h.callback("google", &started)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_state_expires_after_ten_minutes(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", None).await;
    h.ports.clock.advance(std::time::Duration::from_secs(601));
    h.callback("google", &started)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
    assert_eq!(h.service.purge_expired_states(100).await.unwrap(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_malformed_state_is_rejected_without_lookup(pool: PgPool) {
    let h = Harness::new(pool).await;
    for state in ["", "short", "%00%0d%0a", &"A".repeat(5000)] {
        TestRequest::get(&format!("/v1/oauth/google/callback?code=c&state={state}"))
            .send(&h.app())
            .await
            .assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_nonce_mismatch_is_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", None).await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_WEB,
        "s1",
        "other-nonce",
        "a@example.com",
    );
    h.token_for("/google", &started, &claims).await;
    h.callback("google", &started)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // Missing nonce.
    let started = h.start("google", None).await;
    let mut claims = claims;
    claims.as_object_mut().unwrap().remove("nonce");
    h.token_for("/google", &started, &claims).await;
    h.callback("google", &started)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    assert_eq!(h.identity_count().await, 0);
    let failed = h
        .ports
        .audit
        .recorded()
        .iter()
        .filter(|e| e.kind == SecurityEventKind::LoginFailed)
        .count();
    assert_eq!(failed, 2);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_pkce_or_code_rejected_by_provider_fails(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", None).await;
    h.idp.mount_token_error("/google", 400).await;
    h.callback("google", &started)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    assert!(h.ports.session_issuer.logins().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_pkce_verifier_is_bound_to_its_state_row(pool: PgPool) {
    let h = Harness::new(pool).await;
    let a = h.start("google", None).await;
    let b = h.start("google", None).await;
    // Copy-paste of A's sealed verifier into B's row: the AAD (row id)
    // makes it undecryptable.
    sqlx::query(
        "UPDATE oauth_states SET pkce_verifier_ciphertext = \
         (SELECT pkce_verifier_ciphertext FROM oauth_states WHERE state_hash = $1) \
         WHERE state_hash = $2",
    )
    .bind(&authn_crypto::sha256(a.param("state").as_bytes())[..])
    .bind(&authn_crypto::sha256(b.param("state").as_bytes())[..])
    .execute(&h.pool)
    .await
    .unwrap();
    let res = h.callback("google", &b).await;
    assert_eq!(res.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(h.idp.requests_to("/google/token").await.is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_return_to_open_redirects_are_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    for evil in [
        "https://evil.example/",
        "//evil.example",
        "/\\evil.example",
        "/%2F%2Fevil.example",
        "javascript:alert(1)",
        "https://app.example.com/after/extra",
        "/\t/evil.example",
    ] {
        let uri = format!(
            "/v1/oauth/google/start?return_to={}",
            url::form_urlencoded::byte_serialize(evil.as_bytes()).collect::<String>()
        );
        let res = TestRequest::get(&uri).send(&h.app()).await;
        res.assert_error(StatusCode::BAD_REQUEST, "invalid_redirect");
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_states")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "no state for a refused start");
    // The allow-listed absolute target is kept exactly.
    h.start("google", Some("https://app.example.com/after"))
        .await;
    let stored: String = sqlx::query_scalar("SELECT return_to FROM oauth_states")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(stored, "https://app.example.com/after");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_user_cancellation_is_reported_and_burns_the_state(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", None).await;
    TestRequest::get(&format!(
        "/v1/oauth/google/callback?error=access_denied&state={}",
        started.param("state")
    ))
    .cookie("__Host-authn_oauth", &started.binding)
    .send(&h.app())
    .await
    .assert_error(StatusCode::BAD_REQUEST, "oauth_authorization_denied");
    h.callback("google", &started)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_start_is_rate_limited_per_ip(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.start_per_ip =
            authn_core::ports::RateLimitPolicy::new(2, std::time::Duration::from_secs(600));
    })
    .await;
    h.start("google", None).await;
    h.start("google", None).await;
    let res = TestRequest::get("/v1/oauth/google/start")
        .send(&h.app())
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_01_unknown_provider_and_listing(pool: PgPool) {
    let h = Harness::new(pool).await;
    TestRequest::get("/v1/oauth/facebook/start")
        .send(&h.app())
        .await
        .assert_error(StatusCode::NOT_FOUND, "oauth_provider_unknown");
    let res = TestRequest::get("/v1/oauth/providers").send(&h.app()).await;
    assert_eq!(res.status, StatusCode::OK);
    let body: Value = res.json();
    let ids: Vec<&str> = body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["acme", "apple", "github", "google", "microsoft"]);
    let github = body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "github")
        .unwrap();
    assert_eq!(github["native"], false);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_01_disabled_providers_are_absent(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.config.github = None;
        s.config.generic.clear();
    })
    .await;
    let ids: Vec<String> = h.service.providers().into_iter().map(|p| p.id).collect();
    assert!(!ids.contains(&"github".to_owned()));
    TestRequest::get("/v1/oauth/acme/start")
        .send(&h.app())
        .await
        .assert_error(StatusCode::NOT_FOUND, "oauth_provider_unknown");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_07_apple_form_post_login_with_es256_client_secret_and_first_name(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("apple", None).await;
    assert_eq!(started.param("response_mode"), "form_post");
    assert_eq!(started.param("scope"), "openid email name");
    let mut claims = h.claims(
        &h.idp.issuer("/apple"),
        APPLE_WEB,
        "001234.apple.sub",
        "AUTO",
        "abc123@privaterelay.appleid.com",
    );
    claims["email_verified"] = json!("true");
    claims["is_private_email"] = json!("true");
    claims.as_object_mut().unwrap().remove("name");
    h.token_for("/apple", &started, &claims).await;

    let body = format!(
        "state={}&code=apple-code&user={}",
        started.param("state"),
        url::form_urlencoded::byte_serialize(
            br#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"spoof@example.com"}"#
        )
        .collect::<String>()
    );
    let res = TestRequest::post("/v1/oauth/apple/callback")
        .header("content-type", "application/x-www-form-urlencoded")
        .cookie("__Host-authn_oauth", &started.binding)
        .body(body)
        .send(&h.app())
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // The client secret is an ES256 JWT for Apple.
    let form = form_of(&h.idp.requests_to("/apple/token").await[0]);
    let secret = &form["client_secret"];
    let parts: Vec<&str> = secret.split('.').collect();
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], "APPLEKEY01");
    assert_eq!(payload["iss"], "TEAMID1234");
    assert_eq!(payload["sub"], APPLE_WEB);
    assert_eq!(payload["aud"], "https://appleid.apple.com");

    // Name from the first-login `user` field; e-mail only from the token.
    let (email, name): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT email, display_name FROM identities WHERE provider = 'apple'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(email.as_deref(), Some("abc123@privaterelay.appleid.com"));
    assert_eq!(name.as_deref(), Some("Ada Lovelace"));
    let user = h.identity_owner("apple", "001234.apple.sub").await.unwrap();
    let record = UserRepository::find_by_id(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.email.as_deref(),
        Some("abc123@privaterelay.appleid.com")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_01_microsoft_web_login_uses_tenant_issuer_and_tid_oid_subject(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("microsoft", None).await;
    let oid = "aaaaaaaa-0000-0000-0000-000000000001";
    let mut claims = h.claims(
        &format!("{}/ms/{MS_CONSUMERS}/v2.0", h.idp.uri()),
        MS_WEB,
        "pairwise-sub",
        "AUTO",
        "person@outlook.com",
    );
    claims["tid"] = json!(MS_CONSUMERS);
    claims["oid"] = json!(oid);
    claims.as_object_mut().unwrap().remove("email_verified");
    h.token_for("/ms", &started, &claims).await;
    let res = h.callback("microsoft", &started).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(
        h.identity_owner("microsoft", &format!("{MS_CONSUMERS}:{oid}"))
            .await
            .is_some()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_microsoft_work_account_email_is_unverified_without_xms_edov(pool: PgPool) {
    let h = Harness::new(pool).await;
    let oid = "aaaaaaaa-0000-0000-0000-000000000002";
    let make = |h: &Harness, edov: bool| {
        let mut c = h.claims(
            &format!("{}/ms/{MS_TENANT}/v2.0", h.idp.uri()),
            MS_WEB,
            "sub",
            "AUTO",
            "ceo@victim.example",
        );
        c["tid"] = json!(MS_TENANT);
        c["oid"] = json!(oid);
        c["email_verified"] = json!(true); // ignored for Microsoft
        if edov {
            c["xms_edov"] = json!(true);
        }
        c
    };
    // nOAuth: a mutable, unverified `email` claim must not create (or
    // reach) an account.
    let started = h.start("microsoft", None).await;
    h.token_for("/ms", &started, &make(&h, false)).await;
    h.callback("microsoft", &started)
        .await
        .assert_error(StatusCode::FORBIDDEN, "oauth_email_not_verified");
    assert_eq!(h.identity_count().await, 0);

    let started = h.start("microsoft", None).await;
    h.token_for("/ms", &started, &make(&h, true)).await;
    assert_eq!(
        h.callback("microsoft", &started).await.status,
        StatusCode::OK
    );
}

async fn mount_github(h: &Harness, emails: Value) {
    h.idp
        .mount_token_once(
            "/github",
            json!({ "access_token": "gho_test", "token_type": "bearer", "scope": "read:user,user:email" }),
        )
        .await;
    Mock::given(method("GET"))
        .and(path("/github/api/user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 4242, "login": "octo", "name": "Octo Cat" })),
        )
        .mount(&h.idp.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/github/api/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(emails))
        .up_to_n_times(1)
        .mount(&h.idp.server)
        .await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_01_github_login_uses_primary_verified_email(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("github", None).await;
    assert!(!started.params.contains_key("nonce"), "GitHub is not OIDC");
    assert_eq!(started.param("scope"), "read:user user:email");
    mount_github(
        &h,
        json!([
            { "email": "secondary@example.com", "primary": false, "verified": true },
            { "email": "octo@example.com", "primary": true, "verified": true },
        ]),
    )
    .await;
    let res = h.callback("github", &started).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let user = h.identity_owner("github", "4242").await.unwrap();
    let record = UserRepository::find_by_id(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.email.as_deref(), Some("octo@example.com"));
    // The API was called with the access token.
    let api = h.idp.requests_to("/github/api/user").await;
    assert_eq!(api[0].headers["authorization"], "Bearer gho_test");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_github_unverified_primary_email_cannot_create_an_account(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("github", None).await;
    mount_github(
        &h,
        json!([
            { "email": "victim@example.com", "primary": true, "verified": false },
            { "email": "other@example.com", "primary": false, "verified": true },
        ]),
    )
    .await;
    h.callback("github", &started)
        .await
        .assert_error(StatusCode::FORBIDDEN, "oauth_email_not_verified");
    assert_eq!(h.identity_count().await, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_01_generic_oidc_provider_uses_discovery_and_basic_auth(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("acme", None).await;
    assert_eq!(started.location.path(), "/acme/authorize");
    assert_eq!(started.param("scope"), "openid email");
    let claims = h.claims(
        &h.idp.issuer("/acme"),
        ACME_WEB,
        "acme-1",
        "AUTO",
        "e@acme.example",
    );
    h.token_for("/acme", &started, &claims).await;
    let res = h.callback("acme", &started).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(h.identity_owner("oidc:acme", "acme-1").await.is_some());
    // No auth methods advertised → client_secret_basic.
    let token = &h.idp.requests_to("/acme/token").await[0];
    assert!(
        token.headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("Basic ")
    );
    assert!(!form_of(token).contains_key("client_secret"));
    // Discovery is cached.
    let started = h.start("acme", None).await;
    let _ = started;
    assert_eq!(
        h.idp
            .requests_to("/acme/.well-known/openid-configuration")
            .await
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_01_generic_discovery_with_foreign_issuer_is_refused(pool: PgPool) {
    let h = Harness::new(pool).await;
    // A second provider whose discovery document claims another issuer.
    let mut settings = h.settings.clone();
    settings
        .config
        .generic
        .push(authn_core::config::oidc_client::GenericOidcProvider {
            slug: "mixup".to_owned(),
            display_name: "Mix-up".to_owned(),
            issuer_url: h.idp.issuer("/mixup"),
            client: authn_core::config::oidc_client::ProviderClient {
                client_id: "m".to_owned(),
                client_secret: authn_core::secret::SecretString::from("s".to_owned()),
                native_client_ids: Vec::new(),
            },
            scopes: vec!["openid".to_owned()],
            trust_email_verified: true,
        });
    Mock::given(method("GET"))
        .and(path("/mixup/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": h.idp.issuer("/acme"),
            "authorization_endpoint": format!("{}/acme/authorize", h.idp.uri()),
            "token_endpoint": format!("{}/acme/token", h.idp.uri()),
            "jwks_uri": format!("{}/acme/jwks", h.idp.uri()),
        })))
        .mount(&h.idp.server)
        .await;
    let registry = authn_oidc_client::ProviderRegistry::from_settings(&settings).unwrap();
    let service = OidcClientService::with_registry(h.service_deps(), settings, registry);
    let err = service
        .start_web_login(&h.ctx(), "mixup", None, None)
        .await
        .unwrap_err();
    assert!(err.is(authn_core::error::codes::common::SERVICE_UNAVAILABLE));
}

// --- Independent security review: regression tests -------------------------

/// Review finding 1: the callback was neither rate-limited nor exempt from
/// the audit, so any anonymous client could write unlimited `login.failed`
/// records (and run unlimited `UPDATE`s) with random, well-formed `state`
/// values.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_callback_is_rate_limited_and_cannot_flood_the_audit(pool: PgPool) {
    let h = Harness::new(pool).await;
    let budget = h.settings.callback_per_ip.limit;
    let mut throttled = 0;
    for _ in 0..budget + 5 {
        let state = authn_crypto::token::OpaqueToken::generate().unwrap();
        let res = TestRequest::get(&format!(
            "/v1/oauth/google/callback?code=c&state={}",
            state.expose()
        ))
        .send(&h.app())
        .await;
        if res.status == StatusCode::TOO_MANY_REQUESTS {
            throttled += 1;
        } else {
            res.assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
        }
    }
    assert_eq!(throttled, 5);
    let failures = h
        .ports
        .audit
        .recorded()
        .iter()
        .filter(|e| e.kind == SecurityEventKind::LoginFailed)
        .count();
    assert_eq!(failures, usize::try_from(budget).unwrap());
}
