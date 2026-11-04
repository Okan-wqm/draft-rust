#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Native flow (SOC-04), ID-token verification end to end (SOC-03) and MFA
//! policy hand-off (SOC-09).

mod common;

use std::time::Duration;

use authn_core::domain::{ClientKind, FactorKind, LoginMethod};
use authn_core::id::ChallengeId;
use authn_core::ports::{Clock as _, LoginOutcome, PendingChallenge, RequiredAction};
use authn_core::secret::SensitiveString;
use authn_testkit::http::TestRequest;
use common::*;
use http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;

fn google_claims(h: &Harness, nonce: &str, sub: &str) -> Value {
    h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_NATIVE,
        sub,
        nonce,
        &format!("{sub}@example.com"),
    )
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_04_google_native_login_with_server_nonce(pool: PgPool) {
    let h = Harness::new(pool).await;
    let nonce = h.native_nonce("google").await;
    assert_eq!(nonce.len(), 43);
    let token = sign_rs256(KEY_A, "key-a", &google_claims(&h, &nonce, "g-native"));
    let res = TestRequest::post("/v1/oauth/google/native")
        .json(&json!({ "id_token": token, "remember_me": true }))
        .send(&h.app())
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let logins = h.ports.session_issuer.logins();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].client, ClientKind::Native);
    assert_eq!(logins[0].method, LoginMethod::Social);
    assert!(logins[0].remember_me);
    assert!(h.identity_owner("google", "g-native").await.is_some());
    // Nonce stored only as a hash.
    let hash: Vec<u8> = sqlx::query_scalar("SELECT nonce_hash FROM oauth_states")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(hash, authn_crypto::sha256(nonce.as_bytes()));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_04_apple_microsoft_and_generic_native_logins(pool: PgPool) {
    let h = Harness::new(pool).await;
    // Apple (bundle id audience, first-login name from the SDK).
    let nonce = h.native_nonce("apple").await;
    let mut claims = h.claims(
        &h.idp.issuer("/apple"),
        APPLE_NATIVE,
        "apple-1",
        &nonce,
        "x@privaterelay.appleid.com",
    );
    claims["email_verified"] = json!("true");
    let res = TestRequest::post("/v1/oauth/apple/native")
        .json(&json!({
            "id_token": sign_rs256(KEY_A, "key-a", &claims),
            "given_name": "Grace",
            "family_name": "Hopper",
        }))
        .send(&h.app())
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM identities WHERE provider = 'apple'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(name.as_deref(), Some("Grace Hopper"));

    // Microsoft.
    let nonce = h.native_nonce("microsoft").await;
    let mut claims = h.claims(
        &format!("{}/ms/{MS_CONSUMERS}/v2.0", h.idp.uri()),
        MS_NATIVE,
        "x",
        &nonce,
        "ms@outlook.com",
    );
    claims["tid"] = json!(MS_CONSUMERS);
    claims["oid"] = json!("bbbbbbbb-0000-0000-0000-000000000001");
    let res = h
        .native("microsoft", &sign_rs256(KEY_A, "key-a", &claims))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // Generic (discovered JWKS).
    let nonce = h.native_nonce("acme").await;
    let claims = h.claims(
        &h.idp.issuer("/acme"),
        ACME_NATIVE,
        "acme-n",
        &nonce,
        "n@acme.example",
    );
    let res = h.native("acme", &sign_rs256(KEY_A, "key-a", &claims)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(h.identity_count().await, 3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_04_nonce_is_mandatory_single_use_and_provider_bound(pool: PgPool) {
    let h = Harness::new(pool).await;
    // No nonce in the token.
    let mut claims = google_claims(&h, "x", "g1");
    claims.as_object_mut().unwrap().remove("nonce");
    h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_nonce_invalid");
    // A nonce the server never issued.
    let token = sign_rs256(KEY_A, "key-a", &google_claims(&h, "made-up-nonce", "g1"));
    h.native("google", &token)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_nonce_invalid");
    // Replay of a successful token.
    let nonce = h.native_nonce("google").await;
    let token = sign_rs256(KEY_A, "key-a", &google_claims(&h, &nonce, "g1"));
    assert_eq!(h.native("google", &token).await.status, StatusCode::OK);
    h.native("google", &token)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_nonce_invalid");
    // A nonce issued for Apple cannot be used with Google.
    let apple_nonce = h.native_nonce("apple").await;
    let token = sign_rs256(KEY_A, "key-a", &google_claims(&h, &apple_nonce, "g1"));
    h.native("google", &token)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_nonce_invalid");
    // Expired nonce.
    let nonce = h.native_nonce("google").await;
    h.ports.clock.advance(Duration::from_secs(601));
    let token = sign_rs256(KEY_A, "key-a", &google_claims(&h, &nonce, "g1"));
    h.native("google", &token)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_nonce_invalid");
    // A web-flow nonce is not a native nonce.
    let started = h.start("google", None).await;
    let token = sign_rs256(
        KEY_A,
        "key-a",
        &google_claims(&h, &started.param("nonce"), "g1"),
    );
    h.native("google", &token)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_nonce_invalid");
    assert_eq!(h.ports.session_issuer.logins().len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_04_native_audience_is_the_native_client_ids(pool: PgPool) {
    let h = Harness::new(pool).await;
    for aud in [
        json!(GOOGLE_WEB),
        json!("attacker-app"),
        json!([GOOGLE_NATIVE, "attacker-app"]),
    ] {
        let nonce = h.native_nonce("google").await;
        let mut claims = google_claims(&h, &nonce, "g1");
        claims["aud"] = aud.clone();
        h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    }
    // An untrusted extra audience is refused even with our `azp` (OIDC Core
    // 3.1.3.7 rule 3; security review finding 2).
    let nonce = h.native_nonce("google").await;
    let mut claims = google_claims(&h, &nonce, "g1");
    claims["aud"] = json!([GOOGLE_NATIVE, "other"]);
    claims["azp"] = json!(GOOGLE_NATIVE);
    h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // An audience array of accepted ids with a matching azp is accepted.
    let nonce = h.native_nonce("google").await;
    let mut claims = google_claims(&h, &nonce, "g1");
    claims["aud"] = json!([GOOGLE_NATIVE]);
    claims["azp"] = json!(GOOGLE_NATIVE);
    assert_eq!(
        h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
            .await
            .status,
        StatusCode::OK
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_04_github_has_no_native_flow(pool: PgPool) {
    let h = Harness::new(pool).await;
    TestRequest::post("/v1/oauth/nonce")
        .json(&json!({ "provider": "github" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_native_not_supported");
    h.native("github", "a.b.c")
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_native_not_supported");
    TestRequest::post("/v1/oauth/nonce")
        .json(&json!({ "provider": "nope" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::NOT_FOUND, "oauth_provider_unknown");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_03_wrong_issuer_audience_azp_expiry_and_future_iat_are_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    type Mutation = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "wrong iss",
            Box::new(|c: &mut Value| c["iss"] = json!("https://accounts.google.com")),
        ),
        (
            "other provider iss",
            Box::new({
                let apple = h.idp.issuer("/apple");
                move |c: &mut Value| c["iss"] = json!(apple)
            }),
        ),
        (
            "wrong aud",
            Box::new(|c: &mut Value| c["aud"] = json!("someone-else")),
        ),
        (
            "wrong azp",
            Box::new(|c: &mut Value| c["azp"] = json!("someone-else")),
        ),
        (
            "expired",
            Box::new({
                let now = h.now();
                move |c: &mut Value| c["exp"] = json!(now - 3600)
            }),
        ),
        (
            "future iat",
            Box::new({
                let now = h.now();
                move |c: &mut Value| c["iat"] = json!(now + 3600)
            }),
        ),
        (
            "no sub",
            Box::new(|c: &mut Value| {
                c.as_object_mut().unwrap().remove("sub");
            }),
        ),
    ];
    for (name, mutate) in cases {
        let nonce = h.native_nonce("google").await;
        let mut claims = google_claims(&h, &nonce, "g1");
        mutate(&mut claims);
        let res = h
            .native("google", &sign_rs256(KEY_A, "key-a", &claims))
            .await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "{name}: {}",
            res.text()
        );
        res.assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    }
    assert!(h.ports.session_issuer.logins().is_empty());
    assert_eq!(h.identity_count().await, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_03_alg_none_hmac_confusion_and_foreign_keys_are_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let nonce = h.native_nonce("google").await;
    let claims = google_claims(&h, &nonce, "g1");
    // alg: none.
    h.native("google", &unsigned("key-a", &claims))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // HS256 "signed" with the provider's public key material (classic
    // algorithm confusion).
    let jwk = public_jwk(KEY_A, "key-a");
    let n = jwk["n"].as_str().unwrap().as_bytes().to_vec();
    h.native("google", &sign_hs256_with(&n, "key-a", &claims))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // Signed by a key the provider does not publish, claiming its kid.
    h.native("google", &sign_rs256(KEY_B, "key-a", &claims))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // Signed by another provider's key set is irrelevant: kid unknown.
    h.native("google", &sign_rs256(KEY_B, "unknown-kid", &claims))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // The nonce survived all of this (only verified tokens consume it).
    assert_eq!(
        h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
            .await
            .status,
        StatusCode::OK
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_03_jwks_rotation_and_rate_limited_refresh(pool: PgPool) {
    let h = Harness::new(pool).await;
    // Warm the cache with key A.
    let nonce = h.native_nonce("google").await;
    assert_eq!(
        h.native(
            "google",
            &sign_rs256(KEY_A, "key-a", &google_claims(&h, &nonce, "g1"))
        )
        .await
        .status,
        StatusCode::OK
    );
    let fetches = || async { h.idp.requests_to("/google/jwks").await.len() };
    assert_eq!(fetches().await, 1);

    // The provider rotates to key B. The first token with the new kid inside
    // the minimum refresh interval is refused without a download.
    h.idp.server.reset().await;
    h.idp.mount_jwks("/google", &[(KEY_B, "key-b")]).await;
    let nonce = h.native_nonce("google").await;
    let rotated = sign_rs256(KEY_B, "key-b", &google_claims(&h, &nonce, "g1"));
    h.native("google", &rotated)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // Random kids do not cause downloads either.
    for i in 0..5 {
        let token = sign_rs256(
            KEY_B,
            &format!("random-{i}"),
            &google_claims(&h, &nonce, "g1"),
        );
        h.native("google", &token).await;
    }
    assert_eq!(h.idp.requests_to("/google/jwks").await.len(), 0);

    // After the interval, an unknown kid forces exactly one refresh.
    h.ports.clock.advance(Duration::from_secs(61));
    let nonce = h.native_nonce("google").await;
    let rotated = sign_rs256(KEY_B, "key-b", &google_claims(&h, &nonce, "g1"));
    assert_eq!(h.native("google", &rotated).await.status, StatusCode::OK);
    assert_eq!(h.idp.requests_to("/google/jwks").await.len(), 1);
    // The old key is gone from the provider and from the cache.
    let nonce = h.native_nonce("google").await;
    h.native(
        "google",
        &sign_rs256(KEY_A, "key-a", &google_claims(&h, &nonce, "g1")),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_03_microsoft_tenant_spoofing_and_allow_list(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.microsoft_allowed_tenants = vec![MS_TENANT.to_owned()];
    })
    .await;
    let evil = "22222222-2222-2222-2222-222222222222";
    let mk = |h: &Harness, nonce: &str, tid: &str, iss_tid: &str| {
        let mut c = h.claims(
            &format!("{}/ms/{iss_tid}/v2.0", h.idp.uri()),
            MS_NATIVE,
            "x",
            nonce,
            "a@contoso.example",
        );
        c["tid"] = json!(tid);
        c["oid"] = json!("cccccccc-0000-0000-0000-000000000001");
        c["xms_edov"] = json!(true);
        c
    };
    // Token of tenant `evil` presenting the allowed tenant's issuer.
    let nonce = h.native_nonce("microsoft").await;
    h.native(
        "microsoft",
        &sign_rs256(KEY_A, "key-a", &mk(&h, &nonce, evil, MS_TENANT)),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // Consistent token of a tenant that is not allowed.
    h.native(
        "microsoft",
        &sign_rs256(KEY_A, "key-a", &mk(&h, &nonce, evil, evil)),
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    // The allowed tenant.
    assert_eq!(
        h.native(
            "microsoft",
            &sign_rs256(KEY_A, "key-a", &mk(&h, &nonce, MS_TENANT, MS_TENANT))
        )
        .await
        .status,
        StatusCode::OK
    );
    assert!(
        h.identity_owner(
            "microsoft",
            &format!("{MS_TENANT}:cccccccc-0000-0000-0000-000000000001")
        )
        .await
        .is_some()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_09_provider_mfa_is_not_trusted_by_default(pool: PgPool) {
    let h = Harness::new(pool).await;
    let nonce = h.native_nonce("google").await;
    let mut claims = google_claims(&h, &nonce, "g1");
    claims["amr"] = json!(["pwd", "mfa"]);
    assert_eq!(
        h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
            .await
            .status,
        StatusCode::OK
    );
    let login = &h.ports.session_issuer.logins()[0];
    assert!(!login.provider_asserted_mfa);
    // The primary authentication never claims MFA itself.
    assert!(!login.amr.contains(&authn_core::domain::AuthMethodRef::Mfa));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_09_provider_mfa_is_forwarded_only_when_trusted(pool: PgPool) {
    let h = Harness::with(pool, |s| s.config.trust_provider_mfa = true).await;
    for (amr, expected) in [(json!(["pwd", "mfa"]), true), (json!(["pwd"]), false)] {
        let nonce = h.native_nonce("google").await;
        let mut claims = google_claims(&h, &nonce, "g1");
        claims["amr"] = amr;
        h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
            .await;
        let logins = h.ports.session_issuer.logins();
        assert_eq!(logins.last().unwrap().provider_asserted_mfa, expected);
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_09_mfa_challenge_is_returned_instead_of_a_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.ports
        .session_issuer
        .set_next_outcome(LoginOutcome::ChallengeRequired(PendingChallenge {
            challenge_id: ChallengeId::generate(),
            challenge_token: SensitiveString::new("challenge-token"),
            expires_at: h.ports.clock.now() + time::Duration::minutes(5),
            allowed_factors: vec![FactorKind::Totp],
            required_actions: vec![RequiredAction::VerifyMfa],
        }));
    let nonce = h.native_nonce("google").await;
    let res = h
        .native(
            "google",
            &sign_rs256(KEY_A, "key-a", &google_claims(&h, &nonce, "g1")),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["status"], "challenge_required");
    assert_eq!(body["required_actions"], json!(["verify_mfa"]));
    assert!(body.get("session_id").is_none());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_04_native_endpoints_are_rate_limited(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.native_per_ip = authn_core::ports::RateLimitPolicy::new(2, Duration::from_secs(600));
    })
    .await;
    h.native_nonce("google").await;
    h.native_nonce("google").await;
    TestRequest::post("/v1/oauth/nonce")
        .json(&json!({ "provider": "google" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
}

// --- Independent security review: regression tests -------------------------

/// Review finding 4: the client-supplied `given_name` / `family_name` (meant
/// for Apple's first sign-in, whose ID token carries no name) overrode the
/// provider-asserted `name` of every provider, on every login.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_07_native_client_name_is_only_used_for_apple(pool: PgPool) {
    let h = Harness::new(pool).await;
    let nonce = h.native_nonce("google").await;
    let token = sign_rs256(KEY_A, "key-a", &google_claims(&h, &nonce, "g-name"));
    let res = TestRequest::post("/v1/oauth/google/native")
        .json(&json!({ "id_token": token, "given_name": "Injected", "family_name": "Name" }))
        .send(&h.app())
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM identities WHERE subject = 'g-name'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(name.as_deref(), Some("Test User"));
}
