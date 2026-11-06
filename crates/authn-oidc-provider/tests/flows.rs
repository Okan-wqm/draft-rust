#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Conformance-style flows through the provider's routers (OIDP-02 …
//! OIDP-12). The end-to-end variants over the complete server (real
//! sessions, middleware, native-token confusion) are in
//! `crates/authn-server/tests/oidc_provider_e2e.rs`.

mod common;

use authn_core::domain::AuthMethodRef;
use authn_core::ports::SecurityEventKind;
use authn_testkit::http::TestRequest;
use common::*;
use serde_json::{Value, json};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_06_web_client_code_flow_with_pkce_and_independent_id_token_check(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    // First request: consent is needed → hand-off to the interaction page.
    let (location, binding) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid profile email",
            &[],
        )
        .await;
    let id = interaction_id(&location);
    let binding = binding.expect("binding cookie");

    // The page reads the request.
    let view = TestRequest::get(&format!("/v1/oauth2/interactions/{id}"))
        .cookie("__Host-authn_oidc_browser", &binding)
        .send(&h.signed_in())
        .await;
    assert_eq!(view.status, 200, "{}", view.text());
    let view: Value = view.json();
    assert_eq!(view["client"]["name"], "Shop");
    assert_eq!(view["consent_required"], true);
    assert_eq!(view["login_required"], false);
    assert_eq!(view["scopes"], json!(["openid", "profile", "email"]));

    // The user approves.
    let accepted = TestRequest::post(&format!("/v1/oauth2/interactions/{id}/accept"))
        .cookie("__Host-authn_oidc_browser", &binding)
        .send(&h.signed_in())
        .await;
    assert_eq!(accepted.status, 200, "{}", accepted.text());
    let redirect = accepted.json::<Value>()["redirect_to"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(redirect.starts_with(WEB_REDIRECT));
    // RFC 9207 mix-up defence: `iss` in the response; `state` echoed.
    assert_eq!(query_param(&redirect, "iss").as_deref(), Some(ISSUER));
    assert_eq!(query_param(&redirect, "state").as_deref(), Some("st-123"));
    let code = query_param(&redirect, "code").unwrap();
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OAuthConsentGranted)
            .len(),
        1
    );

    let r = h.exchange(&client, &code, WEB_REDIRECT).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let tokens: Value = r.json();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "openid profile email");
    assert!(tokens["refresh_token"].is_string());
    let access = tokens["access_token"].as_str().unwrap();

    // ID token verified with an independent Ed25519 implementation.
    let (header, id_claims) = h
        .verify_independently(tokens["id_token"].as_str().unwrap())
        .await;
    assert_eq!(header["typ"], "JWT");
    assert_eq!(id_claims["iss"], ISSUER);
    assert_eq!(id_claims["aud"], json!([client.client_id]));
    assert_eq!(id_claims["azp"], client.client_id);
    assert_eq!(id_claims["sub"], h.user.to_string());
    assert_eq!(id_claims["nonce"], "n-456");
    assert_eq!(id_claims["at_hash"], expected_at_hash(access));
    assert_eq!(id_claims["auth_time"], h.now().unix_timestamp());
    assert_eq!(id_claims["amr"], json!(["pwd"]));
    assert_eq!(id_claims["acr"], "urn:rust-authentication:acr:aal1");
    assert_eq!(id_claims["sid"], h.session.to_string());
    assert!(id_claims.get("email").is_none(), "no PII in the ID token");

    // RFC 9068 access token.
    let (at_header, at) = h.verify_independently(access).await;
    assert_eq!(at_header["typ"], "at+jwt");
    assert_eq!(at["client_id"], client.client_id);
    assert!(at.get("sid").is_none(), "no sid: never a native token");
    let aud: Vec<String> = serde_json::from_value(at["aud"].clone()).unwrap();
    assert_eq!(
        aud,
        [
            client.client_id.clone(),
            format!("{ISSUER}/v1/oauth2/userinfo")
        ]
    );

    // UserInfo by scope.
    let info = h.userinfo(access).await;
    assert_eq!(info.status, 200, "{}", info.text());
    let info: Value = info.json();
    assert_eq!(info["sub"], h.user.to_string());
    assert_eq!(info["email"], "alice@example.com");
    assert_eq!(info["email_verified"], true);
    assert!(info.get("locale").is_some());
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OAuthTokensIssued)
            .len(),
        1
    );
    // No token material in any audit event.
    let audit = serde_json::to_string(&h.ports.audit.recorded()).unwrap();
    assert!(!audit.contains(&code) && !audit.contains(access));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_05_existing_consent_gives_sso_and_prompt_consent_asks_again(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    h.grant_consent(&client, "openid email").await;
    // Same scopes again: straight back with a code (single sign-on).
    let (location, _) = h
        .authorize(&h.signed_in(), &client, WEB_REDIRECT, "openid email", &[])
        .await;
    assert!(location.starts_with(WEB_REDIRECT), "{location}");
    assert!(query_param(&location, "code").is_some());
    // More scopes, or prompt=consent: the interaction page again.
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid email profile",
            &[],
        )
        .await;
    assert!(location.starts_with(INTERACTION));
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid email",
            &[("prompt", "consent")],
        )
        .await;
    assert!(location.starts_with(INTERACTION));

    // The user lists and revokes the consent: grants go with it.
    let code = h.code_for(&client, WEB_REDIRECT, "openid email").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let list = TestRequest::get("/v1/me/oauth2/consents")
        .send(&h.signed_in())
        .await;
    assert_eq!(list.json::<Value>()["consents"][0]["client_name"], "Shop");
    let r = TestRequest::delete(&format!("/v1/me/oauth2/consents/{}", client.client_id))
        .send(&h.signed_in())
        .await;
    assert_eq!(r.status, 204, "{}", r.text());
    let refreshed = h
        .token(
            &client,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ],
            true,
        )
        .await;
    assert_eq!(refreshed.json::<Value>()["error"], "invalid_grant");
    assert_eq!(
        h.userinfo(tokens["access_token"].as_str().unwrap())
            .await
            .status,
        401
    );
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OAuthConsentRevoked)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_05_first_party_clients_skip_consent(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h
        .register(json!({
            "name": "Own app", "client_type": "confidential", "application_type": "web",
            "redirect_uris": [WEB_REDIRECT], "allowed_scopes": ["openid"], "skip_consent": true,
        }))
        .await;
    let (location, _) = h
        .authorize(&h.signed_in(), &client, WEB_REDIRECT, "openid", &[])
        .await;
    assert!(query_param(&location, "code").is_some(), "{location}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_02_native_public_client_with_loopback_port_and_no_secret(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.native_client().await;
    let redirect = "http://127.0.0.1:53127/callback";
    let code = h.code_for(&client, redirect, "openid email").await;
    // Public client: `none` authentication, PKCE binds the code.
    let r = h
        .token(
            &client,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", redirect),
                ("code_verifier", VERIFIER),
            ],
            false,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    // The private-use scheme also works.
    let code = h
        .code_for(&client, "com.example.app:/oauth", "openid")
        .await;
    assert!(!code.is_empty());
    // A public client presenting a secret is refused.
    let with_secret = Client {
        client_id: client.client_id.clone(),
        secret: Some("x".repeat(43)),
    };
    let r = h
        .token(&with_secret, &[("grant_type", "refresh_token")], true)
        .await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json::<Value>()["error"], "invalid_client");
    assert_eq!(r.header("www-authenticate"), Some("Basic realm=\"oauth2\""));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_02_unregistered_redirects_are_never_followed(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    for bad in [
        "https://evil.example/cb",
        "https://rp.example.com/cb/",
        "https://rp.example.com/CB",
        "https://rp.example.com/cb?x=1",
        "https://rp.example.com:8443/cb",
    ] {
        let query = serde_urlencoded::to_string([
            ("client_id", client.client_id.as_str()),
            ("redirect_uri", bad),
            ("response_type", "code"),
            ("scope", "openid"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .unwrap();
        let r = TestRequest::get(&format!("/v1/oauth2/authorize?{query}"))
            .send(&h.signed_in())
            .await;
        r.assert_error(
            http::StatusCode::BAD_REQUEST,
            "invalid_authorization_request",
        );
        assert!(r.header("location").is_none(), "{bad}");
    }
    // Unknown client: also no redirect.
    let r = TestRequest::get(&format!(
        "/v1/oauth2/authorize?client_id=oc_nope&redirect_uri={}&response_type=code",
        url_encode(WEB_REDIRECT)
    ))
    .send(&h.signed_in())
    .await;
    r.assert_error(
        http::StatusCode::BAD_REQUEST,
        "invalid_authorization_request",
    );
}

fn url_encode(value: &str) -> String {
    serde_urlencoded::to_string([("v", value)])
        .unwrap()
        .strip_prefix("v=")
        .unwrap()
        .to_owned()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_03_missing_and_plain_pkce_are_redirected_errors(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid",
            &[("code_challenge", ""), ("code_challenge_method", "")],
        )
        .await;
    assert!(location.starts_with(WEB_REDIRECT));
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(query_param(&location, "iss").as_deref(), Some(ISSUER));
    assert_eq!(query_param(&location, "state").as_deref(), Some("st-123"));
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid",
            &[("code_challenge_method", "plain")],
        )
        .await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_request")
    );
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid",
            &[("response_type", "token")],
        )
        .await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("unsupported_response_type")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_06_code_replay_revokes_every_token_of_the_grant(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid email").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(h.userinfo(access).await.status, 200);

    let replay = h.exchange(&client, &code, WEB_REDIRECT).await;
    assert_eq!(replay.status, 400);
    assert_eq!(replay.json::<Value>()["error"], "invalid_grant");
    // The tokens of the first exchange are dead.
    let info = h.userinfo(access).await;
    assert_eq!(info.status, 401);
    assert_eq!(
        info.header("www-authenticate"),
        Some("Bearer error=\"invalid_token\"")
    );
    let refreshed = h
        .token(
            &client,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ],
            true,
        )
        .await;
    assert_eq!(refreshed.json::<Value>()["error"], "invalid_grant");
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OAuthCodeReplayDetected)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_06_code_is_bound_to_client_redirect_verifier_and_lifetime(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let other = h
        .register(json!({
            "name": "Other", "client_type": "confidential", "application_type": "web",
            "redirect_uris": [WEB_REDIRECT], "allowed_scopes": ["openid"],
        }))
        .await;

    // Another client cannot redeem it (code injection); the code survives.
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let r = h.exchange(&other, &code, WEB_REDIRECT).await;
    assert_eq!(r.json::<Value>()["error"], "invalid_grant");
    // Wrong redirect URI.
    let r = h
        .exchange(&client, &code, "https://rp.example.com/other")
        .await;
    assert_eq!(r.json::<Value>()["error"], "invalid_grant");
    // Missing verifier.
    let r = h
        .token(
            &client,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", WEB_REDIRECT),
            ],
            true,
        )
        .await;
    assert_eq!(r.json::<Value>()["error"], "invalid_request");
    // Still redeemable by its own client.
    assert_eq!(h.exchange(&client, &code, WEB_REDIRECT).await.status, 200);

    // A wrong verifier burns the code.
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let r = h
        .token(
            &client,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", WEB_REDIRECT),
                ("code_verifier", &"x".repeat(43)),
            ],
            true,
        )
        .await;
    assert_eq!(r.json::<Value>()["error"], "invalid_grant");
    assert_eq!(
        h.exchange(&client, &code, WEB_REDIRECT)
            .await
            .json::<Value>()["error"],
        "invalid_grant"
    );

    // Expired code.
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    h.ports.clock.advance(std::time::Duration::from_secs(61));
    assert_eq!(
        h.exchange(&client, &code, WEB_REDIRECT)
            .await
            .json::<Value>()["error"],
        "invalid_grant"
    );

    // Wrong secret / unknown client.
    let wrong = Client {
        client_id: client.client_id.clone(),
        secret: Some("y".repeat(43)),
    };
    assert_eq!(h.exchange(&wrong, "x", WEB_REDIRECT).await.status, 401);
    // client_secret_post works too.
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let r = h
        .token(
            &client,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", WEB_REDIRECT),
                ("code_verifier", VERIFIER),
            ],
            false,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_07_refresh_rotation_and_replay_detection(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid email").await;
    let first: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let rt1 = first["refresh_token"].as_str().unwrap().to_owned();
    let refresh = |rt: String, scope: Option<&'static str>| {
        let h = &h;
        let client = &client;
        async move {
            let mut fields = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
            ];
            if let Some(scope) = scope {
                fields.push(("scope", scope));
            }
            h.token(client, &fields, true).await
        }
    };
    let second = refresh(rt1.clone(), None).await;
    assert_eq!(second.status, 200, "{}", second.text());
    let second: Value = second.json();
    let rt2 = second["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(rt1, rt2);
    // The refreshed ID token has no nonce.
    let (_, id) = h
        .verify_independently(second["id_token"].as_str().unwrap())
        .await;
    assert!(id.get("nonce").is_none());
    // Narrowing is allowed, widening is not.
    let narrowed = refresh(rt2.clone(), Some("openid")).await;
    assert_eq!(narrowed.json::<Value>()["scope"], "openid");
    let rt3 = narrowed.json::<Value>()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let widened = refresh(rt3.clone(), Some("openid profile")).await;
    assert_eq!(widened.json::<Value>()["error"], "invalid_scope");

    // Replaying a rotated token revokes the whole grant.
    let replay = refresh(rt1, None).await;
    assert_eq!(replay.json::<Value>()["error"], "invalid_grant");
    assert_eq!(
        refresh(rt3, None).await.json::<Value>()["error"],
        "invalid_grant"
    );
    assert_eq!(
        h.userinfo(second["access_token"].as_str().unwrap())
            .await
            .status,
        401
    );
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OAuthRefreshTokenReplayDetected)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_12_ended_session_ends_the_grant(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    // Sign-out everywhere / password reset / suspension end the session.
    h.live.set(h.session, false);
    assert_eq!(
        h.userinfo(tokens["access_token"].as_str().unwrap())
            .await
            .status,
        401
    );
    let r = h
        .token(
            &client,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ],
            true,
        )
        .await;
    assert_eq!(r.json::<Value>()["error"], "invalid_grant");
    let intro = h
        .form_post(
            "/v1/oauth2/introspect",
            &client,
            &[("token", tokens["access_token"].as_str().unwrap())],
        )
        .await;
    assert_eq!(intro.json::<Value>(), json!({"active": false}));
    // A code issued before the session ended cannot be redeemed either.
    h.live.set(h.session, true);
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    h.live.set(h.session, false);
    assert_eq!(
        h.exchange(&client, &code, WEB_REDIRECT)
            .await
            .json::<Value>()["error"],
        "invalid_grant"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_12_account_deletion_removes_grants(pool: sqlx::PgPool) {
    let h = Harness::new(pool.clone()).await;
    let client = h.web_client().await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let mut conn = pool.acquire().await.unwrap();
    authn_store::UserRepository::delete(&mut conn, h.user)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_grants")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
    assert_eq!(
        h.userinfo(tokens["access_token"].as_str().unwrap())
            .await
            .status,
        401
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_04_prompt_none_without_session_or_consent(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let (location, binding) = h
        .authorize(
            &h.anonymous(),
            &client,
            WEB_REDIRECT,
            "openid",
            &[("prompt", "none")],
        )
        .await;
    assert!(binding.is_none());
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(query_param(&location, "iss").as_deref(), Some(ISSUER));
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid",
            &[("prompt", "none")],
        )
        .await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("consent_required")
    );
    h.grant_consent(&client, "openid").await;
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid",
            &[("prompt", "none")],
        )
        .await;
    assert!(query_param(&location, "code").is_some(), "{location}");
    // max_age exceeded: login_required; acr not met: interaction_required.
    h.ports.clock.advance(std::time::Duration::from_secs(600));
    let (location, _) = h
        .authorize(
            &h.as_principal(
                h.principal_with(&[AuthMethodRef::Pwd], h.now() - time::Duration::minutes(10)),
            ),
            &client,
            WEB_REDIRECT,
            "openid",
            &[("prompt", "none"), ("max_age", "60")],
        )
        .await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("login_required")
    );
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "openid",
            &[
                ("prompt", "none"),
                ("acr_values", "urn:rust-authentication:acr:aal2"),
            ],
        )
        .await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("interaction_required")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_04_interaction_without_session_then_login_then_accept(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let (location, binding) = h
        .authorize(&h.anonymous(), &client, WEB_REDIRECT, "openid", &[])
        .await;
    let id = interaction_id(&location);
    let binding = binding.unwrap();
    let view: Value = TestRequest::get(&format!("/v1/oauth2/interactions/{id}"))
        .cookie("__Host-authn_oidc_browser", &binding)
        .send(&h.anonymous())
        .await
        .json();
    assert_eq!(view["authenticated"], false);
    assert_eq!(view["login_required"], true);
    assert_eq!(view["login_reasons"], json!(["no_session"]));
    // Accept needs a session.
    let r = TestRequest::post(&format!("/v1/oauth2/interactions/{id}/accept"))
        .cookie("__Host-authn_oidc_browser", &binding)
        .send(&h.anonymous())
        .await;
    assert_eq!(r.status, 401);
    // Another browser (no / other binding) cannot use the interaction.
    for cookie in [None, Some("A".repeat(43))] {
        let mut req = TestRequest::get(&format!("/v1/oauth2/interactions/{id}"));
        if let Some(c) = &cookie {
            req = req.cookie("__Host-authn_oidc_browser", c);
        }
        req.send(&h.signed_in())
            .await
            .assert_error(http::StatusCode::BAD_REQUEST, "oauth_interaction_invalid");
    }
    // After login (the session principal), accept succeeds once.
    let accept = || {
        TestRequest::post(&format!("/v1/oauth2/interactions/{id}/accept"))
            .cookie("__Host-authn_oidc_browser", &binding)
    };
    assert_eq!(accept().send(&h.signed_in()).await.status, 200);
    accept()
        .send(&h.signed_in())
        .await
        .assert_error(http::StatusCode::BAD_REQUEST, "oauth_interaction_invalid");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_04_prompt_login_and_acr_need_fresh_strong_authentication(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    h.grant_consent(&client, "openid").await;
    let old_login = h.principal_with(&[AuthMethodRef::Pwd], h.now());
    h.ports.clock.advance(std::time::Duration::from_secs(5));
    let (location, binding) = h
        .authorize(
            &h.as_principal(old_login.clone()),
            &client,
            WEB_REDIRECT,
            "openid",
            &[
                ("prompt", "login"),
                ("acr_values", "urn:rust-authentication:acr:aal2"),
            ],
        )
        .await;
    let id = interaction_id(&location);
    let binding = binding.unwrap();
    let accept = |app: axum::Router| {
        let binding = binding.clone();
        let id = id.clone();
        async move {
            TestRequest::post(&format!("/v1/oauth2/interactions/{id}/accept"))
                .cookie("__Host-authn_oidc_browser", &binding)
                .send(&app)
                .await
        }
    };
    let r = accept(h.as_principal(old_login)).await;
    let body = r.assert_error(http::StatusCode::UNAUTHORIZED, "step_up_required");
    let reasons = body.details.unwrap()["login_reasons"].clone();
    assert_eq!(reasons, json!(["prompt_login", "acr"]));
    // Re-authenticated with a second factor after the request.
    h.ports.clock.advance(std::time::Duration::from_secs(5));
    let fresh = h.principal_with(
        &[AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa],
        h.now(),
    );
    let r = accept(h.as_principal(fresh)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let code = query_param(r.json::<Value>()["redirect_to"].as_str().unwrap(), "code").unwrap();
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let (_, id_token) = h
        .verify_independently(tokens["id_token"].as_str().unwrap())
        .await;
    assert_eq!(id_token["acr"], "urn:rust-authentication:acr:aal2");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_04_deny_and_impersonation(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let (location, binding) = h
        .authorize(&h.signed_in(), &client, WEB_REDIRECT, "openid", &[])
        .await;
    let id = interaction_id(&location);
    let r = TestRequest::post(&format!("/v1/oauth2/interactions/{id}/deny"))
        .cookie("__Host-authn_oidc_browser", &binding.unwrap())
        .send(&h.anonymous())
        .await;
    let to = r.json::<Value>()["redirect_to"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(query_param(&to, "error").as_deref(), Some("access_denied"));
    assert_eq!(query_param(&to, "iss").as_deref(), Some(ISSUER));

    // An impersonation session never authorizes a client on the user's
    // behalf: it is treated as no session.
    h.grant_consent(&client, "openid").await;
    let mut impersonated = h.principal();
    impersonated.impersonation = Some(authn_core::domain::Impersonation {
        admin_user_id: authn_core::id::UserId::generate(),
        read_only: false,
        expires_at: h.now() + time::Duration::minutes(10),
    });
    let (location, _) = h
        .authorize(
            &h.as_principal(impersonated),
            &client,
            WEB_REDIRECT,
            "openid",
            &[("prompt", "none")],
        )
        .await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("login_required")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_11_revocation_and_introspection(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let native = h.native_client().await;
    let rs = h
        .register(json!({
            "name": "Resource server", "client_type": "confidential", "application_type": "web",
            "redirect_uris": ["https://rs.example.com/unused"], "allowed_scopes": ["openid"],
        }))
        .await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid email").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();

    let intro: Value = h
        .form_post("/v1/oauth2/introspect", &client, &[("token", access)])
        .await
        .json();
    assert_eq!(intro["active"], true);
    assert_eq!(intro["token_type"], "access_token");
    assert_eq!(intro["client_id"], client.client_id);
    assert_eq!(intro["sub"], h.user.to_string());
    let intro: Value = h
        .form_post("/v1/oauth2/introspect", &client, &[("token", refresh)])
        .await
        .json();
    assert_eq!(intro["active"], true);
    assert_eq!(intro["token_type"], "refresh_token");
    // Another client is not entitled; public clients cannot introspect.
    let other: Value = h
        .form_post("/v1/oauth2/introspect", &rs, &[("token", access)])
        .await
        .json();
    assert_eq!(other, json!({"active": false}));
    let public = h
        .form_post("/v1/oauth2/introspect", &native, &[("token", access)])
        .await;
    assert_eq!(public.status, 401);
    // Unauthenticated callers are refused.
    let r = TestRequest::post("/v1/oauth2/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("token={access}"))
        .send(&h.anonymous())
        .await;
    assert_eq!(r.status, 401);

    // RFC 7009: other clients' tokens and garbage are ignored (200).
    let r = h
        .form_post("/v1/oauth2/revoke", &rs, &[("token", refresh)])
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        h.form_post("/v1/oauth2/introspect", &client, &[("token", refresh)])
            .await
            .json::<Value>()["active"],
        true
    );
    assert_eq!(
        h.form_post("/v1/oauth2/revoke", &client, &[("token", "garbage")])
            .await
            .status,
        200
    );
    // Revoking the access token alone.
    h.form_post("/v1/oauth2/revoke", &client, &[("token", access)])
        .await;
    assert_eq!(h.userinfo(access).await.status, 401);
    assert_eq!(
        h.form_post("/v1/oauth2/introspect", &client, &[("token", refresh)])
            .await
            .json::<Value>()["active"],
        true
    );
    // Revoking the refresh token ends the grant.
    h.form_post("/v1/oauth2/revoke", &client, &[("token", refresh)])
        .await;
    assert_eq!(
        h.form_post("/v1/oauth2/introspect", &client, &[("token", refresh)])
            .await
            .json::<Value>(),
        json!({"active": false})
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_08_resource_indicators_set_the_audience(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let (location, binding) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "orders:read",
            &[("resource", "https://api.example.com")],
        )
        .await;
    let id = interaction_id(&location);
    let r = TestRequest::post(&format!("/v1/oauth2/interactions/{id}/accept"))
        .cookie("__Host-authn_oidc_browser", &binding.unwrap())
        .send(&h.signed_in())
        .await;
    let code = query_param(r.json::<Value>()["redirect_to"].as_str().unwrap(), "code").unwrap();
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    assert!(tokens.get("id_token").is_none(), "no openid, no ID token");
    let (_, at) = h
        .verify_independently(tokens["access_token"].as_str().unwrap())
        .await;
    assert_eq!(at["aud"], json!(["https://api.example.com"]));
    // Without `openid` the token is not a userinfo token.
    assert_eq!(
        h.userinfo(tokens["access_token"].as_str().unwrap())
            .await
            .status,
        401
    );
    // An unregistered resource is refused with invalid_target.
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "orders:read",
            &[("resource", "https://other.example.com")],
        )
        .await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_target")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_08_foreign_shaped_tokens_are_rejected_by_userinfo(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    // The ID token is no access token (typ JWT).
    assert_eq!(
        h.userinfo(tokens["id_token"].as_str().unwrap())
            .await
            .status,
        401
    );
    // A tampered access token.
    let access = tokens["access_token"].as_str().unwrap();
    let mut tampered = access.to_owned();
    tampered.pop();
    tampered.push(if access.ends_with('A') { 'B' } else { 'A' });
    assert_eq!(h.userinfo(&tampered).await.status, 401);
    // Missing token.
    let r = TestRequest::get("/v1/oauth2/userinfo")
        .send(&h.anonymous())
        .await;
    assert_eq!(r.status, 401);
    assert_eq!(r.header("www-authenticate"), Some("Bearer"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_09_discovery_documents(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let doc: Value = TestRequest::get(path).send(&h.anonymous()).await.json();
        assert_eq!(doc["issuer"], ISSUER);
        assert_eq!(
            doc["authorization_endpoint"],
            format!("{ISSUER}/v1/oauth2/authorize")
        );
        assert_eq!(doc["token_endpoint"], format!("{ISSUER}/v1/oauth2/token"));
        assert_eq!(doc["jwks_uri"], format!("{ISSUER}/.well-known/jwks.json"));
        assert_eq!(doc["response_types_supported"], json!(["code"]));
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(doc["authorization_response_iss_parameter_supported"], true);
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            json!(["EdDSA"])
        );
        assert!(
            doc["scopes_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("orders:read"))
        );
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_01_client_registry_is_staff_only_and_validated(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let app = h.signed_in();
    let body = json!({
        "name": "Partner", "client_type": "confidential", "application_type": "web",
        "redirect_uris": [WEB_REDIRECT], "allowed_scopes": ["openid", "email"],
    });
    // Denied by the staff authorizer: nothing is created.
    *h.admin.deny.lock().unwrap() = true;
    let r = TestRequest::post("/v1/admin/oauth2/clients")
        .json(&body)
        .send(&app)
        .await;
    r.assert_error(http::StatusCode::FORBIDDEN, "forbidden");
    TestRequest::get("/v1/admin/oauth2/clients")
        .send(&app)
        .await
        .assert_error(http::StatusCode::FORBIDDEN, "forbidden");
    // No principal at all: 401.
    TestRequest::get("/v1/admin/oauth2/clients")
        .send(&h.anonymous())
        .await
        .assert_error(http::StatusCode::UNAUTHORIZED, "unauthenticated");
    *h.admin.deny.lock().unwrap() = false;

    let r = TestRequest::post("/v1/admin/oauth2/clients")
        .json(&body)
        .send(&app)
        .await;
    assert_eq!(r.status, 201, "{}", r.text());
    let created: Value = r.json();
    let client_id = created["client"]["client_id"].as_str().unwrap().to_owned();
    let secret = created["client_secret"].as_str().unwrap().to_owned();
    assert!(client_id.starts_with("oc_") && client_id.len() == 25);
    assert_eq!(secret.len(), 43);
    // The secret is stored only as a hash and never audited.
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT secret_hash FROM oidc_clients WHERE client_id = $1")
            .bind(&client_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(stored, authn_crypto::sha256(secret.as_bytes()));
    assert!(
        !serde_json::to_string(&h.ports.audit.recorded())
            .unwrap()
            .contains(&secret)
    );
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OAuthClientCreated)
            .len(),
        1
    );

    let list: Value = TestRequest::get("/v1/admin/oauth2/clients")
        .send(&app)
        .await
        .json();
    assert_eq!(list["clients"].as_array().unwrap().len(), 1);
    assert!(list.to_string().find("secret_hash").is_none());

    // Validation: wildcard / http / fragment / unknown scope / reserved audience.
    for (field, value) in [
        ("redirect_uris", json!(["https://*.example.com/cb"])),
        ("redirect_uris", json!(["http://rp.example.com/cb"])),
        ("redirect_uris", json!(["https://rp.example.com/cb#x"])),
        ("allowed_scopes", json!(["admin"])),
        ("allowed_resources", json!(["rust-authentication"])),
        (
            "allowed_resources",
            json!([format!("{ISSUER}/v1/oauth2/userinfo")]),
        ),
        ("allowed_grant_types", json!(["password"])),
        ("allowed_grant_types", json!(["implicit"])),
    ] {
        let mut bad = body.clone();
        bad[field] = value;
        TestRequest::post("/v1/admin/oauth2/clients")
            .json(&bad)
            .send(&app)
            .await
            .assert_error(
                http::StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_client_metadata",
            );
    }

    // Rotate: the old secret stops working.
    let r = TestRequest::post(&format!("/v1/admin/oauth2/clients/{client_id}/secret"))
        .send(&app)
        .await;
    let new_secret = r.json::<Value>()["client_secret"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(new_secret, secret);
    let old = Client {
        client_id: client_id.clone(),
        secret: Some(secret),
    };
    assert_eq!(h.exchange(&old, "x", WEB_REDIRECT).await.status, 401);

    // Disable: grants are revoked, authorization refused without redirect.
    let client = Client {
        client_id: client_id.clone(),
        secret: Some(new_secret),
    };
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let r = TestRequest::patch(&format!("/v1/admin/oauth2/clients/{client_id}"))
        .json(&json!({"disabled": true}))
        .send(&app)
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        h.userinfo(tokens["access_token"].as_str().unwrap())
            .await
            .status,
        401
    );
    let query = serde_urlencoded::to_string([
        ("client_id", client_id.as_str()),
        ("redirect_uri", WEB_REDIRECT),
    ])
    .unwrap();
    TestRequest::get(&format!("/v1/oauth2/authorize?{query}"))
        .send(&app)
        .await
        .assert_error(
            http::StatusCode::BAD_REQUEST,
            "invalid_authorization_request",
        );

    let r = TestRequest::delete(&format!("/v1/admin/oauth2/clients/{client_id}"))
        .send(&app)
        .await;
    assert_eq!(r.status, 204);
    TestRequest::get(&format!("/v1/admin/oauth2/clients/{client_id}"))
        .send(&app)
        .await
        .assert_error(http::StatusCode::NOT_FOUND, "not_found");
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OAuthClientDeleted)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_12_rate_limits_apply_to_authorize_and_token(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let query = serde_urlencoded::to_string([("client_id", client.client_id.as_str())]).unwrap();
    let mut limited = false;
    for _ in 0..70 {
        let r = TestRequest::get(&format!("/v1/oauth2/authorize?{query}"))
            .send(&h.anonymous())
            .await;
        if r.status == 429 {
            assert!(r.header("retry-after").is_some());
            limited = true;
            break;
        }
    }
    assert!(limited, "authorize is rate limited per IP");
    let mut limited = false;
    for _ in 0..130 {
        let r = h.exchange(&client, "x", WEB_REDIRECT).await;
        if r.status == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "token endpoint is rate limited per IP");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_13_purge_removes_expired_rows(pool: sqlx::PgPool) {
    let h = Harness::new(pool.clone()).await;
    let client = h.web_client().await;
    let _ = h
        .authorize(&h.anonymous(), &client, WEB_REDIRECT, "openid", &[])
        .await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let _ = h.exchange(&client, &code, WEB_REDIRECT).await;
    h.ports
        .clock
        .advance(std::time::Duration::from_secs(40 * 86_400));
    let deleted = h.service.purge_expired(1000).await.unwrap();
    assert!(deleted >= 3, "{deleted}");
    for table in [
        "oidc_interactions",
        "oidc_grants",
        "oidc_access_tokens",
        "oidc_refresh_tokens",
    ] {
        let sql = format!("SELECT count(*) FROM {table}");
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table}");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_05_consents_and_grants_are_in_the_data_export(pool: sqlx::PgPool) {
    use authn_core::ports::DataExporter as _;
    let h = Harness::new(pool.clone()).await;
    let client = h.web_client().await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid email").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let mut conn = pool.acquire().await.unwrap();
    let section = authn_oidc_provider::ProviderDataExporter
        .export(&mut conn, h.user)
        .await
        .unwrap();
    assert_eq!(section["consents"][0]["client_name"], "Shop");
    assert_eq!(section["grants"][0]["scopes"], json!(["openid", "email"]));
    let text = section.to_string();
    for secret in [
        tokens["access_token"].as_str().unwrap(),
        tokens["refresh_token"].as_str().unwrap(),
        code.as_str(),
    ] {
        assert!(!text.contains(secret));
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_10_userinfo_claims_follow_the_granted_scopes(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    // `openid` only: just the subject.
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let info: Value = h
        .userinfo(tokens["access_token"].as_str().unwrap())
        .await
        .json();
    assert_eq!(info, json!({"sub": h.user.to_string()}));
    // `profile` adds name / locale / zoneinfo, not the e-mail address.
    let code = h.code_for(&client, WEB_REDIRECT, "openid profile").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let access = tokens["access_token"].as_str().unwrap();
    let info: Value = h.userinfo(access).await.json();
    assert!(info.get("locale").is_some() && info.get("zoneinfo").is_some());
    assert!(info.get("email").is_none());
    // POST works the same (token in the header only).
    let r = TestRequest::post("/v1/oauth2/userinfo")
        .bearer(access)
        .send(&h.anonymous())
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("cache-control"), Some("no-store"));
    // A refresh narrowed to `profile` drops `openid`: no userinfo audience.
    let narrowed: Value = h
        .token(
            &client,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
                ("scope", "profile"),
            ],
            true,
        )
        .await
        .json();
    assert_eq!(
        h.userinfo(narrowed["access_token"].as_str().unwrap())
            .await
            .status,
        401
    );
}

// --- independent audit (wave 11A) --------------------------------------------

/// Accepts the interaction behind `location` as the signed-in user; returns
/// the code.
async fn accept_code(h: &Harness, location: &str, binding: Option<String>) -> String {
    let id = interaction_id(location);
    let r = TestRequest::post(&format!("/v1/oauth2/interactions/{id}/accept"))
        .cookie("__Host-authn_oidc_browser", &binding.unwrap())
        .send(&h.signed_in())
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    query_param(r.json::<Value>()["redirect_to"].as_str().unwrap(), "code").unwrap()
}

/// RFC 8252 §8.6: a public client whose redirect URI cannot prove the
/// client's identity (loopback, private-use scheme) is never authorized
/// without the user: any local app can listen on the loopback interface or
/// claim the same scheme and, with its own PKCE pair, redeem the code. A
/// stored consent, `skip_consent` and `prompt=none` do not change that.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_05_public_native_clients_without_assured_redirect_are_never_auto_approved(
    pool: sqlx::PgPool,
) {
    let h = Harness::new(pool).await;
    let client = h.native_client().await;
    // The user approves the genuine app once.
    let (location, binding) = h
        .authorize(
            &h.signed_in(),
            &client,
            "http://127.0.0.1:50000/callback",
            "openid",
            &[],
        )
        .await;
    accept_code(&h, &location, binding).await;
    // A malicious local app replays the request with its own PKCE pair.
    for redirect in ["http://127.0.0.1:61000/callback", "com.example.app:/oauth"] {
        let (location, _) = h
            .authorize(&h.signed_in(), &client, redirect, "openid", &[])
            .await;
        assert!(location.starts_with(INTERACTION), "{redirect}: {location}");
        let (location, _) = h
            .authorize(
                &h.signed_in(),
                &client,
                redirect,
                "openid",
                &[("prompt", "none")],
            )
            .await;
        assert_eq!(
            query_param(&location, "error").as_deref(),
            Some("consent_required"),
            "{redirect}: {location}"
        );
    }
    // Even a first-party native public client shows the consent page.
    let first_party = h
        .register(json!({
            "name": "Own mobile", "client_type": "public", "application_type": "native",
            "redirect_uris": [NATIVE_REDIRECT], "allowed_scopes": ["openid"],
            "skip_consent": true,
        }))
        .await;
    let (location, binding) = h
        .authorize(&h.signed_in(), &first_party, NATIVE_REDIRECT, "openid", &[])
        .await;
    assert!(location.starts_with(INTERACTION), "{location}");
    let id = interaction_id(&location);
    let view = TestRequest::get(&format!("/v1/oauth2/interactions/{id}"))
        .cookie("__Host-authn_oidc_browser", binding.as_deref().unwrap())
        .send(&h.signed_in())
        .await;
    assert_eq!(view.json::<Value>()["consent_required"], true);
    // A confidential client (the code is useless without its secret) keeps
    // single sign-on.
    let web = h.web_client().await;
    h.grant_consent(&web, "openid").await;
    let (location, _) = h
        .authorize(&h.signed_in(), &web, WEB_REDIRECT, "openid", &[])
        .await;
    assert!(query_param(&location, "code").is_some(), "{location}");
}

/// A consent covers the resources (token audiences, RFC 8707) the user
/// saw, not only the scopes: a later request for another resource of the
/// client asks again instead of silently minting a token for that API.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_05_consent_covers_the_requested_resources(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    h.grant_consent(&client, "orders:read").await;
    let resource = [("resource", "https://api.example.com")];
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "orders:read",
            &resource,
        )
        .await;
    assert!(location.starts_with(INTERACTION), "{location}");
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "orders:read",
            &[("resource", "https://api.example.com"), ("prompt", "none")],
        )
        .await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("consent_required")
    );
    // Once approved, the same request is single sign-on.
    let (location, binding) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "orders:read",
            &resource,
        )
        .await;
    accept_code(&h, &location, binding).await;
    let (location, _) = h
        .authorize(
            &h.signed_in(),
            &client,
            WEB_REDIRECT,
            "orders:read",
            &resource,
        )
        .await;
    assert!(query_param(&location, "code").is_some(), "{location}");
    // The export shows the approved resources.
    let mut conn = h.pool.acquire().await.unwrap();
    let export =
        <authn_oidc_provider::ProviderDataExporter as authn_core::ports::DataExporter>::export(
            &authn_oidc_provider::ProviderDataExporter,
            &mut conn,
            h.user,
        )
        .await
        .unwrap();
    assert_eq!(
        export["consents"][0]["resources"],
        json!(["https://api.example.com"])
    );
}

/// Two parallel exchanges of one code: exactly one gets tokens, the other
/// is a replay that revokes the grant (OIDP-06).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_06_parallel_code_exchanges_have_one_winner_and_revoke(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let (a, b) = tokio::join!(
        h.exchange(&client, &code, WEB_REDIRECT),
        h.exchange(&client, &code, WEB_REDIRECT)
    );
    let ok: Vec<_> = [&a, &b].into_iter().filter(|r| r.status == 200).collect();
    assert_eq!(ok.len(), 1, "{} / {}", a.text(), b.text());
    let loser = if a.status == 200 { &b } else { &a };
    assert_eq!(loser.json::<Value>()["error"], "invalid_grant");
    let access = ok[0].json::<Value>()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(h.userinfo(&access).await.status, 401);
}

/// Two parallel refreshes with one token: at most one rotation, the other
/// counts as a replay and the grant ends (OIDP-07).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_07_parallel_refreshes_count_as_replay(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let client = h.web_client().await;
    let code = h.code_for(&client, WEB_REDIRECT, "openid").await;
    let tokens: Value = h.exchange(&client, &code, WEB_REDIRECT).await.json();
    let rt = tokens["refresh_token"].as_str().unwrap();
    let fields = [("grant_type", "refresh_token"), ("refresh_token", rt)];
    let (a, b) = tokio::join!(
        h.token(&client, &fields, true),
        h.token(&client, &fields, true)
    );
    assert_eq!(
        [&a, &b].iter().filter(|r| r.status == 200).count(),
        1,
        "{} / {}",
        a.text(),
        b.text()
    );
    let winner = if a.status == 200 { &a } else { &b };
    let rt2 = winner.json::<Value>()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = h
        .token(
            &client,
            &[("grant_type", "refresh_token"), ("refresh_token", &rt2)],
            true,
        )
        .await;
    assert_eq!(r.json::<Value>()["error"], "invalid_grant");
}

/// RFC 7009 §2.1 / RFC 7662: a client can neither revoke nor introspect
/// another client's tokens, and the answer does not tell them apart from
/// unknown tokens (OIDP-11).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_11_other_clients_tokens_are_untouchable_and_invisible(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let victim = h.web_client().await;
    let attacker = h
        .register(json!({
            "name": "Other", "client_type": "confidential", "application_type": "web",
            "redirect_uris": [WEB_REDIRECT], "allowed_scopes": ["openid"],
        }))
        .await;
    let code = h.code_for(&victim, WEB_REDIRECT, "openid").await;
    let tokens: Value = h.exchange(&victim, &code, WEB_REDIRECT).await.json();
    for token in [
        tokens["access_token"].as_str().unwrap(),
        tokens["refresh_token"].as_str().unwrap(),
    ] {
        let r = h
            .form_post("/v1/oauth2/introspect", &attacker, &[("token", token)])
            .await;
        assert_eq!(r.json::<Value>(), json!({ "active": false }));
        let r = h
            .form_post("/v1/oauth2/revoke", &attacker, &[("token", token)])
            .await;
        assert_eq!(r.status, 200);
        assert!(r.text().is_empty());
    }
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(h.userinfo(access).await.status, 200);
    let r = h
        .token(
            &victim,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ],
            true,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
}
