#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! OAuth 2.1 / OIDC provider end to end (K-80, OIDP-*): the complete
//! router and middleware stack, real browser sessions (password and
//! passkey logins), the real session revoker and authn-admin's staff-role
//! check. The protocol details (PKCE, replay, refresh rotation, prompt,
//! consent, introspection, revocation) are covered against the provider's
//! own routers in `crates/authn-oidc-provider/tests/flows.rs`; this file
//! proves the wiring: middleware placement, token-type separation from
//! native tokens and the coupling to sign-out, password reset and
//! suspension.

mod common;

use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_testkit::http::{TestRequest, TestResponse};
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{App, Browser, ORIGIN, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs_proto::{AllowCredentials, CreationChallengeResponse, RequestChallengeResponse};

const INTERACTION: &str = "https://app.test.example/oauth/consent";
const REDIRECT: &str = "https://rp.example.com/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

async fn app(pool: PgPool) -> App {
    App::with(pool, |c| {
        c.protect.risk.enabled = false;
        c.oidc_provider.enabled = true;
        c.oidc_provider.interaction_url = Some(INTERACTION.to_owned());
    })
    .await
}

struct Rp {
    client_id: String,
    secret: String,
}

async fn register(app: &App) -> Rp {
    let input = serde_json::from_value(json!({
        "name": "Shop", "client_type": "confidential", "application_type": "web",
        "redirect_uris": [REDIRECT], "allowed_scopes": ["openid", "email", "profile"],
    }))
    .unwrap();
    let created = app
        .services
        .oidc_provider
        .create_client_unchecked(&RequestContext::system(Default::default()), None, input)
        .await
        .unwrap();
    Rp {
        client_id: created.client.client_id,
        secret: created.client_secret.unwrap().expose().to_owned(),
    }
}

async fn signed_in(app: &App, email: &str) -> (UserId, Browser) {
    let id = app.user(email).await;
    let mut browser = app.browser();
    let body = browser.login(app, email, PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    browser.csrf(app).await;
    (id, browser)
}

fn param(location: &str, name: &str) -> Option<String> {
    Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// The browser goes through `/authorize`, the consent page accepts, the
/// RP exchanges the code; returns the token response.
async fn tokens_for(app: &App, browser: &mut Browser, rp: &Rp) -> Value {
    let query = serde_urlencoded::to_string([
        ("client_id", rp.client_id.as_str()),
        ("redirect_uri", REDIRECT),
        ("response_type", "code"),
        ("scope", "openid email"),
        ("state", "s1"),
        ("nonce", "n1"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ])
    .unwrap();
    let r = browser
        .send(app, browser.get(&format!("/v1/oauth2/authorize?{query}")))
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.text());
    let location = r.header("location").unwrap().to_owned();
    let code = if location.starts_with(INTERACTION) {
        let id = param(&location, "interaction_id").unwrap();
        // The consent page (same site) reads the request, then accepts with
        // the session's CSRF token.
        let view = browser
            .send(app, browser.get(&format!("/v1/oauth2/interactions/{id}")))
            .await;
        assert_eq!(view.status, StatusCode::OK, "{}", view.text());
        assert_eq!(view.json::<Value>()["authenticated"], true);
        let r = browser
            .send(
                app,
                browser.post(&format!("/v1/oauth2/interactions/{id}/accept"), &json!({})),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text());
        param(r.json::<Value>()["redirect_to"].as_str().unwrap(), "code").unwrap()
    } else {
        param(&location, "code").unwrap()
    };
    let r = token(
        app,
        rp,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    r.json()
}

async fn token(app: &App, rp: &Rp, fields: &[(&str, &str)]) -> TestResponse {
    form(app, "/v1/oauth2/token", rp, fields).await
}

async fn form(app: &App, path: &str, rp: &Rp, fields: &[(&str, &str)]) -> TestResponse {
    let creds = STANDARD.encode(format!("{}:{}", rp.client_id, rp.secret));
    app.send(
        TestRequest::post(path)
            .header("authorization", &format!("Basic {creds}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(fields).unwrap()),
    )
    .await
}

async fn userinfo(app: &App, access: &str) -> TestResponse {
    app.send(TestRequest::get("/v1/oauth2/userinfo").bearer(access))
        .await
}

async fn refresh(app: &App, rp: &Rp, tokens: &Value) -> TestResponse {
    token(
        app,
        rp,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
        ],
    )
    .await
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_08_provider_and_native_tokens_are_never_interchangeable(pool: PgPool) {
    let app = app(pool).await;
    let rp = register(&app).await;
    let (_, mut browser) = signed_in(&app, "alice@example.com").await;
    let tokens = tokens_for(&app, &mut browser, &rp).await;
    let provider_access = tokens["access_token"].as_str().unwrap();
    // The provider token works where it belongs …
    let info = userinfo(&app, provider_access).await;
    assert_eq!(info.status, StatusCode::OK, "{}", info.text());
    assert_eq!(info.json::<Value>()["email"], "alice@example.com");
    // … and is refused by the native bearer middleware (no `sid`, foreign
    // audience) on every session-protected route.
    for path in ["/v1/me", "/v1/me/sessions", "/v1/me/oauth2/consents"] {
        let r = app
            .send(TestRequest::get(path).bearer(provider_access))
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}");
    }
    // The ID token is not an access token anywhere.
    let id_token = tokens["id_token"].as_str().unwrap();
    assert_eq!(
        app.send(TestRequest::get("/v1/me").bearer(id_token))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        userinfo(&app, id_token).await.status,
        StatusCode::UNAUTHORIZED
    );

    // A native session token is refused by the provider.
    let mut native = app.native();
    let r = app
        .send(native.post(
            "/v1/login/password",
            &json!({"email": "alice@example.com", "password": PASSWORD}),
        ))
        .await;
    native.absorb(&r.json());
    let native_access = native.access.clone().expect("native access token");
    assert_eq!(app.send(native.get("/v1/me")).await.status, StatusCode::OK);
    let r = userinfo(&app, &native_access).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.header("www-authenticate"),
        Some("Bearer error=\"invalid_token\"")
    );
    let intro = form(
        &app,
        "/v1/oauth2/introspect",
        &rp,
        &[("token", &native_access)],
    )
    .await;
    assert_eq!(intro.json::<Value>(), json!({"active": false}));
    // And the native refresh token is no provider refresh token.
    let r = token(
        &app,
        &rp,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", native.refresh.as_deref().unwrap()),
        ],
    )
    .await;
    assert_eq!(r.json::<Value>()["error"], "invalid_grant");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_12_sign_out_everywhere_ends_provider_grants(pool: PgPool) {
    let app = app(pool).await;
    let rp = register(&app).await;
    let (_, mut browser) = signed_in(&app, "bob@example.com").await;
    let tokens = tokens_for(&app, &mut browser, &rp).await;
    assert_eq!(refresh(&app, &rp, &tokens).await.status, StatusCode::OK);
    let r = browser
        .send(&app, browser.post("/v1/logout/all", &json!({})))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let tokens2 = tokens_for_new_browser(&app, &rp, "bob@example.com").await;
    // The old grant is dead, the new one (new session) lives.
    let old = refresh(&app, &rp, &tokens).await;
    assert_eq!(old.json::<Value>()["error"], "invalid_grant");
    assert_eq!(refresh(&app, &rp, &tokens2).await.status, StatusCode::OK);
}

async fn tokens_for_new_browser(app: &App, rp: &Rp, email: &str) -> Value {
    let mut browser = app.browser();
    let body = browser.login(app, email, PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    browser.csrf(app).await;
    tokens_for(app, &mut browser, rp).await
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_12_password_reset_and_suspension_end_provider_grants(pool: PgPool) {
    let app = app(pool).await;
    let rp = register(&app).await;
    let (user, mut browser) = signed_in(&app, "carol@example.com").await;
    let tokens = tokens_for(&app, &mut browser, &rp).await;
    // Password reset revokes every session of the user (PWD-09).
    let mut stranger = app.browser();
    stranger.csrf(&app).await;
    let r = stranger
        .send(
            &app,
            stranger.post(
                "/v1/password/forgot",
                &json!({"email": "carol@example.com"}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.drain().await;
    let authn_core::ports::NotificationKind::PasswordReset { token, .. } =
        app.last_notification("password_reset")
    else {
        panic!("password reset mail")
    };
    let r = stranger
        .send(
            &app,
            stranger.post(
                "/v1/password/reset",
                &json!({"token": token.expose(), "new_password": "a brand new passphrase 2026"}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    assert_eq!(
        refresh(&app, &rp, &tokens).await.json::<Value>()["error"],
        "invalid_grant"
    );
    assert_eq!(
        userinfo(&app, tokens["access_token"].as_str().unwrap())
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    // Suspension: the session check refuses a suspended owner at once.
    let mut browser = app.browser();
    let body = browser
        .login(&app, "carol@example.com", "a brand new passphrase 2026")
        .await;
    assert_eq!(body["status"], "authenticated", "{body}");
    browser.csrf(&app).await;
    let tokens = tokens_for(&app, &mut browser, &rp).await;
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user)
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        userinfo(&app, tokens["access_token"].as_str().unwrap())
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh(&app, &rp, &tokens).await.json::<Value>()["error"],
        "invalid_grant"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_13_disabled_provider_mounts_nothing(pool: PgPool) {
    let app = App::with(pool, |c| c.protect.risk.enabled = false).await;
    for path in [
        "/.well-known/openid-configuration",
        "/v1/oauth2/authorize",
        "/v1/oauth2/userinfo",
        "/v1/admin/oauth2/clients",
    ] {
        let r = app.send(TestRequest::get(path)).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
    }
    let r = app
        .send(
            TestRequest::post("/v1/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body("grant_type=authorization_code"),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_09_discovery_and_shared_jwks_through_the_stack(pool: PgPool) {
    let app = app(pool).await;
    let doc: Value = app
        .send(TestRequest::get("/.well-known/openid-configuration"))
        .await
        .json();
    assert_eq!(doc["issuer"], ORIGIN);
    assert_eq!(doc["jwks_uri"], format!("{ORIGIN}/.well-known/jwks.json"));
    let jwks: Value = app
        .send(TestRequest::get("/.well-known/jwks.json"))
        .await
        .json();
    assert!(!jwks["keys"].as_array().unwrap().is_empty());
    // Clickjacking / caching headers on the authorization endpoint.
    let r = app.send(TestRequest::get("/v1/oauth2/authorize")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.header("x-frame-options").is_some() || r.header("content-security-policy").is_some());
}

// --- staff roles (K-93) ------------------------------------------------------

async fn register_passkey(app: &App, browser: &mut Browser) -> (SoftPasskey, Vec<u8>) {
    let r = browser
        .send(
            app,
            browser.post("/v1/me/passkeys/registration/options", &json!({})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
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
    (key, raw_id)
}

/// A staff member with `role`, signed in with a passkey.
async fn staff(app: &App, email: &str, role: &str) -> Browser {
    let (user, mut browser) = signed_in(app, email).await;
    let (mut key, raw_id) = register_passkey(app, &mut browser).await;
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(user)
        .execute(&app.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO admin_staff_roles (user_id, role, granted_at, updated_at) \
         VALUES ($1, $2, now(), now())",
    )
    .bind(user)
    .bind(role)
    .execute(&app.pool)
    .await
    .unwrap();
    let (handle,): (Vec<u8>,) =
        sqlx::query_as("SELECT user_handle FROM webauthn_user_handles WHERE user_id = $1")
            .bind(user)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    let mut browser = app.browser();
    browser.csrf(app).await;
    let r = browser
        .send(app, browser.post("/v1/login/passkey/options", &json!({})))
        .await;
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
    assertion.response.user_handle = Some(handle);
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/login/passkey",
                &json!({"ceremony_id": options["ceremony_id"], "credential": assertion}),
            ),
        )
        .await;
    assert_eq!(r.json::<Value>()["status"], "authenticated", "{}", r.text());
    browser.csrf(app).await;
    browser
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_01_client_registry_follows_staff_roles(pool: PgPool) {
    let app = app(pool).await;
    let body = json!({
        "name": "Partner", "client_type": "confidential", "application_type": "web",
        "redirect_uris": [REDIRECT], "allowed_scopes": ["openid"],
    });
    // A normal user.
    let (_, mut user) = signed_in(&app, "user@example.com").await;
    let r = user.send(&app, user.get("/v1/admin/oauth2/clients")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());

    // Support staff (read-only and normal): neither read nor manage.
    for (email, role) in [
        ("ro@example.com", "support_readonly"),
        ("support@example.com", "support"),
    ] {
        let mut browser = staff(&app, email, role).await;
        let r = browser
            .send(&app, browser.get("/v1/admin/oauth2/clients"))
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{role}: {}", r.text());
        let r = browser
            .send(&app, browser.post("/v1/admin/oauth2/clients", &body))
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{role}: {}", r.text());
    }
    // Security staff: read, not manage.
    let mut security = staff(&app, "sec@example.com", "security").await;
    let r = security
        .send(&app, security.get("/v1/admin/oauth2/clients"))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let r = security
        .send(&app, security.post("/v1/admin/oauth2/clients", &body))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    // Platform admin: manage.
    let mut admin = staff(&app, "admin@example.com", "platform_admin").await;
    let r = admin
        .send(&app, admin.post("/v1/admin/oauth2/clients", &body))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    let created: Value = r.json();
    assert!(created["client_secret"].is_string());
}
