#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Social login end to end (TST-06, K-51, K-52): the real router with every
//! layer, real PostgreSQL, the real SSRF-safe HTTP client and wiremock
//! identity providers (TST-08: no network). Covers every provider's web
//! flow, the native flow, Apple's cross-site `form_post`, the Microsoft
//! tenant rule, linking / unlinking behind step-up, the PWD-11 / SOC-06
//! last-method rules across modules (server adapters), the ACC-07
//! reservation, the pre-hijacking interaction with password sign-up
//! (ADR 0002), account erasure → Apple token revocation job (K-35) and the
//! open-redirect regressions of `return_to` (TST-02).

mod common;

use std::time::Duration;

use authn_core::ports::{Clock, NotificationKind};
use authn_testkit::http::{TestRequest, TestResponse};
use axum::http::StatusCode;
use common::idp::{
    ACME_WEB, APPLE_WEB, FakeIdp, GITHUB_WEB, GOOGLE_NATIVE, GOOGLE_WEB, MS_TENANT, MS_WEB,
    RETURN_TO, Started, claims, sign_rs256,
};
use common::{App, Browser, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;

async fn app(pool: PgPool) -> (App, FakeIdp) {
    app_with(pool, |_| {}).await
}

async fn app_with(
    pool: PgPool,
    tweak: impl FnOnce(&mut authn_core::config::AppConfig),
) -> (App, FakeIdp) {
    let idp = FakeIdp::start().await;
    let mut config = authn_testkit::config::test_config();
    idp.configure(&mut config);
    let ports = idp.ports(&config);
    let app = App::with_ports(
        pool,
        |c| {
            idp.configure(c);
            tweak(c);
        },
        ports,
    )
    .await;
    (app, idp)
}

fn now(app: &App) -> i64 {
    app.ports.clock.now().unix_timestamp()
}

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// `GET /v1/oauth/{provider}/start` through the stack.
async fn start(app: &App, provider: &str, return_to: Option<&str>) -> TestResponse {
    let uri = match return_to {
        Some(rt) => format!("/v1/oauth/{provider}/start?return_to={}", enc(rt)),
        None => format!("/v1/oauth/{provider}/start"),
    };
    app.send(TestRequest::get(&uri)).await
}

/// The browser callback with the binding cookie.
async fn callback(app: &App, browser: &mut Browser, provider: &str, s: &Started) -> TestResponse {
    let request = browser
        .get(&format!(
            "/v1/oauth/{provider}/callback?code=the-code&state={}",
            s.param("state")
        ))
        .cookie("__Host-authn_oauth", &s.binding);
    browser.send(app, request).await
}

async fn identities_of(app: &App, user: authn_core::id::UserId) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM identities WHERE user_id = $1")
        .bind(user)
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

async fn owner_of(app: &App, provider: &str, subject: &str) -> Option<authn_core::id::UserId> {
    sqlx::query_scalar("SELECT user_id FROM identities WHERE provider = $1 AND subject = $2")
        .bind(provider)
        .bind(subject)
        .fetch_optional(&app.pool)
        .await
        .unwrap()
}

/// A full web login with `provider` (OIDC providers) for `sub` / `email`;
/// returns the signed-in browser and the callback response.
#[allow(clippy::too_many_arguments)]
async fn web_login(
    app: &App,
    idp: &FakeIdp,
    provider: &str,
    prefix: &str,
    iss: &str,
    aud: &str,
    sub: &str,
    email: &str,
    tweak: impl FnOnce(&mut Value),
) -> (Browser, TestResponse) {
    let s = Started::from_response(&start(app, provider, Some(RETURN_TO)).await);
    let mut c = claims(iss, aud, sub, &s.param("nonce"), email, now(app));
    tweak(&mut c);
    idp.token_once(prefix, &c).await;
    let mut browser = app.browser();
    let res = callback(app, &mut browser, provider, &s).await;
    (browser, res)
}

fn assert_signed_in_redirect(res: &TestResponse) {
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
    assert_eq!(res.headers["location"], RETURN_TO);
    assert!(
        res.set_cookies()
            .iter()
            .any(|c| c.starts_with("__Host-authn_session=")),
        "{:?}",
        res.set_cookies()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_google_web_login_through_the_stack_opens_a_session(pool: PgPool) {
    let (app, idp) = app(pool).await;
    let (browser, res) = web_login(
        &app,
        &idp,
        "google",
        "/google",
        &idp.issuer("/google"),
        GOOGLE_WEB,
        "g-1",
        "new@example.com",
        |_| {},
    )
    .await;
    assert_signed_in_redirect(&res);
    let me = app.send(browser.get("/v1/me")).await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.text());
    let user = owner_of(&app, "google", "g-1").await.unwrap();
    assert_eq!(me.json::<Value>()["user_id"], json!(user), "{}", me.text());
    // The identity is listed (no tokens, no subject).
    let list = app.send(browser.get("/v1/me/identities")).await;
    assert_eq!(list.status, StatusCode::OK);
    let text = list.text();
    assert!(
        text.contains("google") && !text.contains("provider-refresh-token"),
        "{text}"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_04_google_native_login_through_the_stack_returns_tokens(pool: PgPool) {
    let (app, idp) = app(pool).await;
    let r = app
        .send(TestRequest::post("/v1/oauth/nonce").json(&json!({"provider": "google"})))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let nonce = r.json::<Value>()["nonce"].as_str().unwrap().to_owned();
    let c = claims(
        &idp.issuer("/google"),
        GOOGLE_NATIVE,
        "g-native",
        &nonce,
        "mobile@example.com",
        now(&app),
    );
    let r = app
        .send(
            TestRequest::post("/v1/oauth/google/native")
                .json(&json!({"id_token": sign_rs256(common::idp::KEY_A, "key-a", &c)})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let body: Value = r.json();
    let access = body["access_token"].as_str().expect("access token");
    assert!(body["refresh_token"].is_string(), "{body}");
    assert!(r.set_cookies().is_empty(), "native flow sets no cookie");
    let me = app.send(TestRequest::get("/v1/me").bearer(access)).await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.text());
    // The nonce is single-use.
    let replay = app
        .send(
            TestRequest::post("/v1/oauth/google/native")
                .json(&json!({"id_token": sign_rs256(common::idp::KEY_A, "key-a", &c)})),
        )
        .await;
    assert!(replay.status.is_client_error(), "{}", replay.text());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_07_apple_form_post_crosses_the_csrf_layer_and_signs_in(pool: PgPool) {
    let (app, idp) = app(pool).await;
    let s = Started::from_response(&start(&app, "apple", Some(RETURN_TO)).await);
    assert_eq!(s.param("response_mode"), "form_post");
    let mut c = claims(
        &idp.issuer("/apple"),
        APPLE_WEB,
        "001234.apple.sub",
        &s.param("nonce"),
        "abc123@privaterelay.appleid.com",
        now(&app),
    );
    c["email_verified"] = json!("true");
    idp.token_once("/apple", &c).await;
    // Apple's cross-site POST: a foreign Origin, no session cookie, no CSRF
    // token. The authentication layer has nothing to check; the single-use
    // state bound to this browser is the CSRF protection.
    let body = format!(
        "state={}&code=apple-code&user={}",
        s.param("state"),
        enc(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#)
    );
    let mut browser = app.browser();
    let res = browser
        .send(
            &app,
            TestRequest::post("/v1/oauth/apple/callback")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", "https://appleid.apple.com")
                .cookie("__Host-authn_oauth", &s.binding)
                .body(body),
        )
        .await;
    assert_signed_in_redirect(&res);
    assert_eq!(app.send(browser.get("/v1/me")).await.status, StatusCode::OK);
    // The client secret was an ES256 JWT (p256 only, SOC-07).
    let token_calls = idp.requests_to("/apple/token").await;
    let form: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(&token_calls[0].body)
            .into_owned()
            .collect();
    assert_eq!(form["client_secret"].split('.').count(), 3);
    // SOC-08 / K-35: Apple's refresh token is kept sealed for revocation.
    let user = owner_of(&app, "apple", "001234.apple.sub").await.unwrap();
    let sealed: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT refresh_token_ciphertext FROM identities WHERE user_id = $1")
            .bind(user)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    let sealed = sealed.expect("sealed refresh token");
    assert!(!sealed.windows(22).any(|w| w == b"provider-refresh-token"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_03_microsoft_tenant_allow_list_through_the_stack(pool: PgPool) {
    let (app, idp) = app(pool).await;
    let oid = "aaaaaaaa-0000-0000-0000-000000000001";
    let tid = MS_TENANT;
    let (_, res) = web_login(
        &app,
        &idp,
        "microsoft",
        "/ms",
        &format!("{}/ms/{tid}/v2.0", idp.uri()),
        MS_WEB,
        "pairwise",
        "worker@contoso.example",
        |c| {
            c["tid"] = json!(tid);
            c["oid"] = json!(oid);
            c["xms_edov"] = json!(true);
        },
    )
    .await;
    assert_signed_in_redirect(&res);
    assert!(
        owner_of(&app, "microsoft", &format!("{tid}:{oid}"))
            .await
            .is_some()
    );

    // Another tenant (not on the allow-list) is refused, whatever it claims.
    let foreign = "22222222-2222-2222-2222-222222222222";
    let (_, res) = web_login(
        &app,
        &idp,
        "microsoft",
        "/ms",
        &format!("{}/ms/{foreign}/v2.0", idp.uri()),
        MS_WEB,
        "pairwise-2",
        "worker@fabrikam.example",
        |c| {
            c["tid"] = json!(foreign);
            c["oid"] = json!(oid);
            c["xms_edov"] = json!(true);
        },
    )
    .await;
    assert!(res.status.is_client_error(), "{}", res.text());
    assert!(
        res.set_cookies()
            .iter()
            .all(|c| !c.starts_with("__Host-authn_session="))
    );
    assert!(
        owner_of(&app, "microsoft", &format!("{foreign}:{oid}"))
            .await
            .is_none()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_01_github_and_generic_providers_through_the_stack(pool: PgPool) {
    let (app, idp) = app(pool).await;
    // GitHub (OAuth 2.0, primary verified address from the API).
    let s = Started::from_response(&start(&app, "github", Some(RETURN_TO)).await);
    assert_eq!(s.param("client_id"), GITHUB_WEB);
    idp.github_once(4242, "octo@example.com").await;
    let mut browser = app.browser();
    let res = callback(&app, &mut browser, "github", &s).await;
    assert_signed_in_redirect(&res);
    assert!(owner_of(&app, "github", "4242").await.is_some());

    // Generic OIDC provider (discovery, exact issuer).
    let (_, res) = web_login(
        &app,
        &idp,
        "acme",
        "/acme",
        &idp.issuer("/acme"),
        ACME_WEB,
        "acme-1",
        "employee@acme.example",
        |_| {},
    )
    .await;
    assert_signed_in_redirect(&res);
    assert!(owner_of(&app, "oidc:acme", "acme-1").await.is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_link_and_unlink_require_step_up_and_obey_the_last_method_rule(pool: PgPool) {
    let (app, idp) = app(pool).await;
    let user = app.user("alice@example.com").await;
    let mut browser = app.browser();
    let body = browser.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");

    // Link Google (fresh login = within the step-up window).
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/me/identities/link",
                &json!({"provider": "google", "return_to": RETURN_TO}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let url = url::Url::parse(r.json::<Value>()["authorization_url"].as_str().unwrap()).unwrap();
    let binding = r
        .set_cookies()
        .into_iter()
        .find_map(|c| {
            c.strip_prefix("__Host-authn_oauth=")
                .map(|v| v.split(';').next().unwrap().to_owned())
        })
        .unwrap();
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();
    let c = claims(
        &idp.issuer("/google"),
        GOOGLE_WEB,
        "alice-google",
        &params["nonce"],
        "alice.other@example.com",
        now(&app),
    );
    idp.token_once("/google", &c).await;
    let res = app
        .send(
            browser
                .get(&format!(
                    "/v1/oauth/google/callback?code=c&state={}",
                    params["state"]
                ))
                .cookie("__Host-authn_oauth", &binding),
        )
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
    assert_eq!(identities_of(&app, user).await, 1);
    app.drain().await;
    assert!(matches!(
        app.last_notification("identity_linked"),
        NotificationKind::IdentityLinked { .. }
    ));

    // PWD-11 across modules: with a linked identity the password may go
    // (the server's password adapter reports `Social`).
    let identity = app
        .send(browser.get("/v1/me/identities"))
        .await
        .json::<Value>()["identities"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Unlink needs a recent authentication.
    app.advance(Duration::from_secs(3600));
    let r = app
        .send(browser.delete(&format!("/v1/me/identities/{identity}")))
        .await;
    r.assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/reauth",
                &json!({"method": "password", "password": PASSWORD}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let r = browser.send(&app, browser.delete("/v1/me/password")).await;
    assert!(
        r.status.is_success(),
        "password removal with a linked identity: {}",
        r.text()
    );

    // Now the identity is the last login method: SOC-06 refuses the unlink
    // (the server's oidc adapter sees no password and no passkey).
    let r = app
        .send(browser.delete(&format!("/v1/me/identities/{identity}")))
        .await;
    r.assert_error(StatusCode::CONFLICT, "identity_last_login_method");
    assert_eq!(identities_of(&app, user).await, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_password_removal_is_refused_without_another_strong_method(pool: PgPool) {
    let (app, _idp) = app(pool).await;
    app.user("bob@example.com").await;
    let mut browser = app.browser();
    browser.login(&app, "bob@example.com", PASSWORD).await;
    // No passkey, no identity: the password is the last method (PWD-11);
    // passwordless e-mail login is not counted as a strong method.
    let r = app.send(browser.delete("/v1/me/password")).await;
    assert!(r.status.is_client_error(), "{}", r.text());
}

/// The attacker registers the victim's address with a password and never
/// verifies it (ADR 0002 pre-hijacking).
async fn attacker_sign_up(app: &App, email: &str, password: &str) {
    let mut attacker = app.browser();
    attacker.csrf(app).await;
    let terms: Vec<Value> = app.send(attacker.get("/v1/terms")).await.json::<Value>()["current"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|t| json!({"document": t["document"], "version": t["version"]}))
        .collect();
    let r = attacker
        .send(
            app,
            attacker.post(
                "/v1/signup",
                &json!({"email": email, "password": password, "accepted_terms": terms}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.drain().await;
}

const ATTACKER_PASSWORD: &str = "attacker chosen pass 9!";

async fn attacker_cannot_sign_in(app: &App) {
    let mut again = app.browser();
    let body = again
        .login(app, "victim@example.com", ATTACKER_PASSWORD)
        .await;
    assert_ne!(body["status"], "authenticated", "{body}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_pre_hijacked_sign_up_never_receives_the_identity_by_default(pool: PgPool) {
    let (app, idp) = app(pool).await;
    attacker_sign_up(&app, "victim@example.com", ATTACKER_PASSWORD).await;
    // Default (no auto-link): the identity is not attached to the
    // attacker's unverified placeholder; the victim is told to sign in.
    let (_, res) = web_login(
        &app,
        &idp,
        "google",
        "/google",
        &idp.issuer("/google"),
        GOOGLE_WEB,
        "victim-google",
        "victim@example.com",
        |_| {},
    )
    .await;
    res.assert_error(StatusCode::CONFLICT, "oauth_link_required");
    assert!(owner_of(&app, "google", "victim-google").await.is_none());
    attacker_cannot_sign_in(&app).await;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_pre_hijacked_sign_up_is_reclaimed_by_the_mailbox_owner(pool: PgPool) {
    let (app, idp) = app_with(pool, |c| {
        c.oidc_client.auto_link_verified_email = true;
        c.oidc_client.auto_link_trusted_providers = vec!["google".to_owned()];
    })
    .await;
    attacker_sign_up(&app, "victim@example.com", ATTACKER_PASSWORD).await;
    let (victim, res) = web_login(
        &app,
        &idp,
        "google",
        "/google",
        &idp.issuer("/google"),
        GOOGLE_WEB,
        "victim-google",
        "victim@example.com",
        |_| {},
    )
    .await;
    assert_signed_in_redirect(&res);
    assert_eq!(app.send(victim.get("/v1/me")).await.status, StatusCode::OK);
    let user = owner_of(&app, "google", "victim-google").await.unwrap();
    // The attacker's unproven password did not survive the mailbox proof.
    attacker_cannot_sign_in(&app).await;
    let password: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM password_credentials WHERE user_id = $1")
            .bind(user)
            .fetch_optional(&app.pool)
            .await
            .unwrap();
    assert!(password.is_none(), "the unproven password must not survive");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_reserved_address_is_refused_through_the_stack(pool: PgPool) {
    let (app, idp) = app(pool).await;
    let owner = app.user("reserved@example.com").await;
    let mut browser = app.browser();
    browser.login(&app, "reserved@example.com", PASSWORD).await;
    // ACC-07: change the address; the old one stays reserved for the owner.
    let r = browser
        .send(
            &app,
            browser.post("/v1/me/email", &json!({"new_email": "moved@example.com"})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.drain().await;
    let NotificationKind::EmailChangeVerification { token, .. } =
        app.last_notification("email_change_verification")
    else {
        panic!()
    };
    let r = browser
        .send(
            &app,
            browser.post(
                "/v1/email/change/confirm",
                &json!({"token": token.expose()}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());

    let (_, res) = web_login(
        &app,
        &idp,
        "google",
        "/google",
        &idp.issuer("/google"),
        GOOGLE_WEB,
        "squatter",
        "reserved@example.com",
        |_| {},
    )
    .await;
    assert!(res.status.is_client_error(), "{}", res.text());
    assert!(res.text().contains("oauth_link_required"), "{}", res.text());
    assert!(owner_of(&app, "google", "squatter").await.is_none());
    let taken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE email_normalized = 'reserved@example.com'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(taken, 0, "the reserved address was not given to anyone");
    let _ = owner;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_erasure_queues_and_the_job_revokes_the_apple_token(pool: PgPool) {
    let (app, idp) = app(pool).await;
    idp.apple_revoke_ok().await;
    let s = Started::from_response(&start(&app, "apple", Some(RETURN_TO)).await);
    let mut c = claims(
        &idp.issuer("/apple"),
        APPLE_WEB,
        "erase.apple.sub",
        &s.param("nonce"),
        "erase@privaterelay.appleid.com",
        now(&app),
    );
    c["email_verified"] = json!("true");
    idp.token_once("/apple", &c).await;
    let mut browser = app.browser();
    let res = browser
        .send(
            &app,
            TestRequest::post("/v1/oauth/apple/callback")
                .header("content-type", "application/x-www-form-urlencoded")
                .cookie("__Host-authn_oauth", &s.binding)
                .body(format!("state={}&code=c", s.param("state"))),
        )
        .await;
    assert_signed_in_redirect(&res);
    assert!(owner_of(&app, "apple", "erase.apple.sub").await.is_some());

    // Erasure (the purge job after the grace period) runs the registered
    // erasure hook in its transaction: the token is queued, then revoked by
    // the job (K-35).
    browser.csrf(&app).await;
    let r = browser.send(&app, browser.delete("/v1/me")).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.text());
    app.advance(Duration::from_secs(60 * 24 * 3600));
    let purged = app.services.accounts.purge_due_deletions(10).await.unwrap();
    assert_eq!(purged.purged, 1);
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_token_revocations")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(queued, 1);
    authn_server::jobs::process_token_revocations(&app.services)
        .await
        .unwrap();
    let calls = idp.requests_to("/apple/revoke").await;
    assert_eq!(calls.len(), 1);
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_token_revocations")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(queued, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn tst_02_social_return_to_cannot_open_redirect(pool: PgPool) {
    let (app, _idp) = app(pool).await;
    for evil in [
        "https://evil.example/after",
        "//evil.example/after",
        "/\\evil.example",
        "https://app.example.com.evil.example/after",
        "https://app.example.com@evil.example/after",
        "javascript:alert(1)",
        "https://app.example.com/after\r\nLocation: https://evil.example",
        "HTTPS://evil.example",
    ] {
        let res = start(&app, "google", Some(evil)).await;
        assert!(
            res.status.is_client_error(),
            "{evil:?} must be refused: {} {}",
            res.status,
            res.text()
        );
        assert!(res.headers.get("location").is_none(), "{evil:?}");
        assert!(
            res.set_cookies()
                .iter()
                .all(|c| !c.starts_with("__Host-authn_oauth=")),
            "{evil:?}: no flow is started"
        );
    }
    // The allow-listed target works.
    let res = start(&app, "google", Some(RETURN_TO)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    let location = res.headers["location"].to_str().unwrap();
    assert!(
        location.starts_with(&format!("{}/google/authorize?", _idp.uri())),
        "{location}"
    );
}

/// Links `provider` (Google) to the signed-in `browser` through the stack.
async fn link_google(app: &App, idp: &FakeIdp, browser: &mut Browser, sub: &str, email: &str) {
    let r = browser
        .send(
            app,
            browser.post(
                "/v1/me/identities/link",
                &json!({"provider": "google", "return_to": RETURN_TO}),
            ),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let url = url::Url::parse(r.json::<Value>()["authorization_url"].as_str().unwrap()).unwrap();
    let binding = r
        .set_cookies()
        .into_iter()
        .find_map(|c| {
            c.strip_prefix("__Host-authn_oauth=")
                .map(|v| v.split(';').next().unwrap().to_owned())
        })
        .unwrap();
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();
    let c = claims(
        &idp.issuer("/google"),
        GOOGLE_WEB,
        sub,
        &params["nonce"],
        email,
        now(app),
    );
    idp.token_once("/google", &c).await;
    let res = app
        .send(
            browser
                .get(&format!(
                    "/v1/oauth/google/callback?code=c&state={}",
                    params["state"]
                ))
                .cookie("__Host-authn_oauth", &binding),
        )
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
}

/// ACC-07 / K-20: a social identity the attacker linked after taking over
/// the mailbox is removed by the owner's revert, in the revert transaction;
/// signing in with it afterwards never reaches the victim's account.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_k20_revert_removes_the_identity_the_attacker_linked(pool: PgPool) {
    let (app, idp) = app(pool).await;
    let victim = app.user("victim@example.com").await;
    let mut attacker = app.browser();
    attacker.login(&app, "victim@example.com", PASSWORD).await;
    attacker.csrf(&app).await;
    let r = attacker
        .send(
            &app,
            attacker.post(
                "/v1/me/email",
                &json!({"new_email": "attacker@evil.example"}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.drain().await;
    let NotificationKind::EmailChangeVerification { token, .. } =
        app.last_notification("email_change_verification")
    else {
        panic!()
    };
    let r = attacker
        .send(
            &app,
            attacker.post(
                "/v1/email/change/confirm",
                &json!({"token": token.expose()}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    app.drain().await;
    let NotificationKind::EmailChanged { revert_token, .. } =
        app.last_notification("email_changed")
    else {
        panic!()
    };
    attacker.csrf(&app).await;
    link_google(
        &app,
        &idp,
        &mut attacker,
        "attacker-google",
        "attacker@evil.example",
    )
    .await;
    assert_eq!(identities_of(&app, victim).await, 1);

    let r = app
        .send(
            TestRequest::post("/v1/email/change/revert")
                .json(&json!({"token": revert_token.expose()})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    assert_eq!(identities_of(&app, victim).await, 0);
    assert_eq!(
        app.send(attacker.get("/v1/me")).await.status,
        StatusCode::UNAUTHORIZED
    );
    // The identity no longer leads to the victim's account.
    let (_, _res) = web_login(
        &app,
        &idp,
        "google",
        "/google",
        &idp.issuer("/google"),
        GOOGLE_WEB,
        "attacker-google",
        "attacker@evil.example",
        |_| {},
    )
    .await;
    assert_ne!(
        owner_of(&app, "google", "attacker-google").await,
        Some(victim)
    );
}

/// `POST /v1/oauth/nonce` for `provider`.
async fn native_nonce(app: &App, provider: &str) -> String {
    let r = app
        .send(TestRequest::post("/v1/oauth/nonce").json(&json!({ "provider": provider })))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{provider}: {}", r.text());
    r.json::<Value>()["nonce"].as_str().unwrap().to_owned()
}

async fn native_login(app: &App, provider: &str, body: &Value) -> TestResponse {
    app.send(TestRequest::post(&format!("/v1/oauth/{provider}/native")).json(body))
        .await
}

fn assert_native_tokens(res: &TestResponse) -> String {
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(res.set_cookies().is_empty(), "native flow sets no cookie");
    let body: Value = res.json();
    assert!(body["refresh_token"].is_string(), "{body}");
    body["access_token"].as_str().unwrap().to_owned()
}

/// Wave 3A audit (TST-06 gap): the native flow of Apple (with the
/// one-time authorization code, K-35), Microsoft (tenant allow-list) and a
/// generic OIDC provider over the full stack; ID tokens of the **web**
/// client or of a foreign tenant are refused natively.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_04_apple_microsoft_and_generic_native_logins_through_the_stack(pool: PgPool) {
    const MS_NATIVE: &str = "ms-mobile-client";
    const ACME_NATIVE: &str = "acme-mobile-client";
    let (app, idp) = app_with(pool, |c| {
        c.oidc_client
            .microsoft
            .as_mut()
            .unwrap()
            .client
            .native_client_ids = vec![MS_NATIVE.to_owned()];
        c.oidc_client.generic[0].client.native_client_ids = vec![ACME_NATIVE.to_owned()];
    })
    .await;

    // Apple: ID token for the app's bundle id + the authorization code,
    // exchanged as that bundle id; only the refresh token is kept, sealed.
    let nonce = native_nonce(&app, "apple").await;
    let mut c = claims(
        &idp.issuer("/apple"),
        common::idp::APPLE_NATIVE,
        "001234.apple.native",
        &nonce,
        "native@privaterelay.appleid.com",
        now(&app),
    );
    c["email_verified"] = json!("true");
    idp.token_once("/apple", &c).await;
    let res = native_login(
        &app,
        "apple",
        &json!({
            "id_token": sign_rs256(common::idp::KEY_A, "key-a", &c),
            "authorization_code": "apple-native-code",
        }),
    )
    .await;
    let access = assert_native_tokens(&res);
    assert_eq!(
        app.send(TestRequest::get("/v1/me").bearer(&access))
            .await
            .status,
        StatusCode::OK
    );
    let calls = idp.requests_to("/apple/token").await;
    assert_eq!(calls.len(), 1);
    let form: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(&calls[0].body)
            .into_owned()
            .collect();
    assert_eq!(form["client_id"], common::idp::APPLE_NATIVE);
    assert_eq!(form["code"], "apple-native-code");
    let user = owner_of(&app, "apple", "001234.apple.native")
        .await
        .unwrap();
    let sealed: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT refresh_token_ciphertext FROM identities WHERE user_id = $1")
            .bind(user)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(sealed.is_some(), "Apple refresh token kept for revocation");
    // An Apple ID token minted for the *web* service id is not a native
    // token.
    let nonce = native_nonce(&app, "apple").await;
    let web = claims(
        &idp.issuer("/apple"),
        APPLE_WEB,
        "001234.apple.other",
        &nonce,
        "other@privaterelay.appleid.com",
        now(&app),
    );
    let res = native_login(
        &app,
        "apple",
        &json!({ "id_token": sign_rs256(common::idp::KEY_A, "key-a", &web) }),
    )
    .await;
    assert!(res.status.is_client_error(), "{}", res.text());
    assert!(
        owner_of(&app, "apple", "001234.apple.other")
            .await
            .is_none()
    );

    // Microsoft: the allowed tenant signs in natively…
    let oid = "aaaaaaaa-0000-0000-0000-000000000009";
    let ms = |tid: &str, nonce: &str, aud: &str| {
        let mut c = claims(
            &format!("{}/ms/{tid}/v2.0", idp.uri()),
            aud,
            "pairwise-native",
            nonce,
            "worker@contoso.example",
            now(&app),
        );
        c["tid"] = json!(tid);
        c["oid"] = json!(oid);
        c["xms_edov"] = json!(true);
        sign_rs256(common::idp::KEY_A, "key-a", &c)
    };
    let nonce = native_nonce(&app, "microsoft").await;
    let res = native_login(
        &app,
        "microsoft",
        &json!({ "id_token": ms(MS_TENANT, &nonce, MS_NATIVE) }),
    )
    .await;
    assert_native_tokens(&res);
    assert!(
        owner_of(&app, "microsoft", &format!("{MS_TENANT}:{oid}"))
            .await
            .is_some()
    );
    // …a foreign tenant does not, nor does a web-client token.
    let foreign = "22222222-2222-2222-2222-222222222222";
    let nonce = native_nonce(&app, "microsoft").await;
    let res = native_login(
        &app,
        "microsoft",
        &json!({ "id_token": ms(foreign, &nonce, MS_NATIVE) }),
    )
    .await;
    assert!(res.status.is_client_error(), "{}", res.text());
    assert!(
        owner_of(&app, "microsoft", &format!("{foreign}:{oid}"))
            .await
            .is_none()
    );
    let nonce = native_nonce(&app, "microsoft").await;
    let res = native_login(
        &app,
        "microsoft",
        &json!({ "id_token": ms(MS_TENANT, &nonce, MS_WEB) }),
    )
    .await;
    assert!(res.status.is_client_error(), "{}", res.text());

    // Generic OIDC provider.
    let nonce = native_nonce(&app, "acme").await;
    let c = claims(
        &idp.issuer("/acme"),
        ACME_NATIVE,
        "acme-native",
        &nonce,
        "mobile@acme.example",
        now(&app),
    );
    let res = native_login(
        &app,
        "acme",
        &json!({ "id_token": sign_rs256(common::idp::KEY_A, "key-a", &c) }),
    )
    .await;
    assert_native_tokens(&res);
    assert!(owner_of(&app, "oidc:acme", "acme-native").await.is_some());
    // GitHub (OAuth 2.0, no ID token) has no native flow.
    let r = app
        .send(TestRequest::post("/v1/oauth/nonce").json(&json!({"provider": "github"})))
        .await;
    assert!(r.status.is_client_error(), "{}", r.text());
}
