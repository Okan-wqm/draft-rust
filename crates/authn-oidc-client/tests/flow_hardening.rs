#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Wave 2A open items of the social-login flows: the link callback is
//! bound to its session (K-03), link / unlink notices (K-18), web login
//! session options (K-32), the profile of a new social account (K-33) and
//! the configurable callback error page (K-36).

mod common;

use std::time::Duration;

use authn_core::domain::{AccountStatus, Locale, Principal};
use authn_core::id::UserId;
use authn_core::ports::NotificationKind;
use authn_oidc_client::{OidcClientService, ProviderRegistry};
use authn_testkit::http::{TestRequest, TestResponse};
use common::*;
use http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;

/// A started browser link flow.
struct LinkStart {
    state: String,
    nonce: String,
    binding: String,
}

async fn start_link(h: &Harness, principal: Principal, provider: &str) -> LinkStart {
    let res = TestRequest::post("/v1/me/identities/link")
        .json(&json!({ "provider": provider, "return_to": "/settings/security" }))
        .send(&h.app_as(principal))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let url = url::Url::parse(res.json::<Value>()["authorization_url"].as_str().unwrap()).unwrap();
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();
    let binding = res.headers["set-cookie"]
        .to_str()
        .unwrap()
        .strip_prefix("__Host-authn_oauth=")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    LinkStart {
        state: params["state"].clone(),
        nonce: params["nonce"].clone(),
        binding,
    }
}

async fn finish_link(h: &Harness, started: &LinkStart, sub: &str) -> TestResponse {
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_WEB,
        sub,
        &started.nonce,
        "linked@gmail.example",
    );
    h.idp
        .mount_token_once(
            "/google",
            json!({ "access_token": "at", "id_token": sign_rs256(KEY_A, "key-a", &claims) }),
        )
        .await;
    TestRequest::get(&format!(
        "/v1/oauth/google/callback?code=c&state={}",
        started.state
    ))
    .cookie("__Host-authn_oauth", &started.binding)
    .send(&h.app())
    .await
}

// --- K-03: the link callback re-validates the starting session -------------

/// K-03: a session revoked (sign-out, password reset, "sign out
/// everywhere") after the link flow started can no longer complete it —
/// the callback asks the session hook inside the link transaction.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_link_callback_rejects_revoked_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("me@example.com", AccountStatus::Active, true).await;
    let principal = h.fresh(user);
    let session = principal.session_id().unwrap();
    let started = start_link(&h, principal, "google").await;
    let stored: Option<sqlx::types::Uuid> =
        sqlx::query_scalar("SELECT session_id FROM oauth_states WHERE flow = 'link'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        stored,
        Some(session.as_uuid()),
        "the flow names its session"
    );

    h.liveness.revoke(session);
    finish_link(&h, &started, "revoked-sub")
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
    assert_eq!(h.identity_owner("google", "revoked-sub").await, None);
    assert_eq!(
        h.liveness.calls.lock().unwrap().as_slice(),
        &[(session, user)]
    );
    assert!(
        h.ports.notifier.with_template("identity_linked").is_empty(),
        "nothing linked, nothing announced"
    );
}

/// K-03: a session that belongs to another user does not authorize the
/// link either (the hook is asked for the state's user).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_link_callback_rejects_a_session_of_another_user(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("me@example.com", AccountStatus::Active, true).await;
    let principal = h.fresh(user);
    let session = principal.session_id().unwrap();
    let started = start_link(&h, principal, "google").await;
    h.liveness.own(session, UserId::generate());
    finish_link(&h, &started, "foreign-sub")
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");
    assert_eq!(h.identity_owner("google", "foreign-sub").await, None);
}

/// K-03: with the session still active the link completes as before.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_link_callback_with_live_session_links(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("me@example.com", AccountStatus::Active, true).await;
    let principal = h.fresh(user);
    let session = principal.session_id().unwrap();
    h.liveness.own(session, user);
    let started = start_link(&h, principal, "google").await;
    let res = finish_link(&h, &started, "live-sub").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.text());
    assert_eq!(h.identity_owner("google", "live-sub").await, Some(user));
}

// --- K-18: link / unlink notices ------------------------------------------

/// K-18 (SOC-06): explicit linking, automatic linking and unlinking each
/// queue one notice to the account's address (with the provider's display
/// name) in the same transaction; refused operations send nothing.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_link_and_unlink_notify_the_account_owner(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h
        .user("owner@example.com", AccountStatus::Active, true)
        .await;
    let principal = h.fresh(user);
    h.liveness.own(principal.session_id().unwrap(), user);
    let started = start_link(&h, principal, "google").await;
    assert_eq!(
        finish_link(&h, &started, "notify-sub").await.status,
        StatusCode::SEE_OTHER
    );
    let linked = h.ports.notifier.with_template("identity_linked");
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].recipient.user_id, Some(user));
    assert_eq!(linked[0].recipient.email.as_str(), "owner@example.com");
    match &linked[0].kind {
        NotificationKind::IdentityLinked { provider, .. } => assert_eq!(provider, "Google"),
        other => panic!("{other:?}"),
    }

    // Linking the same identity to another account is refused: no notice.
    let other = h
        .user("other@example.com", AccountStatus::Active, true)
        .await;
    let p2 = h.fresh(other);
    let again = start_link(&h, p2, "google").await;
    finish_link(&h, &again, "notify-sub")
        .await
        .assert_error(StatusCode::CONFLICT, "identity_already_linked");
    assert_eq!(h.ports.notifier.with_template("identity_linked").len(), 1);

    // Unlink (the account has a password, so it is not the last method).
    h.user_password(user).await;
    let identity: sqlx::types::Uuid =
        sqlx::query_scalar("SELECT id FROM identities WHERE subject = 'notify-sub'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    TestRequest::delete(&format!("/v1/me/identities/{identity}"))
        .send(&h.app_as(h.fresh(user)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let unlinked = h.ports.notifier.with_template("identity_unlinked");
    assert_eq!(unlinked.len(), 1);
    assert_eq!(unlinked[0].recipient.user_id, Some(user));
    match &unlinked[0].kind {
        NotificationKind::IdentityUnlinked { provider, .. } => assert_eq!(provider, "Google"),
        other => panic!("{other:?}"),
    }
}

/// K-18: an automatic link (configured trusted provider) is announced; a
/// brand-new social account is not (nothing was attached to an existing
/// account).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_auto_link_is_announced_but_sign_up_is_not(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.config.auto_link_verified_email = true;
        s.config.auto_link_trusted_providers = vec!["google".to_owned()];
    })
    .await;
    let existing = h
        .user("auto@example.com", AccountStatus::Active, true)
        .await;
    let nonce = h.native_nonce("google").await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_NATIVE,
        "auto-sub",
        &nonce,
        "auto@example.com",
    );
    h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
        .await
        .assert_status(StatusCode::OK);
    let linked = h.ports.notifier.with_template("identity_linked");
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].recipient.user_id, Some(existing));

    let nonce = h.native_nonce("google").await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_NATIVE,
        "new-sub",
        &nonce,
        "brand-new@example.com",
    );
    h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(
        h.ports.notifier.with_template("identity_linked").len(),
        1,
        "sign-up is not a link to an existing account"
    );
}

// --- K-32: web login session options -----------------------------------------

/// K-32 (SES-06, SES-07): `remember_me` / `shared_device` chosen at the
/// web start reach the session pipeline through the stored state.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_06_web_social_login_carries_remember_me_and_shared_device(pool: PgPool) {
    let h = Harness::new(pool).await;
    for (query, remember, shared) in [
        ("?remember_me=true", true, false),
        ("?shared_device=true", false, true),
        ("", false, false),
    ] {
        let res = TestRequest::get(&format!("/v1/oauth/google/start{query}"))
            .send(&h.app())
            .await;
        assert_eq!(res.status, 303, "{}", res.text());
        let started = Started::from_response(&res);
        let sub = format!("opt-{remember}-{shared}");
        let claims = h.claims(
            &h.idp.issuer("/google"),
            GOOGLE_WEB,
            &sub,
            "AUTO",
            &format!("{sub}@example.com"),
        );
        h.token_for("/google", &started, &claims).await;
        assert_eq!(h.callback("google", &started).await.status, StatusCode::OK);
        let login = h.ports.session_issuer.logins().pop().unwrap();
        assert_eq!(login.remember_me, remember, "{query}");
        assert_eq!(login.shared_device, shared, "{query}");
    }
    // Unknown start parameters are still refused.
    TestRequest::get("/v1/oauth/google/start?remember=1")
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

// --- K-33: profile of a new social account -----------------------------------

/// K-33 (ACC-08): a social sign-up creates the `user_profiles` row (display
/// name from the provider, language of the request) through authn-account.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_new_social_account_gets_a_profile(pool: PgPool) {
    let h = Harness::new(pool).await;
    let nonce = h.native_nonce("google").await;
    let mut claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_NATIVE,
        "profile-sub",
        &nonce,
        "profile@example.com",
    );
    claims["name"] = json!("Grace Hopper");
    h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
        .await
        .assert_status(StatusCode::OK);
    let user = h.identity_owner("google", "profile-sub").await.unwrap();
    let profile = h.accounts.profile_of(user).await.unwrap().unwrap();
    assert_eq!(profile.display_name.as_deref(), Some("Grace Hopper"));
    assert_eq!(profile.locale, Locale::En);
    assert!(profile.email_verified);
    assert_eq!(profile.status, AccountStatus::Active);
}

// --- K-36: callback error page --------------------------------------------------

fn service_with_error_redirect(h: &Harness, target: &str) -> Result<OidcClientService, String> {
    let mut settings = h.settings.clone();
    settings.config.error_redirect = Some(target.to_owned());
    let registry = ProviderRegistry::from_settings(&settings).unwrap();
    OidcClientService::with_registry(h.service_deps(), settings, registry)
        .map_err(|e| format!("{e:?}"))
}

/// K-36: with `oidc_client.error_redirect` a failed callback sends the
/// browser to that page with the stable code only; the state's own
/// `return_to` is never used for errors. Without it the error stays JSON.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_callback_errors_redirect_to_the_configured_error_page(pool: PgPool) {
    let h = Harness::new(pool).await;
    // Default: JSON.
    TestRequest::get("/v1/oauth/google/callback?code=c&state=forged")
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "oauth_state_invalid");

    let service = service_with_error_redirect(&h, "/login/error?from=social").unwrap();
    let app =
        authn_testkit::http::with_request_context(authn_oidc_client::router().with_state(service));
    let res = TestRequest::get("/v1/oauth/google/callback?code=c&state=forged")
        .send(&app)
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers["location"],
        "https://auth.test.example/login/error?from=social&error=oauth_state_invalid"
    );
    assert_eq!(res.headers["cache-control"], "no-store");

    // A provider denial after a real start: still only the configured page,
    // not the start's `return_to`.
    let res = TestRequest::get("/v1/oauth/google/start?return_to=%2Fdashboard")
        .send(&app)
        .await;
    let started = Started::from_response(&res);
    let res = TestRequest::get(&format!(
        "/v1/oauth/google/callback?error=access_denied&state={}",
        started.param("state")
    ))
    .cookie("__Host-authn_oauth", &started.binding)
    .send(&app)
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers["location"],
        "https://auth.test.example/login/error?from=social&error=oauth_authorization_denied"
    );
}

/// K-36: the error page is validated at start-up with the redirect
/// validator: absolute targets must be allow-listed, protocol-relative,
/// backslash, userinfo and non-https tricks are refused (no open redirect).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_error_redirect_cannot_be_an_open_redirect(pool: PgPool) {
    let h = Harness::new(pool).await;
    // `https://app.example.com/after` is in protect.redirect_allow_list.
    assert!(service_with_error_redirect(&h, "https://app.example.com/after").is_ok());
    assert!(service_with_error_redirect(&h, "/oops").is_ok());
    for evil in [
        "https://evil.example/phish",
        "//evil.example/phish",
        "/\\evil.example",
        "https://app.example.com@evil.example/after",
        "http://app.example.com/after",
        "javascript:alert(1)",
        "https://app.example.com/after/../../evil",
    ] {
        let err = service_with_error_redirect(&h, evil).unwrap_err();
        assert!(
            !err.contains("evil"),
            "error must not echo the value: {err}"
        );
    }
}

/// Wave 2A audit (K-36): more open-redirect spellings. Whatever start-up
/// accepts, the failed-callback `Location` stays on this server's origin
/// or on the exact allow-listed URL, carries no raw control characters and
/// ends with only the stable `error=<code>` parameter added.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_02_error_redirect_variants_stay_on_allowed_origins(pool: PgPool) {
    let h = Harness::new(pool).await;
    let variants = [
        "/%2F%2Fevil.example",
        "/%5Cevil.example",
        "/\\/evil.example",
        "\\\\evil.example",
        "/\t/evil.example",
        "/ /evil.example",
        "/login\r\nSet-Cookie: x=1",
        "/%0d%0aSet-Cookie:x=1",
        "/..//evil.example",
        "/.//evil.example",
        "%2F%2Fevil.example",
        "https:evil.example",
        "https:/evil.example",
        "https://app.example.com.evil.example/after",
        "https://app.\u{0435}xample.com/after",
        "https://xn--pp-8ba.example.com/after",
        "https://APP.EXAMPLE.COM/after",
        "https://app.example.com/after#@evil.example",
        "https://app.example.com:443@evil.example/after",
        "https://app.example.com:8443/after",
        "https://app.example.com/after?next=https://evil.example",
    ];
    for target in variants {
        let Ok(service) = service_with_error_redirect(&h, target) else {
            continue; // refused at start-up
        };
        let app = authn_testkit::http::with_request_context(
            authn_oidc_client::router().with_state(service),
        );
        let res = TestRequest::get("/v1/oauth/google/callback?code=c&state=forged")
            .send(&app)
            .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{target:?}");
        let location = res.headers["location"].to_str().unwrap().to_owned();
        let url = url::Url::parse(&location).unwrap();
        let origin_ok = (url.scheme() == "https"
            && url.host_str() == Some("auth.test.example")
            && url.port().is_none())
            || location.starts_with("https://app.example.com/after?");
        assert!(origin_ok, "{target:?} -> {location}");
        assert!(
            url.username().is_empty() && url.password().is_none(),
            "{location}"
        );
        assert!(
            !location.bytes().any(|b| b.is_ascii_control()),
            "{location:?}"
        );
        assert!(
            location.ends_with("error=oauth_state_invalid"),
            "{target:?} -> {location}"
        );
    }
}

/// K-03 regression guard: the old risk "link flow survives a revoked
/// session for up to `state_ttl`" with a stale-but-not-revoked session is
/// still bounded by step-up at start (unchanged).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_link_start_still_requires_step_up(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("me@example.com", AccountStatus::Active, true).await;
    TestRequest::post("/v1/me/identities/link")
        .json(&json!({ "provider": "google" }))
        .send(&h.app_as(h.principal(user, Duration::from_secs(3600))))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
}
