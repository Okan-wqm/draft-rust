#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Account matching, linking, unlinking (SOC-05, SOC-06), the
//! pre-hijacking rules of ADR 0002, the PWD-11 race, provider token storage
//! (SOC-08) and the data export (ACC-10).

mod common;

use std::sync::Arc;
use std::time::Duration;

use authn_account::SignupInput;
use authn_core::domain::{AccountStatus, Impersonation};
use authn_core::id::{IdentityId, UserId};
use authn_core::ports::Clock as _;
use authn_core::ports::{DataExporter as _, SecurityEventKind};
use authn_core::secret::{SecretString, SensitiveString};
use authn_oidc_client::{IdentityDataExporter, OidcClientService, PasswordOnlyInventory};
use authn_store::{NewPasswordHash, UserRepository};
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::TestRequest;
use authn_testkit::timing::compare_timings;
use common::*;
use http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;

/// Native Google login of `sub` asserting `email`.
async fn google_login(
    h: &Harness,
    sub: &str,
    email: &str,
    verified: bool,
) -> authn_testkit::http::TestResponse {
    let nonce = h.native_nonce("google").await;
    let mut claims = h.claims(&h.idp.issuer("/google"), GOOGLE_NATIVE, sub, &nonce, email);
    claims["email_verified"] = json!(verified);
    h.native("google", &sign_rs256(KEY_A, "key-a", &claims))
        .await
}

async fn github_like_native(
    h: &Harness,
    provider: &str,
    prefix: &str,
    aud: &str,
    sub: &str,
    email: &str,
) -> authn_testkit::http::TestResponse {
    let nonce = h.native_nonce(provider).await;
    let claims = h.claims(&h.idp.issuer(prefix), aud, sub, &nonce, email);
    h.native(provider, &sign_rs256(KEY_A, "key-a", &claims))
        .await
}

async fn set_password(h: &Harness, user: UserId) {
    let hash = SensitiveString::new("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo");
    let mut conn = h.pool.acquire().await.unwrap();
    UserRepository::set_password(
        &mut conn,
        user,
        &NewPasswordHash {
            password_hash: &hash,
            algorithm: "argon2id",
            pepper_version: Some(1),
        },
        false,
        h.ports.clock.now(),
    )
    .await
    .unwrap();
}

async fn has_password(h: &Harness, user: UserId) -> bool {
    UserRepository::find_password(&h.pool, user)
        .await
        .unwrap()
        .is_some()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_identity_is_matched_by_subject_not_by_email(pool: PgPool) {
    let h = Harness::new(pool).await;
    assert_eq!(
        google_login(&h, "sub-1", "first@example.com", true)
            .await
            .status,
        StatusCode::OK
    );
    let owner = h.identity_owner("google", "sub-1").await.unwrap();
    // Another account owns the address the provider now asserts.
    let other = h
        .user("second@example.com", AccountStatus::Active, true)
        .await;
    assert_eq!(
        google_login(&h, "sub-1", "second@example.com", true)
            .await
            .status,
        StatusCode::OK
    );
    let logins = h.ports.session_issuer.logins();
    assert_eq!(logins.last().unwrap().user_id, owner);
    assert_ne!(owner, other);
    // The account's own address is not changed by the provider.
    let record = UserRepository::find_by_id(&h.pool, owner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.email.as_deref(), Some("first@example.com"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_existing_account_is_never_merged_automatically_by_default(pool: PgPool) {
    let h = Harness::new(pool).await;
    let existing = h
        .user("owner@example.com", AccountStatus::Active, true)
        .await;
    set_password(&h, existing).await;
    google_login(&h, "google-x", "owner@example.com", true)
        .await
        .assert_error(StatusCode::CONFLICT, "oauth_link_required");
    assert_eq!(h.identity_count().await, 0);
    assert!(h.ports.session_issuer.logins().is_empty());
    assert!(has_password(&h, existing).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_auto_link_only_for_trusted_providers_and_verified_email(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.config.auto_link_verified_email = true;
        s.config.auto_link_trusted_providers = vec!["google".to_owned()];
    })
    .await;
    let existing = h
        .user("owner@example.com", AccountStatus::Active, true)
        .await;
    // Untrusted provider (acme): link required.
    github_like_native(
        &h,
        "acme",
        "/acme",
        ACME_NATIVE,
        "acme-1",
        "owner@example.com",
    )
    .await
    .assert_error(StatusCode::CONFLICT, "oauth_link_required");
    // Trusted provider but unverified e-mail: refused before any lookup.
    google_login(&h, "g-1", "owner@example.com", false)
        .await
        .assert_error(StatusCode::FORBIDDEN, "oauth_email_not_verified");
    // Trusted + verified: linked to the existing account.
    assert_eq!(
        google_login(&h, "g-1", "owner@example.com", true)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(h.identity_owner("google", "g-1").await, Some(existing));
    let linked = h.ports.audit.of_kind(SecurityEventKind::IdentityLinked);
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].metadata["linked_by"], "auto_link_verified_email");
    // Suspended accounts are never auto-linked.
    let suspended = h
        .user("sus@example.com", AccountStatus::Suspended, true)
        .await;
    google_login(&h, "g-2", "sus@example.com", true)
        .await
        .assert_error(StatusCode::CONFLICT, "oauth_link_required");
    assert!(h.identity_owner("google", "g-2").await.is_none());
    let _ = suspended;
}

fn signup_input(email: &str, password: &str) -> SignupInput {
    SignupInput {
        email: email.to_owned(),
        password: SecretString::from(password.to_owned()),
        display_name: None,
        locale: None,
        time_zone: None,
        captcha: None,
        accepted_terms: Vec::new(),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_pending_account_never_receives_an_identity_without_auto_link(pool: PgPool) {
    let h = Harness::new(pool).await;
    // The attacker registers the victim's address first (unverified).
    h.accounts
        .signup(
            &h.ctx(),
            signup_input("victim@example.com", "Attacker-Pass-123!"),
        )
        .await
        .unwrap();
    // Registration work runs in the background (ACC-02 timing).
    h.accounts.drain_background_jobs().await;
    let placeholder = UserRepository::find_by_email(
        &h.pool,
        &authn_core::domain::EmailAddress::parse("victim@example.com").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(placeholder.status, AccountStatus::PendingVerification);
    google_login(&h, "victim-google", "victim@example.com", true)
        .await
        .assert_error(StatusCode::CONFLICT, "oauth_link_required");
    assert_eq!(h.identity_count().await, 0, "no trojan identifier");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_pre_hijacked_pending_account_is_reclaimed_by_the_mailbox_owner(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.config.auto_link_verified_email = true;
        s.config.auto_link_trusted_providers = vec!["google".to_owned()];
    })
    .await;
    // Attacker-first pre-hijack: a registration with the attacker's
    // password and a legacy password on the unverified placeholder.
    h.accounts
        .signup(
            &h.ctx(),
            signup_input("victim@example.com", "Attacker-Pass-123!"),
        )
        .await
        .unwrap();
    // Registration work runs in the background (ACC-02 timing).
    h.accounts.drain_background_jobs().await;
    let placeholder = UserRepository::find_by_email(
        &h.pool,
        &authn_core::domain::EmailAddress::parse("victim@example.com").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    set_password(&h, placeholder.id).await;
    let registrations = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pending_registrations WHERE user_id = $1",
        )
        .bind(placeholder.id)
        .fetch_one(&h.pool)
        .await
        .unwrap()
    };
    assert_eq!(registrations().await, 1);

    // The mailbox owner signs in with the provider that verified the address.
    assert_eq!(
        google_login(&h, "victim-google", "victim@example.com", true)
            .await
            .status,
        StatusCode::OK
    );
    let record = UserRepository::find_by_id(&h.pool, placeholder.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, AccountStatus::Active);
    assert!(record.is_email_verified());
    // Nothing the attacker chose survives.
    assert!(
        !has_password(&h, placeholder.id).await,
        "unproven password removed"
    );
    assert_eq!(registrations().await, 0, "pending registrations discarded");
    assert!(h.ports.session_revoker.calls().iter().any(|c| matches!(
        c,
        RevocationCall::AllForUser(u, _, o) if *u == placeholder.id && o.also_trusted_devices
    )));
    assert_eq!(
        h.identity_owner("google", "victim-google").await,
        Some(placeholder.id)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_unverified_email_answer_does_not_reveal_accounts(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.native_per_ip = authn_core::ports::RateLimitPolicy::new(10_000, Duration::from_secs(600));
    })
    .await;
    h.user("exists@example.com", AccountStatus::Active, true)
        .await;
    let existing = google_login(&h, "s-1", "exists@example.com", false).await;
    let missing = google_login(&h, "s-2", "missing@example.com", false).await;
    assert_eq!(existing.status, missing.status);
    let a: Value = existing.json();
    let b: Value = missing.json();
    assert_eq!(a["error"]["code"], b["error"]["code"]);
    assert_eq!(a["error"]["message"], b["error"]["message"]);

    // Timing: the decision is taken before any account lookup.
    let nonce_and_token = |email: &'static str| {
        let h = &h;
        async move {
            let nonce = h
                .service
                .issue_native_nonce(&h.ctx(), "google")
                .await
                .unwrap()
                .nonce;
            let mut claims = h.claims(&h.idp.issuer("/google"), GOOGLE_NATIVE, "t", &nonce, email);
            claims["email_verified"] = json!(false);
            sign_rs256(KEY_A, "key-a", &claims)
        }
    };
    let mut tokens_a = Vec::new();
    let mut tokens_b = Vec::new();
    for _ in 0..30 {
        tokens_a.push(nonce_and_token("exists@example.com").await);
        tokens_b.push(nonce_and_token("missing@example.com").await);
    }
    let tokens_a = std::sync::Mutex::new(tokens_a);
    let tokens_b = std::sync::Mutex::new(tokens_b);
    let req = |id_token: String| authn_oidc_client::NativeLoginRequest {
        id_token,
        remember_me: false,
        shared_device: false,
        given_name: None,
        family_name: None,
    };
    let report = compare_timings(
        25,
        || async {
            let t = tokens_a.lock().unwrap().pop().unwrap();
            let _ = h.service.native_login(&h.ctx(), "google", &req(t)).await;
        },
        || async {
            let t = tokens_b.lock().unwrap().pop().unwrap();
            let _ = h.service.native_login(&h.ctx(), "google", &req(t)).await;
        },
    )
    .await;
    report.assert_indistinguishable(0.5);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_web_link_requires_step_up_and_links_on_callback(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("me@example.com", AccountStatus::Active, true).await;
    // Stale authentication: step-up required.
    let stale = h.principal(user, Duration::from_secs(3600));
    TestRequest::post("/v1/me/identities/link")
        .json(&json!({ "provider": "google" }))
        .send(&h.app_as(stale))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");

    let res = TestRequest::post("/v1/me/identities/link")
        .json(&json!({ "provider": "google", "return_to": "/settings/security" }))
        .send(&h.app_as(h.fresh(user)))
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
    // The provider account has another address: linking does not care.
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_WEB,
        "link-sub",
        &params["nonce"],
        "personal@gmail.example",
    );
    h.idp
        .mount_token_once("/google", json!({ "access_token": "provider-link-token", "id_token": sign_rs256(KEY_A, "key-a", &claims) }))
        .await;
    let callback = TestRequest::get(&format!(
        "/v1/oauth/google/callback?code=c&state={}",
        params["state"]
    ))
    .cookie("__Host-authn_oauth", &binding)
    .send(&h.app())
    .await;
    assert_eq!(
        callback.status,
        StatusCode::SEE_OTHER,
        "{}",
        callback.text()
    );
    assert_eq!(
        callback.headers["location"],
        "https://auth.test.example/settings/security"
    );
    assert_eq!(h.identity_owner("google", "link-sub").await, Some(user));
    assert!(
        h.ports.session_issuer.logins().is_empty(),
        "linking is not a login"
    );

    // Listing shows it without secrets.
    let list = TestRequest::get("/v1/me/identities")
        .send(&h.app_as(h.fresh(user)))
        .await;
    assert_eq!(list.status, StatusCode::OK);
    let body: Value = list.json();
    let item = &body["identities"][0];
    assert_eq!(item["provider"], "google");
    assert!(item.get("subject").is_none());
    assert!(
        !list.text().contains("provider-link-token"),
        "no token material"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_native_link_rules(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h
        .user("alice@example.com", AccountStatus::Active, true)
        .await;
    let bob = h.user("bob@example.com", AccountStatus::Active, true).await;
    async fn link(h: &Harness, user: UserId, sub: &str) -> authn_testkit::http::TestResponse {
        let nonce = h.native_nonce("google").await;
        let claims = h.claims(
            &h.idp.issuer("/google"),
            GOOGLE_NATIVE,
            sub,
            &nonce,
            "x@example.com",
        );
        TestRequest::post("/v1/me/identities/link/native")
            .json(&json!({ "provider": "google", "id_token": sign_rs256(KEY_A, "key-a", &claims) }))
            .send(&h.app_as(h.fresh(user)))
            .await
    }
    assert_eq!(link(&h, alice, "alice-g").await.status, StatusCode::CREATED);
    // Idempotent for the owner.
    assert_eq!(link(&h, alice, "alice-g").await.status, StatusCode::CREATED);
    // Owned by someone else.
    link(&h, bob, "alice-g")
        .await
        .assert_error(StatusCode::CONFLICT, "identity_already_linked");
    // One identity per provider and account.
    link(&h, alice, "alice-g2")
        .await
        .assert_error(StatusCode::CONFLICT, "identity_provider_already_linked");
    // Unverified / pending accounts cannot link (ADR 0002).
    let pending = h
        .user(
            "pending@example.com",
            AccountStatus::PendingVerification,
            false,
        )
        .await;
    link(&h, pending, "pending-g")
        .await
        .assert_error(StatusCode::FORBIDDEN, "identity_link_not_allowed");
    // Read-only impersonation cannot link.
    let mut imp = h.fresh(bob);
    imp.impersonation = Some(Impersonation {
        admin_user_id: UserId::generate(),
        read_only: true,
        expires_at: h.ports.clock.now() + time::Duration::minutes(10),
    });
    let nonce = h.native_nonce("google").await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_NATIVE,
        "bob-g",
        &nonce,
        "x@example.com",
    );
    TestRequest::post("/v1/me/identities/link/native")
        .json(&json!({ "provider": "google", "id_token": sign_rs256(KEY_A, "key-a", &claims) }))
        .send(&h.app_as(imp))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    assert_eq!(h.identity_count().await, 1);
}

async fn link_native(
    h: &Harness,
    user: UserId,
    provider: &str,
    prefix: &str,
    aud: &str,
    sub: &str,
) -> IdentityId {
    let nonce = h.native_nonce(provider).await;
    let mut claims = h.claims(&h.idp.issuer(prefix), aud, sub, &nonce, "x@example.com");
    if provider == "microsoft" {
        claims["iss"] = json!(format!("{}/ms/{MS_CONSUMERS}/v2.0", h.idp.uri()));
        claims["tid"] = json!(MS_CONSUMERS);
        claims["oid"] = json!("dddddddd-0000-0000-0000-000000000001");
    }
    let res = TestRequest::post("/v1/me/identities/link/native")
        .json(&json!({ "provider": provider, "id_token": sign_rs256(KEY_A, "key-a", &claims) }))
        .send(&h.app_as(h.fresh(user)))
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    res.json::<Value>()["id"].as_str().unwrap().parse().unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_unlink_never_removes_the_last_login_method(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("u@example.com", AccountStatus::Active, true).await;
    let google = link_native(&h, user, "google", "/google", GOOGLE_NATIVE, "g").await;
    let apple = link_native(&h, user, "apple", "/apple", APPLE_NATIVE, "a").await;
    let unlink = |id: IdentityId, auth_age: Duration| {
        let app = h.app_as(h.principal(user, auth_age));
        async move {
            TestRequest::delete(&format!("/v1/me/identities/{id}"))
                .send(&app)
                .await
        }
    };
    // Step-up required.
    unlink(google, Duration::from_secs(3600))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    // Two identities: one may go.
    assert_eq!(
        unlink(google, Duration::from_secs(1)).await.status,
        StatusCode::NO_CONTENT
    );
    // The last one only with another method.
    unlink(apple, Duration::from_secs(1))
        .await
        .assert_error(StatusCode::CONFLICT, "identity_last_login_method");
    set_password(&h, user).await;
    assert_eq!(
        unlink(apple, Duration::from_secs(1)).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(h.identity_count().await, 0);
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::IdentityUnlinked)
            .len(),
        2
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_foreign_and_unknown_identities_answer_not_found(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h
        .user("alice@example.com", AccountStatus::Active, true)
        .await;
    let bob = h.user("bob@example.com", AccountStatus::Active, true).await;
    set_password(&h, alice).await;
    let alices = link_native(&h, alice, "google", "/google", GOOGLE_NATIVE, "g").await;
    for id in [alices, IdentityId::generate()] {
        TestRequest::delete(&format!("/v1/me/identities/{id}"))
            .send(&h.app_as(h.fresh(bob)))
            .await
            .assert_error(StatusCode::NOT_FOUND, "not_found");
    }
    assert_eq!(h.identity_count().await, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_11_concurrent_unlinks_cannot_strand_the_account(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("u@example.com", AccountStatus::Active, true).await;
    let a = link_native(&h, user, "google", "/google", GOOGLE_NATIVE, "g").await;
    let b = link_native(&h, user, "apple", "/apple", APPLE_NATIVE, "a").await;
    let mut tasks = Vec::new();
    for id in [a, b] {
        let service = h.service.clone();
        let ctx = h.ctx();
        let principal = h.fresh(user);
        tasks.push(tokio::spawn(async move {
            service.unlink(&ctx, &principal, id).await
        }));
    }
    let mut ok = 0;
    let mut refused = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(()) => ok += 1,
            Err(e) => {
                assert!(
                    e.is(authn_oidc_client::codes::IDENTITY_LAST_LOGIN_METHOD),
                    "{e:?}"
                );
                refused += 1;
            }
        }
    }
    assert_eq!((ok, refused), (1, 1));
    assert_eq!(h.identity_count().await, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_11_unlink_and_password_removal_serialize_on_the_user_row(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("u@example.com", AccountStatus::Active, true).await;
    set_password(&h, user).await;
    let identity = link_native(&h, user, "google", "/google", GOOGLE_NATIVE, "g").await;

    // "Remove the password" as authn-password does it: lock the user row,
    // count other methods through the same connection, delete.
    let pool = h.pool.clone();
    let remover = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        UserRepository::lock_for_update(&mut tx, user)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let identities = OidcClientService::linked_identity_count_in(&mut tx, user)
            .await
            .unwrap();
        if identities > 0 {
            UserRepository::delete_password(&mut tx, user)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            true
        } else {
            tx.rollback().await.unwrap();
            false
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let unlinked = h.service.unlink(&h.ctx(), &h.fresh(user), identity).await;
    let removed = remover.await.unwrap();
    assert!(removed, "the password removal held the lock first");
    assert!(
        unlinked
            .unwrap_err()
            .is(authn_oidc_client::codes::IDENTITY_LAST_LOGIN_METHOD),
        "the unlink saw the committed password removal"
    );
    assert_eq!(h.identity_count().await, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_08_provider_tokens_are_not_stored_by_default(pool: PgPool) {
    let h = Harness::new(pool).await;
    let started = h.start("google", None).await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_WEB,
        "s",
        "AUTO",
        "s@example.com",
    );
    h.token_for("/google", &started, &claims).await;
    assert_eq!(h.callback("google", &started).await.status, StatusCode::OK);
    let (access, refresh): (Option<Vec<u8>>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT access_token_ciphertext, refresh_token_ciphertext FROM identities")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(access.is_none() && refresh.is_none());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_08_stored_provider_tokens_are_envelope_encrypted_with_row_aad(pool: PgPool) {
    let h = Harness::with(pool, |s| s.config.store_provider_tokens = true).await;
    for (sub, email) in [("s1", "one@example.com"), ("s2", "two@example.com")] {
        let started = h.start("google", None).await;
        let claims = h.claims(&h.idp.issuer("/google"), GOOGLE_WEB, sub, "AUTO", email);
        h.token_for("/google", &started, &claims).await;
        assert_eq!(h.callback("google", &started).await.status, StatusCode::OK);
    }
    let rows: Vec<(IdentityId, UserId, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, user_id, access_token_ciphertext, refresh_token_ciphertext FROM identities \
         ORDER BY created_at, id",
    )
    .fetch_all(&h.pool)
    .await
    .unwrap();
    for (_, _, access, refresh) in &rows {
        for ct in [access, refresh] {
            assert!(!ct.windows(8).any(|w| w == b"provider"), "plaintext leaked");
        }
    }
    let (id1, user1, access1, _) = rows[0].clone();
    let (id2, user2, _, _) = rows[1].clone();
    let tokens = h
        .service
        .stored_provider_tokens(user1, id1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tokens.access_token.expose(), "provider-access-token");
    assert_eq!(
        tokens.refresh_token.unwrap().expose(),
        "provider-refresh-token"
    );
    assert!(tokens.expires_at.is_some());
    // Copy-paste attack: identity 1's ciphertext in identity 2's row.
    sqlx::query("UPDATE identities SET access_token_ciphertext = $1 WHERE id = $2")
        .bind(&access1)
        .bind(id2)
        .execute(&h.pool)
        .await
        .unwrap();
    assert!(h.service.stored_provider_tokens(user2, id2).await.is_err());
    // Another user cannot read them.
    assert!(h.service.stored_provider_tokens(user2, id1).await.is_err());
    // The export never contains token material.
    let mut conn = h.pool.acquire().await.unwrap();
    let export = IdentityDataExporter.export(&mut conn, user1).await.unwrap();
    assert_eq!(export["identities"][0]["provider_tokens_stored"], true);
    assert!(!export.to_string().contains("provider-access-token"));
    assert!(
        export["identities"][0]
            .get("access_token_ciphertext")
            .is_none()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_08_turning_storage_off_clears_tokens_on_next_login(pool: PgPool) {
    let on = Harness::with(pool.clone(), |s| s.config.store_provider_tokens = true).await;
    let started = on.start("google", None).await;
    let claims = on.claims(
        &on.idp.issuer("/google"),
        GOOGLE_WEB,
        "s",
        "AUTO",
        "s@example.com",
    );
    on.token_for("/google", &started, &claims).await;
    assert_eq!(on.callback("google", &started).await.status, StatusCode::OK);
    let off = Harness::new(pool).await;
    let started = off.start("google", None).await;
    let claims = off.claims(
        &off.idp.issuer("/google"),
        GOOGLE_WEB,
        "s",
        "AUTO",
        "s@example.com",
    );
    off.token_for("/google", &started, &claims).await;
    assert_eq!(
        off.callback("google", &started).await.status,
        StatusCode::OK
    );
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT access_token_ciphertext FROM identities")
            .fetch_one(&off.pool)
            .await
            .unwrap();
    assert!(stored.is_none());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_custom_inventory_counts_other_methods(pool: PgPool) {
    struct PasskeyUser;
    #[async_trait::async_trait]
    impl authn_oidc_client::LoginMethodInventory for PasskeyUser {
        async fn other_login_methods(
            &self,
            _conn: &mut sqlx::PgConnection,
            _user: UserId,
        ) -> Result<Vec<authn_core::domain::LoginMethod>, authn_core::error::AuthError> {
            Ok(vec![authn_core::domain::LoginMethod::Passkey])
        }
    }
    let h = Harness::with_options(
        pool,
        |_| {},
        Options {
            inventory: Arc::new(PasskeyUser),
        },
    )
    .await;
    let _ = PasswordOnlyInventory;
    let user = h.user("u@example.com", AccountStatus::Active, true).await;
    let id = link_native(&h, user, "google", "/google", GOOGLE_NATIVE, "g").await;
    h.service
        .unlink(&h.ctx(), &h.fresh(user), id)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_identity_routes_require_a_user_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    for req in [
        TestRequest::get("/v1/me/identities"),
        TestRequest::post("/v1/me/identities/link").json(&json!({ "provider": "google" })),
        TestRequest::delete(&format!("/v1/me/identities/{}", IdentityId::generate())),
    ] {
        req.send(&h.app())
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    // API-key principals (no session) are refused.
    let user = h.user("u@example.com", AccountStatus::Active, true).await;
    let mut api_key = h.fresh(user);
    api_key.credential = authn_core::domain::PrincipalCredential::ApiKey {
        api_key_id: authn_core::id::ApiKeyId::generate(),
    };
    TestRequest::get("/v1/me/identities")
        .send(&h.app_as(api_key))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
}

// --- Independent security review: regression tests -------------------------

/// Review finding 3: identities were matched by `(provider, subject)` only.
/// A generic provider's slug is configuration: when `issuer_url` of a slug
/// changes (IdP migration, typo fix, takeover of the old IdP), subjects of
/// the new issuer — a different namespace — landed on the accounts of the
/// old issuer's users. The stored issuer must match the token's.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_generic_identity_is_bound_to_its_issuer(pool: PgPool) {
    let h = Harness::new(pool).await;
    let res = github_like_native(
        &h,
        "acme",
        "/acme",
        ACME_NATIVE,
        "shared-sub",
        "a@acme.example",
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let owner = h.identity_owner("oidc:acme", "shared-sub").await.unwrap();
    // The identity was created under another issuer of the same slug.
    sqlx::query("UPDATE identities SET issuer = 'https://previous-idp.example' WHERE user_id = $1")
        .bind(owner)
        .execute(&h.pool)
        .await
        .unwrap();
    let before = h.ports.session_issuer.logins().len();
    github_like_native(
        &h,
        "acme",
        "/acme",
        ACME_NATIVE,
        "shared-sub",
        "b@acme.example",
    )
    .await
    .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
    assert_eq!(h.ports.session_issuer.logins().len(), before);
    // Re-linking the foreign-issuer identity to the owner is refused as well.
    let nonce = h.native_nonce("acme").await;
    let claims = h.claims(
        &h.idp.issuer("/acme"),
        ACME_NATIVE,
        "shared-sub",
        &nonce,
        "a@acme.example",
    );
    TestRequest::post("/v1/me/identities/link/native")
        .json(&json!({ "provider": "acme", "id_token": sign_rs256(KEY_A, "key-a", &claims) }))
        .send(&h.app_as(h.fresh(owner)))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "oauth_token_invalid");
}

/// Coverage added in review: a reserved address (ACC-07 revert period) gets
/// no new account through social login; the same answer as an existing
/// account (`oauth_link_required`), and nothing is created.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_05_reserved_address_gets_no_new_account(pool: PgPool) {
    struct Reserved;
    #[async_trait::async_trait]
    impl authn_oidc_client::AddressReservations for Reserved {
        async fn is_reserved(
            &self,
            _conn: &mut sqlx::PgConnection,
            email: &authn_core::domain::EmailAddress,
        ) -> Result<bool, authn_core::error::AuthError> {
            Ok(email.normalized() == "reserved@example.com")
        }
    }
    let h = Harness::new(pool).await;
    let mut deps = h.service_deps();
    deps.reservations = Arc::new(Reserved);
    let registry = authn_oidc_client::ProviderRegistry::from_settings(&h.settings).unwrap();
    let mut registry = registry;
    let _ = registry.override_endpoints(
        "google",
        h.idp.endpoints("/google"),
        Some(authn_oidc_client::IssuerRule::Exact(vec![
            h.idp.issuer("/google"),
        ])),
    );
    let service = OidcClientService::with_registry(deps, h.settings.clone(), registry);
    let login = |sub: &'static str, email: &'static str| {
        let service = service.clone();
        let h = &h;
        async move {
            let nonce = h.native_nonce("google").await;
            let claims = h.claims(&h.idp.issuer("/google"), GOOGLE_NATIVE, sub, &nonce, email);
            service
                .native_login(
                    &h.ctx(),
                    "google",
                    &serde_json::from_value(json!({
                        "id_token": sign_rs256(KEY_A, "key-a", &claims)
                    }))
                    .unwrap(),
                )
                .await
        }
    };
    let err = login("r-1", "Reserved@example.com").await.unwrap_err();
    assert!(
        err.is(authn_oidc_client::codes::OAUTH_LINK_REQUIRED),
        "{err:?}"
    );
    assert_eq!(h.identity_count().await, 0);
    assert!(
        UserRepository::find_by_email(
            &h.pool,
            &authn_core::domain::EmailAddress::parse("reserved@example.com").unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
    // Other addresses are unaffected.
    login("r-2", "free@example.com").await.unwrap();
}
