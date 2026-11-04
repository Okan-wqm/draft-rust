#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Sign in with Apple tokens: the envelope-encrypted private key (K-34),
//! the native authorization-code exchange, the sealed refresh token and
//! its revocation on account deletion / unlink (K-35; SOC-07, SOC-08,
//! ACC-09).

mod common;

use std::sync::Arc;
use std::time::Duration;

use authn_core::id::UserId;
use authn_core::ports::{Actor, SecurityEventKind};
use authn_core::secret::SecretString;
use authn_crypto::envelope::EnvelopeContext;
use authn_oidc_client::OidcClientService;
use authn_oidc_client::apple::seal_private_key;
use authn_testkit::http::TestRequest;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const REFRESH: &str = "provider-refresh-token";

/// Web Sign in with Apple of `sub`; returns the account.
async fn apple_web_login(h: &Harness, sub: &str) -> UserId {
    let started = h.start("apple", None).await;
    let mut claims = h.claims(
        &h.idp.issuer("/apple"),
        APPLE_WEB,
        sub,
        "AUTO",
        &format!("{sub}@privaterelay.appleid.com"),
    );
    claims["email_verified"] = json!("true");
    h.token_for("/apple", &started, &claims).await;
    let body = format!("state={}&code=apple-code", started.param("state"));
    let res = TestRequest::post("/v1/oauth/apple/callback")
        .header("content-type", "application/x-www-form-urlencoded")
        .cookie("__Host-authn_oauth", &started.binding)
        .body(body)
        .send(&h.app())
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    h.identity_owner("apple", sub).await.unwrap()
}

#[derive(sqlx::FromRow)]
struct StoredTokens {
    id: sqlx::types::Uuid,
    access_token_ciphertext: Option<Vec<u8>>,
    refresh_token_ciphertext: Option<Vec<u8>>,
    token_client_id: Option<String>,
}

async fn stored(h: &Harness, provider: &str) -> StoredTokens {
    sqlx::query_as(
        "SELECT id, access_token_ciphertext, refresh_token_ciphertext, token_client_id \
         FROM identities WHERE provider = $1",
    )
    .bind(provider)
    .fetch_one(&h.pool)
    .await
    .unwrap()
}

async fn open_refresh(h: &Harness, row: &StoredTokens) -> String {
    let context = EnvelopeContext::new("identities", "refresh_token_ciphertext", row.id).unwrap();
    let plain = h
        .crypto
        .envelopes
        .open(row.refresh_token_ciphertext.as_deref().unwrap(), &context)
        .await
        .unwrap();
    String::from_utf8(plain.expose().to_vec()).unwrap()
}

async fn queued(h: &Harness) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM oauth_token_revocations")
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

fn jwt_claims(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

async fn mount_revoke(h: &Harness, status: u16, body: Value) {
    Mock::given(method("POST"))
        .and(path("/apple/revoke"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&h.idp.server)
        .await;
}

/// Schedules and carries out the deletion of `user` (ACC-09).
async fn delete_account(h: &Harness, user: UserId) {
    h.accounts
        .request_deletion(&h.fresh(user), &h.ctx())
        .await
        .unwrap();
    h.ports.clock.advance(Duration::from_secs(30 * 86_400 + 1));
    assert_eq!(h.accounts.purge_due_deletions(10).await.unwrap().purged, 1);
}

// --- storage ------------------------------------------------------------------

/// K-35 / SOC-08: with `store_provider_tokens` off, only the Apple refresh
/// token is kept — sealed with the row as AAD, with its client id — and
/// only because it is needed for revocation; Google keeps nothing.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_08_apple_refresh_token_is_kept_sealed_for_revocation(pool: PgPool) {
    let h = Harness::new(pool).await;
    apple_web_login(&h, "apple-keep").await;
    let row = stored(&h, "apple").await;
    assert!(
        row.access_token_ciphertext.is_none(),
        "access token not stored"
    );
    let sealed = row.refresh_token_ciphertext.as_deref().unwrap();
    assert!(
        !sealed
            .windows(REFRESH.len())
            .any(|w| w == REFRESH.as_bytes()),
        "not stored in clear"
    );
    assert_eq!(open_refresh(&h, &row).await, REFRESH);
    assert_eq!(row.token_client_id.as_deref(), Some(APPLE_WEB));
    // Bound to its row: another row id cannot open it.
    let other = EnvelopeContext::new(
        "identities",
        "refresh_token_ciphertext",
        sqlx::types::Uuid::now_v7(),
    )
    .unwrap();
    assert!(h.crypto.envelopes.open(sealed, &other).await.is_err());
}

/// K-35: with `apple.revoke_tokens_on_deletion = false` nothing is kept.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_08_apple_token_is_not_kept_when_revocation_is_off(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.config.apple.as_mut().unwrap().revoke_tokens_on_deletion = false;
    })
    .await;
    apple_web_login(&h, "apple-off").await;
    let row = stored(&h, "apple").await;
    assert!(row.access_token_ciphertext.is_none());
    assert!(row.refresh_token_ciphertext.is_none());
}

// --- native authorization code ---------------------------------------------

async fn native_apple(h: &Harness, sub: &str, code: Option<&str>) -> UserId {
    let nonce = h.native_nonce("apple").await;
    let mut claims = h.claims(
        &h.idp.issuer("/apple"),
        APPLE_NATIVE,
        sub,
        &nonce,
        &format!("{sub}@privaterelay.appleid.com"),
    );
    claims["email_verified"] = json!(true);
    let mut body = json!({ "id_token": sign_rs256(KEY_A, "key-a", &claims) });
    if let Some(code) = code {
        body["authorization_code"] = json!(code);
    }
    let res = TestRequest::post("/v1/oauth/apple/native")
        .json(&body)
        .send(&h.app())
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    h.identity_owner("apple", sub).await.unwrap()
}

/// The token-endpoint answer of a native code exchange for `sub`.
async fn mount_native_exchange(h: &Harness, sub: &str) {
    let mut claims = h.claims(
        &h.idp.issuer("/apple"),
        APPLE_NATIVE,
        sub,
        "unused",
        "x@privaterelay.appleid.com",
    );
    claims.as_object_mut().unwrap().remove("nonce");
    h.idp
        .mount_token_once(
            "/apple",
            json!({
                "access_token": "native-access",
                "refresh_token": "native-refresh",
                "expires_in": 3600,
                "token_type": "Bearer",
                "id_token": sign_rs256(KEY_A, "key-a", &claims),
            }),
        )
        .await;
}

/// K-35 (SOC-04, SOC-07): a native Apple authorization code is exchanged
/// as the app's bundle id (client secret `sub` = bundle id, no PKCE / no
/// redirect_uri) and its refresh token is kept sealed with that client id.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_07_native_apple_code_is_exchanged_as_the_bundle_id(pool: PgPool) {
    let h = Harness::new(pool).await;
    mount_native_exchange(&h, "apple-native").await;
    native_apple(&h, "apple-native", Some("native-code")).await;
    let requests = h.idp.requests_to("/apple/token").await;
    assert_eq!(requests.len(), 1);
    let form = form_of(&requests[0]);
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "native-code");
    assert_eq!(form["client_id"], APPLE_NATIVE);
    assert!(!form.contains_key("redirect_uri"));
    assert!(!form.contains_key("code_verifier"));
    let secret = jwt_claims(&form["client_secret"]);
    assert_eq!(secret["sub"], APPLE_NATIVE);
    assert_eq!(secret["iss"], "TEAMID1234");

    let row = stored(&h, "apple").await;
    assert_eq!(row.token_client_id.as_deref(), Some(APPLE_NATIVE));
    assert_eq!(open_refresh(&h, &row).await, "native-refresh");
    assert!(row.access_token_ciphertext.is_none());
}

/// K-35: a code whose exchanged ID token names another Apple account, a
/// refused code and a code sent for another provider never store a token
/// — and never fail the login (the ID token authenticated the user).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_07_foreign_or_refused_apple_codes_store_nothing(pool: PgPool) {
    let h = Harness::new(pool).await;
    mount_native_exchange(&h, "someone-else").await;
    native_apple(&h, "apple-victim", Some("stolen-code")).await;
    assert!(stored(&h, "apple").await.refresh_token_ciphertext.is_none());

    h.idp.mount_token_error("/apple", 400).await;
    native_apple(&h, "apple-victim", Some("bad-code")).await;
    assert!(stored(&h, "apple").await.refresh_token_ciphertext.is_none());

    // Oversized / non-ASCII codes are not even sent.
    let before = h.idp.requests_to("/apple/token").await.len();
    native_apple(&h, "apple-victim", Some(&"x".repeat(5000))).await;
    assert_eq!(h.idp.requests_to("/apple/token").await.len(), before);

    // Google ignores the field.
    let nonce = h.native_nonce("google").await;
    let claims = h.claims(
        &h.idp.issuer("/google"),
        GOOGLE_NATIVE,
        "g-code",
        &nonce,
        "g@example.com",
    );
    TestRequest::post("/v1/oauth/google/native")
        .json(
            &json!({ "id_token": sign_rs256(KEY_A, "key-a", &claims), "authorization_code": "c" }),
        )
        .send(&h.app())
        .await
        .assert_status(StatusCode::OK);
    assert!(h.idp.requests_to("/google/token").await.is_empty());
}

// --- revocation ---------------------------------------------------------------

/// K-35 (ACC-09): deleting the account queues the Apple token in the
/// erasure transaction (re-sealed, no user id); the job revokes it at
/// Apple's revocation endpoint with an ES256 client secret, audits it and
/// empties the queue.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_account_deletion_revokes_the_apple_token(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.accounts
        .register_erasure_hook(Arc::new(h.service.erasure_hook()));
    let user = apple_web_login(&h, "apple-leaving").await;
    delete_account(&h, user).await;
    assert_eq!(h.identity_count().await, 0, "identities cascaded away");
    assert_eq!(queued(&h).await, 1);
    let (provider, client_id, sealed): (String, String, Vec<u8>) =
        sqlx::query_as("SELECT provider, client_id, token_ciphertext FROM oauth_token_revocations")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        (provider.as_str(), client_id.as_str()),
        ("apple", APPLE_WEB)
    );
    assert!(
        !sealed
            .windows(REFRESH.len())
            .any(|w| w == REFRESH.as_bytes())
    );

    mount_revoke(&h, 200, json!({})).await;
    let report = h.service.process_token_revocations(10).await.unwrap();
    assert_eq!(report.revoked, 1);
    let requests = h.idp.requests_to("/apple/revoke").await;
    assert_eq!(requests.len(), 1);
    let form = form_of(&requests[0]);
    assert_eq!(form["token"], REFRESH);
    assert_eq!(form["token_type_hint"], "refresh_token");
    assert_eq!(form["client_id"], APPLE_WEB);
    assert_eq!(jwt_claims(&form["client_secret"])["sub"], APPLE_WEB);
    assert_eq!(queued(&h).await, 0);
    let audited = h
        .ports
        .audit
        .of_kind(SecurityEventKind::IdentityUnlinked)
        .into_iter()
        .find(|e| e.metadata.get("step").is_some())
        .unwrap();
    assert_eq!(audited.actor, Actor::System);
    assert_eq!(audited.metadata["outcome"], "revoked");
    assert!(audited.reason.is_none());
    // Nothing left to do.
    assert_eq!(
        h.service.process_token_revocations(10).await.unwrap(),
        Default::default()
    );
}

/// K-35: Apple being down never blocks the deletion; the revocation is
/// retried with growing waits and, after the last attempt, dropped with a
/// failed audit event. `invalid_grant` (already revoked) counts as done.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_revocation_failures_are_retried_then_audited_never_blocking(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.accounts
        .register_erasure_hook(Arc::new(h.service.erasure_hook()));
    mount_revoke(&h, 503, json!({ "error": "temporarily_unavailable" })).await;
    let user = apple_web_login(&h, "apple-outage").await;
    delete_account(&h, user).await;
    assert!(
        authn_store::UserRepository::find_by_id(&h.pool, user)
            .await
            .unwrap()
            .is_none(),
        "deleted although Apple is down"
    );
    let first = h.service.process_token_revocations(10).await.unwrap();
    assert_eq!(first.retried, 1);
    // Not due again right away.
    assert_eq!(
        h.service.process_token_revocations(10).await.unwrap(),
        Default::default()
    );
    let max = usize::try_from(authn_oidc_client::service::MAX_REVOCATION_ATTEMPTS).unwrap();
    let mut abandoned = 0;
    for _ in 1..max {
        h.ports.clock.advance(Duration::from_secs(7 * 3600));
        abandoned += h
            .service
            .process_token_revocations(10)
            .await
            .unwrap()
            .abandoned;
    }
    assert_eq!(abandoned, 1);
    assert_eq!(h.idp.requests_to("/apple/revoke").await.len(), max);
    assert_eq!(queued(&h).await, 0, "given up: no token kept");
    let failed = h
        .ports
        .audit
        .of_kind(SecurityEventKind::IdentityUnlinked)
        .into_iter()
        .find(|e| e.reason.as_deref() == Some("provider_token_revocation_failed"))
        .unwrap();
    assert_eq!(failed.actor, Actor::System);

    // invalid_grant: nothing left to revoke — done, not retried.
    h.idp.server.reset().await;
    mount_revoke(&h, 400, json!({ "error": "invalid_grant" })).await;
    for prefix in ["/google", "/apple", "/ms", "/acme"] {
        h.idp.mount_jwks(prefix, &[(KEY_A, "key-a")]).await;
    }
    let user = apple_web_login(&h, "apple-gone").await;
    delete_account(&h, user).await;
    let report = h.service.process_token_revocations(10).await.unwrap();
    assert_eq!(report.revoked, 1);
    assert_eq!(queued(&h).await, 0);
}

/// K-35: unlinking Apple queues the revocation of its token in the unlink
/// transaction.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_unlinking_apple_queues_the_token_revocation(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = apple_web_login(&h, "apple-unlink").await;
    h.user_password(user).await;
    let row = stored(&h, "apple").await;
    TestRequest::delete(&format!("/v1/me/identities/{}", row.id))
        .send(&h.app_as(h.fresh(user)))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(queued(&h).await, 1);
    mount_revoke(&h, 200, json!({})).await;
    assert_eq!(
        h.service
            .process_token_revocations(10)
            .await
            .unwrap()
            .revoked,
        1
    );
}

// --- K-34: envelope-encrypted private key -------------------------------------

/// K-34 (SOC-07): `apple.private_key_ciphertext` is decrypted once at
/// start-up by `OidcClientService::build` with the `[crypto]` KEK; the
/// plain constructor refuses an undecrypted key, and a ciphertext of
/// another KEK fails start-up without echoing the value.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_07_service_build_decrypts_an_envelope_encrypted_apple_key(pool: PgPool) {
    let h = Harness::new(pool).await;
    let sealed = seal_private_key(&h.crypto.envelopes, &SecretString::from(EC_KEY.to_owned()))
        .await
        .unwrap();
    let mut settings = h.settings.clone();
    {
        let apple = settings.config.apple.as_mut().unwrap();
        apple.private_key_pem = None;
        apple.private_key_ciphertext = Some(sealed.clone());
    }
    assert!(OidcClientService::new(h.service_deps(), settings.clone()).is_err());
    let service = OidcClientService::build(h.service_deps(), settings.clone())
        .await
        .unwrap();
    assert!(service.providers().iter().any(|p| p.id == "apple"));

    // Sealed under another KEK (another deployment): refused.
    let mut other_config = authn_testkit::config::TestConfigBuilder::new().build();
    other_config.crypto.current_kek_id = "other-kek".to_owned();
    other_config.crypto.keks = vec![authn_core::config::crypto::KekConfig {
        id: "other-kek".to_owned(),
        key: SecretString::from(base64::engine::general_purpose::STANDARD.encode([9_u8; 32])),
    }];
    let foreign = authn_crypto::CryptoServices::from_config(&other_config.crypto)
        .await
        .unwrap()
        .envelopes;
    let sealed = seal_private_key(&foreign, &SecretString::from(EC_KEY.to_owned()))
        .await
        .unwrap();
    let mut bad = settings.clone();
    bad.config.apple.as_mut().unwrap().private_key_ciphertext = Some(sealed.clone());
    let err = OidcClientService::build(h.service_deps(), bad)
        .await
        .unwrap_err();
    use authn_core::secret::ExposeSecret as _;
    assert!(!format!("{err:?}").contains(sealed.expose_secret()));
}
