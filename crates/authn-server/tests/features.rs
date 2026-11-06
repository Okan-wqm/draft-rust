#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ARC-11: the cargo features of the binary (`passkey` and `sms` on by
//! default, `redis` optional) are forwarded to the crates that own them,
//! and the SMS factor behaves as disabled while no provider is configured.

mod common;

use authn_core::config::notify::SmsProviderKind;
use common::{App, PASSWORD};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

/// `name = [..]` entries of the `[features]` table of the server manifest
/// (one feature per line, the manifest's own layout).
fn server_features() -> Vec<(String, Vec<String>)> {
    let manifest = include_str!("../Cargo.toml");
    let section = manifest
        .split_once("\n[features]\n")
        .expect("[features] table")
        .1
        .split("\n[")
        .next()
        .unwrap();
    section
        .lines()
        .filter_map(|line| {
            let (name, list) = line.split_once(" = ")?;
            let list = list.trim().strip_prefix('[')?.strip_suffix(']')?;
            Some((
                name.trim().to_owned(),
                list.split(',')
                    .map(|v| v.trim().trim_matches('"').to_owned())
                    .filter(|v| !v.is_empty())
                    .collect(),
            ))
        })
        .collect()
}

fn feature_list(features: &[(String, Vec<String>)], name: &str) -> Vec<String> {
    features
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("feature `{name}` missing"))
        .1
        .clone()
}

#[test]
fn arc_11_feature_flags_match_the_specification() {
    let features = server_features();
    let default = feature_list(&features, "default");
    assert!(default.contains(&"passkey".to_owned()), "{default:?}");
    assert!(default.contains(&"sms".to_owned()), "{default:?}");
    assert!(
        !default.contains(&"redis".to_owned()),
        "redis is optional: {default:?}"
    );
    for (feature, forwarded) in [
        ("passkey", "authn-webauthn/passkey"),
        ("passkey", "authn-session/passkey"),
        ("sms", "authn-mfa/sms"),
        ("sms", "authn-notify/sms"),
        ("redis", "authn-protect/redis"),
    ] {
        assert!(
            feature_list(&features, feature).contains(&forwarded.to_owned()),
            "`{feature}` must enable `{forwarded}`"
        );
    }
}

/// The passkey ceremony endpoints exist exactly when the `passkey`
/// feature is on (anonymous call: `401` from the authentication layer when
/// the route exists, `404` when it was compiled out).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_11_passkey_routes_follow_the_passkey_feature(pool: PgPool) {
    let app = App::new(pool).await;
    let r = app
        .send(
            authn_testkit::http::TestRequest::post("/v1/me/passkeys/registration/options")
                .header("origin", common::ORIGIN)
                .json(&json!({})),
        )
        .await;
    let expected = if cfg!(feature = "passkey") {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::NOT_FOUND
    };
    assert_eq!(r.status, expected, "{}", r.text());
}

/// K-80: the provider endpoints exist exactly when the `oidc-provider`
/// feature is compiled in **and** `oidc_provider.enabled` is set; the
/// feature is on by default, the switch off by default.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn oidp_13_provider_routes_follow_the_feature_and_the_switch(pool: PgPool) {
    let (_, default_features) = server_features()
        .into_iter()
        .find(|(name, _)| name == "default")
        .unwrap();
    assert!(
        default_features.contains(&"oidc-provider".to_owned()),
        "{default_features:?}"
    );
    let app = App::with(pool, common::enable_oidc_provider).await;
    let r = app
        .send(authn_testkit::http::TestRequest::get(
            "/.well-known/openid-configuration",
        ))
        .await;
    let expected = if cfg!(feature = "oidc-provider") {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    assert_eq!(r.status, expected, "{}", r.text());
}

/// Enrolls an SMS factor through HTTP with the notification module built
/// from the configuration (not the recording fake).
async fn begin_sms(pool: PgPool, provider: SmsProviderKind) -> (StatusCode, serde_json::Value) {
    let app = App::with_ports(
        pool,
        |config| {
            config.mfa.sms.allowed_country_codes = vec!["90".to_owned()];
            config.notify.sms.provider = provider;
        },
        |ports| ports.notifier = None,
    )
    .await;
    app.user("sms@example.com").await;
    let mut browser = app.browser();
    let body = browser.login(&app, "sms@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    let r = browser
        .send(
            &app,
            browser.post("/v1/me/mfa/sms", &json!({"phone_number": "+905551112233"})),
        )
        .await;
    let status = r.status;
    (status, r.json())
}

/// ARC-11 / MFA-06: without a provider (`notify.sms.provider = "none"`,
/// the default) the SMS factor is unavailable; with one it can be enrolled.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_11_sms_without_a_provider_behaves_disabled(pool: PgPool) {
    let (status, body) = begin_sms(pool, SmsProviderKind::None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "mfa_factor_not_available", "{body}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_11_sms_with_a_provider_is_offered(pool: PgPool) {
    let (status, body) = begin_sms(pool, SmsProviderKind::Log).await;
    if cfg!(feature = "sms") {
        assert!(status.is_success(), "{status}: {body}");
    } else {
        assert_eq!(body["error"]["code"], "mfa_factor_not_available", "{body}");
    }
}
