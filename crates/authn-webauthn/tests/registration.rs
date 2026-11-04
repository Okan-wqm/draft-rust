#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Registration ceremonies: PKY-01, PKY-02, PKY-03, PKY-08.

mod common;

use std::time::Duration;

use authn_core::error::codes;
use authn_core::ports::{EventOutcome, NotificationKind, SecurityEventKind};
use authn_webauthn::service::RegistrationIntent;
use authn_webauthn::{PasskeyPolicy, PasskeyUsage, RegistrationOptionsRequest};
use common::{Harness, ORIGIN, create};
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::AuthenticatorBackend;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::softtoken::{AAGUID as SOFTTOKEN_AAGUID, SoftToken};
use webauthn_rs::prelude::AttestationCaListBuilder;
use webauthn_rs_proto::{CreationChallengeResponse, UserVerificationPolicy};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_registration_round_trip_stores_a_verified_passkey(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let registered = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let summary = &registered.summary;
    assert_eq!(summary.name, "Passkey");
    assert_eq!(summary.usage, PasskeyUsage::Both);
    assert!(summary.user_verified);
    assert!(summary.aaguid.is_none(), "attestation none stores no model");
    assert!(summary.clone_suspected_at.is_none());

    let list = h.service.list_passkeys(&h.fresh(alice)).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, summary.id);

    // Audit + notification (PKY-04: notify on add).
    let events = h.ports.audit.of_kind(SecurityEventKind::PasskeyRegistered);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, EventOutcome::Success);
    assert_eq!(events[0].subject_user, Some(alice.user));
    let sent = h.ports.notifier.with_template("mfa_factor_added");
    assert_eq!(sent.len(), 1);
    assert!(matches!(
        sent[0].kind,
        NotificationKind::MfaFactorAdded {
            factor: authn_core::domain::FactorKind::Webauthn,
            ..
        }
    ));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_registration_ceremony_is_single_use(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);
    let mut authenticator = SoftPasskey::new(true);
    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let credential = create(&mut authenticator, &start.options, ORIGIN);
    h.finish_registration(&principal, &start, &credential)
        .await
        .unwrap();
    let replay = h
        .finish_registration(&principal, &start, &credential)
        .await
        .unwrap_err();
    assert_eq!(replay.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
    assert_eq!(h.service.list_passkeys(&principal).await.unwrap().len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_failed_verification_burns_the_ceremony(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);
    let mut authenticator = SoftPasskey::new(true);
    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let good = create(&mut authenticator, &start.options, ORIGIN);
    let mut tampered = good.clone();
    tampered.response.client_data_json = b"{\"type\":\"webauthn.create\"}".to_vec();
    let err = h
        .finish_registration(&principal, &start, &tampered)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_REGISTRATION_FAILED);
    // The genuine response cannot be retried against the burnt challenge.
    let err = h
        .finish_registration(&principal, &start, &good)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_expired_registration_ceremony_is_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);
    let mut authenticator = SoftPasskey::new(true);
    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    assert_eq!(start.expires_at, h.now() + Duration::from_secs(300));
    let credential = create(&mut authenticator, &start.options, ORIGIN);
    h.advance(Duration::from_secs(301));
    let principal = h.fresh(alice);
    let err = h
        .finish_registration(&principal, &start, &credential)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_registration_ceremony_is_bound_to_user_and_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mallory = h.account("mallory@example.com").await;
    let alice_other_session = common::Account {
        user: alice.user,
        session: h.session(alice.user).await,
    };
    let mut authenticator = SoftPasskey::new(true);
    let start = h
        .start_registration(&h.fresh(alice), RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let credential = create(&mut authenticator, &start.options, ORIGIN);

    // Swapping the ceremony into another account or session fails...
    for wrong in [mallory, alice_other_session] {
        let err = h
            .finish_registration(&h.fresh(wrong), &start, &credential)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
    }
    assert!(
        h.service
            .list_passkeys(&h.fresh(mallory))
            .await
            .unwrap()
            .is_empty()
    );
    // ...without consuming it: the owner can still finish.
    h.finish_registration(&h.fresh(alice), &start, &credential)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_concurrent_finishes_register_exactly_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);
    let mut authenticator = SoftPasskey::new(true);
    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let credential = create(&mut authenticator, &start.options, ORIGIN);
    let attempts = (0..8)
        .map(|_| {
            let service = h.service.clone();
            let ctx = h.ctx();
            let principal = principal.clone();
            let request = authn_webauthn::RegistrationVerifyRequest {
                ceremony_id: start.ceremony_id,
                credential: serde_json::to_value(&credential).unwrap(),
                name: None,
            };
            async move { service.finish_registration(&ctx, &principal, request).await }
        })
        .collect();
    let results = common::spawn_all(attempts).await;
    let ok = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok, 1, "{results:?}");
    for err in results.iter().filter_map(|r| r.as_ref().err()) {
        assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
    }
    assert_eq!(h.service.list_passkeys(&principal).await.unwrap().len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_wrong_origin_is_rejected_and_audited(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);

    // A sibling subdomain passes the browser's RP-id check but is not an
    // allowed origin.
    let mut authenticator = SoftPasskey::new(true);
    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let credential = create(
        &mut authenticator,
        &start.options,
        "https://evil.auth.test.example",
    );
    let err = h
        .finish_registration(&principal, &start, &credential)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_REGISTRATION_FAILED);

    // A phishing site relaying the options (a client that skips the RP-id
    // check) is rejected by the server-side origin check.
    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let ccr: CreationChallengeResponse = serde_json::from_value(start.options.clone()).unwrap();
    let credential = AuthenticatorBackend::perform_register(
        &mut authenticator,
        Url::parse("https://auth-test-example.phish").unwrap(),
        ccr.public_key,
        60_000,
    )
    .unwrap();
    let err = h
        .finish_registration(&principal, &start, &credential)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_REGISTRATION_FAILED);

    assert!(
        h.service
            .list_passkeys(&principal)
            .await
            .unwrap()
            .is_empty()
    );
    let events = h.ports.audit.of_kind(SecurityEventKind::PasskeyRegistered);
    assert_eq!(events.len(), 2);
    for event in events {
        assert_eq!(event.outcome, EventOutcome::Failure);
        assert_eq!(event.reason.as_deref(), Some("invalid_origin"));
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_06_android_app_origin_is_accepted_when_configured(pool: PgPool) {
    const APK: &str = "android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
    const OTHER_APK: &str = "android:apk-key-hash:AAAAQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
    let h = Harness::with(pool, |s| s.webauthn.allowed_origins.push(APK.to_owned())).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);
    let mut authenticator = SoftPasskey::new(true);

    // Credential Manager reports the app's signing-certificate origin.
    for (origin, ok) in [(APK, true), (OTHER_APK, false)] {
        let start = h
            .start_registration(&principal, RegistrationIntent::Passwordless)
            .await
            .unwrap();
        let ccr: CreationChallengeResponse = serde_json::from_value(start.options.clone()).unwrap();
        let credential = AuthenticatorBackend::perform_register(
            &mut authenticator,
            Url::parse(origin).unwrap(),
            ccr.public_key,
            60_000,
        )
        .unwrap();
        let result = h.finish_registration(&principal, &start, &credential).await;
        assert_eq!(result.is_ok(), ok, "{origin}: {result:?}");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_passwordless_options_prefer_discoverable_and_require_uv(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let start = h
        .start_registration(&h.fresh(alice), RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let pk = &start.options["publicKey"];
    assert_eq!(pk["rp"]["id"], "auth.test.example");
    assert_eq!(pk["authenticatorSelection"]["residentKey"], "preferred");
    assert_eq!(pk["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(pk["authenticatorSelection"]["userVerification"], "required");
    assert!(
        pk.get("attestation").is_none() || pk["attestation"] == "none",
        "PKY-08: attestation none by default: {pk}"
    );
    assert_eq!(pk["timeout"], 300_000);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_second_factor_key_without_uv_is_second_factor_only(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let start = h
        .start_registration(&h.fresh(alice), RegistrationIntent::SecondFactor)
        .await
        .unwrap();
    let pk = &start.options["publicKey"];
    assert_eq!(
        pk["authenticatorSelection"]["userVerification"],
        "preferred"
    );
    let principal = h.fresh(alice);
    // A security key without PIN: no user verification.
    let mut key = SoftPasskey::new(false);
    let credential = create(&mut key, &start.options, ORIGIN);
    let summary = h
        .finish_registration(&principal, &start, &credential)
        .await
        .unwrap();
    assert_eq!(summary.usage, PasskeyUsage::SecondFactor);
    assert!(!summary.user_verified);
    assert_eq!(summary.name, "Security key");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_passwordless_registration_without_user_verification_is_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);
    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    // A client that downgrades the requirement and an authenticator that
    // skips user verification.
    let mut ccr: CreationChallengeResponse = serde_json::from_value(start.options.clone()).unwrap();
    if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
        sel.user_verification = UserVerificationPolicy::Preferred;
    }
    let mut key = SoftPasskey::new(false);
    let credential = create(&mut key, &serde_json::to_value(ccr).unwrap(), ORIGIN);
    let err = h
        .finish_registration(&principal, &start, &credential)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_REGISTRATION_FAILED);
    let events = h.ports.audit.of_kind(SecurityEventKind::PasskeyRegistered);
    assert_eq!(events[0].reason.as_deref(), Some("user_not_verified"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_03_user_handle_is_random_stable_and_email_independent(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let bob = h.account("bob@example.com").await;
    let options_for =
        |start: &authn_webauthn::RegistrationStart| start.options["publicKey"]["user"].clone();
    let a1 = h
        .start_registration(&h.fresh(alice), RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let a2 = h
        .start_registration(&h.fresh(alice), RegistrationIntent::SecondFactor)
        .await
        .unwrap();
    let b1 = h
        .start_registration(&h.fresh(bob), RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let user_a1 = options_for(&a1);
    // The e-mail is only the display name; the handle is the stored random
    // value, stable across ceremonies and different per user.
    assert_eq!(user_a1["name"], "alice@example.com");
    assert_eq!(user_a1["id"], options_for(&a2)["id"]);
    assert_ne!(user_a1["id"], options_for(&b1)["id"]);

    let handle = h.user_handle(alice.user).await;
    assert_eq!(handle.len(), 16);
    use base64::Engine as _;
    assert_eq!(
        user_a1["id"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&handle)
    );
    assert_ne!(handle, alice.user.as_uuid().as_bytes().to_vec());
    let email_hash = authn_crypto::sha256(b"alice@example.com");
    assert!(!email_hash.windows(16).any(|w| w == handle.as_slice()));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_existing_credentials_are_excluded_from_new_registrations(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let first = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let start = h
        .start_registration(&h.fresh(alice), RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let excluded = start.options["publicKey"]["excludeCredentials"]
        .as_array()
        .unwrap()
        .clone();
    use base64::Engine as _;
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&first.raw_id);
    assert_eq!(excluded.len(), 1);
    assert_eq!(excluded[0]["id"], id);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_step_up_is_required_to_add_passkeys(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    // Default: even the first passkey needs a recent authentication (SES-13).
    let err = h
        .start_registration(&h.stale(alice), RegistrationIntent::Passwordless)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);

    // Relaxed deployments allow the first passkey without step-up, but not
    // additional ones.
    let relaxed = h.service_with(|s| s.webauthn.step_up_for_first_passkey = false);
    let principal = h.stale(alice);
    let start = relaxed
        .start_registration(&h.ctx(), &principal, RegistrationOptionsRequest::default())
        .await
        .unwrap();
    let mut authenticator = SoftPasskey::new(true);
    let credential = create(&mut authenticator, &start.options, ORIGIN);
    relaxed
        .finish_registration(
            &h.ctx(),
            &principal,
            authn_webauthn::RegistrationVerifyRequest {
                ceremony_id: start.ceremony_id,
                credential: serde_json::to_value(&credential).unwrap(),
                name: Some("Laptop".to_owned()),
            },
        )
        .await
        .unwrap();
    let err = relaxed
        .start_registration(&h.ctx(), &principal, RegistrationOptionsRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_registration_requires_a_writable_user_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let err = h
        .start_registration(
            &h.impersonated(alice, true),
            RegistrationIntent::Passwordless,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    let err = h
        .start_registration(
            &h.impersonated(alice, false),
            RegistrationIntent::Passwordless,
        )
        .await
        .unwrap_err();
    // Impersonation never satisfies step-up.
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    let err = h
        .start_registration(
            &h.api_key_principal(alice.user),
            RegistrationIntent::Passwordless,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_passkey_limit_per_user_is_enforced(pool: PgPool) {
    let h = Harness::with(pool, |s| s.webauthn.max_credentials_per_user = 1).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);
    // Two ceremonies started before any finish: the limit is re-checked at
    // finish under the user lock.
    let s1 = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let s2 = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let mut authenticator = SoftPasskey::new(true);
    let c1 = create(&mut authenticator, &s1.options, ORIGIN);
    let c2 = create(&mut authenticator, &s2.options, ORIGIN);
    h.finish_registration(&principal, &s1, &c1).await.unwrap();
    let err = h
        .finish_registration(&principal, &s2, &c2)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_LIMIT_REACHED);
    let err = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_LIMIT_REACHED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_registration_start_is_rate_limited_per_user(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.webauthn.registration_per_user =
            authn_core::ports::RateLimitPolicy::new(2, Duration::from_secs(3600));
    })
    .await;
    let alice = h.account("alice@example.com").await;
    for _ in 0..2 {
        h.start_registration(&h.fresh(alice), RegistrationIntent::Passwordless)
            .await
            .unwrap();
    }
    let err = h
        .start_registration(&h.fresh(alice), RegistrationIntent::Passwordless)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    assert!(err.retry_after().is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_names_are_validated(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let err = h
        .service
        .start_registration(
            &h.ctx(),
            &h.fresh(alice),
            RegistrationOptionsRequest {
                name: Some("evil\u{202E}name".to_owned()),
                usage: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
}

// --- PKY-08 -------------------------------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_08_org_policy_accepts_an_attested_allowed_model(pool: PgPool) {
    let (mut token, ca_root) = SoftToken::new(true).unwrap();
    let mut builder = AttestationCaListBuilder::new();
    builder
        .insert_device_x509(
            ca_root,
            SOFTTOKEN_AAGUID,
            "softtoken".to_owned(),
            Default::default(),
        )
        .unwrap();
    let roots = builder.build();
    let h = Harness::with(pool, move |s| s.attestation_roots = roots).await;
    *h.policy.policy.lock().unwrap() = PasskeyPolicy::allow_only([SOFTTOKEN_AAGUID]);
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);

    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    assert_eq!(start.options["publicKey"]["attestation"], "direct");
    let credential = create(&mut token, &start.options, ORIGIN);
    let summary = h
        .finish_registration(&principal, &start, &credential)
        .await
        .unwrap();
    assert_eq!(summary.aaguid, Some(SOFTTOKEN_AAGUID));
    assert_eq!(summary.attestation_format.as_deref(), Some("packed"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_08_org_policy_rejects_unattested_and_other_models(pool: PgPool) {
    let (_token, ca_root) = SoftToken::new(true).unwrap();
    let mut builder = AttestationCaListBuilder::new();
    builder
        .insert_device_x509(
            ca_root,
            SOFTTOKEN_AAGUID,
            "softtoken".to_owned(),
            Default::default(),
        )
        .unwrap();
    let roots = builder.build();
    let h = Harness::with(pool, move |s| s.attestation_roots = roots).await;
    let alice = h.account("alice@example.com").await;
    let principal = h.fresh(alice);

    // Self-attested software passkey: model not provable.
    *h.policy.policy.lock().unwrap() = PasskeyPolicy::allow_only([SOFTTOKEN_AAGUID]);
    let start = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap();
    let mut soft = SoftPasskey::new(true);
    let credential = create(&mut soft, &start.options, ORIGIN);
    let err = h
        .finish_registration(&principal, &start, &credential)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_NOT_ALLOWED);

    // A model no trusted root vouches for can never be satisfied.
    *h.policy.policy.lock().unwrap() = PasskeyPolicy::allow_only([Uuid::from_u128(0x1234_5678)]);
    let err = h
        .start_registration(&principal, RegistrationIntent::Passwordless)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_NOT_ALLOWED);
    assert!(
        h.service
            .list_passkeys(&principal)
            .await
            .unwrap()
            .is_empty()
    );
}

// --- security review regressions ----------------------------------------------

/// Regression: an administrator impersonating a user (even in writable
/// mode) must never add a passkey — it would keep working as a login method
/// after the impersonation ended (ADM-04). Step-up used to be the only
/// barrier, and `step_up_for_first_passkey = false` removed it for the first
/// passkey.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_impersonation_never_registers_a_passkey(pool: PgPool) {
    let h = Harness::new(pool).await;
    let relaxed = h.service_with(|s| s.webauthn.step_up_for_first_passkey = false);
    let alice = h.account("alice@example.com").await;
    let admin = h.impersonated(alice, false);

    let err = relaxed
        .start_registration(&h.ctx(), &admin, RegistrationOptionsRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);

    // Nor can it finish a ceremony bound to the same session.
    let user = h.stale(alice);
    let start = relaxed
        .start_registration(&h.ctx(), &user, RegistrationOptionsRequest::default())
        .await
        .unwrap();
    let mut authenticator = SoftPasskey::new(true);
    let credential = create(&mut authenticator, &start.options, ORIGIN);
    let verify = |principal| {
        let relaxed = relaxed.clone();
        let ctx = h.ctx();
        let request = authn_webauthn::RegistrationVerifyRequest {
            ceremony_id: start.ceremony_id,
            credential: serde_json::to_value(&credential).unwrap(),
            name: None,
        };
        async move { relaxed.finish_registration(&ctx, &principal, request).await }
    };
    let err = verify(admin).await.unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    assert!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::PasskeyRegistered)
            .is_empty()
    );
    // The refused attempt did not burn the user's own ceremony.
    verify(user).await.unwrap();
}

fn verify_request(
    start: &authn_webauthn::RegistrationStart,
    credential: &webauthn_rs::prelude::RegisterPublicKeyCredential,
) -> authn_webauthn::RegistrationVerifyRequest {
    authn_webauthn::RegistrationVerifyRequest {
        ceremony_id: start.ceremony_id,
        credential: serde_json::to_value(credential).unwrap(),
        name: None,
    }
}

/// PKY-01 / ADM-05 / K-11: a session-less enrollment ceremony is bound to
/// the user and to the SHA-256 of the enrollment link token. A different
/// hash, another user or the session-bound finish cannot consume it; the
/// right hash verifies, and the passkey exists only once the caller's
/// transaction commits.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_enrollment_ceremony_is_bound_to_the_link_hash(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mallory = h.account("mallory@example.com").await;
    let link = [7u8; 32];
    let mut authenticator = SoftPasskey::new(true);

    // Wrong hash / wrong user / the session-bound finish: burned, refused.
    for attempt in 0..3 {
        let start = h
            .service
            .start_enrollment_registration(&h.ctx(), alice.user, link)
            .await
            .unwrap();
        let credential = create(&mut authenticator, &start.options, ORIGIN);
        let err = match attempt {
            0 => h
                .service
                .verify_enrollment_registration(
                    &h.ctx(),
                    alice.user,
                    [8u8; 32],
                    verify_request(&start, &credential),
                )
                .await
                .unwrap_err(),
            1 => h
                .service
                .verify_enrollment_registration(
                    &h.ctx(),
                    mallory.user,
                    link,
                    verify_request(&start, &credential),
                )
                .await
                .unwrap_err(),
            _ => h
                .finish_registration(&h.fresh(alice), &start, &credential)
                .await
                .unwrap_err(),
        };
        assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
    }

    let start = h
        .service
        .start_enrollment_registration(&h.ctx(), alice.user, link)
        .await
        .unwrap();
    let credential = create(&mut authenticator, &start.options, ORIGIN);
    let verified = h
        .service
        .verify_enrollment_registration(
            &h.ctx(),
            alice.user,
            link,
            verify_request(&start, &credential),
        )
        .await
        .unwrap();
    assert_eq!(verified.user_id(), alice.user);
    // Single use: the same ceremony cannot be verified twice.
    let err = h
        .service
        .verify_enrollment_registration(
            &h.ctx(),
            alice.user,
            link,
            verify_request(&start, &credential),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
    // Stored in (and committed with) the caller's transaction.
    let mut tx = h.pool.begin().await.unwrap();
    let summary = h
        .service
        .store_enrollment_in_tx(&mut tx, &h.ctx(), verified)
        .await
        .unwrap();
    assert_eq!(summary.usage, PasskeyUsage::Both);
    tx.commit().await.unwrap();
    let list = h.service.list_passkeys(&h.fresh(alice)).await.unwrap();
    assert_eq!(list.len(), 1);
    let registered = h.ports.audit.of_kind(SecurityEventKind::PasskeyRegistered);
    let last = registered.last().unwrap();
    assert_eq!(last.outcome, EventOutcome::Success);
    assert_eq!(last.metadata["enrollment"], "link");
    assert_eq!(last.actor, authn_core::ports::Actor::User(alice.user));
    assert!(h.ports.notifier.recorded().iter().any(|n| matches!(
        n.kind,
        NotificationKind::MfaFactorAdded { .. }
    ) && n.recipient.user_id
        == Some(alice.user)));
}
