#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Authentication ceremonies used by authn-session: PKY-01, PKY-02, PKY-05,
//! PKY-08.

mod common;

use std::time::Duration;

use authn_core::domain::AuthMethodRef;
use authn_core::error::codes;
use authn_core::id::{CeremonyId, ChallengeId};
use authn_core::ports::{Actor, EventOutcome, SecurityEventKind};
use authn_core::secret::SensitiveString;
use authn_webauthn::service::RegistrationIntent;
use authn_webauthn::{
    AuthenticationFinish, AuthenticationPurpose, AuthenticationTarget, PasskeyPolicy,
};
use common::{Harness, ORIGIN, downgrade_uv, get, get_discoverable};
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

const DISCOVERABLE: AuthenticationTarget = AuthenticationTarget::Discoverable {
    conditional_ui: true,
};

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_discoverable_login_round_trip(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let handle = h.user_handle(alice.user).await;

    let start = h.start_auth(DISCOVERABLE).await;
    // Username-less + conditional UI, user verification required.
    assert_eq!(start.options["mediation"], "conditional");
    let pk = &start.options["publicKey"];
    assert_eq!(pk["allowCredentials"], serde_json::json!([]));
    assert_eq!(pk["userVerification"], "required");
    assert_eq!(pk["rpId"], "auth.test.example");
    assert_eq!(start.binding_token.expose().len(), 43);

    h.advance(Duration::from_secs(10));
    let assertion = get_discoverable(
        &mut authenticator,
        &start.options,
        &passkey.raw_id,
        &handle,
        ORIGIN,
    );
    let result = h
        .finish_auth(&start, DISCOVERABLE, &assertion)
        .await
        .unwrap();
    assert_eq!(result.user_id, alice.user);
    assert_eq!(result.credential_id, passkey.summary.id);
    assert_eq!(result.purpose, AuthenticationPurpose::Login);
    assert!(result.user_verified);
    assert!(!result.backup_eligible && !result.backup_state);
    assert_eq!(
        result.amr,
        vec![AuthMethodRef::Hwk, AuthMethodRef::User, AuthMethodRef::Mfa]
    );

    // Last use and counter are recorded (PKY-04 / PKY-05).
    let list = h.service.list_passkeys(&h.fresh(alice)).await.unwrap();
    assert_eq!(list[0].last_used_at, Some(h.now()));
    assert!(h.sign_count(passkey.summary.id).await > 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_conditional_mediation_is_optional(pool: PgPool) {
    let h = Harness::new(pool).await;
    let start = h
        .start_auth(AuthenticationTarget::Discoverable {
            conditional_ui: false,
        })
        .await;
    assert!(
        start.options.get("mediation").is_none(),
        "{}",
        start.options
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_passwordless_login_requires_user_verification(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let handle = h.user_handle(alice.user).await;
    let start = h.start_auth(DISCOVERABLE).await;
    // A client that downgrades `userVerification`: the authenticator only
    // proves presence.
    let assertion = get_discoverable(
        &mut authenticator,
        &downgrade_uv(&start.options),
        &passkey.raw_id,
        &handle,
        ORIGIN,
    );
    let err = h
        .finish_auth(&start, DISCOVERABLE, &assertion)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_second_factor_only_keys_cannot_log_in_passwordless(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut key = SoftPasskey::new(false);
    let registered = h
        .register(&mut key, alice, RegistrationIntent::SecondFactor)
        .await;
    let handle = h.user_handle(alice.user).await;
    let start = h.start_auth(DISCOVERABLE).await;
    let assertion = get_discoverable(
        &mut key,
        &downgrade_uv(&start.options),
        &registered.raw_id,
        &handle,
        ORIGIN,
    );
    let err = h
        .finish_auth(&start, DISCOVERABLE, &assertion)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_second_factor_round_trip_bound_to_login_challenge(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    // A UV-less security key: the ceremony asks for "preferred".
    let mut key = SoftPasskey::new(false);
    let registered = h
        .register(&mut key, alice, RegistrationIntent::SecondFactor)
        .await;
    let challenge = h.challenge(alice.user).await;
    let other_challenge = h.challenge(alice.user).await;
    let target = AuthenticationTarget::SecondFactor {
        user_id: alice.user,
        challenge_id: challenge,
    };
    let start = h.start_auth(target).await;
    let pk = &start.options["publicKey"];
    assert_eq!(pk["userVerification"], "preferred");
    assert_eq!(pk["allowCredentials"].as_array().unwrap().len(), 1);
    assert!(pk.get("hints").is_none(), "{pk}");
    let assertion = get(&mut key, &start.options, ORIGIN);

    // Swapped into another login challenge: rejected, not consumed.
    let swapped = AuthenticationTarget::SecondFactor {
        user_id: alice.user,
        challenge_id: other_challenge,
    };
    let err = h
        .finish_auth(&start, swapped, &assertion)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);

    let result = h.finish_auth(&start, target, &assertion).await.unwrap();
    assert_eq!(result.user_id, alice.user);
    assert_eq!(result.credential_id, registered.summary.id);
    assert_eq!(result.purpose, AuthenticationPurpose::SecondFactor);
    assert!(!result.user_verified);
    assert_eq!(result.amr, vec![AuthMethodRef::Hwk, AuthMethodRef::User]);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_second_factor_with_passkeys_requires_user_verification(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    h.register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::SecondFactor {
        user_id: alice.user,
        challenge_id: h.challenge(alice.user).await,
    };
    let start = h.start_auth(target).await;
    // Every allowed passkey was registered with UV, so UV is required.
    assert_eq!(start.options["publicKey"]["userVerification"], "required");
    let assertion = get(&mut authenticator, &downgrade_uv(&start.options), ORIGIN);
    let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);

    let start = h.start_auth(target).await;
    let assertion = get(&mut authenticator, &start.options, ORIGIN);
    let result = h.finish_auth(&start, target, &assertion).await.unwrap();
    assert!(result.user_verified);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_step_up_round_trip_requires_a_user_verifying_passkey(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let target = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    // Only a second-factor key: not usable for step-up.
    let mut key = SoftPasskey::new(false);
    h.register(&mut key, alice, RegistrationIntent::SecondFactor)
        .await;
    let err = h
        .service
        .start_authentication(&h.ctx(), target, &PasskeyPolicy::unrestricted())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_NOT_AVAILABLE);

    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let start = h.start_auth(target).await;
    let pk = &start.options["publicKey"];
    assert_eq!(pk["userVerification"], "required");
    assert_eq!(pk["allowCredentials"].as_array().unwrap().len(), 1);
    let assertion = get(&mut authenticator, &start.options, ORIGIN);
    let result = h.finish_auth(&start, target, &assertion).await.unwrap();
    assert_eq!(result.credential_id, passkey.summary.id);
    assert_eq!(result.purpose, AuthenticationPurpose::StepUp);
    assert!(result.user_verified);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_authentication_ceremony_is_single_use(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    h.register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    let start = h.start_auth(target).await;
    let assertion = get(&mut authenticator, &start.options, ORIGIN);
    h.finish_auth(&start, target, &assertion).await.unwrap();
    // Replaying the same ceremony…
    let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
    // …or the captured assertion against a fresh ceremony fails.
    let fresh = h.start_auth(target).await;
    let err = h.finish_auth(&fresh, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_concurrent_finishes_authenticate_exactly_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    h.register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    let start = h.start_auth(target).await;
    let assertion = serde_json::to_value(get(&mut authenticator, &start.options, ORIGIN)).unwrap();
    let attempts = (0..8)
        .map(|_| {
            let service = h.service.clone();
            let ctx = h.ctx();
            let finish = AuthenticationFinish {
                ceremony_id: start.ceremony_id,
                binding_token: start.binding_token.clone(),
                target,
                credential: assertion.clone(),
            };
            async move { service.finish_authentication(&ctx, finish).await }
        })
        .collect();
    let results = common::spawn_all(attempts).await;
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "{results:?}"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_expired_authentication_ceremony_is_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    h.register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    let start = h.start_auth(target).await;
    let assertion = get(&mut authenticator, &start.options, ORIGIN);
    h.advance(Duration::from_secs(301));
    let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_swapped_or_unbound_ceremonies_are_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let bob = h.account("bob@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    h.register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let alice_step_up = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    let start = h.start_auth(alice_step_up).await;
    let assertion = get(&mut authenticator, &start.options, ORIGIN);
    let other_session = h.session(alice.user).await;

    let wrong_targets = [
        // Another user's session.
        AuthenticationTarget::StepUp {
            user_id: bob.user,
            session_id: bob.session,
        },
        // Same user, another session.
        AuthenticationTarget::StepUp {
            user_id: alice.user,
            session_id: other_session,
        },
        // Another purpose.
        AuthenticationTarget::SecondFactor {
            user_id: alice.user,
            challenge_id: ChallengeId::generate(),
        },
        DISCOVERABLE,
    ];
    for target in wrong_targets {
        let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
        assert_eq!(
            err.code(),
            codes::webauthn::PASSKEY_CEREMONY_INVALID,
            "{target:?}"
        );
    }
    // Wrong / malformed binding token, unknown ceremony.
    for (ceremony_id, token) in [
        (start.ceremony_id, "A".repeat(43)),
        (start.ceremony_id, "not a token".to_owned()),
        (
            CeremonyId::generate(),
            start.binding_token.expose().to_owned(),
        ),
    ] {
        let err = h
            .service
            .finish_authentication(
                &h.ctx(),
                AuthenticationFinish {
                    ceremony_id,
                    binding_token: SensitiveString::new(token),
                    target: alice_step_up,
                    credential: serde_json::to_value(&assertion).unwrap(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::webauthn::PASSKEY_CEREMONY_INVALID);
    }
    // None of the attempts consumed the ceremony.
    h.finish_auth(&start, alice_step_up, &assertion)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_assertion_from_wrong_origin_is_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    h.register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    let start = h.start_auth(target).await;
    let assertion = get(
        &mut authenticator,
        &start.options,
        "https://evil.auth.test.example",
    );
    let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_discoverable_login_rejects_foreign_or_unknown_handles(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let bob = h.account("bob@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let mut bob_key = SoftPasskey::new(true);
    h.register(&mut bob_key, bob, RegistrationIntent::Passwordless)
        .await;
    let bob_handle = h.user_handle(bob.user).await;
    // Alice's credential presented under Bob's handle, then under a random
    // handle: no account is matched.
    for handle in [bob_handle, Uuid::new_v4().as_bytes().to_vec()] {
        let start = h.start_auth(DISCOVERABLE).await;
        let assertion = get_discoverable(
            &mut authenticator,
            &start.options,
            &passkey.raw_id,
            &handle,
            ORIGIN,
        );
        let err = h
            .finish_auth(&start, DISCOVERABLE, &assertion)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_05_counter_regression_flags_a_cloned_passkey(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let handle = h.user_handle(alice.user).await;
    // Another copy of the key has been used 100 times.
    h.bump_stored_counter(passkey.summary.id, 100).await;

    let start = h.start_auth(DISCOVERABLE).await;
    let assertion = get_discoverable(
        &mut authenticator,
        &start.options,
        &passkey.raw_id,
        &handle,
        ORIGIN,
    );
    let err = h
        .finish_auth(&start, DISCOVERABLE, &assertion)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);

    let events = h
        .ports
        .audit
        .of_kind(SecurityEventKind::PasskeyCloneSuspected);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.outcome, EventOutcome::Failure);
    assert_eq!(event.reason.as_deref(), Some("counter_regression"));
    assert_eq!(event.subject_user, Some(alice.user));
    assert_eq!(event.actor, Actor::Anonymous);
    assert_eq!(
        event.resource.as_ref().unwrap().id,
        passkey.summary.id.to_string()
    );
    let list = h.service.list_passkeys(&h.fresh(alice)).await.unwrap();
    assert!(list[0].clone_suspected_at.is_some());
    // The stored counter was not lowered.
    assert_eq!(h.sign_count(passkey.summary.id).await, 100);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_05_counter_regression_after_ceremony_start_is_detected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    // The ceremony snapshot holds the old counter; the clone is used in
    // between (concurrent use).
    let start = h.start_auth(target).await;
    h.bump_stored_counter(passkey.summary.id, 50).await;
    let assertion = get(&mut authenticator, &start.options, ORIGIN);
    let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);
    let events = h
        .ports
        .audit
        .of_kind(SecurityEventKind::PasskeyCloneSuspected);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, Actor::User(alice.user));
    assert_eq!(h.sign_count(passkey.summary.id).await, 50);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_05_counter_increases_on_every_use(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    let mut last = h.sign_count(passkey.summary.id).await;
    for _ in 0..3 {
        let start = h.start_auth(target).await;
        let assertion = get(&mut authenticator, &start.options, ORIGIN);
        h.finish_auth(&start, target, &assertion).await.unwrap();
        let now = h.sign_count(passkey.summary.id).await;
        assert!(now > last);
        last = now;
    }
    assert!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::PasskeyCloneSuspected)
            .is_empty()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_04_deleted_passkey_cannot_finish_a_pending_ceremony(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    h.set_password(alice.user).await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::SecondFactor {
        user_id: alice.user,
        challenge_id: h.challenge(alice.user).await,
    };
    let start = h.start_auth(target).await;
    let assertion = get(&mut authenticator, &start.options, ORIGIN);
    h.service
        .delete_passkey(&h.ctx(), &h.fresh(alice), passkey.summary.id)
        .await
        .unwrap();
    let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_02_second_factor_needs_an_enrolled_passkey(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let target = AuthenticationTarget::SecondFactor {
        user_id: alice.user,
        challenge_id: h.challenge(alice.user).await,
    };
    let err = h
        .service
        .start_authentication(&h.ctx(), target, &PasskeyPolicy::unrestricted())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_NOT_AVAILABLE);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_08_policy_applies_to_existing_passkeys(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let policy = PasskeyPolicy::allow_only([Uuid::from_u128(42)]);
    // Known user: the unattested passkey is filtered out.
    let target = AuthenticationTarget::SecondFactor {
        user_id: alice.user,
        challenge_id: h.challenge(alice.user).await,
    };
    let err = h
        .service
        .start_authentication(&h.ctx(), target, &policy)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_NOT_AVAILABLE);
    // Discoverable: rejected at finish once the user is known.
    let handle = h.user_handle(alice.user).await;
    let start = h
        .service
        .start_authentication(&h.ctx(), DISCOVERABLE, &policy)
        .await
        .unwrap();
    let assertion = get_discoverable(
        &mut authenticator,
        &start.options,
        &passkey.raw_id,
        &handle,
        ORIGIN,
    );
    let err = h
        .finish_auth(&start, DISCOVERABLE, &assertion)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_authentication_start_is_rate_limited_per_ip(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.webauthn.authentication_per_ip =
            authn_core::ports::RateLimitPolicy::new(3, Duration::from_secs(900));
    })
    .await;
    for _ in 0..3 {
        h.start_auth(DISCOVERABLE).await;
    }
    let err = h
        .service
        .start_authentication(&h.ctx(), DISCOVERABLE, &PasskeyPolicy::unrestricted())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    // Another client is unaffected.
    h.service
        .start_authentication(
            &h.ctx_from("198.51.100.7".parse().unwrap()),
            DISCOVERABLE,
            &PasskeyPolicy::unrestricted(),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_01_expired_ceremonies_are_purged(pool: PgPool) {
    let h = Harness::new(pool).await;
    for _ in 0..3 {
        h.start_auth(DISCOVERABLE).await;
    }
    assert_eq!(h.service.purge_expired_ceremonies().await.unwrap(), 0);
    h.advance(Duration::from_secs(301));
    h.start_auth(DISCOVERABLE).await;
    assert_eq!(h.service.purge_expired_ceremonies().await.unwrap(), 3);
    let (left,): (i64,) = sqlx::query_as("SELECT count(*) FROM webauthn_ceremonies")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(left, 1);
}

// --- security review regressions ----------------------------------------------

/// Authenticator-data flag bits (WebAuthn §6.1).
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKUP_STATE: u8 = 0x10;

/// What an attacker without the private key can send: a real assertion
/// whose authenticator-data flags were changed and whose signature is
/// garbage (a syntactically valid, mathematically wrong ECDSA signature).
fn forge_flags(assertion: &mut webauthn_rs_proto::PublicKeyCredential, bits: u8) {
    assertion.response.authenticator_data[32] |= bits;
    assertion.response.signature = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
}

/// Regression: `webauthn-rs` checks the backup flags *before* the signature,
/// so those errors are not evidence of a clone. They used to mark the
/// passkey `clone_suspected_at` and record `passkey.clone_suspected`, which
/// anyone who knew a credential id (second-factor `allowCredentials`) could
/// trigger without the authenticator.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_05_unsigned_backup_flag_tampering_never_flags_a_clone(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let bob = h.account("bob@example.com").await;
    let mut alice_key = SoftPasskey::new(false);
    let alice_reg = h
        .register(&mut alice_key, alice, RegistrationIntent::SecondFactor)
        .await;
    let mut bob_passkey = SoftPasskey::new(true);
    let bob_reg = h
        .register(&mut bob_passkey, bob, RegistrationIntent::Passwordless)
        .await;
    let bob_handle = h.user_handle(bob.user).await;

    // 1. Second factor (security-key ceremony, no backup-eligibility
    //    upgrade): the attacker knows the password and flips BE.
    let target = AuthenticationTarget::SecondFactor {
        user_id: alice.user,
        challenge_id: h.challenge(alice.user).await,
    };
    let start = h.start_auth(target).await;
    let mut assertion = get(&mut alice_key, &start.options, ORIGIN);
    forge_flags(&mut assertion, FLAG_BACKUP_ELIGIBLE);
    let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);

    // 2. Step-up (passkey ceremony): backed up without being eligible.
    let target = AuthenticationTarget::StepUp {
        user_id: bob.user,
        session_id: bob.session,
    };
    let start = h.start_auth(target).await;
    let mut assertion = get(&mut bob_passkey, &start.options, ORIGIN);
    forge_flags(&mut assertion, FLAG_BACKUP_STATE);
    let err = h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);

    // 3. Discoverable login (unauthenticated): BE flipped.
    let start = h.start_auth(DISCOVERABLE).await;
    let mut assertion = get_discoverable(
        &mut bob_passkey,
        &start.options,
        &bob_reg.raw_id,
        &bob_handle,
        ORIGIN,
    );
    forge_flags(&mut assertion, FLAG_BACKUP_ELIGIBLE);
    let err = h
        .finish_auth(&start, DISCOVERABLE, &assertion)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);

    assert!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::PasskeyCloneSuspected)
            .is_empty()
    );
    for (account, id) in [(alice, alice_reg.summary.id), (bob, bob_reg.summary.id)] {
        let list = h.service.list_passkeys(&h.fresh(account)).await.unwrap();
        let passkey = list.iter().find(|p| p.id == id).unwrap();
        assert_eq!(passkey.clone_suspected_at, None, "{id} was flagged");
    }

    // The genuine authenticators still work.
    let target = AuthenticationTarget::StepUp {
        user_id: bob.user,
        session_id: bob.session,
    };
    let start = h.start_auth(target).await;
    let assertion = get(&mut bob_passkey, &start.options, ORIGIN);
    h.finish_auth(&start, target, &assertion).await.unwrap();
}

/// Regression: the organization policy (PKY-08) applies to every
/// authentication, even when the caller passes no restriction — in
/// particular to discoverable login, where authn-session cannot know the
/// user (and therefore the policy) before the assertion arrives.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_08_policy_source_applies_to_every_authentication(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    // Registered before the organization restricted authenticator models.
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let handle = h.user_handle(alice.user).await;
    *h.policy.policy.lock().unwrap() = PasskeyPolicy::allow_only([Uuid::from_u128(42)]);

    // Discoverable login: the caller cannot know the policy at start.
    let start = h.start_auth(DISCOVERABLE).await;
    let assertion = get_discoverable(
        &mut authenticator,
        &start.options,
        &passkey.raw_id,
        &handle,
        ORIGIN,
    );
    let err = h
        .finish_auth(&start, DISCOVERABLE, &assertion)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::webauthn::PASSKEY_AUTHENTICATION_FAILED);

    // Known user: the caller forgot the policy.
    for target in [
        AuthenticationTarget::SecondFactor {
            user_id: alice.user,
            challenge_id: h.challenge(alice.user).await,
        },
        AuthenticationTarget::StepUp {
            user_id: alice.user,
            session_id: alice.session,
        },
    ] {
        let err = h
            .service
            .start_authentication(&h.ctx(), target, &PasskeyPolicy::unrestricted())
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            codes::webauthn::PASSKEY_NOT_AVAILABLE,
            "{target:?}"
        );
    }

    // Lifting the restriction makes the passkey usable again.
    *h.policy.policy.lock().unwrap() = PasskeyPolicy::unrestricted();
    let start = h.start_auth(DISCOVERABLE).await;
    let assertion = get_discoverable(
        &mut authenticator,
        &start.options,
        &passkey.raw_id,
        &handle,
        ORIGIN,
    );
    let result = h
        .finish_auth(&start, DISCOVERABLE, &assertion)
        .await
        .unwrap();
    assert_eq!(result.user_id, alice.user);
}

/// PKY-05 / K-19: the first clone detection of a passkey queues the
/// `passkey_clone_suspected` e-mail to its owner in the same transaction as
/// the flag and the audit event; a repeated detection of the already
/// flagged passkey does not e-mail again (the outbox also limits per
/// recipient).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pky_05_clone_suspicion_notifies_the_owner_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.account("alice@example.com").await;
    let mut authenticator = SoftPasskey::new(true);
    let passkey = h
        .register(&mut authenticator, alice, RegistrationIntent::Passwordless)
        .await;
    let handle = h.user_handle(alice.user).await;
    h.ports.notifier.take();
    for attempt in 0..2 {
        h.bump_stored_counter(passkey.summary.id, 100 + attempt)
            .await;
        let start = h.start_auth(DISCOVERABLE).await;
        let assertion = get_discoverable(
            &mut authenticator,
            &start.options,
            &passkey.raw_id,
            &handle,
            ORIGIN,
        );
        h.finish_auth(&start, DISCOVERABLE, &assertion)
            .await
            .unwrap_err();
    }
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::PasskeyCloneSuspected)
            .len(),
        2
    );
    let sent = h.ports.notifier.with_template("passkey_clone_suspected");
    assert_eq!(sent.len(), 1, "one e-mail per suspected passkey");
    assert_eq!(sent[0].recipient.user_id, Some(alice.user));
    assert_eq!(sent[0].recipient.email.as_str(), "alice@example.com");
    // Step-up path (known user) notifies too, for another passkey.
    let mut other = SoftPasskey::new(true);
    let second = h
        .register(&mut other, alice, RegistrationIntent::Passwordless)
        .await;
    let target = AuthenticationTarget::StepUp {
        user_id: alice.user,
        session_id: alice.session,
    };
    let start = h.start_auth(target).await;
    h.bump_stored_counter(second.summary.id, 50).await;
    let assertion = get(&mut other, &start.options, ORIGIN);
    h.finish_auth(&start, target, &assertion).await.unwrap_err();
    assert_eq!(
        h.ports
            .notifier
            .with_template("passkey_clone_suspected")
            .len(),
        2
    );
}
