#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Account pre-hijacking (Sudhodanan & Paverd, USENIX Security 2022) —
//! regression tests for ADR 0002 (ACC-02, ACC-04, ACC-05, ACC-07).
//!
//! Invariant under test: no sequence of registrations, resends,
//! verifications, e-mail changes or password resets lets anybody but the
//! mailbox owner end up controlling a verified account with credentials
//! they chose without proving mailbox control in the same flow — and the
//! mailbox owner can always recover.

mod common;

use std::time::Duration;

use authn_account::{AccountAwareSessionRevoker, MailboxProof};
use authn_core::domain::AccountStatus;
use authn_core::id::SessionId;
use authn_core::ports::{
    Clock as _, RateLimitPolicy, RevocationReason, RevokeOptions, SecurityEventKind, SessionRevoker,
};
use authn_store::UserRepository;
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::TestRequest;
use common::{Harness, PASSWORD, PASSWORD_2, chosen, new_password, registrations, secret};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

/// The attacker's password.
const ATTACKER: &str = PASSWORD;
/// The mailbox owner's password.
const OWNER: &str = PASSWORD_2;

/// Link token and code of every verification e-mail to `email`, oldest
/// first.
fn all_verifications(h: &Harness, email: &str) -> Vec<(String, String)> {
    h.mails("email_verification", email)
        .into_iter()
        .map(|mail| match mail.kind {
            authn_core::ports::NotificationKind::EmailVerification { token, code, .. } => {
                (token.expose().to_owned(), code.expose().to_owned())
            }
            other => panic!("unexpected {other:?}"),
        })
        .collect()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_attacker_first_link_alone_never_activates_the_attackers_password(pool: PgPool) {
    let h = Harness::new(pool).await;
    // The attacker registers the victim's address first (classic
    // pre-hijacking) and keeps the handle.
    let attacker_handle = h.signup_with("victim@example.com", ATTACKER).await;
    let user = h.user("victim@example.com").await.unwrap().id;
    let (token, code) = all_verifications(&h, "victim@example.com").pop().unwrap();

    // The victim clicks the e-mailed link on their own device.
    let res = TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token }))
        .send(&h.app())
        .await;
    let err = res.assert_error(StatusCode::FORBIDDEN, "registration_confirmation_required");
    assert_eq!(
        err.details.unwrap()["methods"],
        json!(["password", "new_password"])
    );
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.status, AccountStatus::PendingVerification);
    assert!(record.email_verified_at.is_none());
    assert!(
        !h.password_matches(user, ATTACKER).await,
        "no credential yet"
    );

    // Guessing "their" password does not help; it is not theirs.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token, "password": OWNER }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::FORBIDDEN, "registration_password_mismatch");

    // The mailbox owner sets their own password with the link: they win.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token, "new_password": OWNER }))
        .send(&h.app())
        .await
        .assert_status(StatusCode::OK);
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.status, AccountStatus::Active);
    assert!(h.password_matches(user, OWNER).await);
    assert!(!h.password_matches(user, ATTACKER).await);
    // The registrant's profile choices were discarded with their password.
    let profile = h.service.profile_of(user).await.unwrap().unwrap();
    assert_eq!(profile.display_name, None);
    assert_eq!(registrations(&h.pool, user).await, 0);
    let verified = h.audit.events.of_kind(SecurityEventKind::EmailVerified);
    assert_eq!(
        verified.last().unwrap().metadata["method"],
        "link_new_password"
    );

    // The attacker's handle and code are dead.
    let err = h
        .verify_code(Some(&attacker_handle), &code)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_code");
    // Registering again only notifies the owner; the password stays.
    h.signup_with("victim@example.com", ATTACKER).await;
    assert_eq!(
        h.mails("registration_attempt", "victim@example.com").len(),
        1
    );
    assert!(h.password_matches(user, OWNER).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_attacker_first_then_victim_registers_and_gets_own_credentials(pool: PgPool) {
    let h = Harness::new(pool).await;
    // The attacker even picks the spelling of the address.
    let attacker_handle = h.signup_with("VICTIM@example.com", ATTACKER).await;
    let user = h.user("victim@example.com").await.unwrap().id;
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("VICTIM@example.com")
    );
    // The victim registers later: same account placeholder, but a separate
    // registration bound to the victim's own link, code and handle — not an
    // "already exists" dead end.
    let victim_handle = h.signup_with("victim@example.com", OWNER).await;
    assert_eq!(h.user("victim@example.com").await.unwrap().id, user);
    assert_eq!(registrations(&h.pool, user).await, 2);
    let mails = all_verifications(&h, "victim@example.com");
    assert_eq!(mails.len(), 2);
    let (attacker_token, attacker_code) = mails[0].clone();
    let (victim_token, _) = mails[1].clone();
    assert!(
        h.ports.session_revoker.calls().is_empty(),
        "registering never touches the account"
    );

    // The victim's browser holds the victim's handle. Whichever link of the
    // account it opens (here: the attacker's registration e-mail), the
    // mailbox owner completes *their own* registration — never the
    // attacker's (K-58: the owner's registration may have got no e-mail).
    h.verify_link(&attacker_token, Some(&victim_handle), None)
        .await
        .unwrap();
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::EmailVerified)
            .last()
            .unwrap()
            .metadata["method"],
        "link_registering_client_other_registration"
    );
    // The victim's own link died with the completion.
    let err = h
        .verify_link(&victim_token, Some(&victim_handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    assert!(h.password_matches(user, OWNER).await);
    assert!(!h.password_matches(user, ATTACKER).await);
    assert_eq!(registrations(&h.pool, user).await, 0);
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("victim@example.com"),
        "the winner's own spelling"
    );

    // Every secret of the attacker's registration is dead now.
    let err = h
        .verify_link(&attacker_token, Some(&attacker_handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    let err = h
        .verify_code(Some(&attacker_handle), &attacker_code)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_code");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_attacker_second_cannot_overwrite_or_inherit_the_victims_registration(pool: PgPool) {
    let h = Harness::new(pool).await;
    let victim_handle = h.signup_with("victim@example.com", OWNER).await;
    let user = h.user("victim@example.com").await.unwrap().id;
    // The attacker re-registers between the victim's signup and verification.
    let attacker_handle = h.signup_with("victim@example.com", ATTACKER).await;
    assert_eq!(registrations(&h.pool, user).await, 2);
    assert!(h.ports.session_revoker.calls().is_empty());
    assert!(
        UserRepository::find_password(&h.pool, user)
            .await
            .unwrap()
            .is_none(),
        "no registration writes a credential"
    );
    let mails = all_verifications(&h, "victim@example.com");
    let (victim_token, victim_code) = mails[0].clone();
    let (attacker_token, _) = mails[1].clone();

    // On another device, the attacker's link does not take the victim's
    // password (it is not that registration's).
    let err = h
        .verify_link(&attacker_token, None, Some(chosen(OWNER)))
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "registration_password_mismatch");
    // The victim's code needs the victim's handle; the attacker cannot
    // use it with theirs.
    let err = h
        .verify_code(Some(&attacker_handle), &victim_code)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_code");
    // The victim clicks the newest e-mail (the attacker's registration) in
    // the registering browser: it activates the *victim's* registration
    // (the handle's), never the attacker's (K-58).
    h.verify_link(&attacker_token, Some(&victim_handle), None)
        .await
        .unwrap();
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.status, AccountStatus::Active);
    assert!(h.password_matches(user, OWNER).await);
    assert!(!h.password_matches(user, ATTACKER).await);

    // The attacker's link — even with the attacker's own handle — is dead.
    let err = h
        .verify_link(&attacker_token, Some(&attacker_handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    let err = h
        .verify_link(&victim_token, Some(&victim_handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_link_on_another_device_requires_the_chosen_password(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup_with("phone@example.com", OWNER).await;
    let user = h.user("phone@example.com").await.unwrap().id;
    let (token, _) = all_verifications(&h, "phone@example.com").pop().unwrap();
    // Registered on the laptop, link opened on the phone (no cookie).
    let err = h.verify_link(&token, None, None).await.unwrap_err();
    assert_eq!(err.code().code(), "registration_confirmation_required");
    h.verify_link(&token, None, Some(chosen(OWNER)))
        .await
        .unwrap();
    assert!(h.password_matches(user, OWNER).await);
    let verified = h.audit.events.of_kind(SecurityEventKind::EmailVerified);
    assert_eq!(
        verified.last().unwrap().metadata["method"],
        "link_chosen_password"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_chosen_password_answers_are_limited_per_registration(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup_with("guess@example.com", ATTACKER).await;
    let user = h.user("guess@example.com").await.unwrap().id;
    let (token, _) = all_verifications(&h, "guess@example.com").pop().unwrap();
    for _ in 0..authn_account::MAX_PASSWORD_CONFIRMATIONS {
        let err = h
            .verify_link(&token, None, Some(chosen("wrong guess but long enough")))
            .await
            .unwrap_err();
        assert_eq!(err.code().code(), "registration_password_mismatch");
    }
    // Even the right password is refused now (no online guessing of the
    // registration's password through the link page) …
    let err = h
        .verify_link(&token, None, Some(chosen(ATTACKER)))
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "registration_password_mismatch");
    // … but the mailbox owner can always finish with a new password.
    h.verify_link(&token, None, Some(new_password(OWNER)))
        .await
        .unwrap();
    assert!(h.password_matches(user, OWNER).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_code_needs_the_registering_clients_handle_and_cannot_be_replayed(pool: PgPool) {
    let h = Harness::new(pool).await;
    let victim_handle = h.signup_with("code@example.com", OWNER).await;
    let attacker_handle = h.signup_with("code@example.com", ATTACKER).await;
    let user = h.user("code@example.com").await.unwrap().id;
    let mails = all_verifications(&h, "code@example.com");
    let (_, victim_code) = mails[0].clone();

    // The old "e-mail + code" form completes nothing.
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "email": "code@example.com", "code": victim_code }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    // A code read from the mailbox does not work with another registration's
    // handle (e.g. the attacker phishing the code out of the victim).
    let err = h
        .verify_code(Some(&attacker_handle), &victim_code)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_code");
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::PendingVerification
    );
    // The registering client completes; the same code cannot be replayed.
    h.verify_code(Some(&victim_handle), &victim_code)
        .await
        .unwrap();
    assert!(h.password_matches(user, OWNER).await);
    let err = h
        .verify_code(Some(&victim_handle), &victim_code)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_code");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_concurrent_registrations_for_the_same_address_yield_one_account(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.account.registration_notice_per_email =
            RateLimitPolicy::new(100, Duration::from_secs(86_400));
    })
    .await;
    let passwords: Vec<String> = (0..6).map(|i| format!("{PASSWORD} variant {i}")).collect();
    let mut tasks = Vec::new();
    for password in &passwords {
        let service = h.service.clone();
        let ctx = h.ctx();
        let input = Harness::signup_input("race@example.com", password);
        tasks.push(tokio::spawn(async move {
            service
                .signup(&ctx, input)
                .await
                .unwrap()
                .handle()
                .expose()
                .to_owned()
        }));
    }
    let mut handles = Vec::new();
    for task in tasks {
        handles.push(task.await.unwrap());
    }
    h.drain().await;
    let (users,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM users WHERE email_normalized = 'race@example.com'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(users, 1);
    let user = h.user("race@example.com").await.unwrap().id;
    assert_eq!(registrations(&h.pool, user).await, 6);
    let mails = all_verifications(&h, "race@example.com");
    assert_eq!(mails.len(), 6);

    // Every registering client completes its own registration at once:
    // exactly one wins, and the account holds exactly the winner's password.
    let mut tasks = Vec::new();
    for (token, _) in &mails {
        for handle in &handles {
            let service = h.service.clone();
            let ctx = h.ctx();
            let token = token.clone();
            let handle = handle.clone();
            tasks.push(tokio::spawn(async move {
                service
                    .verify_email_link(
                        &ctx,
                        &secret(&token),
                        &authn_account::LinkConfirmation {
                            registration: Some(secret(&handle)),
                            ..Default::default()
                        },
                    )
                    .await
            }));
        }
    }
    let mut ok = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(registrations(&h.pool, user).await, 0);
    let mut matching = 0;
    for password in &passwords {
        if h.password_matches(user, password).await {
            matching += 1;
        }
    }
    assert_eq!(matching, 1);
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::AccountStatusChanged)
            .len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_05_password_reset_on_unverified_account_hands_it_to_the_mailbox_owner(pool: PgPool) {
    let h = Harness::new(pool).await;
    // An unverified account that already has the attacker's password (older
    // data or another module) and a pending registration of the attacker.
    let user = h
        .unverified_with_password("victim@example.com", ATTACKER)
        .await;
    let attacker_handle = h.signup_with("victim@example.com", ATTACKER).await;
    let (attacker_token, _) = all_verifications(&h, "victim@example.com").pop().unwrap();
    assert_eq!(registrations(&h.pool, user).await, 1);

    // authn-password completes an e-mailed reset (PWD-09): new password,
    // then the SessionRevoker port with `PasswordReset`, same transaction.
    let revoker =
        AccountAwareSessionRevoker::new(h.ports.session_revoker.clone(), h.service.clone());
    let new_hash = h.crypto.passwords.hash(&secret(OWNER)).await.unwrap();
    let mut tx = h.pool.begin().await.unwrap();
    UserRepository::set_password(
        &mut tx,
        user,
        &authn_store::NewPasswordHash {
            password_hash: &new_hash.hash,
            algorithm: new_hash.algorithm.as_str(),
            pepper_version: new_hash.pepper_version,
        },
        false,
        h.ports.clock.now(),
    )
    .await
    .unwrap();
    revoker
        .revoke_all_for_user(
            &mut tx,
            user,
            RevocationReason::PasswordReset,
            RevokeOptions {
                also_trusted_devices: true,
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Mailbox owner wins: verified, active, the owner's password; every
    // session revoked (by the inner revoker) and the attacker's pending
    // registration gone.
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.status, AccountStatus::Active);
    assert!(record.email_verified_at.is_some());
    assert!(h.password_matches(user, OWNER).await);
    assert!(!h.password_matches(user, ATTACKER).await);
    assert_eq!(registrations(&h.pool, user).await, 0);
    assert!(h.ports.session_revoker.calls().iter().any(|c| matches!(
        c,
        RevocationCall::AllForUser(u, RevocationReason::PasswordReset, o)
            if *u == user && o.also_trusted_devices
    )));
    let err = h
        .verify_link(&attacker_token, Some(&attacker_handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "invalid_or_expired_token");
    let verified = h.audit.events.of_kind(SecurityEventKind::EmailVerified);
    assert_eq!(
        verified.last().unwrap().metadata["method"],
        "password_reset"
    );

    // A registration's placeholder has no password, so authn-password never
    // issues a reset for it (it only replaces existing passwords): the
    // mailbox owner finishes through the link with a new password instead.
    h.signup_with("placeholder@example.com", ATTACKER).await;
    let placeholder = h.user("placeholder@example.com").await.unwrap().id;
    assert!(
        UserRepository::find_password(&h.pool, placeholder)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_05_rolled_back_reset_changes_nothing(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h
        .unverified_with_password("victim@example.com", ATTACKER)
        .await;
    let revoker =
        AccountAwareSessionRevoker::new(h.ports.session_revoker.clone(), h.service.clone());
    let mut tx = h.pool.begin().await.unwrap();
    revoker
        .revoke_all_for_user(
            &mut tx,
            user,
            RevocationReason::PasswordReset,
            RevokeOptions::default(),
        )
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.status, AccountStatus::PendingVerification);
    assert!(record.email_verified_at.is_none());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_05_passwordless_mailbox_proof_removes_an_unproven_password(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h
        .unverified_with_password("victim@example.com", ATTACKER)
        .await;
    h.signup_with("victim@example.com", ATTACKER).await;
    // E.g. authn-session completed a magic link to this address.
    let mut tx = h.pool.begin().await.unwrap();
    let verified = h
        .service
        .confirm_mailbox_control_in_tx(&mut tx, Some(&h.ctx()), user, MailboxProof::Passwordless)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(verified);
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.status, AccountStatus::Active);
    assert!(
        UserRepository::find_password(&h.pool, user)
            .await
            .unwrap()
            .is_none(),
        "the attacker's password is gone"
    );
    assert_eq!(registrations(&h.pool, user).await, 0);
    assert!(h.ports.session_revoker.calls().iter().any(|c| matches!(
        c,
        RevocationCall::AllForUser(u, RevocationReason::PasswordChanged, _) if *u == user
    )));
    // Already verified: nothing happens (an active account keeps its
    // password).
    let active = h.active_user("ok@example.com").await;
    let mut tx = h.pool.begin().await.unwrap();
    assert!(
        !h.service
            .confirm_mailbox_control_in_tx(&mut tx, None, active, MailboxProof::Passwordless)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert!(h.password_matches(active, PASSWORD).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_session_issued_link_needs_the_account_holder(pool: PgPool) {
    let h = Harness::new(pool).await;
    // A limited-mode account with the attacker's password asks for a
    // verification e-mail; it lands in the victim's mailbox.
    let user = h
        .unverified_with_password("victim@example.com", ATTACKER)
        .await;
    h.service
        .resend_own_verification(&h.fresh(user), &h.ctx())
        .await
        .unwrap();
    let (token, code) = all_verifications(&h, "victim@example.com").pop().unwrap();
    // The victim clicks it: the link alone does not verify the attacker's
    // account, and the code is useless without the attacker's session.
    let err = h.verify_link(&token, None, None).await.unwrap_err();
    assert_eq!(err.code().code(), "registration_confirmation_required");
    let err = h
        .verify_link(&token, None, Some(chosen(OWNER)))
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "registration_password_mismatch");
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "email": "victim@example.com", "code": code }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    assert!(
        h.user_by_id(user)
            .await
            .unwrap()
            .email_verified_at
            .is_none()
    );
    // The mailbox owner takes the account over with a new password; whoever
    // knew the old one loses every session.
    h.verify_link(&token, None, Some(new_password(OWNER)))
        .await
        .unwrap();
    assert!(h.password_matches(user, OWNER).await);
    assert!(!h.password_matches(user, ATTACKER).await);
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
    assert!(h.ports.session_revoker.calls().iter().any(|c| matches!(
        c,
        RevocationCall::AllForUser(u, RevocationReason::PasswordChanged, o)
            if *u == user && o.also_trusted_devices
    )));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_05_later_registration_keeps_the_placeholder_until_it_expires(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup_with("victim@example.com", ATTACKER).await;
    let user = h.user("victim@example.com").await.unwrap().id;
    h.ports.clock.advance(Duration::from_secs(6 * 86_400));
    let victim_handle = h.signup_with("victim@example.com", OWNER).await;
    // Day 7+: the attacker's registration expired, the victim's has not —
    // the account is kept and the victim can still finish.
    h.ports.clock.advance(Duration::from_secs(86_400 + 60));
    assert_eq!(h.service.purge_unverified_accounts(100).await.unwrap(), 0);
    assert_eq!(registrations(&h.pool, user).await, 1, "expired one deleted");
    // The victim's 24-hour link has expired meanwhile: a resend (bound to
    // the victim's handle) gives a fresh one.
    h.service
        .resend_verification(
            &h.ctx(),
            "victim@example.com",
            Some(&secret(&victim_handle)),
        )
        .await
        .unwrap();
    h.drain().await;
    let (token, _) = all_verifications(&h, "victim@example.com").pop().unwrap();
    h.verify_link(&token, Some(&victim_handle), None)
        .await
        .unwrap();
    assert!(h.password_matches(user, OWNER).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_email_change_link_requires_the_account_holders_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    // The attacker's own, verified account asks to move to the victim's
    // (unregistered) address; the confirmation lands in the victim's
    // mailbox.
    let attacker = h.active_user("attacker@evil.example").await;
    let bystander = h.active_user("bystander@example.com").await;
    h.service
        .request_email_change(&h.fresh(attacker), &h.ctx(), "victim@example.com")
        .await
        .unwrap();
    h.drain().await;
    let mail = h
        .mails("email_change_verification", "victim@example.com")
        .pop()
        .unwrap();
    let token = match mail.kind {
        authn_core::ports::NotificationKind::EmailChangeVerification { token, .. } => {
            token.expose().to_owned()
        }
        other => panic!("{other:?}"),
    };
    // The victim clicks it without being the account holder: nothing
    // happens (otherwise the attacker's account — with its password and
    // passkeys — would be verified for the victim's mailbox).
    TestRequest::post("/v1/email/change/confirm")
        .json(&json!({ "token": token }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    TestRequest::post("/v1/email/change/confirm")
        .json(&json!({ "token": token }))
        .send(&h.app_as(&h.fresh(bystander)))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
    assert_eq!(
        h.user_by_id(attacker).await.unwrap().email.as_deref(),
        Some("attacker@evil.example")
    );
    // Not consumed by those attempts: the real requester can still confirm.
    TestRequest::post("/v1/email/change/confirm")
        .json(&json!({ "token": token }))
        .send(&h.app_as(&h.fresh(attacker)))
        .await
        .assert_status(StatusCode::OK);
}

/// Revokes all sessions of `user` through the account-aware revoker.
async fn revoke(h: &Harness, user: authn_core::id::UserId, reason: RevocationReason) {
    let revoker =
        AccountAwareSessionRevoker::new(h.ports.session_revoker.clone(), h.service.clone());
    let mut tx = h.pool.begin().await.unwrap();
    revoker
        .revoke_all_for_user(&mut tx, user, reason, RevokeOptions::default())
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn pending_change_tokens(h: &Harness, user: authn_core::id::UserId) -> i64 {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM one_time_tokens WHERE user_id = $1 \
         AND purpose IN ('email_change', 'email_change_code') \
         AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $2",
    )
    .bind(user)
    .bind(h.ports.clock.now())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    n
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_pending_email_change_ends_on_reset_and_sign_out_everywhere(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("owner@example.com").await;
    let request = |to: &'static str| {
        let h = &h;
        async move {
            h.service
                .request_email_change(&h.fresh(user), &h.ctx(), to)
                .await
                .unwrap();
            h.drain().await;
        }
    };
    for reason in [
        RevocationReason::PasswordReset,
        RevocationReason::UserRequest,
        RevocationReason::PasswordChanged,
        RevocationReason::NotMe,
        RevocationReason::RefreshTokenReuse,
    ] {
        h.ports.clock.advance(Duration::from_secs(1));
        request("attacker@evil.example").await;
        assert_eq!(pending_change_tokens(&h, user).await, 2, "{reason:?}");
        revoke(&h, user, reason).await;
        assert_eq!(pending_change_tokens(&h, user).await, 0, "{reason:?}");
    }
    // `revoke_all_except` (password change, PWD-06) too.
    request("attacker@evil.example").await;
    let revoker =
        AccountAwareSessionRevoker::new(h.ports.session_revoker.clone(), h.service.clone());
    let mut tx = h.pool.begin().await.unwrap();
    revoker
        .revoke_all_except(
            &mut tx,
            user,
            SessionId::generate(),
            RevocationReason::PasswordChanged,
            RevokeOptions::default(),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(pending_change_tokens(&h, user).await, 0);
    // Unrelated revocations keep it; the emergency revocation ends every
    // user's pending change.
    request("attacker@evil.example").await;
    let mut tx = h.pool.begin().await.unwrap();
    revoker
        .revoke_for_user_in_org(
            &mut tx,
            user,
            authn_core::id::OrgId::generate(),
            RevocationReason::MembershipRemoved,
        )
        .await
        .unwrap();
    revoker
        .revoke_all_for_user(
            &mut tx,
            user,
            RevocationReason::Expired,
            RevokeOptions::default(),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(pending_change_tokens(&h, user).await, 2);
    let mut tx = h.pool.begin().await.unwrap();
    revoker
        .revoke_everything(&mut tx, RevocationReason::Emergency)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(pending_change_tokens(&h, user).await, 0);
    // The inner revoker saw every call.
    assert!(
        h.ports
            .session_revoker
            .calls()
            .iter()
            .any(|c| matches!(c, RevocationCall::Everything(RevocationReason::Emergency)))
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_reset_keeps_the_revert_link_of_a_completed_change(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("owner@example.com").await;
    h.service
        .request_email_change(&h.fresh(user), &h.ctx(), "attacker@evil.example")
        .await
        .unwrap();
    h.drain().await;
    let mail = h
        .mails("email_change_verification", "attacker@evil.example")
        .pop()
        .unwrap();
    let token = match mail.kind {
        authn_core::ports::NotificationKind::EmailChangeVerification { token, .. } => {
            token.expose().to_owned()
        }
        other => panic!("{other:?}"),
    };
    h.service
        .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&token))
        .await
        .unwrap();
    let revert = match h
        .mails("email_changed", "owner@example.com")
        .pop()
        .unwrap()
        .kind
    {
        authn_core::ports::NotificationKind::EmailChanged { revert_token, .. } => {
            revert_token.expose().to_owned()
        }
        other => panic!("{other:?}"),
    };
    revoke(&h, user, RevocationReason::PasswordReset).await;
    // The owner's way back survives.
    h.service
        .revert_email_change(&h.ctx(), &secret(&revert))
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("owner@example.com")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_10_export_lists_pending_registrations_without_secrets(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h
        .unverified_with_password("limited@example.com", PASSWORD)
        .await;
    let handle = h.signup_with("limited@example.com", ATTACKER).await;
    let export = h
        .service
        .export_data(&h.fresh(user), &h.ctx())
        .await
        .unwrap();
    let pending = &export["sections"]["account"]["pending_registrations"];
    assert_eq!(pending.as_array().unwrap().len(), 1, "{export}");
    assert_eq!(pending[0]["requested_from_ip"], "198.51.100.7");
    let text = export.to_string();
    assert!(!text.contains("$argon2id$"), "no password hash");
    assert!(!text.contains(&handle), "no handle");
    let (token, code) = all_verifications(&h, "limited@example.com").pop().unwrap();
    assert!(!text.contains(&token));
    assert!(!text.contains(&format!("\"{code}\"")));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_11_new_password_on_the_link_page_needs_its_own_terms_acceptance(pool: PgPool) {
    use authn_core::config::account::{TermsDocument, TermsVersionConfig};
    let h = Harness::with(pool, |s| {
        s.account.require_terms_acceptance = true;
        s.account.terms = vec![TermsVersionConfig {
            document: TermsDocument::TermsOfService,
            version: "2026-01".to_owned(),
            url: None,
            published_at: time::OffsetDateTime::UNIX_EPOCH,
            requires_reacceptance: false,
        }];
    })
    .await;
    h.service.sync_terms_versions().await.unwrap();
    // The squatter accepted the terms; that acceptance is not the owner's.
    let input = serde_json::from_value(json!({
        "email": "victim@example.com",
        "password": ATTACKER,
        "accepted_terms": [{ "document": "terms_of_service", "version": "2026-01" }],
    }))
    .unwrap();
    h.service.signup(&h.ctx(), input).await.unwrap();
    h.drain().await;
    let user = h.user("victim@example.com").await.unwrap().id;
    let (token, _) = all_verifications(&h, "victim@example.com").pop().unwrap();
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token, "new_password": OWNER }))
        .send(&h.app())
        .await
        .assert_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "terms_acceptance_required",
        );
    TestRequest::post("/v1/email/verify")
        .json(&json!({ "token": token, "new_password": OWNER,
            "accepted_terms": [{ "document": "terms_of_service", "version": "2026-01" }] }))
        .header("user-agent", "owner-browser/1.0")
        .send(&h.app())
        .await
        .assert_status(StatusCode::OK);
    let rows: Vec<(Option<String>,)> =
        sqlx::query_as("SELECT user_agent FROM consents WHERE user_id = $1")
            .bind(user)
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(rows, vec![(Some("owner-browser/1.0".to_owned()),)]);
    assert!(h.password_matches(user, OWNER).await);
}

/// Inner revoker that supports `revoke_everything_except` (authn-session's
/// does; the testkit fake keeps the port's refusing default).
struct ExceptRevoker {
    kept: std::sync::Mutex<Vec<authn_core::id::SessionId>>,
}

#[async_trait::async_trait]
impl authn_core::ports::SessionRevoker for ExceptRevoker {
    async fn revoke_session(
        &self,
        _conn: &mut sqlx::PgConnection,
        _session: authn_core::id::SessionId,
        _reason: RevocationReason,
    ) -> Result<bool, authn_core::error::AuthError> {
        Ok(false)
    }
    async fn revoke_all_for_user(
        &self,
        _conn: &mut sqlx::PgConnection,
        _user: authn_core::id::UserId,
        _reason: RevocationReason,
        _options: RevokeOptions,
    ) -> Result<u64, authn_core::error::AuthError> {
        Ok(0)
    }
    async fn revoke_all_except(
        &self,
        _conn: &mut sqlx::PgConnection,
        _user: authn_core::id::UserId,
        _keep: authn_core::id::SessionId,
        _reason: RevocationReason,
        _options: RevokeOptions,
    ) -> Result<u64, authn_core::error::AuthError> {
        Ok(0)
    }
    async fn revoke_for_user_in_org(
        &self,
        _conn: &mut sqlx::PgConnection,
        _user: authn_core::id::UserId,
        _org: authn_core::id::OrgId,
        _reason: RevocationReason,
    ) -> Result<u64, authn_core::error::AuthError> {
        Ok(0)
    }
    async fn revoke_all_for_org(
        &self,
        _conn: &mut sqlx::PgConnection,
        _org: authn_core::id::OrgId,
        _reason: RevocationReason,
    ) -> Result<u64, authn_core::error::AuthError> {
        Ok(0)
    }
    async fn revoke_everything(
        &self,
        _conn: &mut sqlx::PgConnection,
        _reason: RevocationReason,
    ) -> Result<u64, authn_core::error::AuthError> {
        Ok(0)
    }
    async fn revoke_everything_except(
        &self,
        _conn: &mut sqlx::PgConnection,
        keep: authn_core::id::SessionId,
        _reason: RevocationReason,
    ) -> Result<u64, authn_core::error::AuthError> {
        self.kept.lock().unwrap().push(keep);
        Ok(7)
    }
}

/// K-10 (ADM-06): the emergency "revoke every session except the
/// caller's" goes through the account-aware revoker with the same account
/// consequence as `revoke_everything` (every pending e-mail change ends)
/// instead of failing with the port's refusing default.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_emergency_revoke_except_caller_ends_pending_email_changes(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("owner@example.com").await;
    h.service
        .request_email_change(&h.fresh(user), &h.ctx(), "attacker@evil.example")
        .await
        .unwrap();
    h.drain().await;
    assert_eq!(pending_change_tokens(&h, user).await, 2);
    let inner = std::sync::Arc::new(ExceptRevoker {
        kept: std::sync::Mutex::new(Vec::new()),
    });
    let revoker = AccountAwareSessionRevoker::new(inner.clone(), h.service.clone());
    let keep = authn_core::id::SessionId::generate();
    let mut tx = h.pool.begin().await.unwrap();
    let revoked = revoker
        .revoke_everything_except(&mut tx, keep, RevocationReason::Emergency)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(revoked, 7, "the inner revoker's count is returned");
    assert_eq!(inner.kept.lock().unwrap().as_slice(), &[keep]);
    assert_eq!(pending_change_tokens(&h, user).await, 0);
}

// --- K-58: ADR 0002 residual risks ---------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_k58_exhausted_email_budget_never_drops_the_owners_registration(pool: PgPool) {
    // Targeted sign-up DoS: the attacker spends the address's daily e-mail
    // budget (3) so the owner's own registration gets no e-mail. It used to
    // be dropped silently; now it is stored and the owner completes it with
    // any e-mailed link opened in their browser.
    let h = Harness::new(pool).await;
    for _ in 0..4 {
        h.signup_with("target@example.com", ATTACKER).await;
    }
    let user = h.user("target@example.com").await.unwrap().id;
    let before = all_verifications(&h, "target@example.com").len();
    let owner_handle = h.signup_with("target@example.com", OWNER).await;
    assert_eq!(
        all_verifications(&h, "target@example.com").len(),
        before,
        "no e-mail past the budget (mail bombing)"
    );
    assert_eq!(registrations(&h.pool, user).await, 5, "stored nonetheless");
    let (any_link, _) = all_verifications(&h, "target@example.com")[0].clone();
    h.verify_link(&any_link, Some(&owner_handle), None)
        .await
        .unwrap();
    assert!(h.password_matches(user, OWNER).await);
    assert!(!h.password_matches(user, ATTACKER).await);
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_02_k58_a_link_never_completes_a_registration_of_another_account(pool: PgPool) {
    let h = Harness::new(pool).await;
    let other_handle = h.signup_with("other@example.com", ATTACKER).await;
    h.signup_with("target@example.com", OWNER).await;
    let (target_link, _) = all_verifications(&h, "target@example.com")[0].clone();
    let err = h
        .verify_link(&target_link, Some(&other_handle), None)
        .await
        .unwrap_err();
    assert_eq!(err.code().code(), "registration_confirmation_required");
    let other = h.user("other@example.com").await.unwrap();
    assert_eq!(other.status, AccountStatus::PendingVerification);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_04_k58_code_guesses_per_address_are_capped_per_day(pool: PgPool) {
    // However many registrations the attacker creates for the target
    // address (each with five guesses of its own), at most five code
    // submissions per day reach the address.
    let h = Harness::with(pool, |s| {
        s.registration_code_guesses = RateLimitPolicy::new(
            authn_account::REGISTRATION_CODE_GUESSES_PER_DAY,
            Duration::from_secs(24 * 3600),
        );
    })
    .await;
    let mut handles = Vec::new();
    for _ in 0..3 {
        handles.push(h.signup_with("target@example.com", ATTACKER).await);
    }
    let mut outcomes = Vec::new();
    for handle in handles.iter().cycle().take(8) {
        let err = h.verify_code(Some(handle), "000000").await.unwrap_err();
        outcomes.push(err.code().code().to_owned());
    }
    assert_eq!(outcomes[..5], ["invalid_code"; 5]);
    assert_eq!(outcomes[5..], ["rate_limited"; 3], "{outcomes:?}");
    // The mailbox owner is never locked out: the link still completes.
    let owner_handle = h.signup_with("target@example.com", OWNER).await;
    let (link, _) = all_verifications(&h, "target@example.com").pop().unwrap();
    h.verify_link(&link, Some(&owner_handle), None)
        .await
        .unwrap();
}
