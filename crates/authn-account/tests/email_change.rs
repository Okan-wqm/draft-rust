#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! E-mail change and revert: ACC-07.

mod common;

use authn_core::ports::Clock as _;

use std::time::Duration;

use authn_core::domain::AccountStatus;
use authn_core::id::UserId;
use authn_core::ports::{DomainEventKind, NotificationKind, RevocationReason, SecurityEventKind};
use authn_store::{NewOneTimeToken, OneTimeTokenRepository, TokenPurpose, TokenSubject};
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::TestRequest;
use common::{Harness, PASSWORD, secret};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

fn change_secrets(h: &Harness, new_email: &str) -> (String, String) {
    match h
        .mails("email_change_verification", new_email)
        .pop()
        .unwrap()
        .kind
    {
        NotificationKind::EmailChangeVerification { token, code, .. } => {
            (token.expose().to_owned(), code.expose().to_owned())
        }
        other => panic!("{other:?}"),
    }
}

fn revert_token(h: &Harness, old_email: &str) -> String {
    match h.mails("email_changed", old_email).pop().unwrap().kind {
        NotificationKind::EmailChanged {
            revert_token,
            new_email_masked,
            ..
        } => {
            assert!(new_email_masked.contains("***"), "{new_email_masked}");
            revert_token.expose().to_owned()
        }
        other => panic!("{other:?}"),
    }
}

async fn request(h: &Harness, user: UserId, new_email: &str) {
    TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": new_email }))
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_status(StatusCode::ACCEPTED);
    h.drain().await;
}

/// A password-reset token as authn-password would issue it (to check that
/// address changes revoke it).
async fn issue_reset_token(h: &Harness, user: UserId) -> authn_crypto::token::OpaqueToken {
    let token = authn_crypto::token::OpaqueToken::generate().unwrap();
    let mut conn = h.pool.acquire().await.unwrap();
    let now = h.ports.clock.now();
    OneTimeTokenRepository::create(
        &mut conn,
        &NewOneTimeToken {
            id: authn_core::id::OneTimeTokenId::generate(),
            purpose: TokenPurpose::PasswordReset,
            token_hash: token.hash(),
            subject: TokenSubject::user(user),
            group_id: None,
            target: None,
            max_attempts: 1,
            metadata: json!({}),
            created_ip: None,
            created_at: now,
            expires_at: now + time::Duration::minutes(30),
        },
        true,
    )
    .await
    .unwrap();
    token
}

async fn reset_token_active(h: &Harness, token: &authn_crypto::token::OpaqueToken) -> bool {
    OneTimeTokenRepository::find_active_link(
        &h.pool,
        TokenPurpose::PasswordReset,
        &token.hash(),
        h.ports.clock.now(),
    )
    .await
    .unwrap()
    .is_some()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_email_change_requires_step_up(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("old@example.com").await;
    TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": "new@example.com" }))
        .send(&h.app_as(&h.stale(user)))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": "new@example.com" }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let mut impersonated = h.fresh(user);
    impersonated.impersonation = Some(authn_core::domain::Impersonation {
        admin_user_id: UserId::generate(),
        read_only: false,
        expires_at: h.ports.clock.now() + time::Duration::minutes(10),
    });
    TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": "new@example.com" }))
        .send(&h.app_as(&impersonated))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": "OLD@example.com" }))
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "email_unchanged");
    h.drain().await;
    assert!(
        h.mails("email_change_verification", "new@example.com")
            .is_empty()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_link_confirmation_changes_address_and_notifies_old_one(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("old@example.com").await;
    let reset = issue_reset_token(&h, user).await;
    request(&h, user, "New@Example.org").await;
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::EmailChangeRequested)
            .len(),
        1
    );
    let (token, _) = change_secrets(&h, "new@example.org");
    // Nothing changes before confirmation.
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("old@example.com")
    );
    TestRequest::post("/v1/email/change/confirm")
        .json(&json!({ "token": token }))
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_status(StatusCode::OK);
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.email.as_deref(), Some("New@example.org"));
    assert!(record.email_verified_at.is_some());
    // The old address gets the revert link; reset tokens sent to it die.
    revert_token(&h, "old@example.com");
    assert!(!reset_token_active(&h, &reset).await);
    assert!(
        h.ports
            .events
            .recorded()
            .iter()
            .any(|e| e.kind == DomainEventKind::UserEmailChanged)
    );
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::EmailChanged)
            .len(),
        1
    );
    // Single use.
    TestRequest::post("/v1/email/change/confirm")
        .json(&json!({ "token": token }))
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_code_confirmation_by_the_signed_in_user(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("old@example.com").await;
    request(&h, user, "mobile@example.org").await;
    let (_, code) = change_secrets(&h, "mobile@example.org");
    let app = h.app_as(&h.fresh(user));
    TestRequest::post("/v1/me/email/confirm")
        .json(&json!({ "code": if code == "000000" { "111111" } else { "000000" } }))
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    TestRequest::post("/v1/me/email/confirm")
        .json(&json!({ "code": code }))
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("mobile@example.org")
    );
    // Another user cannot use the code: codes are bound to their owner.
    let other = h.active_user("other@example.com").await;
    TestRequest::post("/v1/me/email/confirm")
        .json(&json!({ "code": code }))
        .send(&h.app_as(&h.fresh(other)))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_taken_address_is_indistinguishable_for_the_requester(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("me@example.com").await;
    let victim = h.active_user("taken@example.com").await;
    h.ports.notifier.take();
    let free = TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": "free@example.com" }))
        .send(&h.app_as(&h.fresh(user)))
        .await;
    let taken = TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": "taken@example.com" }))
        .send(&h.app_as(&h.fresh(user)))
        .await;
    assert_eq!(free.status, taken.status);
    assert_eq!(free.body, taken.body);
    h.drain().await;
    assert!(
        h.mails("email_change_verification", "taken@example.com")
            .is_empty()
    );
    let notice = h.mails("registration_attempt", "taken@example.com");
    assert_eq!(notice.len(), 1);
    assert_eq!(notice[0].recipient.user_id, Some(victim));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_revert_restores_address_revokes_sessions_and_forces_reset(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("owner@example.com").await;
    // An attacker with a stolen session changes the address …
    request(&h, user, "attacker@evil.example").await;
    let (token, _) = change_secrets(&h, "attacker@evil.example");
    h.service
        .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&token))
        .await
        .unwrap();
    // … requests a password reset to the new address and schedules deletion.
    let reset = issue_reset_token(&h, user).await;
    h.service
        .request_deletion(&h.fresh(user), &h.ctx())
        .await
        .unwrap();
    assert!(h.password_matches(user, PASSWORD).await);

    // The owner reverts from the old address.
    let revert = revert_token(&h, "owner@example.com");
    let res = TestRequest::post("/v1/email/change/revert")
        .json(&json!({ "token": revert }))
        .send(&h.app())
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(
        res.json::<serde_json::Value>(),
        json!({ "password_reset_required": true })
    );
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.email.as_deref(), Some("owner@example.com"));
    assert_eq!(record.status, AccountStatus::Active, "deletion cancelled");
    // Every session and trusted device is revoked in the same transaction.
    assert!(h.ports.session_revoker.calls().iter().any(|c| matches!(
        c,
        RevocationCall::AllForUser(u, RevocationReason::EmailChangeReverted, opts)
            if *u == user && opts.also_trusted_devices
    )));
    // The attacker's reset link is dead and the known password is useless.
    assert!(!reset_token_active(&h, &reset).await);
    assert!(!h.password_matches(user, PASSWORD).await);
    let credential = authn_store::UserRepository::find_password(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert!(credential.must_change);
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::EmailChangeReverted)
            .len(),
        1
    );
    // The revert link is single use.
    TestRequest::post("/v1/email/change/revert")
        .json(&json!({ "token": revert }))
        .send(&h.app())
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_old_address_is_reserved_during_the_revert_period(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("keep@example.com").await;
    request(&h, user, "moved@example.com").await;
    let (token, _) = change_secrets(&h, "moved@example.com");
    h.service
        .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&token))
        .await
        .unwrap();
    let revert = revert_token(&h, "keep@example.com");
    h.ports.notifier.take();
    // An attacker tries to take the old address to block the revert.
    h.signup("keep@example.com").await;
    assert!(h.user("keep@example.com").await.is_none(), "reserved");
    let notice = h.mails("registration_attempt", "keep@example.com");
    assert_eq!(notice.len(), 1);
    assert_eq!(notice[0].recipient.user_id, Some(user));
    // Another account cannot switch to it either.
    let other = h.active_user("other@example.com").await;
    request(&h, other, "keep@example.com").await;
    assert!(
        h.mails("email_change_verification", "keep@example.com")
            .is_empty()
    );
    // The revert still works.
    h.service
        .revert_email_change(&h.ctx(), &secret(&revert))
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("keep@example.com")
    );
    // After the revert period the reservation is cleaned up.
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM email_reservations")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "released by the revert");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_reservations_expire_with_the_revert_link(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("a@example.com").await;
    request(&h, user, "b@example.com").await;
    let (token, _) = change_secrets(&h, "b@example.com");
    h.service
        .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&token))
        .await
        .unwrap();
    let revert = revert_token(&h, "a@example.com");
    h.ports.clock.advance(Duration::from_secs(7 * 86_400 + 60));
    assert_eq!(h.service.purge_expired_reservations(100).await.unwrap(), 1);
    assert!(
        h.service
            .revert_email_change(&h.ctx(), &secret(&revert))
            .await
            .is_err(),
        "revert link expired after 7 days"
    );
    // Now the address is free again.
    h.signup("a@example.com").await;
    assert!(h.user("a@example.com").await.is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_revert_invalidates_other_revert_links(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("first@example.com").await;
    // first -> second (revert link R1 to first) -> third (R2 to second).
    for (from, to) in [
        ("first@example.com", "second@example.com"),
        ("second@example.com", "third@example.com"),
    ] {
        request(&h, user, to).await;
        let (token, _) = change_secrets(&h, to);
        h.service
            .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&token))
            .await
            .unwrap();
        revert_token(&h, from);
    }
    let r1 = revert_token(&h, "first@example.com");
    let r2 = revert_token(&h, "second@example.com");
    h.service
        .revert_email_change(&h.ctx(), &secret(&r1))
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("first@example.com")
    );
    // The intermediate address cannot take the account back.
    assert!(
        h.service
            .revert_email_change(&h.ctx(), &secret(&r2))
            .await
            .is_err()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_verification_link_for_new_address_is_bound_to_it(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("x@example.com").await;
    request(&h, user, "y@example.com").await;
    let (first, _) = change_secrets(&h, "y@example.com");
    request(&h, user, "z@example.com").await;
    // A newer request revokes the older link.
    assert!(
        h.service
            .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&first))
            .await
            .is_err()
    );
    let (second, _) = change_secrets(&h, "z@example.com");
    h.service
        .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&second))
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("z@example.com")
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_concurrent_confirmations_apply_once(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("c@example.com").await;
    request(&h, user, "d@example.com").await;
    let (token, _) = change_secrets(&h, "d@example.com");
    let mut handles = Vec::new();
    for _ in 0..6 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let token = token.clone();
        let principal = h.fresh(user);
        handles.push(tokio::spawn(async move {
            service
                .confirm_email_change_link(Some(&principal), &ctx, &secret(&token))
                .await
        }));
    }
    let mut ok = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(h.mails("email_changed", "c@example.com").len(), 1);
}

/// Confirms a change of `user` to `to` with the e-mailed link.
async fn change(h: &Harness, user: UserId, to: &str) {
    request(h, user, to).await;
    let (token, _) = change_secrets(h, to);
    h.service
        .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&token))
        .await
        .unwrap();
}

/// Security review: an attacker with a stolen, freshly authenticated
/// session changes the address twice (owner -> evil1 -> evil2) and then
/// reverts the *second* change with the link sent to evil1, which he
/// controls. That revert must not cancel the original owner's revert link.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_intermediate_revert_cannot_cancel_the_owners_revert(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("owner@example.com").await;
    h.ports.clock.advance(Duration::from_secs(60));
    change(&h, user, "evil1@example.net").await;
    h.ports.clock.advance(Duration::from_secs(60));
    change(&h, user, "evil2@example.net").await;
    let owner_revert = revert_token(&h, "owner@example.com");
    let attacker_revert = revert_token(&h, "evil1@example.net");
    h.ports.clock.advance(Duration::from_secs(60));
    h.service
        .revert_email_change(&h.ctx(), &secret(&attacker_revert))
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("evil1@example.net")
    );
    // The owner's link (sent before the attacker's) still works.
    let outcome = h
        .service
        .revert_email_change(&h.ctx(), &secret(&owner_revert))
        .await
        .unwrap();
    assert!(outcome.password_reset_required);
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("owner@example.com")
    );
    // Nothing is left that could move the account again.
    let (active,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM one_time_tokens WHERE user_id = $1 \
         AND purpose = 'email_change_revert' AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(user)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(active, 0);
}

/// Security review: when a revert moves the account away from an address
/// that an earlier revert link still points to, that address stays reserved
/// for the account — nobody can register it and block the earlier revert.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_address_left_by_a_revert_stays_reserved_for_earlier_links(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("home@example.com").await;
    h.ports.clock.advance(Duration::from_secs(60));
    change(&h, user, "work@example.net").await;
    h.ports.clock.advance(Duration::from_secs(60));
    change(&h, user, "home@example.com").await;
    let home_revert = revert_token(&h, "home@example.com");
    let work_revert = revert_token(&h, "work@example.net");
    // Whoever reads work@ reverts the account to it, leaving home@ ...
    h.service
        .revert_email_change(&h.ctx(), &secret(&work_revert))
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("work@example.net")
    );
    // ... which cannot be squatted while the earlier link is valid.
    h.signup("home@example.com").await;
    assert!(h.user("home@example.com").await.is_none(), "still reserved");
    h.service
        .revert_email_change(&h.ctx(), &secret(&home_revert))
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("home@example.com")
    );
}

/// Security review (ACC-02 for signed-in requesters): a request for a taken
/// address must end the previous pending change exactly like a request for
/// a free address does; otherwise a still-working earlier link reveals that
/// the address is registered.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_request_for_taken_address_ends_the_previous_pending_change(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.active_user("taken@example.com").await;
    let user = h.active_user("prober@example.com").await;
    request(&h, user, "mine@example.net").await;
    let (link, code) = change_secrets(&h, "mine@example.net");
    request(&h, user, "taken@example.com").await;
    TestRequest::post("/v1/email/change/confirm")
        .json(&json!({ "token": link }))
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
    TestRequest::post("/v1/me/email/confirm")
        .json(&json!({ "code": code }))
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_error(StatusCode::BAD_REQUEST, "invalid_code");
    assert_eq!(
        h.user_by_id(user).await.unwrap().email.as_deref(),
        Some("prober@example.com")
    );
}

/// Security review: wrong-code answers are the same whether a code exists
/// (free address) or not (taken address) — including after the code is
/// locked out (no distinguishable `too_many_attempts`).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_code_attempts_do_not_reveal_whether_the_address_is_taken(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.active_user("taken@example.com").await;
    let a = h.active_user("a@example.com").await;
    let b = h.active_user("b@example.com").await;
    request(&h, a, "taken@example.com").await;
    request(&h, b, "free@example.com").await;
    let (_, real) = change_secrets(&h, "free@example.com");
    let wrong = format!("{:06}", (real.parse::<u32>().unwrap() + 1) % 1_000_000);
    let mut answers = Vec::new();
    for user in [a, b] {
        let mut sequence = Vec::new();
        for _ in 0..7 {
            let response = TestRequest::post("/v1/me/email/confirm")
                .json(&json!({ "code": wrong }))
                .send(&h.app_as(&h.fresh(user)))
                .await;
            sequence.push((response.status, response.error().code));
        }
        answers.push(sequence);
    }
    assert_eq!(answers[0], answers[1]);
    assert!(
        answers[0]
            .iter()
            .all(|(status, code)| *status == StatusCode::BAD_REQUEST && code == "invalid_code"),
        "{:?}",
        answers[0]
    );
}

/// K-40: the restored address is told about the revert (and the forced
/// password reset) by an `email_change_reverted` notice queued in the
/// revert's transaction; a failed revert sends nothing.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_revert_notifies_the_restored_address(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("restored@example.com").await;
    request(&h, user, "attacker@evil.example").await;
    let (token, _) = change_secrets(&h, "attacker@evil.example");
    h.service
        .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&token))
        .await
        .unwrap();
    let revert = revert_token(&h, "restored@example.com");
    assert!(
        h.ports
            .notifier
            .with_template("email_change_reverted")
            .is_empty()
    );

    // A forged token reverts nothing and notifies nobody.
    let forged = authn_crypto::token::OpaqueToken::generate().unwrap();
    assert!(
        h.service
            .revert_email_change(&h.ctx(), &secret(forged.expose()))
            .await
            .is_err()
    );
    assert!(
        h.ports
            .notifier
            .with_template("email_change_reverted")
            .is_empty()
    );

    let before = h.ports.clock.now();
    h.service
        .revert_email_change(&h.ctx(), &secret(&revert))
        .await
        .unwrap();
    let sent = h.mails("email_change_reverted", "restored@example.com");
    assert_eq!(sent.len(), 1, "exactly one notice, to the restored address");
    assert_eq!(sent[0].recipient.user_id, Some(user));
    match &sent[0].kind {
        NotificationKind::EmailChangeReverted { at } => assert!(*at >= before),
        other => panic!("{other:?}"),
    }
    assert!(
        h.mails("email_change_reverted", "attacker@evil.example")
            .is_empty(),
        "the abandoned address learns nothing"
    );
}
