#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Password reset at service level: PWD-07 (request), PWD-08 (link and
//! code), PWD-09 (completion).

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::domain::AccountStatus;
use authn_core::error::{AuthError, codes};
use authn_core::id::UserId;
use authn_core::ports::{
    Actor, Clock, EventOutcome, NotificationKind, RateLimitPolicy, RevocationReason, RevokeOptions,
    SecurityEventKind,
};
use authn_password::{ProfileHints, ProfileLookup, ResetProof};
use authn_store::UserRepository;
use authn_testkit::fakes::RevocationCall;
use authn_testkit::timing::compare_timings;
use common::{Harness, STRONG, STRONG_2, STRONG_3, email, secret};

fn link(token: &str) -> ResetProof {
    ResetProof::Link {
        token: secret(token),
    }
}

fn code_proof(address: &str, code: &str) -> ResetProof {
    ResetProof::Code {
        email: email(address),
        code: secret(code),
    }
}

fn wrong(code: &str) -> String {
    let first = code.chars().next().unwrap();
    let replacement = if first == '0' { '1' } else { '0' };
    let rest: String = code.chars().skip(1).collect();
    format!("{replacement}{rest}")
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_reset_token_is_256_bit_single_use_and_only_its_hash_is_stored(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com", Some(STRONG)).await;
    let (token, code) = h.forgot("alice@example.com").await;

    // 256 bits, URL-safe base64 without padding.
    assert_eq!(token.len(), 43);
    assert_eq!(
        data_encoding::BASE64URL_NOPAD
            .decode(token.as_bytes())
            .unwrap()
            .len(),
        32
    );
    let code = code.expect("mobile code issued");
    assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));

    // Only hashes are stored; link expires after 30 min, code after 15 min.
    let rows: Vec<(Vec<u8>, String, time::OffsetDateTime, time::OffsetDateTime)> = sqlx::query_as(
        "SELECT token_hash, kind, created_at, expires_at FROM one_time_tokens \
             WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL ORDER BY kind",
    )
    .bind(user)
    .fetch_all(&h.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    let (code_row, link_row) = (&rows[0], &rows[1]);
    assert_eq!((code_row.1.as_str(), link_row.1.as_str()), ("code", "link"));
    assert_eq!(link_row.0, authn_crypto::sha256(token.as_bytes()).to_vec());
    assert_ne!(link_row.0, token.as_bytes());
    assert_ne!(code_row.0, code.as_bytes());
    assert_eq!(link_row.3 - link_row.2, time::Duration::minutes(30));
    assert_eq!(code_row.3 - code_row.2, time::Duration::minutes(15));

    h.service
        .complete_reset(&h.ctx(), link(&token), &secret(STRONG_2))
        .await
        .unwrap();
    assert!(h.password_is(user, STRONG_2).await);
    assert!(!h.password_is(user, STRONG).await);

    // Single use: the link and its sibling code are dead.
    let err = h
        .service
        .complete_reset(&h.ctx(), link(&token), &secret(STRONG_3))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            code_proof("alice@example.com", &code),
            &secret(STRONG_3),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    assert!(h.password_is(user, STRONG_2).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_new_request_revokes_previous_link_and_code(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("bob@example.com", Some(STRONG)).await;
    let (old_token, old_code) = h.forgot("bob@example.com").await;
    let (new_token, _) = h.forgot("bob@example.com").await;
    assert_ne!(old_token, new_token);
    for proof in [
        link(&old_token),
        code_proof("bob@example.com", &old_code.unwrap()),
    ] {
        let err = h
            .service
            .complete_reset(&h.ctx(), proof, &secret(STRONG_2))
            .await
            .unwrap_err();
        assert!(
            err.is(codes::common::INVALID_OR_EXPIRED_TOKEN) || err.is(codes::common::INVALID_CODE)
        );
    }
    h.service
        .complete_reset(&h.ctx(), link(&new_token), &secret(STRONG_2))
        .await
        .unwrap();
    assert!(h.password_is(user, STRONG_2).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_link_expires_after_thirty_minutes_and_code_after_fifteen(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("carol@example.com", Some(STRONG)).await;
    let (token, code) = h.forgot("carol@example.com").await;
    h.ports.clock.advance(Duration::from_secs(16 * 60));
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            code_proof("carol@example.com", &code.unwrap()),
            &secret(STRONG_2),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    h.ports.clock.advance(Duration::from_secs(15 * 60));
    let err = h
        .service
        .complete_reset(&h.ctx(), link(&token), &secret(STRONG_2))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    assert!(h.password_is(user, STRONG).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_only_eligible_accounts_receive_an_email_and_every_request_is_audited(
    pool: sqlx::PgPool,
) {
    let h = Harness::new(pool).await;
    let suspended = h
        .user_with_status(
            "suspended@example.com",
            Some(STRONG),
            AccountStatus::Suspended,
        )
        .await;
    h.user("passkey-only@example.com", None).await;
    let locked = h
        .user_with_status("locked@example.com", Some(STRONG), AccountStatus::Locked)
        .await;
    for address in [
        "nobody@example.com",
        "suspended@example.com",
        "passkey-only@example.com",
        "locked@example.com",
    ] {
        h.service
            .request_reset(&h.ctx(), &email(address))
            .await
            .unwrap();
    }
    h.service.drain_background_jobs().await;
    let sent = h.ports.notifier.with_template("password_reset");
    assert_eq!(
        sent.len(),
        1,
        "only the (soft-)locked account is eligible (PRT-03)"
    );
    assert_eq!(sent[0].recipient.user_id, Some(locked));
    let events = h
        .ports
        .audit
        .of_kind(SecurityEventKind::PasswordResetRequested);
    assert_eq!(events.len(), 4);
    let unknown = events
        .iter()
        .find(|e| e.reason.as_deref() == Some("unknown_account"))
        .unwrap();
    assert_eq!(unknown.subject_user, None);
    assert_eq!(unknown.outcome, EventOutcome::Failure);
    assert!(events.iter().any(|e| e.subject_user == Some(suspended)
        && e.reason.as_deref() == Some("account_not_eligible")));
    // Audit events never contain the address or the token.
    let json = serde_json::to_string(&events).unwrap();
    assert!(!json.contains("nobody@") && !json.contains("suspended@"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_requests_are_rate_limited_per_email_and_per_ip_alike_for_unknown_accounts(
    pool: sqlx::PgPool,
) {
    let h = Harness::new(pool).await;
    h.user("dave@example.com", Some(STRONG)).await;
    for address in ["dave@example.com", "ghost@example.com"] {
        for _ in 0..3 {
            h.service
                .request_reset(&h.ctx(), &email(address))
                .await
                .unwrap();
        }
        let err = h
            .service
            .request_reset(&h.ctx(), &email(address))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::RATE_LIMITED, "{address}");
        assert!(err.retry_after().is_some());
    }
    // 8 requests counted for this IP so far (the IP limit is checked first);
    // the per-IP budget is 20 per hour.
    for i in 0..12 {
        h.service
            .request_reset(&h.ctx(), &email(&format!("user{i}@example.com")))
            .await
            .unwrap();
    }
    let err = h
        .service
        .request_reset(&h.ctx(), &email("fresh@example.com"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    h.service.drain_background_jobs().await;
    assert_eq!(h.ports.notifier.with_template("password_reset").len(), 3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_08_mobile_code_resets_the_password_and_burns_the_link(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("erin@example.com", Some(STRONG)).await;
    let (token, code) = h.forgot("erin@example.com").await;
    h.service
        .complete_reset(
            &h.ctx(),
            code_proof(" Erin@Example.com ", &code.unwrap()),
            &secret(STRONG_2),
        )
        .await
        .unwrap();
    assert!(h.password_is(user, STRONG_2).await);
    let err = h
        .service
        .complete_reset(&h.ctx(), link(&token), &secret(STRONG_3))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_08_code_attempts_are_limited_then_the_code_is_burned(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("frank@example.com", Some(STRONG)).await;
    let (_, code) = h.forgot("frank@example.com").await;
    let code = code.unwrap();
    for _ in 0..5 {
        let err = h
            .service
            .complete_reset(
                &h.ctx(),
                code_proof("frank@example.com", &wrong(&code)),
                &secret(STRONG_2),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_CODE);
    }
    // Locked out: even the right code fails, with the same error.
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            code_proof("frank@example.com", &code),
            &secret(STRONG_2),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    assert!(h.password_is(user, STRONG).await);
    let failures = h
        .ports
        .audit
        .of_kind(SecurityEventKind::PasswordResetCompleted);
    assert_eq!(failures.len(), 6);
    assert!(failures.iter().all(|e| e.outcome == EventOutcome::Failure));
    assert_eq!(failures[0].reason.as_deref(), Some("wrong_code"));
    assert_eq!(failures[4].reason.as_deref(), Some("code_locked_out"));
    assert_eq!(failures[5].reason.as_deref(), Some("no_active_code"));

    // On top of the per-code limit, submissions per address are limited
    // (10 per hour by default) whether or not the account exists.
    for _ in 0..4 {
        let _ = h
            .service
            .complete_reset(
                &h.ctx(),
                code_proof("frank@example.com", "000000"),
                &secret(STRONG_2),
            )
            .await;
    }
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            code_proof("frank@example.com", "000000"),
            &secret(STRONG_2),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_08_code_failures_do_not_reveal_whether_the_account_exists(pool: sqlx::PgPool) {
    let h = Harness::with(pool, |s| {
        s.code_failure_floor = Duration::from_millis(60);
        s.password.reset.code_attempts_per_email =
            RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.password.reset.verify_per_ip = RateLimitPolicy::new(1000, Duration::from_secs(3600));
        s.password.reset.code_max_attempts = 100;
    })
    .await;
    h.user("grace@example.com", Some(STRONG)).await;
    let (_, code) = h.forgot("grace@example.com").await;
    let bad = wrong(&code.unwrap());
    for address in ["grace@example.com", "nobody@example.com"] {
        let err = h
            .service
            .complete_reset(&h.ctx(), code_proof(address, &bad), &secret(STRONG_2))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_CODE);
        assert!(err.details().is_none());
    }
    let report = compare_timings(
        11,
        || async {
            let _ = h
                .service
                .complete_reset(
                    &h.ctx(),
                    code_proof("grace@example.com", &bad),
                    &secret(STRONG_2),
                )
                .await;
        },
        || async {
            let _ = h
                .service
                .complete_reset(
                    &h.ctx(),
                    code_proof("nobody@example.com", &bad),
                    &secret(STRONG_2),
                )
                .await;
        },
    )
    .await;
    report.assert_indistinguishable(0.3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_09_policy_violation_does_not_consume_the_link_or_the_code(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("heidi@example.com", Some(STRONG)).await;
    let (token, code) = h.forgot("heidi@example.com").await;
    for proof in [
        link(&token),
        code_proof("heidi@example.com", code.as_deref().unwrap()),
    ] {
        let err = h
            .service
            .complete_reset(&h.ctx(), proof, &secret("password1234"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::password::PASSWORD_POLICY_VIOLATION);
    }
    // The e-mail address is a zxcvbn input on the code path too.
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            code_proof("heidi@example.com", code.as_deref().unwrap()),
            &secret("heidi@example.com"),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_POLICY_VIOLATION);
    h.service
        .complete_reset(
            &h.ctx(),
            code_proof("heidi@example.com", code.as_deref().unwrap()),
            &secret(STRONG_2),
        )
        .await
        .unwrap();
    assert!(h.password_is(user, STRONG_2).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_09_reset_revokes_every_session_refresh_token_and_trusted_device(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("ivan@example.com", Some(STRONG)).await;
    h.set_password(user, STRONG, true).await;
    let (token, _) = h.forgot("ivan@example.com").await;
    h.ports.notifier.take();
    h.ports.session_revoker.set_revoked_count(3);
    h.service
        .complete_reset(&h.ctx(), link(&token), &secret(STRONG_2))
        .await
        .unwrap();

    assert_eq!(
        h.ports.session_revoker.calls(),
        vec![RevocationCall::AllForUser(
            user,
            RevocationReason::PasswordReset,
            RevokeOptions {
                also_trusted_devices: true
            }
        )]
    );
    // must_change_password is cleared by the reset (PWD-12).
    let stored = UserRepository::find_password(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.must_change);
    assert_eq!(stored.changed_at, h.ports.clock.now());
    // Notification and audit.
    let sent = h.ports.notifier.take();
    assert_eq!(sent.len(), 1);
    assert!(matches!(
        sent[0].kind,
        NotificationKind::PasswordChanged { .. }
    ));
    assert_eq!(sent[0].recipient.user_id, Some(user));
    let events = h
        .ports
        .audit
        .of_kind(SecurityEventKind::PasswordResetCompleted);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, Actor::User(user));
    assert_eq!(events[0].metadata["method"], "link");
    assert_eq!(events[0].metadata["sessions_revoked"], 3);
    // MFA is not bypassed: no session was issued by the reset.
    assert!(h.ports.session_issuer.logins().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_09_concurrent_link_consumption_has_exactly_one_winner(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("judy@example.com", Some(STRONG)).await;
    let (token, _) = h.forgot("judy@example.com").await;
    let ctx = h.ctx();
    let (p2, p3) = (secret(STRONG_2), secret(STRONG_3));
    let (a, b) = tokio::join!(
        h.service.complete_reset(&ctx, link(&token), &p2),
        h.service.complete_reset(&ctx, link(&token), &p3),
    );
    assert!(a.is_ok() != b.is_ok(), "exactly one winner: {a:?} {b:?}");
    let loser = a.as_ref().err().or(b.as_ref().err()).unwrap();
    assert_eq!(loser.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    let winner = if a.is_ok() { STRONG_2 } else { STRONG_3 };
    assert!(h.password_is(user, winner).await);
    assert_eq!(h.ports.session_revoker.calls().len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_09_concurrent_code_consumption_has_exactly_one_winner(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("ken@example.com", Some(STRONG)).await;
    let (_, code) = h.forgot("ken@example.com").await;
    let code = code.unwrap();
    let ctx = h.ctx();
    let (p2, p3) = (secret(STRONG_2), secret(STRONG_3));
    let (a, b) = tokio::join!(
        h.service
            .complete_reset(&ctx, code_proof("ken@example.com", &code), &p2),
        h.service
            .complete_reset(&ctx, code_proof("ken@example.com", &code), &p3),
    );
    assert!(a.is_ok() != b.is_ok(), "exactly one winner: {a:?} {b:?}");
    let winner = if a.is_ok() { STRONG_2 } else { STRONG_3 };
    assert!(h.password_is(user, winner).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_09_reset_is_refused_when_the_account_was_suspended_meanwhile(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("leo@example.com", Some(STRONG)).await;
    let (token, _) = h.forgot("leo@example.com").await;
    let mut conn = h.pool.acquire().await.unwrap();
    assert!(
        UserRepository::update_status(
            &mut conn,
            user,
            AccountStatus::Active,
            AccountStatus::Suspended,
            Some("admin_action"),
            None,
            h.ports.clock.now(),
        )
        .await
        .unwrap()
    );
    drop(conn);
    let err = h
        .service
        .complete_reset(&h.ctx(), link(&token), &secret(STRONG_2))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    assert!(h.ports.session_revoker.calls().is_empty());
    assert!(
        h.service
            .verify_login_password(&h.ctx(), Some(user), &secret(STRONG))
            .await
            .unwrap()
            .is_valid()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_09_garbage_tokens_never_reach_the_database_and_fail_uniformly(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    for token in [
        "",
        "short",
        "' OR 1=1 --",
        &"A".repeat(43),
        &"A".repeat(10_000),
        "../../etc/passwd",
    ] {
        let err = h
            .service
            .complete_reset(&h.ctx(), link(token), &secret(STRONG_2))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            codes::common::INVALID_OR_EXPIRED_TOKEN,
            "{token}"
        );
    }
    for c in ["", "12345", "1234567", "12a456", "１２３４５６"] {
        let err = h
            .service
            .complete_reset(&h.ctx(), code_proof("x@example.com", c), &secret(STRONG_2))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_CODE, "{c}");
    }
}

// --- security review regressions -------------------------------------------

/// What happens to the account while the background reset job sits between
/// its unlocked account lookup and its locked re-check (the job reads the
/// profile in exactly that window).
#[derive(Clone, Copy)]
enum Race {
    /// The account moves to another address (ACC-07).
    ChangeEmail(&'static str),
    /// The password is removed (PWD-11).
    RemovePassword,
}

struct RacingProfiles {
    pool: sqlx::PgPool,
    race: Race,
}

#[async_trait]
impl ProfileLookup for RacingProfiles {
    async fn profile(&self, user: UserId) -> Result<ProfileHints, AuthError> {
        let mut conn = self.pool.acquire().await.unwrap();
        match self.race {
            Race::ChangeEmail(address) => {
                assert!(
                    UserRepository::update_email(&mut conn, user, &email(address), None)
                        .await
                        .unwrap()
                );
            }
            Race::RemovePassword => {
                assert!(
                    UserRepository::delete_password(&mut conn, user)
                        .await
                        .unwrap()
                );
            }
        }
        Ok(ProfileHints::default())
    }
}

async fn active_reset_secrets(h: &Harness, user: UserId) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM one_time_tokens WHERE user_id = $1 \
         AND purpose IN ('password_reset', 'password_reset_code') \
         AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(user)
    .fetch_one(&h.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_reset_mail_never_goes_to_an_address_the_account_left_during_the_request(
    pool: sqlx::PgPool,
) {
    let h = Harness::with_profiles(
        pool.clone(),
        Arc::new(RacingProfiles {
            pool,
            race: Race::ChangeEmail("moved-away@example.com"),
        }),
    )
    .await;
    let user = h.user("left-behind@example.com", Some(STRONG)).await;
    h.service
        .request_reset(&h.ctx(), &email("left-behind@example.com"))
        .await
        .unwrap();
    h.service.drain_background_jobs().await;
    assert!(
        h.ports.notifier.with_template("password_reset").is_empty(),
        "a reset token was mailed to an address the account no longer owns"
    );
    assert_eq!(active_reset_secrets(&h, user).await, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_10_reset_is_not_issued_when_the_password_is_removed_during_the_request(
    pool: sqlx::PgPool,
) {
    let h = Harness::with_profiles(
        pool.clone(),
        Arc::new(RacingProfiles {
            pool,
            race: Race::RemovePassword,
        }),
    )
    .await;
    let user = h.user("racing-removal@example.com", Some(STRONG)).await;
    h.service
        .request_reset(&h.ctx(), &email("racing-removal@example.com"))
        .await
        .unwrap();
    h.service.drain_background_jobs().await;
    assert!(h.ports.notifier.with_template("password_reset").is_empty());
    assert_eq!(active_reset_secrets(&h, user).await, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_reset_secrets_die_when_the_account_changes_its_address(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("old-address@example.com", Some(STRONG)).await;
    let (token, code) = h.forgot("old-address@example.com").await;
    let code = code.unwrap();
    // The account moves to a new address and nothing revokes the secrets
    // mailed to the old one.
    let mut conn = h.pool.acquire().await.unwrap();
    assert!(
        UserRepository::update_email(
            &mut conn,
            user,
            &email("new-address@example.com"),
            Some(h.ports.clock.now()),
        )
        .await
        .unwrap()
    );
    drop(conn);
    // Link first: a refused link is rolled back, a verified code would
    // revoke the link with its group.
    let err = h
        .service
        .complete_reset(&h.ctx(), link(&token), &secret(STRONG_2))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    for address in ["new-address@example.com", "old-address@example.com"] {
        let err = h
            .service
            .complete_reset(&h.ctx(), code_proof(address, &code), &secret(STRONG_2))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_CODE, "{address}");
    }
    assert!(h.password_is(user, STRONG).await);
    assert!(h.ports.session_revoker.calls().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_10_reset_never_adds_a_password_to_a_passwordless_account(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("now-passwordless@example.com", Some(STRONG)).await;
    let (token, code) = h.forgot("now-passwordless@example.com").await;
    let code = code.unwrap();
    // The password is gone while the secrets are still alive (e.g. the
    // request raced a removal).
    let mut conn = h.pool.acquire().await.unwrap();
    assert!(
        UserRepository::delete_password(&mut conn, user)
            .await
            .unwrap()
    );
    drop(conn);
    let err = h
        .service
        .complete_reset(&h.ctx(), link(&token), &secret(STRONG_2))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            code_proof("now-passwordless@example.com", &code),
            &secret(STRONG_2),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    assert!(
        UserRepository::find_password(&h.pool, user)
            .await
            .unwrap()
            .is_none(),
        "an e-mailed secret added a password without step-up"
    );
    assert!(h.ports.session_revoker.calls().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_08_unknown_address_code_failures_do_the_same_audit_work(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            code_proof("nobody@example.com", "123456"),
            &secret(STRONG_2),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_CODE);
    let events = h
        .ports
        .audit
        .of_kind(SecurityEventKind::PasswordResetCompleted);
    assert_eq!(events.len(), 1, "known addresses write one audit event too");
    assert_eq!(events[0].outcome, EventOutcome::Failure);
    assert_eq!(events[0].reason.as_deref(), Some("unknown_account"));
    assert_eq!(events[0].subject_user, None);
    assert!(!serde_json::to_string(&events).unwrap().contains("nobody@"));
}
