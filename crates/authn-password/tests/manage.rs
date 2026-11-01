#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Self-service password management: PWD-06 (change), PWD-10 (add),
//! PWD-11 (remove), PWD-12 (required change after an admin flag).

mod common;

use std::time::Duration;

use authn_core::domain::{Impersonation, LoginMethod, PrincipalCredential};
use authn_core::error::codes;
use authn_core::id::{ApiKeyId, SessionId, UserId};
use authn_core::ports::{
    Actor, EventOutcome, NotificationKind, RevocationReason, RevokeOptions, SecurityEventKind,
};
use authn_store::UserRepository;
use authn_testkit::fakes::RevocationCall;
use common::{Harness, STRONG, STRONG_2, STRONG_3, secret};

const FRESH: Duration = Duration::from_secs(60);
const STALE: Duration = Duration::from_secs(3600);

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_06_change_with_current_password_revokes_other_sessions_and_notifies(
    pool: sqlx::PgPool,
) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com", Some(STRONG)).await;
    let principal = h.principal(user, STALE);
    let current_session = principal.session_id().unwrap();
    h.service
        .change_password(
            &h.ctx(),
            &principal,
            Some(&secret(STRONG)),
            &secret(STRONG_2),
        )
        .await
        .unwrap();
    assert!(h.password_is(user, STRONG_2).await);
    assert_eq!(
        h.ports.session_revoker.calls(),
        vec![RevocationCall::AllExcept(
            user,
            current_session,
            RevocationReason::PasswordChanged,
            RevokeOptions::default()
        )]
    );
    let sent = h.ports.notifier.with_template("password_changed");
    assert_eq!(sent.len(), 1);
    let NotificationKind::PasswordChanged { ip_masked, .. } = &sent[0].kind else {
        panic!("unexpected notification");
    };
    assert_eq!(ip_masked.as_deref(), Some("127.0.0.x"));
    let events = h.ports.audit.of_kind(SecurityEventKind::PasswordChanged);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, EventOutcome::Success);
    assert_eq!(events[0].actor, Actor::User(user));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_06_change_without_current_password_requires_recent_step_up(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("bob@example.com", Some(STRONG)).await;
    let err = h
        .service
        .change_password(&h.ctx(), &h.principal(user, STALE), None, &secret(STRONG_2))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    assert!(h.password_is(user, STRONG).await);
    h.service
        .change_password(&h.ctx(), &h.principal(user, FRESH), None, &secret(STRONG_2))
        .await
        .unwrap();
    assert!(h.password_is(user, STRONG_2).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_06_wrong_current_password_is_refused_audited_and_rate_limited(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("carol@example.com", Some(STRONG)).await;
    let principal = h.principal(user, FRESH);
    for _ in 0..5 {
        let err = h
            .service
            .change_password(
                &h.ctx(),
                &principal,
                Some(&secret(STRONG_3)),
                &secret(STRONG_2),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::password::CURRENT_PASSWORD_INCORRECT);
    }
    // Even the right password is refused once the per-user budget is spent.
    let err = h
        .service
        .change_password(
            &h.ctx(),
            &principal,
            Some(&secret(STRONG)),
            &secret(STRONG_2),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    assert!(h.password_is(user, STRONG).await);
    let events = h.ports.audit.of_kind(SecurityEventKind::PasswordChanged);
    assert_eq!(events.len(), 5);
    assert!(
        events
            .iter()
            .all(|e| e.reason.as_deref() == Some("wrong_current_password"))
    );
    assert!(h.ports.session_revoker.calls().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_06_new_password_must_satisfy_policy_and_differ_from_the_current(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("dave@example.com", Some(STRONG)).await;
    let principal = h.principal(user, FRESH);
    let err = h
        .service
        .change_password(&h.ctx(), &principal, Some(&secret(STRONG)), &secret(STRONG))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_UNCHANGED);
    // NFKC-equivalent spelling of the same password is the same password.
    let err = h
        .service
        .change_password(
            &h.ctx(),
            &principal,
            None,
            &secret("tramway galaxy orchid lantern ４７"),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_UNCHANGED);
    for weak in ["short", "password1234", "dave@example.com"] {
        let err = h
            .service
            .change_password(&h.ctx(), &principal, None, &secret(weak))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            codes::password::PASSWORD_POLICY_VIOLATION,
            "{weak}"
        );
        assert!(
            !err.details().unwrap()["violations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    h.ports.breached_passwords.add_breached(STRONG_3);
    let err = h
        .service
        .change_password(&h.ctx(), &principal, None, &secret(STRONG_3))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_POLICY_VIOLATION);
    assert_eq!(err.details().unwrap()["violations"][0]["code"], "breached");
    assert!(h.password_is(user, STRONG).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_06_impersonation_api_keys_and_passwordless_accounts_cannot_change(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("erin@example.com", Some(STRONG)).await;
    let mut impersonated = h.principal(user, FRESH);
    impersonated.impersonation = Some(Impersonation {
        admin_user_id: UserId::generate(),
        read_only: false,
        expires_at: time::OffsetDateTime::UNIX_EPOCH,
    });
    let mut api_key = h.principal(user, FRESH);
    api_key.credential = PrincipalCredential::ApiKey {
        api_key_id: ApiKeyId::generate(),
    };
    for principal in [&impersonated, &api_key] {
        let err = h
            .service
            .change_password(
                &h.ctx(),
                principal,
                Some(&secret(STRONG)),
                &secret(STRONG_2),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::FORBIDDEN);
    }
    let passwordless = h.user("passkey@example.com", None).await;
    let err = h
        .service
        .change_password(
            &h.ctx(),
            &h.principal(passwordless, FRESH),
            None,
            &secret(STRONG_2),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_NOT_SET);
    assert!(h.password_is(user, STRONG).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_06_change_revokes_pending_reset_tokens(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("frank@example.com", Some(STRONG)).await;
    let (token, _) = h.forgot("frank@example.com").await;
    h.service
        .change_password(&h.ctx(), &h.principal(user, FRESH), None, &secret(STRONG_2))
        .await
        .unwrap();
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            authn_password::ResetProof::Link {
                token: secret(&token),
            },
            &secret(STRONG_3),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    assert!(h.password_is(user, STRONG_2).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_10_passwordless_account_can_add_a_password_after_step_up(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("grace@example.com", None).await;
    let err = h
        .service
        .add_password(&h.ctx(), &h.principal(user, STALE), &secret(STRONG))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let err = h
        .service
        .add_password(&h.ctx(), &h.principal(user, FRESH), &secret("password1234"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_POLICY_VIOLATION);
    h.service
        .add_password(&h.ctx(), &h.principal(user, FRESH), &secret(STRONG))
        .await
        .unwrap();
    assert!(h.password_is(user, STRONG).await);
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::PasswordAdded)
            .len(),
        1
    );
    assert_eq!(h.ports.notifier.with_template("password_changed").len(), 1);
    // A second add is a conflict, never an overwrite.
    let err = h
        .service
        .add_password(&h.ctx(), &h.principal(user, FRESH), &secret(STRONG_2))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_ALREADY_SET);
    assert!(h.password_is(user, STRONG).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_10_concurrent_adds_store_exactly_one_password(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("heidi@example.com", None).await;
    let principal = h.principal(user, FRESH);
    let ctx = h.ctx();
    let (p1, p2) = (secret(STRONG), secret(STRONG_2));
    let (a, b) = tokio::join!(
        h.service.add_password(&ctx, &principal, &p1),
        h.service.add_password(&ctx, &principal, &p2),
    );
    assert!(a.is_ok() != b.is_ok(), "{a:?} {b:?}");
    let loser = a.as_ref().err().or(b.as_ref().err()).unwrap();
    assert_eq!(loser.code(), codes::password::PASSWORD_ALREADY_SET);
    let winner = if a.is_ok() { STRONG } else { STRONG_2 };
    assert!(h.password_is(user, winner).await);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_11_password_removal_requires_step_up_and_another_strong_method(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("ivan@example.com", Some(STRONG)).await;
    let err = h
        .service
        .remove_password(&h.ctx(), &h.principal(user, STALE))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);

    // E-mail based methods are not strong enough.
    *h.methods.0.lock().unwrap() = vec![LoginMethod::MagicLink, LoginMethod::EmailCode];
    let err = h
        .service
        .remove_password(&h.ctx(), &h.principal(user, FRESH))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_REMOVAL_NOT_ALLOWED);
    assert!(h.password_is(user, STRONG).await);
    let refused = h.ports.audit.of_kind(SecurityEventKind::PasswordRemoved);
    assert_eq!(refused[0].reason.as_deref(), Some("no_other_strong_method"));

    *h.methods.0.lock().unwrap() = vec![LoginMethod::MagicLink, LoginMethod::Passkey];
    let (token, _) = h.forgot("ivan@example.com").await;
    h.service
        .remove_password(&h.ctx(), &h.principal(user, FRESH))
        .await
        .unwrap();
    assert!(
        UserRepository::find_password(&h.pool, user)
            .await
            .unwrap()
            .is_none()
    );
    let removed = h.ports.audit.of_kind(SecurityEventKind::PasswordRemoved);
    assert_eq!(removed.last().unwrap().outcome, EventOutcome::Success);
    assert_eq!(
        removed.last().unwrap().metadata["remaining_methods"],
        serde_json::json!(["passkey"])
    );
    // Pending reset links cannot re-add a password behind the user's back.
    let err = h
        .service
        .complete_reset(
            &h.ctx(),
            authn_password::ResetProof::Link {
                token: secret(&token),
            },
            &secret(STRONG_2),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    // Nothing left to remove.
    let err = h
        .service
        .remove_password(&h.ctx(), &h.principal(user, FRESH))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_NOT_SET);
    // A social identity counts as strong as well.
    let other = h.user("judy@example.com", Some(STRONG)).await;
    *h.methods.0.lock().unwrap() = vec![LoginMethod::Social];
    h.service
        .remove_password(&h.ctx(), &h.principal(other, FRESH))
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_12_required_change_needs_the_flag_and_clears_it(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("ken@example.com", Some(STRONG)).await;
    let keep = SessionId::generate();
    // Without the flag the required-action path is closed.
    let err = h
        .service
        .apply_required_password_change(&h.ctx(), user, Some(keep), &secret(STRONG_2))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);

    h.service
        .set_must_change_password(&h.ctx(), Actor::System, user, true)
        .await
        .unwrap();
    let err = h
        .service
        .apply_required_password_change(&h.ctx(), user, Some(keep), &secret(STRONG))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_UNCHANGED);
    h.service
        .apply_required_password_change(&h.ctx(), user, Some(keep), &secret(STRONG_2))
        .await
        .unwrap();
    let stored = UserRepository::find_password(&h.pool, user)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.must_change);
    assert!(h.password_is(user, STRONG_2).await);
    assert_eq!(
        h.ports.session_revoker.calls(),
        vec![RevocationCall::AllExcept(
            user,
            keep,
            RevocationReason::PasswordChanged,
            RevokeOptions::default()
        )]
    );
    let events = h.ports.audit.of_kind(SecurityEventKind::PasswordChanged);
    assert_eq!(events.last().unwrap().metadata["required_change"], true);
}
