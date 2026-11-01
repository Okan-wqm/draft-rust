#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Account status state machine against the database: ACC-06.

mod common;

use authn_core::ports::Clock as _;

use std::time::Duration;

use authn_account::{DenialReason, LoginAssessment, StatusChange};
use authn_core::domain::AccountStatus;
use authn_core::id::UserId;
use authn_core::ports::{Actor, SecurityEventKind};
use common::Harness;
use sqlx::PgPool;

fn admin() -> Actor {
    Actor::User(UserId::generate())
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_06_every_transition_is_audited_with_from_and_to(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("life@example.com").await;
    h.audit.events.take();
    let actor = admin();
    let steps = [
        (AccountStatus::Suspended, "admin_suspension"),
        (AccountStatus::Active, "admin_reinstated"),
        (AccountStatus::Disabled, "admin_disabled"),
        (AccountStatus::Active, "admin_enabled"),
    ];
    for (to, reason) in steps {
        let t = h
            .service
            .change_status(&h.ctx(), user, &StatusChange::new(to, reason, actor))
            .await
            .unwrap();
        assert_eq!(t.to, to);
        let stored = h.user_by_id(user).await.unwrap();
        assert_eq!(stored.status, to);
        assert_eq!(stored.status_reason.as_deref(), Some(reason));
    }
    let events = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountStatusChanged);
    assert_eq!(events.len(), steps.len());
    for (event, (to, reason)) in events.iter().zip(steps) {
        assert_eq!(event.metadata["to"], to.as_str());
        assert_eq!(event.metadata["reason"], reason);
        assert_eq!(event.actor, actor);
        assert_eq!(event.subject_user, Some(user));
        assert!(event.ip.is_some(), "request context attached");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_06_forbidden_transitions_are_rejected_and_not_written(pool: PgPool) {
    let h = Harness::new(pool).await;
    h.signup("pending@example.com").await;
    let pending = h.user("pending@example.com").await.unwrap().id;
    h.audit.events.take();
    for to in [
        AccountStatus::Active,
        AccountStatus::Locked,
        AccountStatus::PendingVerification,
    ] {
        let err = h
            .service
            .change_status(&h.ctx(), pending, &StatusChange::new(to, "test", admin()))
            .await
            .unwrap_err();
        assert_eq!(
            err.code().code(),
            "account_status_transition_not_allowed",
            "{to}"
        );
    }
    // Suspending and reinstating an unverified account returns it to
    // verification, never to active.
    h.service
        .change_status(
            &h.ctx(),
            pending,
            &StatusChange::new(AccountStatus::Suspended, "admin_suspension", admin()),
        )
        .await
        .unwrap();
    assert!(
        h.service
            .change_status(
                &h.ctx(),
                pending,
                &StatusChange::new(AccountStatus::Active, "admin_reinstated", admin()),
            )
            .await
            .is_err()
    );
    h.service
        .change_status(
            &h.ctx(),
            pending,
            &StatusChange::new(
                AccountStatus::PendingVerification,
                "admin_reinstated",
                admin(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(pending).await.unwrap().status,
        AccountStatus::PendingVerification
    );
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::AccountStatusChanged)
            .len(),
        2
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_06_temporary_lock_requires_an_end_and_expires(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("locked@example.com").await;
    let mut lock = StatusChange::new(AccountStatus::Locked, "admin_lock", admin());
    assert_eq!(
        h.service
            .change_status(&h.ctx(), user, &lock)
            .await
            .unwrap_err()
            .code()
            .code(),
        "validation_failed"
    );
    let until = h.ports.clock.now() + time::Duration::minutes(30);
    lock.locked_until = Some(until);
    h.service
        .change_status(&h.ctx(), user, &lock)
        .await
        .unwrap();
    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(
        h.service.assess_login(&record).await.unwrap(),
        LoginAssessment::Denied(DenialReason::Locked { until })
    );
    let err = DenialReason::Locked { until }.into_error(h.ports.clock.now());
    assert_eq!(err.code().code(), "account_locked");
    assert_eq!(err.retry_after(), Some(Duration::from_secs(1800)));

    assert_eq!(h.service.release_expired_locks(10).await.unwrap(), 0);
    h.ports.clock.advance(Duration::from_secs(31 * 60));
    // Expired lock: login is allowed even before the cleanup job runs …
    assert!(matches!(
        h.service.assess_login(&record).await.unwrap(),
        LoginAssessment::Allowed { .. }
    ));
    // … and the job moves the account back to active (audited).
    assert_eq!(h.service.release_expired_locks(10).await.unwrap(), 1);
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_06_blocking_statuses_deny_login_with_their_code(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("blocked@example.com").await;
    for (to, code) in [
        (AccountStatus::Suspended, "account_suspended"),
        (AccountStatus::Disabled, "account_disabled"),
    ] {
        h.service
            .change_status(&h.ctx(), user, &StatusChange::new(to, "test", admin()))
            .await
            .unwrap();
        let record = h.user_by_id(user).await.unwrap();
        let LoginAssessment::Denied(reason) = h.service.assess_login(&record).await.unwrap() else {
            panic!("{to} must deny login");
        };
        assert_eq!(reason.into_error(h.ports.clock.now()).code().code(), code);
        h.service
            .change_status(
                &h.ctx(),
                user,
                &StatusChange::new(AccountStatus::Active, "test", admin()),
            )
            .await
            .unwrap();
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_06_change_status_in_caller_transaction_rolls_back_with_it(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("tx@example.com").await;
    let mut tx = h.pool.begin().await.unwrap();
    h.service
        .change_status_in_tx(
            &mut tx,
            &h.ctx(),
            user,
            &StatusChange::new(AccountStatus::Suspended, "admin_suspension", admin()),
        )
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Active
    );

    let mut tx = h.pool.begin().await.unwrap();
    h.service
        .change_status_in_tx(
            &mut tx,
            &h.ctx(),
            user,
            &StatusChange::new(AccountStatus::Suspended, "admin_suspension", admin()),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        h.user_by_id(user).await.unwrap().status,
        AccountStatus::Suspended
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_06_concurrent_transitions_serialize_on_the_row(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("conc@example.com").await;
    h.audit.events.take();
    let mut handles = Vec::new();
    for _ in 0..6 {
        let service = h.service.clone();
        let ctx = h.ctx();
        handles.push(tokio::spawn(async move {
            service
                .change_status(
                    &ctx,
                    user,
                    &StatusChange::new(AccountStatus::Suspended, "admin_suspension", Actor::System),
                )
                .await
        }));
    }
    let mut ok = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(
        ok, 1,
        "active -> suspended happens once; the rest are no-ops"
    );
    assert_eq!(
        h.audit
            .events
            .of_kind(SecurityEventKind::AccountStatusChanged)
            .len(),
        1
    );
}

/// Security review: the generic status API (authn-admin) cannot put an
/// account into `pending_deletion` (no schedule, no cancel link: it would
/// never be purged) or `deleted` (a "deleted" row that still holds the
/// address and personal data, never erased). Those statuses belong to the
/// deletion flow (ACC-09).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_06_deletion_statuses_are_not_settable_through_the_status_api(pool: PgPool) {
    let h = Harness::new(pool).await;
    let active = h.active_user("keep-active@example.com").await;
    h.signup("keep-pending@example.com").await;
    let pending = h.user("keep-pending@example.com").await.unwrap().id;
    h.audit.events.take();
    for (user, to) in [
        (active, AccountStatus::PendingDeletion),
        (pending, AccountStatus::PendingDeletion),
        (pending, AccountStatus::Deleted),
    ] {
        let change = StatusChange::new(to, "admin_deletion", admin());
        let err = h
            .service
            .change_status(&h.ctx(), user, &change)
            .await
            .unwrap_err();
        assert_eq!(err.code().code(), "account_status_transition_not_allowed");
        let mut tx = h.pool.begin().await.unwrap();
        let err = h
            .service
            .change_status_in_tx(&mut tx, &h.ctx(), user, &change)
            .await
            .unwrap_err();
        assert_eq!(err.code().code(), "account_status_transition_not_allowed");
        tx.commit().await.unwrap();
    }
    assert_eq!(
        h.user_by_id(active).await.unwrap().status,
        AccountStatus::Active
    );
    assert_eq!(
        h.user_by_id(pending).await.unwrap().status,
        AccountStatus::PendingVerification
    );
    assert!(
        h.audit
            .events
            .of_kind(SecurityEventKind::AccountStatusChanged)
            .is_empty()
    );
    // The deletion flow itself still works.
    h.service
        .request_deletion(&h.fresh(active), &h.ctx())
        .await
        .unwrap();
    assert_eq!(
        h.user_by_id(active).await.unwrap().status,
        AccountStatus::PendingDeletion
    );
}
