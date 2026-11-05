#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! APIs for modules that prove mailbox control themselves (social login):
//! reservation lookup (K-02, ACC-07), provisioning a verified account with
//! its profile (K-33, ACC-08), staff mailbox proofs in the user's own
//! events (K-14) and erasure hooks (K-35, ACC-09).

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_account::{
    AccountErasureHook, DisposableDomains, MailboxProof, ProvisionOutcome, VerifiedUserProvision,
};
use authn_core::domain::{AccountStatus, EmailAddress, Locale};
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::{Actor, DomainEventKind, NotificationKind, SecurityEventKind};
use authn_store::UserRepository;
use authn_testkit::http::TestRequest;
use common::{Harness, PASSWORD, secret};
use http::StatusCode;
use serde_json::json;
use sqlx::{PgConnection, PgPool};

fn email(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).unwrap()
}

/// Changes `user`'s address to `to` (old address becomes reserved).
async fn change_address(h: &Harness, user: UserId, to: &str) {
    TestRequest::post("/v1/me/email")
        .json(&json!({ "new_email": to }))
        .send(&h.app_as(&h.fresh(user)))
        .await
        .assert_status(StatusCode::ACCEPTED);
    h.drain().await;
    let token = match h.mails("email_change_verification", to).pop().unwrap().kind {
        NotificationKind::EmailChangeVerification { token, .. } => token.expose().to_owned(),
        other => panic!("{other:?}"),
    };
    h.service
        .confirm_email_change_link(Some(&h.fresh(user)), &h.ctx(), &secret(&token))
        .await
        .unwrap();
}

fn provision<'a>(address: &'a EmailAddress, name: Option<&'a str>) -> VerifiedUserProvision<'a> {
    VerifiedUserProvision {
        email: address,
        display_name: name,
        locale: Locale::Tr,
        method: "social",
        provider: Some("google"),
    }
}

/// K-02: the reservation an e-mail change leaves on the old address is
/// visible through `is_address_reserved_in` on the caller's connection —
/// also inside an open transaction — and ends with the revert period.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_reservation_lookup_on_the_given_connection(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("old@example.com").await;
    change_address(&h, user, "new@example.com").await;

    let mut tx = h.pool.begin().await.unwrap();
    assert!(
        h.service
            .is_address_reserved_in(&mut tx, &email("OLD@example.com"))
            .await
            .unwrap(),
        "old address reserved for its previous owner"
    );
    assert!(
        !h.service
            .is_address_reserved_in(&mut tx, &email("someone-else@example.com"))
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();

    h.ports.clock.advance(Duration::from_secs(7 * 86_400 + 1));
    let mut conn = h.pool.acquire().await.unwrap();
    assert!(
        !h.service
            .is_address_reserved_in(&mut conn, &email("old@example.com"))
            .await
            .unwrap(),
        "reservation ends with the revert period"
    );
}

/// K-33: a provisioned account is `active`, verified, has a profile row
/// (normalized display name, language, UTC) and the usual creation events.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_08_provisioned_social_account_gets_a_profile(pool: PgPool) {
    let h = Harness::new(pool).await;
    let address = email("Ada@Example.com");
    let mut tx = h.pool.begin().await.unwrap();
    let outcome = h
        .service
        .provision_verified_user_in_tx(
            &mut tx,
            &h.ctx(),
            provision(&address, Some("  Ada   Lovelace ")),
        )
        .await
        .unwrap();
    let ProvisionOutcome::Created(user) = outcome else {
        panic!("{outcome:?}");
    };
    tx.commit().await.unwrap();

    let record = h.user_by_id(user).await.unwrap();
    assert_eq!(record.status, AccountStatus::Active);
    assert!(record.is_email_verified());
    assert!(
        UserRepository::find_password(&h.pool, user)
            .await
            .unwrap()
            .is_none(),
        "no credential is created"
    );
    let profile = h.service.profile_of(user).await.unwrap().unwrap();
    assert_eq!(profile.display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(profile.locale, Locale::Tr);
    assert_eq!(profile.time_zone, "UTC");
    assert!(
        h.ports
            .events
            .recorded()
            .iter()
            .any(|e| e.kind == DomainEventKind::UserCreated && e.user_id == Some(user))
    );
    let registered = h.audit.events.of_kind(SecurityEventKind::AccountRegistered);
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].subject_user, Some(user));
    assert_eq!(registered[0].metadata["method"], "social");
    assert_eq!(registered[0].metadata["provider"], "google");

    // A name that fails the ACC-03 rules is dropped, not stored.
    let other = email("mallory@example.com");
    let mut tx = h.pool.begin().await.unwrap();
    let ProvisionOutcome::Created(second) = h
        .service
        .provision_verified_user_in_tx(&mut tx, &h.ctx(), provision(&other, Some("Аdmin")))
        .await
        .unwrap()
    else {
        panic!("not created");
    };
    tx.commit().await.unwrap();
    let profile = h.service.profile_of(second).await.unwrap().unwrap();
    assert_eq!(profile.display_name, None);
}

/// K-33 / ADR 0002: an existing account (verified or not) is never
/// touched, a reserved address is never handed out, and a rolled-back
/// transaction leaves nothing behind.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_07_provisioning_never_takes_an_existing_or_reserved_address(pool: PgPool) {
    let h = Harness::new(pool).await;
    let pending = h
        .unverified_with_password("pending@example.com", PASSWORD)
        .await;
    let mut tx = h.pool.begin().await.unwrap();
    match h
        .service
        .provision_verified_user_in_tx(
            &mut tx,
            &h.ctx(),
            provision(&email("pending@example.com"), None),
        )
        .await
        .unwrap()
    {
        ProvisionOutcome::Existing(record) => assert_eq!(record.id, pending),
        other => panic!("{other:?}"),
    }
    tx.rollback().await.unwrap();
    let record = h.user_by_id(pending).await.unwrap();
    assert_eq!(record.status, AccountStatus::PendingVerification);
    assert!(!record.is_email_verified(), "not verified by provisioning");

    let owner = h.active_user("held@example.com").await;
    change_address(&h, owner, "moved@example.com").await;
    let mut tx = h.pool.begin().await.unwrap();
    assert!(matches!(
        h.service
            .provision_verified_user_in_tx(
                &mut tx,
                &h.ctx(),
                provision(&email("held@example.com"), None)
            )
            .await
            .unwrap(),
        ProvisionOutcome::Reserved
    ));
    tx.rollback().await.unwrap();
    assert!(h.user("held@example.com").await.is_none());

    // Rolled back: nothing remains.
    let mut tx = h.pool.begin().await.unwrap();
    assert!(matches!(
        h.service
            .provision_verified_user_in_tx(
                &mut tx,
                &h.ctx(),
                provision(&email("rollback@example.com"), None)
            )
            .await
            .unwrap(),
        ProvisionOutcome::Created(_)
    ));
    tx.rollback().await.unwrap();
    assert!(h.user("rollback@example.com").await.is_none());
}

/// ACC-12 applies to provisioned accounts too.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_12_provisioning_honours_the_disposable_domain_list(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.disposable_domains = Some(Arc::new(DisposableDomains::from_domains([
            "mailinator.com",
        ])));
    })
    .await;
    let mut tx = h.pool.begin().await.unwrap();
    let err = h
        .service
        .provision_verified_user_in_tx(
            &mut tx,
            &h.ctx(),
            provision(&email("x@mailinator.com"), None),
        )
        .await
        .unwrap_err();
    assert!(
        err.is(authn_core::error::codes::account::EMAIL_DOMAIN_NOT_ALLOWED),
        "{err:?}"
    );
}

/// K-63: the domain list is decided before any lookup — an existing
/// account with a (now) blocked address is answered exactly like a
/// missing one.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_12_k63_blocked_domain_is_decided_before_the_account_lookup(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.disposable_domains = Some(Arc::new(DisposableDomains::from_domains([
            "mailinator.com",
        ])));
    })
    .await;
    let mut tx = h.pool.begin().await.unwrap();
    let created = h
        .service
        .provision_verified_user_in_tx(
            &mut tx,
            &h.ctx(),
            provision(&email("old@example.com"), None),
        )
        .await
        .unwrap();
    assert!(matches!(created, ProvisionOutcome::Created(_)));
    tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE users SET email = 'old@mailinator.com', email_normalized = 'old@mailinator.com'",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    for address in ["old@mailinator.com", "new@mailinator.com"] {
        let mut tx = h.pool.begin().await.unwrap();
        let err = h
            .service
            .provision_verified_user_in_tx(&mut tx, &h.ctx(), provision(&email(address), None))
            .await
            .unwrap_err();
        assert!(
            err.is(authn_core::error::codes::account::EMAIL_DOMAIN_NOT_ALLOWED),
            "{address}: {err:?}"
        );
        tx.rollback().await.unwrap();
    }
}

/// K-14: when an administrator marks an address verified (ADM-03), the
/// user's own events carry neither the administrator's user id nor the
/// administrator's IP / user agent (`Actor::System`, no client context;
/// the request id is kept for correlation with authn-admin's
/// `admin.action` event). A self-service proof keeps the user's context.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_admin_mailbox_proof_shows_no_staff_identity_to_the_user(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h
        .unverified_with_password("member@example.com", PASSWORD)
        .await;
    let admin = UserId::generate();
    let ctx = h.ctx();
    let mut tx = h.pool.begin().await.unwrap();
    assert!(
        h.service
            .confirm_mailbox_control_in_tx(
                &mut tx,
                Some(&ctx),
                user,
                MailboxProof::Administrator { admin },
            )
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let events: Vec<_> = h
        .audit
        .events
        .recorded()
        .into_iter()
        .filter(|e| e.subject_user == Some(user))
        .collect();
    assert!(
        events
            .iter()
            .any(|e| e.kind == SecurityEventKind::EmailVerified)
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind == SecurityEventKind::AccountStatusChanged)
    );
    for event in &events {
        assert_eq!(event.actor, Actor::System, "{:?}", event.kind);
        assert_eq!(event.ip, None, "no staff IP in the user's events");
        assert_eq!(event.user_agent, None);
        assert_eq!(event.impersonator, None);
        assert_eq!(event.request_id, Some(ctx.request_id));
        let text = serde_json::to_string(&event.metadata).unwrap();
        assert!(!text.contains(&admin.to_string()), "{text}");
    }
    let verified = events
        .iter()
        .find(|e| e.kind == SecurityEventKind::EmailVerified)
        .unwrap();
    assert_eq!(verified.metadata["method"], "administrator");

    // Self-service proofs are unchanged: the user is the actor, with the
    // request's context.
    let other = h
        .unverified_with_password("self@example.com", PASSWORD)
        .await;
    let mut tx = h.pool.begin().await.unwrap();
    h.service
        .confirm_mailbox_control_in_tx(&mut tx, Some(&ctx), other, MailboxProof::Passwordless)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mine = h
        .audit
        .events
        .of_kind(SecurityEventKind::EmailVerified)
        .into_iter()
        .find(|e| e.subject_user == Some(other))
        .unwrap();
    assert_eq!(mine.actor, Actor::User(other));
    assert_eq!(mine.ip, Some(ctx.client_ip));
}

/// Audit finding (wave 2A audit, K-14): status changes made by platform
/// staff (authn-admin suspend / unsuspend / unlock call
/// `change_status_in_tx` with `Actor::System` and the administrator's
/// request) must not carry the administrator's IP / user agent into the
/// user's own `account.status_changed` event — the audit sink stores a
/// subject-owned event's client data as the user's and the user's view
/// shows it (masked). The request id is kept for correlation. A change the
/// user makes is unchanged.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_08_staff_status_change_shows_no_staff_network_to_the_user(pool: PgPool) {
    use authn_account::StatusChange;
    let h = Harness::new(pool).await;
    let user = h.active_user("suspended@example.com").await;
    let ctx = h.ctx(); // the administrator's request
    let mut tx = h.pool.begin().await.unwrap();
    h.service
        .change_status_in_tx(
            &mut tx,
            &ctx,
            user,
            &StatusChange::new(AccountStatus::Suspended, "admin_suspension", Actor::System),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    h.service
        .change_status(
            &ctx,
            user,
            &StatusChange::new(AccountStatus::Active, "admin_unsuspension", Actor::System),
        )
        .await
        .unwrap();
    let staff: Vec<_> = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountStatusChanged)
        .into_iter()
        .filter(|e| {
            e.subject_user == Some(user)
                && ["admin_suspension", "admin_unsuspension"]
                    .contains(&e.metadata["reason"].as_str().unwrap_or_default())
        })
        .collect();
    assert_eq!(staff.len(), 2);
    for event in &staff {
        assert_eq!(event.actor, Actor::System);
        assert_eq!(event.ip, None, "staff IP in the user's event");
        assert_eq!(
            event.user_agent, None,
            "staff user agent in the user's event"
        );
        assert_eq!(event.request_id, Some(ctx.request_id));
    }

    // The user's own change keeps the request's context.
    let me = h.active_user("self-disabled@example.com").await;
    h.service
        .change_status(
            &ctx,
            me,
            &StatusChange::new(AccountStatus::Disabled, "self", Actor::User(me)),
        )
        .await
        .unwrap();
    let own = h
        .audit
        .events
        .of_kind(SecurityEventKind::AccountStatusChanged)
        .into_iter()
        .find(|e| e.subject_user == Some(me) && e.metadata["reason"] == "self")
        .unwrap();
    assert_eq!(own.ip, Some(ctx.client_ip));
}

/// Records the users an erasure hook saw, and whether their row still
/// existed on the hook's connection.
#[derive(Default)]
struct RecordingHook {
    seen: Mutex<Vec<(UserId, bool)>>,
}

#[async_trait]
impl AccountErasureHook for RecordingHook {
    async fn before_erasure_in_tx(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<(), AuthError> {
        let exists = UserRepository::find_by_id(&mut *conn, user)
            .await?
            .is_some();
        self.seen.lock().unwrap().push((user, exists));
        Ok(())
    }
}

/// Fails like a broken database statement would.
struct FailingHook;

#[async_trait]
impl AccountErasureHook for FailingHook {
    async fn before_erasure_in_tx(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<(), AuthError> {
        Err(AuthError::internal("hook failed"))
    }
}

/// K-35 (ACC-09): registered erasure hooks run inside the erasure
/// transaction, before the user row is deleted; an error rolls the
/// erasure back (the job retries it later).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_09_erasure_hooks_run_in_the_erasure_transaction(pool: PgPool) {
    let h = Harness::new(pool).await;
    let hook = Arc::new(RecordingHook::default());
    h.service.register_erasure_hook(hook.clone());
    let user = h.active_user("leaving@example.com").await;
    h.service
        .request_deletion(&h.fresh(user), &h.ctx())
        .await
        .unwrap();
    h.ports.clock.advance(Duration::from_secs(30 * 86_400 + 1));
    assert_eq!(h.service.purge_due_deletions(10).await.unwrap().purged, 1);
    assert_eq!(hook.seen.lock().unwrap().as_slice(), &[(user, true)]);
    assert!(h.user_by_id(user).await.is_none());

    // A failing hook keeps the account (retried on the next run).
    let h2 = Harness::new(h.pool.clone()).await;
    h2.service.register_erasure_hook(Arc::new(FailingHook));
    let kept = h2.active_user("kept@example.com").await;
    h2.service
        .request_deletion(&h2.fresh(kept), &h2.ctx())
        .await
        .unwrap();
    h2.ports.clock.advance(Duration::from_secs(30 * 86_400 + 1));
    assert!(h2.service.purge_due_deletions(10).await.is_err());
    assert!(h2.user_by_id(kept).await.is_some());
}
