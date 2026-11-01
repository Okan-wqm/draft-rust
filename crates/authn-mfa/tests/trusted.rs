#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! MFA-09: trusted devices — signed token + DB row, 30-day default,
//! revocation (API, password reset / logout-all in the caller's
//! transaction, MFA change), disabled for admins and by policy.

mod common;

use std::time::Duration;

use authn_core::error::codes;
use authn_core::ports::{RevocationReason, SecurityEventKind};
use authn_mfa::OrgMfaPolicy;
use common::Harness;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_trusted_device_token_round_trip_and_binding(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let issued = h
        .service
        .trust_device(&h.ctx(), alice, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        issued.expires_at,
        h.now() + Duration::from_secs(30 * 86_400)
    );
    let token = issued.token.expose().to_owned();
    assert!(!format!("{issued:?}").contains(&token));
    assert!(
        h.service
            .is_trusted_device(alice, &token, true)
            .await
            .unwrap()
    );
    // Bound to Alice: useless for Bob.
    assert!(
        !h.service
            .is_trusted_device(bob, &token, true)
            .await
            .unwrap()
    );
    // Tampered / garbage tokens are simply "not trusted".
    let mut tampered = token.clone().into_bytes();
    let last = tampered.len() - 2;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    for bad in [tampered.as_str(), "", "td1.x.y.z.w", &"A".repeat(5000)] {
        assert!(!h.service.is_trusted_device(alice, bad, true).await.unwrap());
    }
    // Only the hash is stored.
    let (hash,): (Vec<u8>,) =
        sqlx::query_as("SELECT token_hash FROM trusted_devices WHERE id = $1")
            .bind(issued.device_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(hash.len(), 32);
    assert!(
        !hash
            .windows(8)
            .any(|w| token.as_bytes().windows(8).any(|t| t == w))
    );
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::TrustedDeviceAdded)
            .len(),
        1
    );
    let list = h
        .service
        .list_trusted_devices(&h.fresh(alice))
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].ip.as_deref(), Some("203.0.113.x"));
    assert!(list[0].last_used_at.is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_expires_after_thirty_days(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let issued = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    h.advance(Duration::from_secs(30 * 86_400 - 1));
    assert!(
        h.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap()
    );
    h.advance(Duration::from_secs(2));
    assert!(
        !h.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap()
    );
    let report = h.service.purge_expired().await.unwrap();
    assert_eq!(report.trusted_devices, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_disabled_for_admins_by_policy_and_by_configuration(pool: sqlx::PgPool) {
    let h = Harness::new(pool.clone()).await;
    let user = h.user("alice@example.com").await;
    let admin = h.user("root@example.com").await;
    // Organization policy forbids it.
    assert!(
        h.service
            .trust_device(&h.ctx(), user, false)
            .await
            .unwrap()
            .is_none()
    );
    let issued = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !h.service
            .is_trusted_device(user, issued.token.expose(), false)
            .await
            .unwrap()
    );
    // Platform admins never get trusted devices; an admin promoted later
    // loses them immediately.
    h.make_admin(admin).await;
    assert!(
        h.service
            .trust_device(&h.ctx(), admin, true)
            .await
            .unwrap()
            .is_none()
    );
    let before = h.user("later@example.com").await;
    let token = h
        .service
        .trust_device(&h.ctx(), before, true)
        .await
        .unwrap()
        .unwrap();
    h.make_admin(before).await;
    assert!(
        !h.service
            .is_trusted_device(before, token.token.expose(), true)
            .await
            .unwrap()
    );
    // Disabled by configuration.
    let off = Harness::with(pool, |s| s.mfa.trusted_device.enabled = false).await;
    let carol = off.user("carol@example.com").await;
    assert!(
        off.service
            .trust_device(&off.ctx(), carol, true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !off.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_revocation_api(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mallory = h.user("mallory@example.com").await;
    let a = h
        .service
        .trust_device(&h.ctx(), alice, true)
        .await
        .unwrap()
        .unwrap();
    let b = h
        .service
        .trust_device(&h.ctx(), alice, true)
        .await
        .unwrap()
        .unwrap();
    // Someone else's device id: not found, nothing revoked.
    let err = h
        .service
        .revoke_trusted_device(&h.ctx(), &h.fresh(mallory), a.device_id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    assert!(
        h.service
            .is_trusted_device(alice, a.token.expose(), true)
            .await
            .unwrap()
    );
    // Revoking needs a session but no step-up (protective action).
    let stale = h.principal(alice, Duration::from_secs(3600));
    h.service
        .revoke_trusted_device(&h.ctx(), &stale, a.device_id)
        .await
        .unwrap();
    assert!(
        !h.service
            .is_trusted_device(alice, a.token.expose(), true)
            .await
            .unwrap()
    );
    assert!(
        h.service
            .is_trusted_device(alice, b.token.expose(), true)
            .await
            .unwrap()
    );
    assert_eq!(
        h.service
            .revoke_all_trusted_devices(&h.ctx(), &stale)
            .await
            .unwrap(),
        1
    );
    assert!(
        !h.service
            .is_trusted_device(alice, b.token.expose(), true)
            .await
            .unwrap()
    );
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::TrustedDeviceRevoked)
            .len(),
        2
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_password_reset_and_logout_all_revoke_in_the_callers_transaction(
    pool: sqlx::PgPool,
) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let issued = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    // Rolled back: devices stay trusted.
    let mut tx = h.pool.begin().await.unwrap();
    let n = h
        .service
        .revoke_trusted_devices_in_tx(&mut tx, user, RevocationReason::PasswordReset)
        .await
        .unwrap();
    assert_eq!(n, 1);
    tx.rollback().await.unwrap();
    assert!(
        h.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap()
    );
    // Committed: revoked, with the reason recorded.
    let mut tx = h.pool.begin().await.unwrap();
    h.service
        .revoke_trusted_devices_in_tx(&mut tx, user, RevocationReason::PasswordReset)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        !h.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap()
    );
    let (reason,): (String,) =
        sqlx::query_as("SELECT revoked_reason FROM trusted_devices WHERE id = $1")
            .bind(issued.device_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(reason, "password_reset");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_mfa_changes_revoke_trusted_devices(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    h.enroll_totp(user).await;
    let issued = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    h.service
        .regenerate_recovery_codes(&h.ctx(), &h.fresh(user))
        .await
        .unwrap();
    assert!(
        !h.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap()
    );
    let issued = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    h.enroll_totp(user).await;
    assert!(
        !h.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_active_devices_per_user_are_bounded(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let first = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..20 {
        h.advance(Duration::from_secs(1));
        h.service
            .trust_device(&h.ctx(), user, true)
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        h.service
            .list_trusted_devices(&h.fresh(user))
            .await
            .unwrap()
            .len(),
        20
    );
    assert!(
        !h.service
            .is_trusted_device(user, first.token.expose(), true)
            .await
            .unwrap()
    );
}

/// Security review: an organization that switched trusted devices off must
/// not be bypassed by a login whose context (passed by the caller) allows
/// them — the strictest policy over all memberships applies.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn mfa_09_any_membership_policy_can_disable_trusted_devices(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let issued = h
        .service
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    // The user joins an organization that forbids trusted devices.
    *h.policy.org.lock().unwrap() = Some(OrgMfaPolicy {
        trusted_devices_allowed: false,
        ..OrgMfaPolicy::default()
    });
    assert!(
        !h.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap(),
        "an existing device must not skip MFA"
    );
    assert!(
        h.service
            .trust_device(&h.ctx(), user, true)
            .await
            .unwrap()
            .is_none(),
        "no new device may be trusted"
    );
    // Once no membership forbids it, the (unrevoked) device works again.
    *h.policy.org.lock().unwrap() = None;
    assert!(
        h.service
            .is_trusted_device(user, issued.token.expose(), true)
            .await
            .unwrap()
    );
}
