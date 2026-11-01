#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-11: ownership transfer with acceptance by the target.

mod common;

use std::time::Duration;

use authn_core::error::codes;
use authn_core::ports::SecurityEventKind;
use authn_org::service::members::UpdateMember;
use authn_org::service::transfer::RequestOwnershipTransfer;
use authn_testkit::http::TestRequest;
use common::{ADMIN_ROLE_ID, Harness, MEMBER_ROLE_ID, OWNER_ROLE_ID, secret, token_json};
use http::StatusCode;
use sqlx::PgPool;

fn to(user: authn_core::id::UserId) -> RequestOwnershipTransfer {
    RequestOwnershipTransfer {
        target_user_id: user,
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_11_transfer_needs_owner_step_up_and_target_acceptance(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let admin = h.user("admin@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, bob, MEMBER_ROLE_ID).await;
    h.add_member(org, admin, ADMIN_ROLE_ID).await;

    let err = h
        .service
        .request_ownership_transfer(&h.ctx(), &h.fresh(admin), org, to(admin))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        codes::common::FORBIDDEN,
        "admins lack org:transfer_ownership"
    );
    let err = h
        .service
        .request_ownership_transfer(&h.ctx(), &h.stale(alice), org, to(bob))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let outsider = h.user("outsider@example.com").await;
    for target in [alice, outsider] {
        let err = h
            .service
            .request_ownership_transfer(&h.ctx(), &h.fresh(alice), org, to(target))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_TRANSFER_TARGET_INVALID);
    }

    let pending = h
        .service
        .request_ownership_transfer(&h.ctx(), &h.fresh(alice), org, to(bob))
        .await
        .unwrap();
    assert_eq!(pending.target_user_id, bob);
    let token = h.transfer_token();
    let mail = h.ports.notifier.last().unwrap();
    assert_eq!(mail.recipient.email.as_str(), "bob@example.com");
    // Nothing changed yet.
    assert_eq!(h.membership_of(org, alice).await.unwrap().1, OWNER_ROLE_ID);

    // Another member who got hold of the token cannot use it, and does not
    // burn it.
    let err = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.fresh(admin), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    // The target must step up.
    let err = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.stale(bob), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let done = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.fresh(bob), &secret(&token))
        .await
        .unwrap();
    assert_eq!(done.new_owner, bob);
    assert_eq!(done.previous_owner, alice);
    assert_eq!(h.membership_of(org, bob).await.unwrap().1, OWNER_ROLE_ID);
    assert_eq!(h.membership_of(org, alice).await.unwrap().1, ADMIN_ROLE_ID);
    assert!(h.revoked_in_org(alice, org));
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OrgOwnershipTransferred)
            .len(),
        1
    );
    // Single use.
    let err = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.fresh(bob), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_11_new_request_cancel_and_expiry_invalidate_tokens(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let carol = h.user("carol@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, bob, MEMBER_ROLE_ID).await;
    h.add_member(org, carol, MEMBER_ROLE_ID).await;
    h.service
        .request_ownership_transfer(&h.ctx(), &h.fresh(alice), org, to(bob))
        .await
        .unwrap();
    let to_bob = h.transfer_token();
    h.service
        .request_ownership_transfer(&h.ctx(), &h.fresh(alice), org, to(carol))
        .await
        .unwrap();
    let to_carol = h.transfer_token();
    let err = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.fresh(bob), &secret(&to_bob))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        codes::common::INVALID_OR_EXPIRED_TOKEN,
        "superseded"
    );
    h.service
        .cancel_ownership_transfer(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap();
    let err = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.fresh(carol), &secret(&to_carol))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        codes::common::INVALID_OR_EXPIRED_TOKEN,
        "cancelled"
    );

    h.service
        .request_ownership_transfer(&h.ctx(), &h.fresh(alice), org, to(carol))
        .await
        .unwrap();
    let late = h.transfer_token();
    h.advance(h.settings.org.ownership_transfer_ttl + Duration::from_secs(1));
    let err = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.fresh(carol), &secret(&late))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        codes::common::INVALID_OR_EXPIRED_TOKEN,
        "expired"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_11_stale_transfers_cannot_be_completed(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let dave = h.user("dave@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, bob, MEMBER_ROLE_ID).await;
    h.add_member(org, dave, OWNER_ROLE_ID).await;
    h.service
        .request_ownership_transfer(&h.ctx(), &h.fresh(alice), org, to(bob))
        .await
        .unwrap();
    let token = h.transfer_token();
    // Alice is demoted before Bob accepts: her offer is void.
    let (alice_m, _, _) = h.membership_of(org, alice).await.unwrap();
    h.service
        .update_member(
            &h.ctx(),
            &h.fresh(dave),
            org,
            alice_m,
            UpdateMember {
                role_id: Some(MEMBER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap();
    let err = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.fresh(bob), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    assert_eq!(h.membership_of(org, bob).await.unwrap().1, MEMBER_ROLE_ID);

    // Removed and re-added target: the old offer does not carry over.
    h.service
        .request_ownership_transfer(&h.ctx(), &h.fresh(dave), org, to(bob))
        .await
        .unwrap();
    let token = h.transfer_token();
    let (bob_m, _, _) = h.membership_of(org, bob).await.unwrap();
    h.service
        .remove_member(&h.ctx(), &h.fresh(dave), org, bob_m)
        .await
        .unwrap();
    h.advance(Duration::from_secs(1));
    h.add_member(org, bob, MEMBER_ROLE_ID).await;
    let err = h
        .service
        .accept_ownership_transfer(&h.ctx(), &h.fresh(bob), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_11_http_flow(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, bob, MEMBER_ROLE_ID).await;
    TestRequest::post(&format!("/v1/orgs/{org}/ownership-transfer"))
        .json(&serde_json::json!({"target_user_id": bob}))
        .send(&h.app_as(h.fresh(alice)))
        .await
        .assert_status(StatusCode::ACCEPTED);
    let res = TestRequest::post("/v1/ownership-transfers/accept")
        .json(&token_json(&h.transfer_token()))
        .send(&h.app_as(h.fresh(bob)))
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(
        res.json::<serde_json::Value>()["new_owner"],
        bob.to_string()
    );
}
