#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-02 (memberships, last owner) and ORG-04 (escalation guard).

mod common;

use authn_core::domain::PageRequest;
use authn_core::error::codes;
use authn_core::ports::SecurityEventKind;
use authn_org::model::MemberStatus;
use authn_org::service::members::UpdateMember;
use authn_org::service::roles::CreateRole;
use authn_testkit::http::TestRequest;
use common::{ADMIN_ROLE_ID, Harness, MEMBER_ROLE_ID, OWNER_ROLE_ID, VIEWER_ROLE_ID};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_users_belong_to_several_orgs_and_members_are_listed(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let a = h.org(alice, "a").await;
    let b = h.org(bob, "b").await;
    h.add_member(a, bob, MEMBER_ROLE_ID).await;
    h.add_member(b, alice, VIEWER_ROLE_ID).await;
    let members = h
        .service
        .list_members(&h.ctx(), &h.fresh(bob), a, &PageRequest::default())
        .await
        .unwrap();
    assert_eq!(members.items.len(), 2);
    let emails: Vec<_> = members
        .items
        .iter()
        .filter_map(|m| m.email.clone())
        .collect();
    assert!(emails.contains(&"alice@example.com".to_owned()));
    assert!(emails.contains(&"bob@example.com".to_owned()));
    // Pagination.
    let first = h
        .service
        .list_members(
            &h.ctx(),
            &h.fresh(bob),
            a,
            &PageRequest {
                limit: Some(1),
                cursor: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert!(first.next_cursor.is_some());
    // A forged cursor is rejected, not trusted.
    let err = h
        .service
        .list_members(
            &h.ctx(),
            &h.fresh(bob),
            a,
            &PageRequest {
                limit: Some(1),
                cursor: Some("bogus".into()),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_last_owner_cannot_leave_be_removed_suspended_or_demoted(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let (member, _, _) = h.membership_of(org, alice).await.unwrap();
    let err = h
        .service
        .leave_organization(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_LAST_OWNER);
    let err = h
        .service
        .remove_member(&h.ctx(), &h.fresh(alice), org, member)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_LAST_OWNER);
    let err = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            member,
            UpdateMember {
                role_id: Some(ADMIN_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_LAST_OWNER);

    // With a second owner, the first one may leave.
    let bob = h.user("bob@example.com").await;
    h.add_member(org, bob, OWNER_ROLE_ID).await;
    h.service
        .leave_organization(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap();
    assert!(h.membership_of(org, alice).await.is_none());
    assert!(h.revoked_in_org(alice, org));
    // Bob is now the last owner.
    let err = h
        .service
        .leave_organization(&h.ctx(), &h.fresh(bob), org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_LAST_OWNER);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_concurrent_demotions_never_leave_an_org_without_owner(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, bob, OWNER_ROLE_ID).await;
    let (alice_m, _, _) = h.membership_of(org, alice).await.unwrap();
    let (bob_m, _, _) = h.membership_of(org, bob).await.unwrap();
    // Each owner demotes the other at the same time.
    let s1 = h.service.clone();
    let s2 = h.service.clone();
    let (ctx1, ctx2) = (h.ctx(), h.ctx());
    let (p1, p2) = (h.fresh(alice), h.fresh(bob));
    let demote = UpdateMember {
        role_id: Some(ADMIN_ROLE_ID),
        status: None,
    };
    let d1 = demote.clone();
    let d2 = demote;
    let (r1, r2) = tokio::join!(
        async move { s1.update_member(&ctx1, &p1, org, bob_m, d1).await },
        async move { s2.update_member(&ctx2, &p2, org, alice_m, d2).await },
    );
    let successes = [r1.is_ok(), r2.is_ok()].iter().filter(|ok| **ok).count();
    assert_eq!(successes, 1, "{r1:?} {r2:?}");
    let owners: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memberships WHERE org_id = $1 AND role_id = $2 AND status = 'active'",
    )
    .bind(org)
    .bind(OWNER_ROLE_ID)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(owners, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_suspension_and_downgrade_revoke_org_sessions(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let carol = h.user("carol@example.com").await;
    let org = h.org(alice, "acme").await;
    let bob_m = h.add_member(org, bob, ADMIN_ROLE_ID).await;
    let carol_m = h.add_member(org, carol, VIEWER_ROLE_ID).await;

    // Upgrade: no revocation.
    let updated = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            carol_m,
            UpdateMember {
                role_id: Some(MEMBER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.role.key, "member");
    // member ⊉ viewer (viewer has roles:read etc.): that is a downgrade.
    assert!(h.revoked_in_org(carol, org));

    let downgraded = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            bob_m,
            UpdateMember {
                role_id: Some(VIEWER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(downgraded.role.key, "viewer");
    assert!(h.revoked_in_org(bob, org));
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::MemberRoleChanged)
            .len(),
        2
    );

    let suspended = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            bob_m,
            UpdateMember {
                role_id: None,
                status: Some(MemberStatus::Suspended),
            },
        )
        .await
        .unwrap();
    assert_eq!(suspended.status, MemberStatus::Suspended);
    // A suspended member has no access at all (looks like an outsider).
    let err = h
        .service
        .get_organization(&h.ctx(), &h.fresh(bob), org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    // Nobody suspends themselves.
    let (alice_m, _, _) = h.membership_of(org, alice).await.unwrap();
    let err = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            alice_m,
            UpdateMember {
                role_id: None,
                status: Some(MemberStatus::Suspended),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::CONFLICT);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_04_admins_cannot_grant_owner_or_manage_owners(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let admin = h.user("admin@example.com").await;
    let carol = h.user("carol@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, admin, ADMIN_ROLE_ID).await;
    let carol_m = h.add_member(org, carol, MEMBER_ROLE_ID).await;
    let (alice_m, _, _) = h.membership_of(org, alice).await.unwrap();

    let err = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(admin),
            org,
            carol_m,
            UpdateMember {
                role_id: Some(OWNER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    // Nor promote themselves.
    let (admin_m, _, _) = h.membership_of(org, admin).await.unwrap();
    let err = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(admin),
            org,
            admin_m,
            UpdateMember {
                role_id: Some(OWNER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    // Nor demote, suspend or remove an owner.
    for input in [
        UpdateMember {
            role_id: Some(VIEWER_ROLE_ID),
            status: None,
        },
        UpdateMember {
            role_id: None,
            status: Some(MemberStatus::Suspended),
        },
    ] {
        let err = h
            .service
            .update_member(&h.ctx(), &h.fresh(admin), org, alice_m, input)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    }
    let err = h
        .service
        .remove_member(&h.ctx(), &h.fresh(admin), org, alice_m)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    // Granting owner needs step-up even for owners.
    let err = h
        .service
        .update_member(
            &h.ctx(),
            &h.stale(alice),
            org,
            carol_m,
            UpdateMember {
                role_id: Some(OWNER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let promoted = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            carol_m,
            UpdateMember {
                role_id: Some(OWNER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(promoted.role.key, "owner");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_04_custom_role_with_permissions_the_actor_lacks_cannot_be_granted(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let manager = h.user("manager@example.com").await;
    let target = h.user("target@example.com").await;
    let org = h.org(alice, "acme").await;
    // A limited "people manager": can update members and read roles only
    // (plus what the `member` role holds, so members can be managed).
    let people = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            CreateRole {
                key: "people".into(),
                name: "People".into(),
                description: None,
                permissions: vec![
                    "org:read".into(),
                    "members:read".into(),
                    "members:update".into(),
                    "roles:read".into(),
                ],
            },
        )
        .await
        .unwrap();
    h.add_member(org, manager, people.id).await;
    let target_m = h.add_member(org, target, MEMBER_ROLE_ID).await;
    // Admin has far more than "people" → refused.
    let err = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(manager),
            org,
            target_m,
            UpdateMember {
                role_id: Some(ADMIN_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    // Granting the same role (subset of own permissions) is fine.
    let ok = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(manager),
            org,
            target_m,
            UpdateMember {
                role_id: Some(people.id),
                status: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(ok.role.key, "people");
    // A role id of another organization is invisible.
    let other_owner = h.user("other@example.com").await;
    let other = h.org(other_owner, "other").await;
    let foreign = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(other_owner),
            other,
            CreateRole {
                key: "people".into(),
                name: "People".into(),
                description: None,
                permissions: vec!["members:read".into()],
            },
        )
        .await
        .unwrap();
    let err = h
        .service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            target_m,
            UpdateMember {
                role_id: Some(foreign.id),
                status: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_removal_revokes_sessions_and_is_audited(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    let bob_m = h.add_member(org, bob, MEMBER_ROLE_ID).await;
    let app = h.app_as(h.fresh(alice));
    TestRequest::delete(&format!("/v1/orgs/{org}/members/{bob_m}"))
        .send(&app)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(h.membership_of(org, bob).await.is_none());
    assert!(h.revoked_in_org(bob, org));
    let removed = h.ports.audit.of_kind(SecurityEventKind::MemberRemoved);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].subject_user, Some(bob));
    // Again: gone.
    TestRequest::delete(&format!("/v1/orgs/{org}/members/{bob_m}"))
        .send(&app)
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    // PATCH through HTTP with an invalid status value.
    let (alice_m, _, _) = h.membership_of(org, alice).await.unwrap();
    TestRequest::patch(&format!("/v1/orgs/{org}/members/{alice_m}"))
        .json(&json!({"status": "root"}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_database_refuses_to_drop_the_last_owner(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let err = sqlx::query("UPDATE memberships SET status = 'suspended' WHERE org_id = $1")
        .bind(org)
        .execute(&h.pool)
        .await
        .unwrap_err();
    let store = authn_store::StoreError::from(err);
    assert!(
        matches!(store, authn_store::StoreError::CheckViolation { ref constraint } if constraint == "org_last_owner_check"),
        "{store:?}"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_membership_check_for_organization_switch(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    // A custom role without any permission still is a membership.
    let empty = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            CreateRole {
                key: "billing_only".into(),
                name: "Billing only".into(),
                description: None,
                permissions: vec!["billing:read".into()],
            },
        )
        .await
        .unwrap();
    let bob_m = h.add_member(org, bob, empty.id).await;
    let ip = Some("203.0.113.10".parse().unwrap());
    let auth = h
        .service
        .check_membership(&h.impersonated(bob, true), org, ip)
        .await
        .unwrap();
    assert_eq!(auth.role_id, empty.id);
    // Outsiders and suspended members: 404.
    let carol = h.user("carol@example.com").await;
    let err = h
        .service
        .check_membership(&h.fresh(carol), org, ip)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    h.service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            bob_m,
            UpdateMember {
                role_id: None,
                status: Some(MemberStatus::Suspended),
            },
        )
        .await
        .unwrap();
    let err = h
        .service
        .check_membership(&h.fresh(bob), org, ip)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
}
