#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-03 (RBAC, custom roles, single authorize function) and ORG-04.

mod common;

use authn_core::error::codes;
use authn_core::ports::SecurityEventKind;
use authn_org::permission::{BuiltinRole, Permission, PermissionSet};
use authn_org::service::roles::{CreateRole, UpdateRole};
use authn_testkit::http::TestRequest;
use common::{ADMIN_ROLE_ID, Harness, MEMBER_ROLE_ID};
use http::StatusCode;
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_03_builtin_role_seed_matches_the_catalog(pool: PgPool) {
    for role in BuiltinRole::ALL {
        let (key, permissions): (String, Vec<String>) = sqlx::query_as(
            "SELECT r.key, ARRAY(SELECT permission FROM role_permissions WHERE role_id = r.id) \
             FROM roles r WHERE r.id = $1 AND r.is_builtin",
        )
        .bind(role.id())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(key, role.as_str());
        assert_eq!(
            PermissionSet::from_db(&permissions),
            role.permissions(),
            "{role}"
        );
        assert_eq!(
            permissions.len(),
            role.permissions().len(),
            "unknown permission in seed"
        );
    }
}

fn role(key: &str, permissions: &[&str]) -> CreateRole {
    CreateRole {
        key: key.into(),
        name: key.to_uppercase(),
        description: Some("test role".into()),
        permissions: permissions.iter().map(|p| (*p).to_owned()).collect(),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_03_custom_roles_drive_authorization(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    let auditor = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            role("auditor", &["audit:read", "org:read"]),
        )
        .await
        .unwrap();
    assert!(!auditor.builtin);
    assert_eq!(
        auditor.permissions,
        vec![Permission::OrgRead, Permission::AuditRead]
    );
    h.add_member(org, bob, auditor.id).await;
    // The single authorize() function: allowed, denied, other permission.
    h.service
        .authorize(&h.ctx(), &h.fresh(bob), Permission::AuditRead, org)
        .await
        .unwrap();
    let err = h
        .service
        .authorize(&h.ctx(), &h.fresh(bob), Permission::MembersRead, org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);

    let roles = h
        .service
        .list_roles(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap();
    assert_eq!(roles.len(), BuiltinRole::ALL.len() + 1);
    assert!(roles.iter().take(5).all(|r| r.builtin));
    assert_eq!(
        h.ports.audit.of_kind(SecurityEventKind::RoleCreated).len(),
        1
    );

    // Removing a permission revokes the holders' sessions and applies on
    // the next request.
    h.service
        .update_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            auditor.id,
            UpdateRole {
                name: None,
                description: Some(String::new()),
                permissions: Some(vec!["org:read".into()]),
            },
        )
        .await
        .unwrap();
    assert!(h.changed_in_org(bob, org));
    assert!(
        !h.revoked_in_org(bob, org),
        "K-41: a role change is not a removal"
    );
    let err = h
        .service
        .authorize(&h.ctx(), &h.fresh(bob), Permission::AuditRead, org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_04_roles_cannot_exceed_the_editors_permissions(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let admin = h.user("admin@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, admin, ADMIN_ROLE_ID).await;
    // Admin lacks billing:manage.
    let err = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(admin),
            org,
            role("cashier", &["billing:manage"]),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    // Owner-only permissions never go on a custom role, not even by owners.
    for perm in ["org:delete", "org:transfer_ownership"] {
        let err = h
            .service
            .create_role(&h.ctx(), &h.fresh(alice), org, role("evil", &[perm]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION, "{perm}");
    }
    // An owner-made role with billing:manage cannot be edited or deleted by
    // the admin (they would manage more than they hold).
    let cashier = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            role("cashier", &["billing:manage", "org:read"]),
        )
        .await
        .unwrap();
    let err = h
        .service
        .update_role(
            &h.ctx(),
            &h.fresh(admin),
            org,
            cashier.id,
            UpdateRole {
                name: Some("Renamed".into()),
                ..UpdateRole::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    let err = h
        .service
        .delete_role(&h.ctx(), &h.fresh(admin), org, cashier.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    // Unknown catalog entries are invalid input.
    let err = h
        .service
        .create_role(&h.ctx(), &h.fresh(alice), org, role("x", &["root:all"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_03_builtin_roles_are_immutable_and_used_roles_cannot_be_deleted(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    let err = h
        .service
        .update_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            MEMBER_ROLE_ID,
            UpdateRole {
                permissions: Some(vec!["members:read".into()]),
                ..UpdateRole::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_BUILTIN_ROLE_IMMUTABLE);
    let err = h
        .service
        .delete_role(&h.ctx(), &h.fresh(alice), org, MEMBER_ROLE_ID)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_BUILTIN_ROLE_IMMUTABLE);

    let support = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            role("support", &["members:read"]),
        )
        .await
        .unwrap();
    let err = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            role("support", &["members:read"]),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_KEY_TAKEN);
    let bob_m = h.add_member(org, bob, support.id).await;
    let err = h
        .service
        .delete_role(&h.ctx(), &h.fresh(alice), org, support.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_IN_USE);
    h.service
        .remove_member(&h.ctx(), &h.fresh(alice), org, bob_m)
        .await
        .unwrap();
    h.service
        .delete_role(&h.ctx(), &h.fresh(alice), org, support.id)
        .await
        .unwrap();
    assert_eq!(
        h.ports.audit.of_kind(SecurityEventKind::RoleDeleted).len(),
        1
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_03_custom_role_limit_and_catalog_endpoint(pool: PgPool) {
    let h = Harness::with(pool, |s| s.org.limits.custom_roles = 1).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    h.service
        .create_role(&h.ctx(), &h.fresh(alice), org, role("one", &["org:read"]))
        .await
        .unwrap();
    let err = h
        .service
        .create_role(&h.ctx(), &h.fresh(alice), org, role("two", &["org:read"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_LIMIT_REACHED);

    let res = TestRequest::get("/v1/org-permissions")
        .send(&h.app_as(h.fresh(alice)))
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let entries = body["permissions"].as_array().unwrap();
    assert_eq!(entries.len(), Permission::ALL.len());
    assert!(
        entries
            .iter()
            .any(|e| e["permission"] == "org:delete" && e["owner_only"] == true)
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_04_database_refuses_owner_only_permissions_on_custom_roles(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let custom = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            role("custom", &["org:read"]),
        )
        .await
        .unwrap();
    let err =
        sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ($1, 'org:delete')")
            .bind(custom.id)
            .execute(&h.pool)
            .await
            .unwrap_err();
    let store = authn_store::StoreError::from(err);
    assert!(
        matches!(store, authn_store::StoreError::CheckViolation { ref constraint } if constraint == "role_permissions_owner_only_check"),
        "{store:?}"
    );
}
