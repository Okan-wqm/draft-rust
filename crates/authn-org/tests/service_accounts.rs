#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-09: service accounts.

mod common;

use authn_core::domain::PageRequest;
use authn_core::error::codes;
use authn_core::ports::SecurityEventKind;
use authn_org::model::ServiceAccountStatus;
use authn_org::permission::Permission;
use authn_org::service::api_keys::CreateApiKey;
use authn_org::service::service_accounts::{CreateServiceAccount, UpdateServiceAccount};
use common::{ADMIN_ROLE_ID, Harness, MEMBER_ROLE_ID, OWNER_ROLE_ID, VIEWER_ROLE_ID};
use sqlx::PgPool;

fn sa(name: &str, role: authn_core::id::RoleId) -> CreateServiceAccount {
    CreateServiceAccount {
        name: name.into(),
        description: Some("deploy bot".into()),
        role_id: role,
    }
}

async fn sa_key(
    h: &Harness,
    owner: authn_core::id::UserId,
    org: authn_core::id::OrgId,
    sa: authn_core::id::ServiceAccountId,
) -> String {
    h.service
        .create_api_key(
            &h.ctx(),
            &h.fresh(owner),
            org,
            CreateApiKey {
                name: "k".into(),
                scopes: vec!["org:read".into(), "members:read".into()],
                expires_at: None,
                service_account_id: Some(sa),
            },
        )
        .await
        .unwrap()
        .key
        .expose()
        .to_owned()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_09_service_accounts_are_org_owned_and_authenticate_by_key_only(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let bot = h
        .service
        .create_service_account(&h.ctx(), &h.fresh(alice), org, sa("deploy", MEMBER_ROLE_ID))
        .await
        .unwrap();
    assert_eq!(bot.status, ServiceAccountStatus::Active);
    assert_eq!(bot.role.key, "member");
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::ServiceAccountCreated)
            .len(),
        1
    );
    let err = h
        .service
        .create_service_account(&h.ctx(), &h.fresh(alice), org, sa("deploy", MEMBER_ROLE_ID))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::SERVICE_ACCOUNT_NAME_TAKEN);
    let list = h
        .service
        .list_service_accounts(&h.ctx(), &h.fresh(alice), org, &PageRequest::default())
        .await
        .unwrap();
    assert_eq!(list.items.len(), 1);

    let key = sa_key(&h, alice, org, bot.id).await;
    let principal = h
        .service
        .authenticate_api_key(&h.ctx(), &key)
        .await
        .unwrap();
    assert!(principal.user_id().is_none());
    h.service
        .authorize(&h.ctx(), &principal, Permission::MembersRead, org)
        .await
        .unwrap();
    // Service accounts cannot act as humans (accept invitations, leave…).
    let err = h
        .service
        .leave_organization(&h.ctx(), &principal, org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_09_service_accounts_are_never_owners_and_respect_escalation(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let admin = h.user("admin@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, admin, ADMIN_ROLE_ID).await;
    let err = h
        .service
        .create_service_account(&h.ctx(), &h.fresh(alice), org, sa("root", OWNER_ROLE_ID))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
    // An owner-made SA with billing:manage (billing role) is out of the
    // admin's reach.
    let billing = h
        .service
        .create_service_account(
            &h.ctx(),
            &h.fresh(alice),
            org,
            sa("billing", common::BILLING_ROLE_ID),
        )
        .await
        .unwrap();
    let err = h
        .service
        .create_service_account(
            &h.ctx(),
            &h.fresh(admin),
            org,
            sa("billing2", common::BILLING_ROLE_ID),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    let err = h
        .service
        .update_service_account(
            &h.ctx(),
            &h.fresh(admin),
            org,
            billing.id,
            UpdateServiceAccount {
                status: Some(ServiceAccountStatus::Disabled),
                ..UpdateServiceAccount::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    let err = h
        .service
        .delete_service_account(&h.ctx(), &h.fresh(admin), org, billing.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    // The database refuses owner service accounts regardless of the code.
    let err = sqlx::query("UPDATE service_accounts SET role_id = $1 WHERE id = $2")
        .bind(OWNER_ROLE_ID)
        .bind(billing.id)
        .execute(&h.pool)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("service_accounts_not_owner_check"),
        "{err}"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_09_disabling_and_deleting_stop_its_keys(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let bot = h
        .service
        .create_service_account(&h.ctx(), &h.fresh(alice), org, sa("deploy", VIEWER_ROLE_ID))
        .await
        .unwrap();
    let key = sa_key(&h, alice, org, bot.id).await;
    h.service
        .authenticate_api_key(&h.ctx(), &key)
        .await
        .unwrap();
    let disabled = h
        .service
        .update_service_account(
            &h.ctx(),
            &h.fresh(alice),
            org,
            bot.id,
            UpdateServiceAccount {
                name: Some("deploy-old".into()),
                description: Some(String::new()),
                role_id: None,
                status: Some(ServiceAccountStatus::Disabled),
            },
        )
        .await
        .unwrap();
    assert_eq!(disabled.status, ServiceAccountStatus::Disabled);
    assert_eq!(disabled.description, None);
    assert!(
        h.service
            .authenticate_api_key(&h.ctx(), &key)
            .await
            .is_err()
    );
    // No new keys for a disabled account.
    let err = h
        .service
        .create_api_key(
            &h.ctx(),
            &h.fresh(alice),
            org,
            CreateApiKey {
                name: "k2".into(),
                scopes: vec!["org:read".into()],
                expires_at: None,
                service_account_id: Some(bot.id),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::SERVICE_ACCOUNT_DISABLED);
    h.service
        .delete_service_account(&h.ctx(), &h.fresh(alice), org, bot.id)
        .await
        .unwrap();
    let keys: i64 =
        sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE service_account_id = $1")
            .bind(bot.id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(keys, 0);
    let err = h
        .service
        .get_service_account(&h.ctx(), &h.fresh(alice), org, bot.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_09_limit(pool: PgPool) {
    let h = Harness::with(pool, |s| s.org.limits.service_accounts = 1).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    h.service
        .create_service_account(&h.ctx(), &h.fresh(alice), org, sa("one", VIEWER_ROLE_ID))
        .await
        .unwrap();
    let err = h
        .service
        .create_service_account(&h.ctx(), &h.fresh(alice), org, sa("two", VIEWER_ROLE_ID))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_LIMIT_REACHED);
}
