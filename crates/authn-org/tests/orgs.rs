#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-01 (organization CRUD) and ORG-12 (deletion with grace period).

mod common;

use std::time::Duration;

use authn_core::domain::PageRequest;
use authn_core::error::codes;
use authn_core::ports::{DataExporter, RevocationReason, SecurityEventKind};
use authn_org::OrgDataExporter;
use authn_org::model::OrgStatus;
use authn_org::service::orgs::{CreateOrganization, UpdateOrganization};
use authn_testkit::fakes::{DenyAllRateLimiter, RevocationCall};
use authn_testkit::http::TestRequest;
use common::{Harness, MEMBER_ROLE_ID, OWNER_ROLE_ID};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_creator_becomes_owner_and_slug_is_unique(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h
        .service
        .create_organization(
            &h.ctx(),
            &h.fresh(alice),
            CreateOrganization {
                name: "  Acme Inc. ".into(),
                slug: "Acme".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(org.slug, "acme");
    assert_eq!(org.name, "Acme Inc.");
    assert_eq!(org.status, OrgStatus::Active);
    let (_, role, status) = h.membership_of(org.id, alice).await.unwrap();
    assert_eq!(role, OWNER_ROLE_ID);
    assert_eq!(status, "active");
    assert_eq!(
        h.ports.audit.of_kind(SecurityEventKind::OrgCreated).len(),
        1
    );
    assert!(
        h.ports
            .events
            .recorded()
            .iter()
            .any(|e| e.kind.as_str() == "organization.created")
    );

    let bob = h.user("bob@example.com").await;
    let err = h
        .service
        .create_organization(
            &h.ctx(),
            &h.fresh(bob),
            CreateOrganization {
                name: "Other".into(),
                slug: "acme".into(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_SLUG_TAKEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_input_is_validated_and_spoofing_characters_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    for (name, slug) in [
        ("Acme", "-acme"),
        ("Acme", "admin"),
        ("", "acme"),
        ("Pay\u{202E}lapyap", "acme"),
        ("Acme\u{200B}", "acme"),
    ] {
        let err = h
            .service
            .create_organization(
                &h.ctx(),
                &h.fresh(alice),
                CreateOrganization {
                    name: name.into(),
                    slug: slug.into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            codes::common::VALIDATION_FAILED,
            "{name:?} {slug:?}"
        );
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_unverified_users_api_keys_and_read_only_impersonation_cannot_create(pool: PgPool) {
    let h = Harness::new(pool).await;
    let unverified = h.unverified_user("new@example.com").await;
    let err = h
        .service
        .create_organization(
            &h.ctx(),
            &h.fresh(unverified),
            CreateOrganization {
                name: "Spam".into(),
                slug: "spam".into(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_EMAIL_VERIFICATION_REQUIRED);

    let alice = h.user("alice@example.com").await;
    let err = h
        .service
        .create_organization(
            &h.ctx(),
            &h.impersonated(alice, true),
            CreateOrganization {
                name: "X".into(),
                slug: "x".into(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);

    let mut key_principal = h.fresh(alice);
    key_principal.credential = authn_core::domain::PrincipalCredential::ApiKey {
        api_key_id: authn_core::id::ApiKeyId::generate(),
    };
    let err = h
        .service
        .create_organization(
            &h.ctx(),
            &key_principal,
            CreateOrganization {
                name: "X".into(),
                slug: "x".into(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_creation_is_rate_limited_per_user(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.org.creates_per_user =
            authn_core::ports::RateLimitPolicy::new(2, Duration::from_secs(86_400));
    })
    .await;
    let alice = h.user("alice@example.com").await;
    h.org(alice, "one").await;
    h.org(alice, "two").await;
    let err = h
        .service
        .create_organization(
            &h.ctx(),
            &h.fresh(alice),
            CreateOrganization {
                name: "Three".into(),
                slug: "three".into(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    assert!(err.retry_after().is_some());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_read_update_and_list_my_organizations(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let other = h.org(alice, "acme-two").await;
    let viewer = h.user("viewer@example.com").await;
    h.add_member(org, viewer, common::VIEWER_ROLE_ID).await;

    let read = h
        .service
        .get_organization(&h.ctx(), &h.fresh(viewer), org)
        .await
        .unwrap();
    assert_eq!(read.slug, "acme");
    let err = h
        .service
        .update_organization(
            &h.ctx(),
            &h.fresh(viewer),
            org,
            UpdateOrganization {
                name: Some("Hacked".into()),
                slug: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);

    let updated = h
        .service
        .update_organization(
            &h.ctx(),
            &h.fresh(alice),
            org,
            UpdateOrganization {
                name: Some("Acme Renamed".into()),
                slug: Some("acme-renamed".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.slug, "acme-renamed");
    let err = h
        .service
        .update_organization(
            &h.ctx(),
            &h.fresh(alice),
            other,
            UpdateOrganization {
                name: None,
                slug: Some("acme-renamed".into()),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_SLUG_TAKEN);

    let page = h
        .service
        .list_my_organizations(
            &h.fresh(alice),
            &PageRequest {
                limit: Some(1),
                cursor: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    let next = page.next_cursor.clone().unwrap();
    let page2 = h
        .service
        .list_my_organizations(
            &h.fresh(alice),
            &PageRequest {
                limit: Some(1),
                cursor: Some(next),
            },
        )
        .await
        .unwrap();
    assert_eq!(page2.items.len(), 1);
    assert_ne!(
        page.items[0].organization.id,
        page2.items[0].organization.id
    );
    assert!(page2.next_cursor.is_none());

    let viewer_orgs = h
        .service
        .list_my_organizations(&h.fresh(viewer), &PageRequest::default())
        .await
        .unwrap();
    assert_eq!(viewer_orgs.items.len(), 1);
    assert_eq!(viewer_orgs.items[0].role.key, "viewer");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_http_create_and_read(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let app = h.app_as(h.fresh(alice));
    let res = TestRequest::post("/v1/orgs")
        .json(&json!({"name": "Acme", "slug": "acme"}))
        .send(&app)
        .await;
    res.assert_status(StatusCode::CREATED);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: serde_json::Value = res.json();
    let id = body["id"].as_str().unwrap().to_owned();
    let res = TestRequest::get(&format!("/v1/orgs/{id}")).send(&app).await;
    res.assert_status(StatusCode::OK);
    let res = TestRequest::get("/v1/orgs").send(&app).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(
        res.json::<serde_json::Value>()["items"][0]["role"]["key"],
        "owner"
    );
    // Unknown fields are rejected.
    TestRequest::post("/v1/orgs")
        .json(&json!({"name": "Acme", "slug": "acme2", "owner_id": "x"}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    // Without a principal.
    TestRequest::get("/v1/orgs")
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_12_deletion_needs_owner_and_step_up_and_blocks_writes(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let admin = h.user("admin@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, admin, common::ADMIN_ROLE_ID).await;

    let err = h
        .service
        .schedule_deletion(&h.ctx(), &h.fresh(admin), org)
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        codes::common::FORBIDDEN,
        "admins lack org:delete"
    );
    let err = h
        .service
        .schedule_deletion(&h.ctx(), &h.stale(alice), org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);

    let scheduled = h
        .service
        .schedule_deletion(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap();
    assert_eq!(scheduled.status, OrgStatus::PendingDeletion);
    assert_eq!(
        scheduled.deletion_scheduled_for,
        Some(h.now() + h.settings.org.deletion_grace_period)
    );
    assert!(h.revocations().contains(&RevocationCall::AllForOrg(
        org,
        RevocationReason::OrgPolicyChanged
    )));
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OrgDeletionScheduled)
            .len(),
        1
    );

    // Reads still work, writes are blocked.
    h.service
        .get_organization(&h.ctx(), &h.fresh(admin), org)
        .await
        .unwrap();
    let err = h
        .service
        .update_organization(
            &h.ctx(),
            &h.fresh(admin),
            org,
            UpdateOrganization {
                name: Some("X".into()),
                slug: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_PENDING_DELETION);
    let err = h
        .service
        .schedule_deletion(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_PENDING_DELETION);

    // Cancel (owner + step-up).
    let err = h
        .service
        .cancel_deletion(&h.ctx(), &h.stale(alice), org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let restored = h
        .service
        .cancel_deletion(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap();
    assert_eq!(restored.status, OrgStatus::Active);
    let err = h
        .service
        .cancel_deletion(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_DELETION_NOT_SCHEDULED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_12_purge_deletes_everything_after_the_grace_period(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let keep = h.org(alice, "keep").await;
    h.service
        .schedule_deletion(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap();
    assert_eq!(h.service.purge_due_deletions(10).await.unwrap(), 0);
    h.advance(h.settings.org.deletion_grace_period + Duration::from_secs(1));
    assert_eq!(h.service.purge_due_deletions(10).await.unwrap(), 1);
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM memberships WHERE org_id = $1")
        .bind(org)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)")
            .bind(org)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(!exists);
    assert_eq!(
        h.ports.audit.of_kind(SecurityEventKind::OrgDeleted).len(),
        1
    );
    // The other organization is untouched.
    h.service
        .get_organization(&h.ctx(), &h.fresh(alice), keep)
        .await
        .unwrap();
    let err = h
        .service
        .get_organization(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_sole_owner_query_supports_account_deletion(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let solo = h.org(alice, "solo").await;
    let shared = h.org(alice, "shared").await;
    h.add_member(shared, bob, OWNER_ROLE_ID).await;
    let mut conn = h.pool.acquire().await.unwrap();
    let orgs = h
        .service
        .sole_owner_organizations(&mut conn, alice)
        .await
        .unwrap();
    assert_eq!(orgs, vec![solo]);
    assert!(
        h.service
            .sole_owner_organizations(&mut conn, bob)
            .await
            .unwrap()
            .is_empty()
    );
    // Database guard: deleting the sole owner's account is refused.
    let err = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(alice)
        .execute(&h.pool)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("active owner"), "{err}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_data_export_contains_memberships_without_secrets(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let bob = h.user("bob@example.com").await;
    h.add_member(org, bob, MEMBER_ROLE_ID).await;
    let mut conn = h.pool.acquire().await.unwrap();
    let export = OrgDataExporter.export(&mut conn, bob).await.unwrap();
    assert_eq!(OrgDataExporter.section(), "organizations");
    assert_eq!(export["memberships"][0]["org_slug"], "acme");
    assert_eq!(export["memberships"][0]["role"], "member");
    let text = export.to_string();
    assert!(!text.contains("secret_hash") && !text.contains("token"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_rate_limiter_outage_denies_creation(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let service = h.with_rate_limiter(std::sync::Arc::new(DenyAllRateLimiter::default()));
    let err = service
        .create_organization(
            &h.ctx(),
            &h.fresh(alice),
            CreateOrganization {
                name: "Acme".into(),
                slug: "acme".into(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
}
