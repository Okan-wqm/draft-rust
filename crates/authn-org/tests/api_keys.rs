#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-08: API keys and their authentication.

mod common;

use std::time::Duration;

use authn_core::domain::{PrincipalCredential, Subject};
use authn_core::error::codes;
use authn_core::ports::SecurityEventKind;
use authn_org::model::{ApiKeyOwner, ApiKeyState};
use authn_org::permission::Permission;
use authn_org::policy::OrgPolicyInput;
use authn_org::service::api_keys::{CreateApiKey, RotateApiKey};
use authn_org::service::members::UpdateMember;
use authn_org::service::service_accounts::CreateServiceAccount;
use authn_testkit::http::TestRequest;
use common::{ADMIN_ROLE_ID, Harness, VIEWER_ROLE_ID};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

fn key(name: &str, scopes: &[&str]) -> CreateApiKey {
    CreateApiKey {
        name: name.into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        expires_at: None,
        service_account_id: None,
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_key_is_shown_once_and_only_its_hash_is_stored(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("ci", &["members:read"]))
        .await
        .unwrap();
    let text = created.key.expose().to_owned();
    assert!(text.starts_with("ak_live_"));
    assert!(authn_org::parse_api_key(&text).is_ok());
    assert_eq!(created.api_key.state, ApiKeyState::Active);
    assert_eq!(created.api_key.owner, ApiKeyOwner::User { user_id: alice });
    assert_eq!(
        created.api_key.expires_at,
        h.now() + h.settings.org.api_keys.default_lifetime
    );
    // Database: SHA-256 only, the key text appears nowhere.
    let (hash, prefix): (Vec<u8>, String) =
        sqlx::query_as("SELECT secret_hash, display_prefix FROM api_keys WHERE id = $1")
            .bind(created.api_key.id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(hash, authn_crypto::sha256(text.as_bytes()).to_vec());
    assert!(text.starts_with(&prefix));
    let dump: String =
        sqlx::query_scalar("SELECT row_to_json(k)::text FROM api_keys k WHERE id = $1")
            .bind(created.api_key.id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    let secret_part = text.split('_').nth(2).unwrap();
    assert!(!dump.contains(secret_part));
    // Listing and reading never return it either.
    let listed = h
        .service
        .get_api_key(&h.ctx(), &h.fresh(alice), org, created.api_key.id)
        .await
        .unwrap();
    assert!(
        !serde_json::to_string(&listed)
            .unwrap()
            .contains(secret_part)
    );
    // Debug output of the creation result is redacted; audit has no key.
    assert!(!format!("{created:?}").contains(secret_part));
    let audit =
        serde_json::to_string(&h.ports.audit.of_kind(SecurityEventKind::ApiKeyCreated)).unwrap();
    assert!(!audit.contains(secret_part));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_authentication_returns_a_scoped_principal(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let created = h
        .service
        .create_api_key(
            &h.ctx(),
            &h.fresh(alice),
            org,
            key("ci", &["members:read", "org:read"]),
        )
        .await
        .unwrap();
    let principal = h
        .service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
    assert_eq!(principal.subject, Subject::User { user_id: alice });
    assert!(
        matches!(principal.credential, PrincipalCredential::ApiKey { api_key_id } if api_key_id == created.api_key.id)
    );
    assert_eq!(principal.active_org, Some(org));
    assert!(principal.auth_time.is_none() && principal.amr.is_empty());
    assert!(!principal.is_platform_admin);
    // Scope-limited even though the owner is `owner`.
    h.service
        .authorize(&h.ctx(), &principal, Permission::MembersRead, org)
        .await
        .unwrap();
    let err = h
        .service
        .authorize(&h.ctx(), &principal, Permission::MembersInvite, org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    // Keys never satisfy step-up: they cannot create keys.
    let err = h
        .service
        .create_api_key(&h.ctx(), &principal, org, key("x", &["org:read"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    // last_used_* recorded.
    let summary = h
        .service
        .get_api_key(&h.ctx(), &h.fresh(alice), org, created.api_key.id)
        .await
        .unwrap();
    assert_eq!(summary.last_used_at, Some(h.now()));
    assert_eq!(summary.last_used_ip, Some("203.0.113.10".parse().unwrap()));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_last_use_updates_are_throttled(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("ci", &["org:read"]))
        .await
        .unwrap();
    let first = h.now();
    h.service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
    h.advance(Duration::from_secs(30));
    h.service
        .authenticate_api_key(
            &h.ctx_from("198.51.100.1".parse().unwrap()),
            created.key.expose(),
        )
        .await
        .unwrap();
    let s = h
        .service
        .get_api_key(&h.ctx(), &h.fresh(alice), org, created.api_key.id)
        .await
        .unwrap();
    assert_eq!(s.last_used_at, Some(first), "within the interval: no write");
    h.advance(Duration::from_secs(31));
    h.service
        .authenticate_api_key(
            &h.ctx_from("198.51.100.1".parse().unwrap()),
            created.key.expose(),
        )
        .await
        .unwrap();
    let s = h
        .service
        .get_api_key(&h.ctx(), &h.fresh(alice), org, created.api_key.id)
        .await
        .unwrap();
    assert_eq!(s.last_used_at, Some(h.now()));
    assert_eq!(s.last_used_ip, Some("198.51.100.1".parse().unwrap()));
}

/// K-70: a successful authentication is one statement while the key's
/// last use is within `last_used_update_interval` (the owner's status is
/// joined in; the throttled write is not sent), two when the write is due.
/// The owner's status still decides (suspension stops the key at once).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_k_70_recently_used_key_authenticates_in_one_statement(pool: PgPool) {
    use authn_testkit::bench::count_queries;
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("ci", &["org:read"]))
        .await
        .unwrap();
    let raw = created.key.expose().to_owned();
    let (result, log) = count_queries(h.service.authenticate_api_key(&h.ctx(), &raw)).await;
    result.unwrap();
    assert_eq!(log.count(), 2, "first use: lookup + last-use write\n{log}");
    h.advance(Duration::from_secs(30));
    let (result, log) = count_queries(h.service.authenticate_api_key(&h.ctx(), &raw)).await;
    result.unwrap();
    assert_eq!(
        log.count(),
        1,
        "within the interval: the lookup only\n{log}"
    );
    h.advance(Duration::from_secs(31));
    let (result, log) = count_queries(h.service.authenticate_api_key(&h.ctx(), &raw)).await;
    result.unwrap();
    assert_eq!(
        log.count(),
        2,
        "interval over: the write is due again\n{log}"
    );
    // Within the interval again, the joined owner status still applies.
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(alice)
        .execute(&h.pool)
        .await
        .unwrap();
    let err = h
        .service
        .authenticate_api_key(&h.ctx(), &raw)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::UNAUTHENTICATED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_every_failure_is_the_same_401_and_failures_are_limited(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.org.api_keys.auth_failures_per_ip =
            authn_core::ports::RateLimitPolicy::new(3, Duration::from_secs(900));
    })
    .await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("ci", &["org:read"]))
        .await
        .unwrap();
    let revoked = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("old", &["org:read"]))
        .await
        .unwrap();
    h.service
        .revoke_api_key(&h.ctx(), &h.fresh(alice), org, revoked.api_key.id)
        .await
        .unwrap();
    let well_formed_unknown = authn_org::GeneratedApiKey::generate("live").unwrap();
    let other_env = authn_org::GeneratedApiKey::generate("test").unwrap();
    let mut typo = created.key.expose().to_owned().into_bytes();
    let i = "ak_live_".len() + 5;
    typo[i] = if typo[i] == b'x' { b'y' } else { b'x' };
    let typo = String::from_utf8(typo).unwrap();
    // Garbage, wrong environment and bad checksums: no database work and
    // not counted against the IP.
    for raw in [
        "",
        "ak_",
        "not-a-key",
        typo.as_str(),
        other_env.expose(),
        &"ak_live_".repeat(50),
    ] {
        let err = h
            .service
            .authenticate_api_key(&h.ctx(), raw)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::UNAUTHENTICATED, "{raw}");
    }
    // Well-formed but unknown / revoked: same 401, audited, counted.
    for raw in [
        well_formed_unknown.expose(),
        revoked.key.expose(),
        well_formed_unknown.expose(),
    ] {
        let err = h
            .service
            .authenticate_api_key(&h.ctx(), raw)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::UNAUTHENTICATED);
    }
    let failures = h.ports.audit.of_kind(SecurityEventKind::ApiKeyAuthFailed);
    assert_eq!(failures.len(), 3);
    assert!(
        failures
            .iter()
            .any(|e| e.reason.as_deref() == Some("revoked"))
    );
    assert!(
        failures
            .iter()
            .any(|e| e.reason.as_deref() == Some("unknown_key"))
    );
    assert!(
        !serde_json::to_string(&failures)
            .unwrap()
            .contains(well_formed_unknown.expose())
    );
    // The fourth failure from the same IP is throttled (and not audited).
    let err = h
        .service
        .authenticate_api_key(&h.ctx(), well_formed_unknown.expose())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::ApiKeyAuthFailed)
            .len(),
        3
    );
    // A valid key from that IP still works (only failures are limited).
    h.service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_expiry_is_mandatory_and_bounded(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    for expires_at in [
        h.now() - Duration::from_secs(1),
        h.now() + Duration::from_secs(60),
        h.now() + Duration::from_secs(366 * 86_400),
    ] {
        let mut input = key("ci", &["org:read"]);
        input.expires_at = Some(expires_at);
        let err = h
            .service
            .create_api_key(&h.ctx(), &h.fresh(alice), org, input)
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::org::API_KEY_EXPIRY_INVALID);
    }
    let mut input = key("short", &["org:read"]);
    input.expires_at = Some(h.now() + Duration::from_secs(3600));
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, input)
        .await
        .unwrap();
    h.service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
    h.advance(Duration::from_secs(3601));
    let err = h
        .service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::UNAUTHENTICATED);
    let s = h
        .service
        .get_api_key(&h.ctx(), &h.fresh(alice), org, created.api_key.id)
        .await
        .unwrap();
    assert_eq!(s.state, ApiKeyState::Expired);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_scopes_cannot_exceed_the_creator(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let admin = h.user("admin@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, admin, ADMIN_ROLE_ID).await;
    let err = h
        .service
        .create_api_key(
            &h.ctx(),
            &h.fresh(admin),
            org,
            key("x", &["billing:manage"]),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    for scopes in [vec![], vec!["org:delete"], vec!["unknown:scope"]] {
        let err = h
            .service
            .create_api_key(&h.ctx(), &h.fresh(alice), org, key("x", &scopes))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::org::API_KEY_SCOPE_INVALID, "{scopes:?}");
    }
    // A key's rights shrink with its owner's role.
    let created = h
        .service
        .create_api_key(
            &h.ctx(),
            &h.fresh(admin),
            org,
            key("ci", &["members:invite", "org:read"]),
        )
        .await
        .unwrap();
    let (admin_m, _, _) = h.membership_of(org, admin).await.unwrap();
    h.service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            admin_m,
            UpdateMember {
                role_id: Some(VIEWER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap();
    let principal = h
        .service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
    let err = h
        .service
        .authorize(&h.ctx(), &principal, Permission::MembersInvite, org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    h.service
        .authorize(&h.ctx(), &principal, Permission::OrgRead, org)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_rotation_has_a_grace_period_and_revocation_cascades(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let old = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("ci", &["org:read"]))
        .await
        .unwrap();
    let err = h
        .service
        .rotate_api_key(
            &h.ctx(),
            &h.stale(alice),
            org,
            old.api_key.id,
            RotateApiKey::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    let new = h
        .service
        .rotate_api_key(
            &h.ctx(),
            &h.fresh(alice),
            org,
            old.api_key.id,
            RotateApiKey {
                expires_at: None,
                grace_period_seconds: Some(600),
            },
        )
        .await
        .unwrap();
    assert_ne!(new.key.expose(), old.key.expose());
    assert_eq!(new.api_key.rotated_from_id, Some(old.api_key.id));
    assert_eq!(new.api_key.scopes, vec![Permission::OrgRead]);
    // Both work during the grace period.
    h.service
        .authenticate_api_key(&h.ctx(), old.key.expose())
        .await
        .unwrap();
    h.service
        .authenticate_api_key(&h.ctx(), new.key.expose())
        .await
        .unwrap();
    // Rotating the old one again is refused.
    let err = h
        .service
        .rotate_api_key(
            &h.ctx(),
            &h.fresh(alice),
            org,
            old.api_key.id,
            RotateApiKey::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::API_KEY_INACTIVE);
    h.advance(Duration::from_secs(601));
    assert!(
        h.service
            .authenticate_api_key(&h.ctx(), old.key.expose())
            .await
            .is_err()
    );
    h.service
        .authenticate_api_key(&h.ctx(), new.key.expose())
        .await
        .unwrap();
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::ApiKeyRotated)
            .len(),
        1
    );

    // Revoking a fresh rotation also kills the predecessor in grace.
    let newer = h
        .service
        .rotate_api_key(
            &h.ctx(),
            &h.fresh(alice),
            org,
            new.api_key.id,
            RotateApiKey::default(),
        )
        .await
        .unwrap();
    h.service
        .authenticate_api_key(&h.ctx(), new.key.expose())
        .await
        .unwrap();
    let revoked = h
        .service
        .revoke_api_key(&h.ctx(), &h.fresh(alice), org, newer.api_key.id)
        .await
        .unwrap();
    assert_eq!(revoked.state, ApiKeyState::Revoked);
    assert!(
        h.service
            .authenticate_api_key(&h.ctx(), newer.key.expose())
            .await
            .is_err()
    );
    assert!(
        h.service
            .authenticate_api_key(&h.ctx(), new.key.expose())
            .await
            .is_err()
    );
    // Idempotent revoke.
    h.service
        .revoke_api_key(&h.ctx(), &h.fresh(alice), org, newer.api_key.id)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_personal_keys_are_rotated_by_their_owner_only_and_die_with_the_membership(
    pool: PgPool,
) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    let bob_m = h.add_member(org, bob, ADMIN_ROLE_ID).await;
    let bobs = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(bob), org, key("bob", &["org:read"]))
        .await
        .unwrap();
    // Alice (owner) must not mint a credential that acts as Bob.
    let err = h
        .service
        .rotate_api_key(
            &h.ctx(),
            &h.fresh(alice),
            org,
            bobs.api_key.id,
            RotateApiKey::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    // Suspending Bob disables his keys immediately.
    h.service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            bob_m,
            UpdateMember {
                role_id: None,
                status: Some(authn_org::model::MemberStatus::Suspended),
            },
        )
        .await
        .unwrap();
    assert!(
        h.service
            .authenticate_api_key(&h.ctx(), bobs.key.expose())
            .await
            .is_err()
    );
    // Removing him deletes them.
    h.service
        .remove_member(&h.ctx(), &h.fresh(alice), org, bob_m)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE user_id = $1")
        .bind(bob)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_suspended_accounts_and_ip_allowlists_stop_keys(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, bob, ADMIN_ROLE_ID).await;
    let mut admin_session = h.fresh(alice);
    admin_session.amr = vec![authn_core::domain::AuthMethodRef::Pwd];
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(bob), org, key("bob", &["org:read"]))
        .await
        .unwrap();
    // Account suspended by the platform → the key stops.
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(bob)
        .execute(&h.pool)
        .await
        .unwrap();
    assert!(
        h.service
            .authenticate_api_key(&h.ctx(), created.key.expose())
            .await
            .is_err()
    );
    sqlx::query("UPDATE users SET status = 'active' WHERE id = $1")
        .bind(bob)
        .execute(&h.pool)
        .await
        .unwrap();
    h.service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
    // IP allow-list applies to API keys too.
    h.service
        .update_policy(
            &h.ctx(),
            &admin_session,
            org,
            OrgPolicyInput {
                ip_allowlist: Some(vec!["203.0.113.0/24".into()]),
                ..OrgPolicyInput::default()
            },
        )
        .await
        .unwrap();
    h.service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
    let err = h
        .service
        .authenticate_api_key(
            &h.ctx_from("198.51.100.1".parse().unwrap()),
            created.key.expose(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::UNAUTHENTICATED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_http_middleware_authenticates_bearer_and_header_keys(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let created = h
        .service
        .create_api_key(
            &h.ctx(),
            &h.fresh(alice),
            org,
            key("ci", &["members:read", "org:read"]),
        )
        .await
        .unwrap();
    let app = h.app_with_api_keys();
    TestRequest::get(&format!("/v1/orgs/{org}/members"))
        .bearer(created.key.expose())
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    TestRequest::get(&format!("/v1/orgs/{org}"))
        .header("x-api-key", created.key.expose())
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    // Scope missing → 403; wrong key → 401; ambiguous → 401.
    TestRequest::get(&format!("/v1/orgs/{org}/api-keys"))
        .bearer(created.key.expose())
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    let res = TestRequest::get(&format!("/v1/orgs/{org}"))
        .bearer("ak_live_0000000000000000000000000000000000000000000_000000")
        .send(&app)
        .await;
    res.assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    TestRequest::get(&format!("/v1/orgs/{org}"))
        .bearer(created.key.expose())
        .header("x-api-key", created.key.expose())
        .send(&app)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    // Keys cannot create keys (no step-up) nor organizations (`/v1/orgs`
    // is not an organization endpoint: the key authenticates nobody there).
    TestRequest::post(&format!("/v1/orgs/{org}/api-keys"))
        .bearer(created.key.expose())
        .json(&json!({"name": "x", "scopes": ["org:read"]}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    TestRequest::post("/v1/orgs")
        .bearer(created.key.expose())
        .json(&json!({"name": "x", "slug": "x"}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    // Creation through HTTP: the key is in the body once, no-store.
    let res = TestRequest::post(&format!("/v1/orgs/{org}/api-keys"))
        .json(&json!({"name": "deploy", "scopes": ["org:read"]}))
        .send(&h.app_as(h.fresh(alice)))
        .await;
    res.assert_status(StatusCode::CREATED);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: serde_json::Value = res.json();
    assert!(body["key"].as_str().unwrap().starts_with("ak_live_"));
    assert!(body["api_key"].get("secret_hash").is_none());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_service_account_keys_need_an_active_service_account_and_role_scopes(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let sa = h
        .service
        .create_service_account(
            &h.ctx(),
            &h.fresh(alice),
            org,
            CreateServiceAccount {
                name: "ci".into(),
                description: None,
                role_id: VIEWER_ROLE_ID,
            },
        )
        .await
        .unwrap();
    let mut input = key("ci", &["members:invite"]);
    input.service_account_id = Some(sa.id);
    let err = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, input)
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        codes::org::API_KEY_SCOPE_INVALID,
        "outside the SA role"
    );
    let mut input = key("ci", &["members:read"]);
    input.service_account_id = Some(sa.id);
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, input)
        .await
        .unwrap();
    assert_eq!(
        created.api_key.owner,
        ApiKeyOwner::ServiceAccount {
            service_account_id: sa.id
        }
    );
    let principal = h
        .service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
    assert_eq!(
        principal.subject,
        Subject::ServiceAccount {
            service_account_id: sa.id,
            org_id: org
        }
    );
    h.service
        .authorize(&h.ctx(), &principal, Permission::MembersRead, org)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_active_key_limit(pool: PgPool) {
    let h = Harness::with(pool, |s| s.org.limits.api_keys = 1).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let first = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("one", &["org:read"]))
        .await
        .unwrap();
    let err = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("two", &["org:read"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_LIMIT_REACHED);
    h.service
        .revoke_api_key(&h.ctx(), &h.fresh(alice), org, first.api_key.id)
        .await
        .unwrap();
    h.service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("two", &["org:read"]))
        .await
        .unwrap();
}

/// Security review: a personal API key acts as its user only on the
/// organization endpoints of its organization. On account-level endpoints
/// of other modules (`/v1/me/…`), which check neither scopes nor the
/// credential type, the middleware must not produce a principal.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_api_keys_are_not_accepted_outside_organization_endpoints(pool: PgPool) {
    use authn_core::domain::Principal;
    use axum::Router;
    use axum::routing::get;

    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("ci", &["org:read"]))
        .await
        .unwrap();
    // Stand-in for another module's account endpoint (e.g. GET /v1/me/profile).
    let whoami = Router::new().route(
        "/v1/me/whoami",
        get(|principal: Principal| async move {
            principal
                .user_id()
                .map(|u| u.to_string())
                .unwrap_or_default()
        }),
    );
    let app = authn_testkit::http::with_request_context(
        authn_org::router()
            .merge(whoami)
            .with_state(h.service.clone())
            .layer(axum::middleware::from_fn_with_state(
                h.service.clone(),
                authn_org::api_key_middleware,
            )),
    );
    // The key still works where it belongs.
    TestRequest::get(&format!("/v1/orgs/{org}"))
        .bearer(created.key.expose())
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    // Elsewhere it authenticates nobody: no principal reaches the handler.
    for (name, value) in [
        ("authorization", format!("Bearer {}", created.key.expose())),
        ("x-api-key", created.key.expose().to_owned()),
    ] {
        TestRequest::get("/v1/me/whoami")
            .header(name, &value)
            .send(&app)
            .await
            .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    // Dot segments never smuggle a key to another endpoint.
    TestRequest::get(&format!("/v1/orgs/{org}/../../me/whoami"))
        .bearer(created.key.expose())
        .send(&app)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

/// Security review: revoking the newest key of a rotation chain only revoked
/// its direct predecessor; a grand-predecessor still in its grace period
/// (A → B → C, revoke C) kept working.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_revoking_a_key_revokes_its_whole_rotation_chain(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let a = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("ci", &["org:read"]))
        .await
        .unwrap();
    let grace = RotateApiKey {
        expires_at: None,
        grace_period_seconds: Some(3600),
    };
    let b = h
        .service
        .rotate_api_key(&h.ctx(), &h.fresh(alice), org, a.api_key.id, grace.clone())
        .await
        .unwrap();
    let c = h
        .service
        .rotate_api_key(&h.ctx(), &h.fresh(alice), org, b.api_key.id, grace)
        .await
        .unwrap();
    for k in [&a, &b, &c] {
        h.service
            .authenticate_api_key(&h.ctx(), k.key.expose())
            .await
            .unwrap();
    }
    let revoked = h
        .service
        .revoke_api_key(&h.ctx(), &h.fresh(alice), org, c.api_key.id)
        .await
        .unwrap();
    assert_eq!(revoked.state, ApiKeyState::Revoked);
    for k in [&a, &b, &c] {
        let err = h
            .service
            .authenticate_api_key(&h.ctx(), k.key.expose())
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::UNAUTHENTICATED);
        let summary = h
            .service
            .get_api_key(&h.ctx(), &h.fresh(alice), org, k.api_key.id)
            .await
            .unwrap();
        assert_eq!(summary.state, ApiKeyState::Revoked);
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_08_keys_of_suspended_or_deleting_organizations_are_refused(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let created = h
        .service
        .create_api_key(&h.ctx(), &h.fresh(alice), org, key("ci", &["org:read"]))
        .await
        .unwrap();
    h.service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
    for status in ["suspended", "pending_deletion"] {
        sqlx::query(
            "UPDATE organizations SET status = $2, deletion_scheduled_for = \
             CASE WHEN $2 = 'pending_deletion' THEN now() + interval '30 days' END \
             WHERE id = $1",
        )
        .bind(org.as_uuid())
        .bind(status)
        .execute(&h.pool)
        .await
        .unwrap();
        let err = h
            .service
            .authenticate_api_key(&h.ctx(), created.key.expose())
            .await
            .unwrap_err();
        // The same uniform 401 as an unknown key.
        assert_eq!(err.code(), codes::common::UNAUTHENTICATED, "{status}");
    }
    let failures = h.ports.audit.of_kind(SecurityEventKind::ApiKeyAuthFailed);
    assert_eq!(failures.len(), 2);
    assert!(
        failures
            .iter()
            .all(|e| e.reason.as_deref() == Some("org_inactive"))
    );
    // Reactivated: the key works again (it was never revoked).
    sqlx::query(
        "UPDATE organizations SET status = 'active', deletion_scheduled_for = NULL WHERE id = $1",
    )
    .bind(org.as_uuid())
    .execute(&h.pool)
    .await
    .unwrap();
    h.service
        .authenticate_api_key(&h.ctx(), created.key.expose())
        .await
        .unwrap();
}
