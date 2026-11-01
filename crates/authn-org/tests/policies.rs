#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-07: organization security policy.

mod common;

use std::time::Duration;

use authn_core::domain::{AuthMethodRef, FactorKind, LoginMethod};
use authn_core::error::codes;
use authn_core::ports::{RevocationReason, SecurityEventKind};
use authn_org::permission::Permission;
use authn_org::policy::{OrgPolicy, OrgPolicyInput};
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::TestRequest;
use common::{ADMIN_ROLE_ID, Harness, VIEWER_ROLE_ID};
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_defaults_and_read_permission(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let viewer = h.user("viewer@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, viewer, VIEWER_ROLE_ID).await;
    let policy = h
        .service
        .get_policy(&h.ctx(), &h.fresh(viewer), org)
        .await
        .unwrap();
    assert_eq!(policy, OrgPolicy::default());
    assert_eq!(h.service.policy(org).await.unwrap(), OrgPolicy::default());
    let err = h
        .service
        .update_policy(&h.ctx(), &h.fresh(viewer), org, OrgPolicyInput::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_update_needs_step_up_is_audited_and_tightening_revokes_sessions(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let input = OrgPolicyInput {
        mfa_required: true,
        allowed_login_methods: Some(vec![LoginMethod::Passkey, LoginMethod::Password]),
        allowed_mfa_factors: Some(vec![FactorKind::Totp, FactorKind::Webauthn]),
        max_session_lifetime_seconds: Some(8 * 3600),
        ip_allowlist: Some(vec!["203.0.113.0/24".into()]),
        trusted_devices_allowed: false,
        ..OrgPolicyInput::default()
    };
    let mut stale = h.with_mfa(alice);
    stale.auth_time = Some(h.now() - Duration::from_secs(3600));
    let err = h
        .service
        .update_policy(&h.ctx(), &stale, org, input.clone())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);

    let policy = h
        .service
        .update_policy(&h.ctx(), &h.with_mfa(alice), org, input)
        .await
        .unwrap();
    assert!(policy.mfa_required);
    assert!(!policy.trusted_devices_allowed);
    assert_eq!(h.service.policy(org).await.unwrap(), policy);
    assert!(h.revocations().contains(&RevocationCall::AllForOrg(
        org,
        RevocationReason::OrgPolicyChanged
    )));
    let audited = h.ports.audit.of_kind(SecurityEventKind::OrgPolicyChanged);
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].metadata["tightened"], true);
    assert_eq!(audited[0].metadata["policy"]["mfa_required"], true);
    assert_eq!(audited[0].metadata["previous"]["mfa_required"], false);

    // Relaxing does not revoke again.
    let before = h.revocations().len();
    h.service
        .update_policy(&h.ctx(), &h.with_mfa(alice), org, OrgPolicyInput::default())
        .await
        .unwrap();
    assert_eq!(h.revocations().len(), before);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_lockout_guard(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let err = h
        .service
        .update_policy(
            &h.ctx(),
            &h.fresh(alice),
            org,
            OrgPolicyInput {
                ip_allowlist: Some(vec!["10.0.0.0/8".into()]),
                ..OrgPolicyInput::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_POLICY_LOCKOUT);
    assert_eq!(err.details().unwrap()["reason"], "ip_allowlist");
    let err = h
        .service
        .update_policy(
            &h.ctx(),
            &h.fresh(alice),
            org,
            OrgPolicyInput {
                phishing_resistant_mfa_required: true,
                ..OrgPolicyInput::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_POLICY_LOCKOUT);
    let mut passkey = h.fresh(alice);
    passkey.amr = vec![AuthMethodRef::Hwk, AuthMethodRef::Mfa];
    let policy = h
        .service
        .update_policy(
            &h.ctx(),
            &passkey,
            org,
            OrgPolicyInput {
                phishing_resistant_mfa_required: true,
                ..OrgPolicyInput::default()
            },
        )
        .await
        .unwrap();
    assert!(policy.mfa_required && policy.phishing_resistant_mfa_required);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_policy_is_enforced_on_every_org_request(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, bob, ADMIN_ROLE_ID).await;
    h.service
        .update_policy(
            &h.ctx(),
            &h.with_mfa(alice),
            org,
            OrgPolicyInput {
                mfa_required: true,
                ip_allowlist: Some(vec!["203.0.113.0/24".into()]),
                max_session_lifetime_seconds: Some(3600),
                ..OrgPolicyInput::default()
            },
        )
        .await
        .unwrap();
    // Password-only session of Bob: MFA required.
    let err = h
        .service
        .authorize(&h.ctx(), &h.fresh(bob), Permission::OrgRead, org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_POLICY_MFA_REQUIRED);
    // From outside the allow-list.
    let err = h
        .service
        .authorize(
            &h.ctx_from("198.51.100.1".parse().unwrap()),
            &h.with_mfa(bob),
            Permission::OrgRead,
            org,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_POLICY_IP_DENIED);
    // IPv4-mapped IPv6 is the same address.
    h.service
        .authorize(
            &h.ctx_from("::ffff:203.0.113.99".parse().unwrap()),
            &h.with_mfa(bob),
            Permission::OrgRead,
            org,
        )
        .await
        .unwrap();
    // Session older than the cap → re-authenticate.
    let mut old = h.with_mfa(bob);
    old.auth_time = Some(h.now() - Duration::from_secs(3601));
    let err = h
        .service
        .authorize(&h.ctx(), &old, Permission::OrgRead, org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    // Through HTTP: the 403 does not leak anything about other tenants.
    TestRequest::get(&format!("/v1/orgs/{org}"))
        .send(&h.app_as(h.fresh(bob)))
        .await
        .assert_error(StatusCode::FORBIDDEN, "org_policy_mfa_required");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_read_api_for_session_and_mfa(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let strict = h.org(alice, "strict").await;
    let lax = h.org(alice, "lax").await;
    let suspended_member_org = h.org(alice, "other").await;
    let bob = h.user("bob@example.com").await;
    h.add_member(strict, bob, VIEWER_ROLE_ID).await;
    h.add_member(lax, bob, VIEWER_ROLE_ID).await;
    let m = h
        .add_member(suspended_member_org, bob, VIEWER_ROLE_ID)
        .await;
    sqlx::query("UPDATE memberships SET status = 'suspended' WHERE id = $1")
        .bind(m)
        .execute(&h.pool)
        .await
        .unwrap();
    h.service
        .update_policy(
            &h.ctx(),
            &h.with_mfa(alice),
            strict,
            OrgPolicyInput {
                mfa_required: true,
                allowed_mfa_factors: Some(vec![FactorKind::Totp]),
                ..OrgPolicyInput::default()
            },
        )
        .await
        .unwrap();
    let mut conn = h.pool.acquire().await.unwrap();
    let policies = h.service.policies_for_user(&mut conn, bob).await.unwrap();
    assert_eq!(policies.len(), 2, "suspended memberships do not count");
    let strict_policy = policies.iter().find(|(o, _)| *o == strict).unwrap();
    assert!(strict_policy.1.mfa_required);
    assert!(!strict_policy.1.allows_factor(FactorKind::Sms));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_07_http_put_validates_input(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let app = h.app_as(h.with_mfa(alice));
    TestRequest::put(&format!("/v1/orgs/{org}/policy"))
        .json(&json!({"ip_allowlist": ["not-a-network"]}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    TestRequest::put(&format!("/v1/orgs/{org}/policy"))
        .json(&json!({"allowed_login_methods": ["telepathy"]}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    let res = TestRequest::put(&format!("/v1/orgs/{org}/policy"))
        .json(&json!({"mfa_required": true, "ip_allowlist": ["203.0.113.7/24"]}))
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["ip_allowlist"][0], "203.0.113.0/24");
    assert_eq!(body["trusted_devices_allowed"], true);
}
