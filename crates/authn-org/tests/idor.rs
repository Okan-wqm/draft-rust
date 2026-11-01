#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-10 / ARC-10: tenant isolation. An attacker who fully controls
//! organization A (owner, step-up fresh, MFA, API key with every scope)
//! targets organization B through **every** organization endpoint, both
//! by B's organization id and by B's resource ids under A's path. Every
//! attempt must be `404 not_found` and B must be unchanged afterwards.

mod common;

use authn_core::domain::PageRequest;
use authn_core::id::{OrgId, ServiceAccountId};
use authn_org::permission::Permission;
use authn_org::service::api_keys::CreateApiKey;
use authn_org::service::domains::AddDomain;
use authn_org::service::invitations::CreateInvitation;
use authn_org::service::roles::CreateRole;
use authn_org::service::service_accounts::CreateServiceAccount;
use authn_testkit::http::{TestRequest, TestResponse};
use axum::Router;
use common::{Harness, MEMBER_ROLE_ID, VIEWER_ROLE_ID};
use http::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;

/// Resource ids of one organization.
struct Tenant {
    org: OrgId,
    member: String,
    role: String,
    invitation: String,
    domain: String,
    api_key: String,
    api_key_text: String,
    service_account: ServiceAccountId,
    service_account_key: String,
}

async fn tenant(h: &Harness, owner_email: &str, slug: &str) -> (authn_core::id::UserId, Tenant) {
    let owner = h.user(owner_email).await;
    let org = h.org(owner, slug).await;
    let member_user = h.user(&format!("member@{slug}.example")).await;
    let member = h.add_member(org, member_user, MEMBER_ROLE_ID).await;
    let ctx = h.ctx();
    let p = h.with_mfa(owner);
    let role = h
        .service
        .create_role(
            &ctx,
            &p,
            org,
            CreateRole {
                key: "custom".into(),
                name: "Custom".into(),
                description: None,
                permissions: vec!["org:read".into(), "members:read".into()],
            },
        )
        .await
        .unwrap();
    let invitation = h
        .service
        .create_invitation(
            &ctx,
            &p,
            org,
            CreateInvitation {
                email: format!("invitee@{slug}.example"),
                role_id: MEMBER_ROLE_ID,
            },
        )
        .await
        .unwrap();
    let domain = h
        .service
        .add_domain(
            &ctx,
            &p,
            org,
            AddDomain {
                domain: format!("{slug}.example"),
            },
        )
        .await
        .unwrap();
    let all_scopes: Vec<String> = Permission::ALL
        .iter()
        .filter(|p| !p.is_owner_only())
        .map(|p| p.as_str().to_owned())
        .collect();
    let api_key = h
        .service
        .create_api_key(
            &ctx,
            &p,
            org,
            CreateApiKey {
                name: "all".into(),
                scopes: all_scopes,
                expires_at: None,
                service_account_id: None,
            },
        )
        .await
        .unwrap();
    let sa = h
        .service
        .create_service_account(
            &ctx,
            &p,
            org,
            CreateServiceAccount {
                name: "bot".into(),
                description: None,
                role_id: VIEWER_ROLE_ID,
            },
        )
        .await
        .unwrap();
    let sa_key = h
        .service
        .create_api_key(
            &ctx,
            &p,
            org,
            CreateApiKey {
                name: "bot".into(),
                scopes: vec![
                    "org:read".into(),
                    "members:read".into(),
                    "roles:read".into(),
                ],
                expires_at: None,
                service_account_id: Some(sa.id),
            },
        )
        .await
        .unwrap();
    (
        owner,
        Tenant {
            org,
            member: member.to_string(),
            role: role.id.to_string(),
            invitation: invitation.id.to_string(),
            domain: domain.id.to_string(),
            api_key: api_key.api_key.id.to_string(),
            api_key_text: api_key.key.expose().to_owned(),
            service_account: sa.id,
            service_account_key: sa_key.key.expose().to_owned(),
        },
    )
}

/// Every organization-scoped endpoint, addressed with organization
/// `org_in_path` and the resource ids of `target`.
fn attacks(
    org_in_path: OrgId,
    target: &Tenant,
    attacker_user: &str,
) -> Vec<(Method, String, Option<Value>)> {
    let o = org_in_path;
    let t = target;
    let sa = t.service_account;
    vec![
        (Method::GET, format!("/v1/orgs/{o}"), None),
        (
            Method::PATCH,
            format!("/v1/orgs/{o}"),
            Some(json!({"name": "pwned"})),
        ),
        (Method::DELETE, format!("/v1/orgs/{o}"), None),
        (Method::POST, format!("/v1/orgs/{o}/deletion/cancel"), None),
        (Method::POST, format!("/v1/orgs/{o}/leave"), None),
        (Method::GET, format!("/v1/orgs/{o}/members"), None),
        (
            Method::GET,
            format!("/v1/orgs/{o}/members/{}", t.member),
            None,
        ),
        (
            Method::PATCH,
            format!("/v1/orgs/{o}/members/{}", t.member),
            Some(json!({"role_id": VIEWER_ROLE_ID})),
        ),
        (
            Method::DELETE,
            format!("/v1/orgs/{o}/members/{}", t.member),
            None,
        ),
        (Method::GET, format!("/v1/orgs/{o}/roles"), None),
        (
            Method::POST,
            format!("/v1/orgs/{o}/roles"),
            Some(json!({"key": "evil", "name": "Evil", "permissions": ["org:read"]})),
        ),
        (
            Method::PATCH,
            format!("/v1/orgs/{o}/roles/{}", t.role),
            Some(json!({"name": "pwned"})),
        ),
        (
            Method::DELETE,
            format!("/v1/orgs/{o}/roles/{}", t.role),
            None,
        ),
        (Method::GET, format!("/v1/orgs/{o}/invitations"), None),
        (
            Method::POST,
            format!("/v1/orgs/{o}/invitations"),
            Some(json!({"email": "spam@evil.example", "role_id": MEMBER_ROLE_ID})),
        ),
        (
            Method::DELETE,
            format!("/v1/orgs/{o}/invitations/{}", t.invitation),
            None,
        ),
        (
            Method::POST,
            format!("/v1/orgs/{o}/invitations/{}/resend", t.invitation),
            None,
        ),
        (Method::GET, format!("/v1/orgs/{o}/domains"), None),
        (
            Method::POST,
            format!("/v1/orgs/{o}/domains"),
            Some(json!({"domain": "pwned.example"})),
        ),
        (
            Method::PATCH,
            format!("/v1/orgs/{o}/domains/{}", t.domain),
            Some(json!({"auto_join": false})),
        ),
        (
            Method::DELETE,
            format!("/v1/orgs/{o}/domains/{}", t.domain),
            None,
        ),
        (
            Method::POST,
            format!("/v1/orgs/{o}/domains/{}/verify", t.domain),
            None,
        ),
        (Method::GET, format!("/v1/orgs/{o}/policy"), None),
        (Method::PUT, format!("/v1/orgs/{o}/policy"), Some(json!({}))),
        (Method::GET, format!("/v1/orgs/{o}/api-keys"), None),
        (
            Method::POST,
            format!("/v1/orgs/{o}/api-keys"),
            Some(json!({"name": "evil", "scopes": ["org:read"]})),
        ),
        (
            Method::GET,
            format!("/v1/orgs/{o}/api-keys/{}", t.api_key),
            None,
        ),
        (
            Method::DELETE,
            format!("/v1/orgs/{o}/api-keys/{}", t.api_key),
            None,
        ),
        (
            Method::POST,
            format!("/v1/orgs/{o}/api-keys/{}/rotate", t.api_key),
            None,
        ),
        (Method::GET, format!("/v1/orgs/{o}/service-accounts"), None),
        (
            Method::POST,
            format!("/v1/orgs/{o}/service-accounts"),
            Some(json!({"name": "evil", "role_id": VIEWER_ROLE_ID})),
        ),
        (
            Method::GET,
            format!("/v1/orgs/{o}/service-accounts/{sa}"),
            None,
        ),
        (
            Method::PATCH,
            format!("/v1/orgs/{o}/service-accounts/{sa}"),
            Some(json!({"status": "disabled"})),
        ),
        (
            Method::DELETE,
            format!("/v1/orgs/{o}/service-accounts/{sa}"),
            None,
        ),
        (
            Method::POST,
            format!("/v1/orgs/{o}/ownership-transfer"),
            Some(json!({"target_user_id": attacker_user})),
        ),
        (
            Method::DELETE,
            format!("/v1/orgs/{o}/ownership-transfer"),
            None,
        ),
    ]
}

/// The subset of [`attacks`] that address a resource id (meaningful under
/// the attacker's own organization path).
fn resource_attacks(own_org: OrgId, target: &Tenant) -> Vec<(Method, String, Option<Value>)> {
    attacks(own_org, target, "00000000-0000-0000-0000-000000000000")
        .into_iter()
        .filter(|(_, path, _)| {
            [
                &target.member,
                &target.role,
                &target.invitation,
                &target.domain,
                &target.api_key,
            ]
            .iter()
            .any(|id| path.contains(id.as_str()))
                || path.contains(&target.service_account.to_string())
        })
        .collect()
}

async fn send(
    app: &Router,
    method: &Method,
    path: &str,
    body: Option<&Value>,
    bearer: Option<&str>,
) -> TestResponse {
    let mut req = TestRequest::new(method.clone(), path);
    if let Some(body) = body {
        req = req.json(body);
    }
    if let Some(key) = bearer {
        req = req.bearer(key);
    }
    req.send(app).await
}

async fn snapshot(h: &Harness, org: OrgId) -> Value {
    let row: (Value,) = sqlx::query_as(
        "SELECT json_build_object(
            'org', (SELECT row_to_json(o) FROM (SELECT name, slug, status FROM organizations WHERE id = $1) o),
            'members', (SELECT json_agg(json_build_object('u', user_id, 'r', role_id, 's', status) ORDER BY id) FROM memberships WHERE org_id = $1),
            'roles', (SELECT json_agg(json_build_object('n', name, 'p', ARRAY(SELECT permission FROM role_permissions WHERE role_id = r.id ORDER BY permission)) ORDER BY id) FROM roles r WHERE org_id = $1),
            'invitations', (SELECT json_agg(json_build_object('s', status, 'h', encode(token_hash, 'hex'), 'c', send_count) ORDER BY id) FROM invitations WHERE org_id = $1),
            'domains', (SELECT json_agg(json_build_object('d', domain, 's', status, 'a', auto_join) ORDER BY id) FROM org_domains WHERE org_id = $1),
            'policy', (SELECT row_to_json(p) FROM (SELECT mfa_required, ip_allowlist::text[] AS ip FROM org_policies WHERE org_id = $1) p),
            'keys', (SELECT json_agg(json_build_object('r', revoked_at, 'g', rotation_grace_until) ORDER BY id) FROM api_keys WHERE org_id = $1),
            'service_accounts', (SELECT json_agg(json_build_object('n', name, 's', status) ORDER BY id) FROM service_accounts WHERE org_id = $1),
            'transfers', (SELECT count(*) FROM one_time_tokens WHERE group_id = $1)
        )",
    )
    .bind(org)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    row.0
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_10_org_10_every_endpoint_hides_other_tenants_from_a_session_owner(pool: PgPool) {
    let h = Harness::new(pool).await;
    let (attacker, a) = tenant(&h, "mallory@evil.example", "evil").await;
    let (_victim, b) = tenant(&h, "alice@victim.example", "victim").await;
    let before = snapshot(&h, b.org).await;
    // Fully privileged in A: owner, step-up fresh, MFA.
    let app = h.app_as(h.with_mfa(attacker));
    let mut checked = 0;
    for (method, path, body) in attacks(b.org, &b, &attacker.to_string())
        .into_iter()
        .chain(resource_attacks(a.org, &b))
    {
        let res = send(&app, &method, &path, body.as_ref(), None).await;
        assert_eq!(
            res.status,
            StatusCode::NOT_FOUND,
            "{method} {path}: {}",
            res.text()
        );
        assert_eq!(res.error().code, "not_found", "{method} {path}");
        checked += 1;
    }
    assert!(
        checked >= 50,
        "only {checked} cross-tenant requests checked"
    );
    assert_eq!(snapshot(&h, b.org).await, before, "tenant B was modified");
}

/// `path` with every id of `target` replaced by a fresh random id: the
/// response for a foreign resource must be identical to the response for
/// a resource that does not exist at all.
fn control_path(path: &str, target: &Tenant) -> String {
    let mut out = path.to_owned();
    for id in [
        target.org.to_string(),
        target.member.clone(),
        target.role.clone(),
        target.invitation.clone(),
        target.domain.clone(),
        target.api_key.clone(),
        target.service_account.to_string(),
    ] {
        out = out.replace(&id, &uuid::Uuid::now_v7().to_string());
    }
    out
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_10_api_keys_and_service_accounts_are_confined_to_their_org(pool: PgPool) {
    let h = Harness::new(pool).await;
    let (attacker, a) = tenant(&h, "mallory@evil.example", "evil").await;
    let (_victim, b) = tenant(&h, "alice@victim.example", "victim").await;
    let before = snapshot(&h, b.org).await;
    let app = h.app_with_api_keys();
    let mut not_found = 0;
    for key in [&a.api_key_text, &a.service_account_key] {
        for (method, path, body) in attacks(b.org, &b, &attacker.to_string())
            .into_iter()
            .chain(resource_attacks(a.org, &b))
        {
            let res = send(&app, &method, &path, body.as_ref(), Some(key)).await;
            assert!(!res.status.is_success(), "{method} {path}: {}", res.text());
            // Indistinguishable from a request for ids that do not exist.
            let control = send(
                &app,
                &method,
                &control_path(&path, &b),
                body.as_ref(),
                Some(key),
            )
            .await;
            assert_eq!(
                (res.status, res.error().code),
                (control.status, control.error().code),
                "{method} {path}"
            );
            if res.status == StatusCode::NOT_FOUND {
                not_found += 1;
            }
        }
    }
    assert!(not_found >= 40, "only {not_found} answered 404");
    assert_eq!(snapshot(&h, b.org).await, before, "tenant B was modified");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_10_org_10_foreign_ids_cannot_be_used_as_references(pool: PgPool) {
    let h = Harness::new(pool).await;
    let (attacker, a) = tenant(&h, "mallory@evil.example", "evil").await;
    let (_victim, b) = tenant(&h, "alice@victim.example", "victim").await;
    let app = h.app_as(h.with_mfa(attacker));
    // B's custom role inside A: as a member's role, an invitation's role, a
    // service account's role; B's service account as a key owner.
    let cases = [
        (
            Method::PATCH,
            format!("/v1/orgs/{}/members/{}", a.org, a.member),
            json!({"role_id": b.role}),
        ),
        (
            Method::POST,
            format!("/v1/orgs/{}/invitations", a.org),
            json!({"email": "x@evil.example", "role_id": b.role}),
        ),
        (
            Method::POST,
            format!("/v1/orgs/{}/service-accounts", a.org),
            json!({"name": "x", "role_id": b.role}),
        ),
        (
            Method::POST,
            format!("/v1/orgs/{}/api-keys", a.org),
            json!({"name": "x", "scopes": ["org:read"], "service_account_id": b.service_account}),
        ),
    ];
    for (method, path, body) in cases {
        let res = send(&app, &method, &path, Some(&body), None).await;
        res.assert_error(StatusCode::NOT_FOUND, "not_found");
    }
    // Listings of A never contain B's rows.
    let members = h
        .service
        .list_members(&h.ctx(), &h.fresh(attacker), a.org, &PageRequest::default())
        .await
        .unwrap();
    assert!(members.items.iter().all(|m| m.id.to_string() != b.member));
    let keys = h
        .service
        .list_api_keys(&h.ctx(), &h.fresh(attacker), a.org, &PageRequest::default())
        .await
        .unwrap();
    assert!(keys.items.iter().all(|k| k.id.to_string() != b.api_key));
    let roles = h
        .service
        .list_roles(&h.ctx(), &h.fresh(attacker), a.org)
        .await
        .unwrap();
    assert!(roles.iter().all(|r| r.id.to_string() != b.role));
    // A crafted principal claiming B as its organization does not help.
    let mut forged = h.with_mfa(attacker);
    forged.active_org = Some(b.org);
    let err = h
        .service
        .authorize(&h.ctx(), &forged, Permission::OrgRead, b.org)
        .await
        .unwrap_err();
    assert_eq!(err.code(), authn_core::error::codes::common::NOT_FOUND);
    // Unknown and malformed ids: 404 / 400, same as foreign ones.
    TestRequest::get(&format!("/v1/orgs/{}", OrgId::generate()))
        .send(&app)
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    TestRequest::get("/v1/orgs/not-a-uuid")
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "bad_request");
}
