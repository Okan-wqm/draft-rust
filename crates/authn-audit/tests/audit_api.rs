#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Own security events and organization audit log endpoints (AUD-04).

mod common;

use std::time::Duration;

use authn_audit::AuditPermission;
use authn_core::config::audit::AuditConfig;
use authn_core::domain::Locale;
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, RequestId, ServiceAccountId, UserId};
use authn_core::ports::{Actor, AuditSink, RateLimitPolicy, SecurityEvent, SecurityEventKind};
use authn_testkit::http::TestRequest;
use common::{
    Harness, create_org, create_user, impersonated, service_account_principal, user_principal,
};
use http::StatusCode;
use serde_json::Value;
use sqlx::PgPool;

const DAY: Duration = Duration::from_secs(86_400);

fn ctx(ip: &str) -> RequestContext {
    RequestContext {
        request_id: RequestId::generate(),
        client_ip: ip.parse().unwrap(),
        peer_ip: ip.parse().unwrap(),
        user_agent: Some("TestAgent/1.0".into()),
        device_id: None,
        locale: Locale::En,
    }
}

async fn record(h: &Harness, event: SecurityEvent) {
    h.service.sink().record(event).await.unwrap();
}

fn kinds(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["kind"].as_str().unwrap().to_owned())
        .collect()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_user_sees_own_events_of_the_visible_window_only(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let me = create_user(&pool).await;
    record(
        &h,
        SecurityEvent::new(SecurityEventKind::PasswordChanged, h.now())
            .with_context(&ctx("203.0.113.5"))
            .with_actor(Actor::User(me))
            .with_subject(me),
    )
    .await;
    h.ports.clock.advance(DAY * 100);
    record(
        &h,
        SecurityEvent::new(SecurityEventKind::LoginSucceeded, h.now())
            .with_context(&ctx("203.0.113.5"))
            .with_actor(Actor::User(me))
            .with_subject(me)
            .with_meta("method", "password"),
    )
    .await;
    let app = h.app(Some(user_principal(me, None)));
    let res = TestRequest::get("/v1/me/security-events").send(&app).await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(
        kinds(&body),
        vec!["login.succeeded"],
        "older than 90 days hidden"
    );
    let item = &body["items"][0];
    assert_eq!(item["actor"], "self");
    assert_eq!(item["impersonated"], false);
    assert_eq!(item["ip"], "203.0.113.5", "own request: full IP");
    assert_eq!(item["user_agent"], "TestAgent/1.0");
    assert_eq!(item["metadata"]["method"], "password");
    assert!(body.get("next_cursor").is_none());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_user_never_sees_other_users_events_or_personal_data(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let me = create_user(&pool).await;
    let other = create_user(&pool).await;
    let org_admin = create_user(&pool).await;
    let org = create_org(&pool).await;
    // Someone else's login.
    record(
        &h,
        SecurityEvent::new(SecurityEventKind::LoginSucceeded, h.now())
            .with_context(&ctx("198.51.100.20"))
            .with_actor(Actor::User(other))
            .with_subject(other),
    )
    .await;
    // An org admin removes me: I see the event but not the admin's IP / UA.
    record(
        &h,
        SecurityEvent::new(SecurityEventKind::MemberRemoved, h.now())
            .with_context(&ctx("192.0.2.200"))
            .with_actor(Actor::User(org_admin))
            .with_subject(me)
            .with_org(org),
    )
    .await;
    // A failed login attempt on my account by an anonymous caller: masked.
    record(
        &h,
        SecurityEvent::new(SecurityEventKind::LoginFailed, h.now())
            .with_context(&ctx("203.0.113.77"))
            .with_subject(me)
            .failed("wrong_password"),
    )
    .await;

    let app = h.app(Some(user_principal(me, None)));
    let body: Value = TestRequest::get("/v1/me/security-events")
        .send(&app)
        .await
        .json();
    assert_eq!(kinds(&body), vec!["login.failed", "org.member_removed"]);
    let failed = &body["items"][0];
    assert_eq!(failed["actor"], "anonymous");
    assert_eq!(failed["ip"], "203.0.113.x");
    let removed = &body["items"][1];
    assert_eq!(removed["actor"], "user");
    assert_eq!(removed["ip"], Value::Null);
    assert_eq!(removed["user_agent"], Value::Null);
    let text = body.to_string();
    for leaked in [
        "198.51.100.20",
        "192.0.2.200",
        &other.to_string(),
        &org_admin.to_string(),
    ] {
        assert!(!text.contains(leaked), "{leaked} leaked: {text}");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_impersonated_actions_are_flagged_without_exposing_the_admin(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let me = create_user(&pool).await;
    let admin = create_user(&pool).await;
    let mut event = SecurityEvent::new(SecurityEventKind::SessionsRevoked, h.now())
        .with_context(&ctx("192.0.2.9"))
        .with_actor(Actor::User(me))
        .with_subject(me);
    event.impersonator = Some(admin);
    record(&h, event).await;
    let app = h.app(Some(user_principal(me, None)));
    let body: Value = TestRequest::get("/v1/me/security-events")
        .send(&app)
        .await
        .json();
    let item = &body["items"][0];
    assert_eq!(item["actor"], "administrator");
    assert_eq!(item["impersonated"], true);
    assert_eq!(item["ip"], Value::Null);
    assert!(!body.to_string().contains("192.0.2.9"));
    assert!(!body.to_string().contains(&admin.to_string()));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_keyset_pagination_returns_every_event_once(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let me = create_user(&pool).await;
    for i in 0..7_u64 {
        // Two events per instant exercise the id tie-breaker.
        if i % 2 == 0 {
            h.ports.clock.advance(Duration::from_secs(1));
        }
        record(
            &h,
            SecurityEvent::new(SecurityEventKind::LoginSucceeded, h.now())
                .with_actor(Actor::User(me))
                .with_meta("n", i),
        )
        .await;
    }
    let app = h.app(Some(user_principal(me, None)));
    let mut seen = Vec::new();
    let mut uri = "/v1/me/security-events?limit=3".to_owned();
    loop {
        let body: Value = TestRequest::get(&uri).send(&app).await.json();
        for item in body["items"].as_array().unwrap() {
            seen.push(item["metadata"]["n"].as_u64().unwrap());
        }
        match body["next_cursor"].as_str() {
            Some(cursor) => uri = format!("/v1/me/security-events?limit=3&cursor={cursor}"),
            None => break,
        }
    }
    assert_eq!(seen.len(), 7);
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted, (0..7).collect::<Vec<_>>());
    TestRequest::get("/v1/me/security-events?cursor=not-a-cursor")
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_requires_an_authenticated_user_and_is_rate_limited(pool: PgPool) {
    let mut config = AuditConfig::default();
    config.rate_limits.events_read = RateLimitPolicy::new(2, Duration::from_secs(60));
    let h = Harness::with_config(pool.clone(), &config);
    TestRequest::get("/v1/me/security-events")
        .send(&h.app(None))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let org = create_org(&pool).await;
    TestRequest::get("/v1/me/security-events")
        .send(&h.app(Some(service_account_principal(
            ServiceAccountId::generate(),
            org,
        ))))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");

    let me = create_user(&pool).await;
    let app = h.app(Some(user_principal(me, None)));
    for _ in 0..2 {
        TestRequest::get("/v1/me/security-events")
            .send(&app)
            .await
            .assert_status(StatusCode::OK);
    }
    let res = TestRequest::get("/v1/me/security-events").send(&app).await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(res.header("retry-after").is_some());
}

async fn org_fixture(h: &Harness, pool: &PgPool) -> (OrgId, OrgId, UserId, UserId) {
    let org_a = create_org(pool).await;
    let org_b = create_org(pool).await;
    let admin = create_user(pool).await;
    let member = create_user(pool).await;
    h.policy
        .grant_user(admin, org_a, &[AuditPermission::AuditRead]);
    record(
        h,
        SecurityEvent::new(SecurityEventKind::MemberAdded, h.now())
            .with_context(&ctx("203.0.113.44"))
            .with_actor(Actor::User(admin))
            .with_subject(member)
            .with_org(org_a)
            .with_resource("membership", "0192f3a4-1b2c-7d3e-8f90-0123456789ab"),
    )
    .await;
    record(
        h,
        SecurityEvent::new(SecurityEventKind::ApiKeyCreated, h.now())
            .with_actor(Actor::User(admin))
            .with_org(org_a)
            .with_resource("api_key", "0192f3a4-1b2c-7d3e-8f90-0123456789ac"),
    )
    .await;
    record(
        h,
        SecurityEvent::new(SecurityEventKind::MemberRoleChanged, h.now())
            .with_actor(Actor::User(admin))
            .with_subject(member)
            .with_org(org_a)
            .failed("last_owner"),
    )
    .await;
    // Another tenant's event.
    record(
        h,
        SecurityEvent::new(SecurityEventKind::MemberAdded, h.now())
            .with_actor(Actor::User(member))
            .with_org(org_b),
    )
    .await;
    (org_a, org_b, admin, member)
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_org_audit_log_requires_permission_and_hides_other_tenants(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let (org_a, org_b, admin, member) = org_fixture(&h, &pool).await;
    let admin_app = h.app(Some(user_principal(admin, None)));

    let res = TestRequest::get(&format!("/v1/orgs/{org_a}/audit-events"))
        .send(&admin_app)
        .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(
        kinds(&body),
        vec![
            "org.member_role_changed",
            "api_key.created",
            "org.member_added"
        ]
    );
    let added = &body["items"][2];
    assert_eq!(added["actor_user_id"], admin.to_string());
    assert_eq!(added["subject_user_id"], member.to_string());
    assert_eq!(added["ip_network"], "203.0.113.x");

    // Cross-tenant, unknown org and missing permission are all 404.
    for (app, org) in [
        (&admin_app, org_b),
        (&admin_app, OrgId::generate()),
        (&h.app(Some(user_principal(member, None))), org_a),
    ] {
        TestRequest::get(&format!("/v1/orgs/{org}/audit-events"))
            .send(app)
            .await
            .assert_error(StatusCode::NOT_FOUND, "not_found");
    }
    // A service account of another organization, even if the policy were
    // misconfigured to allow it.
    let sa = ServiceAccountId::generate();
    h.policy
        .grant_service_account(sa, org_a, &[AuditPermission::AuditRead]);
    TestRequest::get(&format!("/v1/orgs/{org_a}/audit-events"))
        .send(&h.app(Some(service_account_principal(sa, org_b))))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    TestRequest::get(&format!("/v1/orgs/{org_a}/audit-events"))
        .send(&h.app(Some(service_account_principal(sa, org_a))))
        .await
        .assert_status(StatusCode::OK);
    TestRequest::get("/v1/orgs/not-an-id/audit-events")
        .send(&admin_app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "bad_request");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_org_audit_log_filters(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let (org_a, _org_b, admin, member) = org_fixture(&h, &pool).await;
    let app = h.app(Some(user_principal(admin, None)));
    let get = |query: String| {
        let app = app.clone();
        async move {
            TestRequest::get(&format!("/v1/orgs/{org_a}/audit-events?{query}"))
                .send(&app)
                .await
        }
    };
    let body: Value = get("kind=api_key.created".into()).await.json();
    assert_eq!(kinds(&body), vec!["api_key.created"]);
    let body: Value = get("category=org".into()).await.json();
    assert_eq!(
        kinds(&body),
        vec!["org.member_role_changed", "org.member_added"]
    );
    let body: Value = get("outcome=failure".into()).await.json();
    assert_eq!(kinds(&body), vec!["org.member_role_changed"]);
    let body: Value = get("resource_type=membership".into()).await.json();
    assert_eq!(kinds(&body), vec!["org.member_added"]);
    let body: Value = get(format!("actor_user_id={admin}")).await.json();
    assert_eq!(body["items"].as_array().unwrap().len(), 3);
    let body: Value = get(format!("actor_user_id={member}")).await.json();
    assert_eq!(
        body["items"].as_array().unwrap().len(),
        0,
        "member acted only in org B"
    );
    let body: Value = get("since=2030-01-01T00:00:00Z".into()).await.json();
    assert!(body["items"].as_array().unwrap().is_empty());
    let body: Value = get("until=2030-01-01T00:00:00Z&limit=1".into())
        .await
        .json();
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert!(body["next_cursor"].is_string());
    for bad in [
        "kind=org.nope",
        "category=nope",
        "outcome=maybe",
        "since=yesterday",
        "resource_type=x%27%3B%20DROP%20TABLE%20audit_events",
        "unknown_param=1",
    ] {
        get(bad.into())
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_org_audit_log_hides_platform_staff(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let org = create_org(&pool).await;
    let owner = create_user(&pool).await;
    let staff = create_user(&pool).await;
    h.policy
        .grant_user(owner, org, &[AuditPermission::AuditRead]);
    let mut event = SecurityEvent::new(SecurityEventKind::OrgPolicyChanged, h.now())
        .with_context(&ctx("192.0.2.50"))
        .with_actor(Actor::User(owner))
        .with_org(org);
    event.impersonator = Some(staff);
    record(&h, event).await;
    record(
        &h,
        SecurityEvent::new(SecurityEventKind::AdminAction, h.now())
            .with_context(&ctx("192.0.2.51"))
            .with_actor(Actor::User(staff))
            .with_org(org),
    )
    .await;
    let body: Value = TestRequest::get(&format!("/v1/orgs/{org}/audit-events"))
        .send(&h.app(Some(user_principal(owner, None))))
        .await
        .json();
    let text = body.to_string();
    assert!(!text.contains("192.0.2."), "{text}");
    assert_eq!(body["items"][0]["kind"], "admin.action");
    assert_eq!(body["items"][0]["actor_user_id"], Value::Null);
    assert_eq!(body["items"][1]["impersonated"], true);
    assert_eq!(body["items"][1]["actor_user_id"], Value::Null);
    assert!(!text.contains(&staff.to_string()), "{text}");
    let _ = impersonated; // helper used by other test files
}

/// Security review: organization IP allow-lists (ORG-07) can only be
/// enforced when the policy sees the resolved client IP of the request.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_04_access_policy_receives_the_client_ip(pool: PgPool) {
    let h = Harness::new(pool.clone());
    let (org_a, _, admin, _) = org_fixture(&h, &pool).await;
    let client: std::net::IpAddr = "198.51.100.23".parse().unwrap();
    let res = TestRequest::get(&format!("/v1/orgs/{org_a}/audit-events"))
        .peer_ip(client)
        .send(&h.app(Some(user_principal(admin, Some(h.now())))))
        .await;
    res.assert_status(StatusCode::OK);
    let res = TestRequest::get(&format!("/v1/orgs/{org_a}/webhooks"))
        .peer_ip(client)
        .send(&h.app(Some(user_principal(admin, Some(h.now())))))
        .await;
    res.assert_error(StatusCode::NOT_FOUND, "not_found");
    let seen = h.policy.client_ips();
    assert_eq!(seen, vec![Some(client), Some(client)]);
}
