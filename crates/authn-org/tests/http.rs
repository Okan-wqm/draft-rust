#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Router-level behaviour: authentication required everywhere, read-only
//! impersonation, cache headers, OpenAPI coverage (ARC-03, ARC-09).

mod common;

use authn_org::OrgApi;
use authn_testkit::http::TestRequest;
use common::Harness;
use http::{Method, StatusCode};
use serde_json::json;
use sqlx::PgPool;
use utoipa::OpenApi;

const PATHS: &[(&str, &[&str])] = &[
    ("/v1/orgs", &["get", "post"]),
    ("/v1/org-permissions", &["get"]),
    ("/v1/orgs/{org_id}", &["get", "patch", "delete"]),
    ("/v1/orgs/{org_id}/deletion/cancel", &["post"]),
    ("/v1/orgs/{org_id}/leave", &["post"]),
    ("/v1/orgs/{org_id}/members", &["get"]),
    (
        "/v1/orgs/{org_id}/members/{member_id}",
        &["get", "patch", "delete"],
    ),
    ("/v1/orgs/{org_id}/roles", &["get", "post"]),
    ("/v1/orgs/{org_id}/roles/{role_id}", &["patch", "delete"]),
    ("/v1/orgs/{org_id}/invitations", &["get", "post"]),
    ("/v1/orgs/{org_id}/invitations/{invitation_id}", &["delete"]),
    (
        "/v1/orgs/{org_id}/invitations/{invitation_id}/resend",
        &["post"],
    ),
    ("/v1/invitations/preview", &["post"]),
    ("/v1/invitations/accept", &["post"]),
    ("/v1/orgs/{org_id}/domains", &["get", "post"]),
    (
        "/v1/orgs/{org_id}/domains/{domain_id}",
        &["patch", "delete"],
    ),
    ("/v1/orgs/{org_id}/domains/{domain_id}/verify", &["post"]),
    ("/v1/orgs/{org_id}/policy", &["get", "put"]),
    ("/v1/orgs/{org_id}/api-keys", &["get", "post"]),
    ("/v1/orgs/{org_id}/api-keys/{key_id}", &["get", "delete"]),
    ("/v1/orgs/{org_id}/api-keys/{key_id}/rotate", &["post"]),
    ("/v1/orgs/{org_id}/service-accounts", &["get", "post"]),
    (
        "/v1/orgs/{org_id}/service-accounts/{service_account_id}",
        &["get", "patch", "delete"],
    ),
    ("/v1/orgs/{org_id}/ownership-transfer", &["post", "delete"]),
    ("/v1/ownership-transfers/accept", &["post"]),
];

#[test]
fn arc_09_org_03_every_route_is_documented_in_openapi() {
    let doc = serde_json::to_value(OrgApi::openapi()).unwrap();
    let paths = doc["paths"].as_object().unwrap();
    for (path, methods) in PATHS {
        let entry = paths
            .get(*path)
            .unwrap_or_else(|| panic!("{path} undocumented"));
        for method in *methods {
            assert!(entry.get(*method).is_some(), "{method} {path} undocumented");
        }
    }
    assert_eq!(
        paths.len(),
        PATHS.len(),
        "documented paths without a route?"
    );
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    for schema in [
        "Organization",
        "OrgPolicy",
        "ApiKeySummary",
        "CreatedApiKey",
        "Permission",
    ] {
        assert!(schemas.contains_key(schema), "{schema}");
    }
}

fn concrete(path: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    let mut out = String::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        out.push('/');
        if segment.starts_with('{') {
            out.push_str(&id);
        } else {
            out.push_str(segment);
        }
    }
    out
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_10_every_endpoint_requires_authentication(pool: PgPool) {
    let h = Harness::new(pool).await;
    let app = h.app();
    for (path, methods) in PATHS {
        for method in *methods {
            let method = Method::from_bytes(method.to_uppercase().as_bytes()).unwrap();
            let res = TestRequest::new(method.clone(), &concrete(path))
                .json(&json!({}))
                .send(&app)
                .await;
            assert!(
                res.status == StatusCode::UNAUTHORIZED
                    || res.status == StatusCode::UNPROCESSABLE_ENTITY,
                "{method} {path}: {}",
                res.status
            );
            assert_ne!(res.status, StatusCode::OK, "{method} {path}");
        }
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_03_read_only_impersonation_can_read_but_not_write(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let app = h.app_as(h.impersonated(alice, true));
    let res = TestRequest::get(&format!("/v1/orgs/{org}/members"))
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    TestRequest::patch(&format!("/v1/orgs/{org}"))
        .json(&json!({"name": "Hijacked"}))
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    TestRequest::post(&format!("/v1/orgs/{org}/invitations"))
        .json(&json!({"email": "x@example.com", "role_id": common::MEMBER_ROLE_ID}))
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    TestRequest::post(&format!("/v1/orgs/{org}/leave"))
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    // Writable impersonation still cannot satisfy step-up.
    let app = h.app_as(h.impersonated(alice, false));
    TestRequest::delete(&format!("/v1/orgs/{org}"))
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_01_errors_use_the_standard_envelope_and_localize(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let app = h.app_as(h.fresh(alice));
    let err = TestRequest::get(&format!("/v1/orgs/{}", uuid::Uuid::now_v7()))
        .accept_language("tr")
        .send(&app)
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    assert_eq!(err.message, "İstenen kaynak bulunamadı.");
    assert!(err.request_id.is_some());
    TestRequest::post("/v1/orgs")
        .body("{not json")
        .header("content-type", "application/json")
        .send(&app)
        .await
        .assert_error(StatusCode::BAD_REQUEST, "bad_request");
}
