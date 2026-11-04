#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Every path of the merged OpenAPI document is routed (ARC-09, OPS-09).
//! Its own test binary: it sends hundreds of requests and would starve the
//! shared test connection budget of parallel tests.

mod common;

use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::{App, ORIGIN};
use serde_json::Value;
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_09_every_documented_path_is_routed(pool: PgPool) {
    // A documented path that answers 404 `not_found` from the fallback is
    // not mounted (module router missing from `app.rs`).
    let app = App::new(pool).await;
    let doc: Value = app.send(TestRequest::get("/openapi.json")).await.json();
    let zero = "00000000-0000-0000-0000-000000000000";
    for (path, item) in doc["paths"].as_object().unwrap() {
        // Mobile association files answer 404 until apps are configured.
        if path.starts_with("/.well-known/") && !path.ends_with("jwks.json") {
            continue;
        }
        let concrete = path
            .split('/')
            .map(|seg| if seg.starts_with('{') { zero } else { seg })
            .collect::<Vec<_>>()
            .join("/");
        for method in item.as_object().unwrap().keys() {
            let request = TestRequest::new(method.to_uppercase().parse().unwrap(), &concrete)
                .header("origin", ORIGIN);
            let res = app.send(request).await;
            let fallback = res.status == StatusCode::NOT_FOUND
                && res.text().contains("\"not_found\"")
                && res.header("allow").is_none();
            let method_missing = res.status == StatusCode::METHOD_NOT_ALLOWED;
            assert!(
                !(fallback && !concrete.contains(zero)) && !method_missing,
                "{method} {path} is documented but not routed ({})",
                res.status
            );
        }
    }
}
