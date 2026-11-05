#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! OPS-02 / SES-04 (wave 3A audit): the protection class of **every** route
//! of the assembled router, enumerated rather than sampled.
//!
//! * Every state-changing route is behind slot 8 (authentication + CSRF):
//!   a request carrying a valid session cookie but no CSRF token is
//!   refused with `403 csrf_failed` before any handler runs — except the
//!   exact, reviewed list of session-less routes ([`SESSION_LESS`]).
//! * Every `/v1/me…`, `/v1/admin/…` (but the enrollment link) and
//!   `/v1/orgs…` route refuses an anonymous caller.
//! * The OpenAPI document lists every routed `/v1/…` and `/.well-known/…`
//!   path of every module (otherwise the enumeration above would silently
//!   skip an undocumented route).
//!
//! Its own test binary: it sends hundreds of requests.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use authn_testkit::http::TestRequest;
use axum::http::{Method, StatusCode};
use common::{App, ORIGIN, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;

/// The only routes merged outside the authentication + CSRF layer
/// (`app.rs::session_less_routes`, contracts §15.3): the break-glass
/// passkey enrollment link (K-11), authenticated by the link token in the
/// body.
const SESSION_LESS: &[(&str, &str)] = &[
    ("POST", "/v1/admin/enrollment/options"),
    ("POST", "/v1/admin/enrollment/verify"),
];

const ZERO: &str = "00000000-0000-0000-0000-000000000000";

fn concrete(path: &str) -> String {
    path.split('/')
        .map(|seg| match seg {
            "{provider}" => "google",
            s if s.starts_with('{') => ZERO,
            s => s,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `(METHOD, path)` of every documented operation.
async fn documented(app: &App) -> Vec<(String, String)> {
    let doc: Value = app.send(TestRequest::get("/openapi.json")).await.json();
    let mut out = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            out.push((method.to_uppercase(), path.clone()));
        }
    }
    assert!(out.len() > 50, "the OpenAPI document looks truncated");
    out
}

fn is_state_changing(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_02_every_state_changing_route_is_behind_authentication_and_csrf(pool: PgPool) {
    let app = App::new(pool).await;
    app.user("alice@example.com").await;
    let mut browser = app.browser();
    let body = browser.login(&app, "alice@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");

    let mut outside = BTreeSet::new();
    for (method, path) in documented(&app).await {
        if !is_state_changing(&method) {
            continue;
        }
        // A same-origin request with the session cookie and no CSRF token.
        let mut request = TestRequest::new(method.parse().unwrap(), &concrete(&path))
            .json(&json!({}))
            .header("origin", ORIGIN);
        for (name, value) in &browser.cookies {
            request = request.cookie(name, value);
        }
        let res = app.send(request).await;
        let refused = res.status == StatusCode::FORBIDDEN && res.text().contains("csrf_failed");
        if !refused {
            outside.insert((method.clone(), path.clone()));
        }
    }
    let expected: BTreeSet<(String, String)> = SESSION_LESS
        .iter()
        .map(|(m, p)| ((*m).to_owned(), (*p).to_owned()))
        .collect();
    assert_eq!(
        outside, expected,
        "state-changing routes that skip the authentication + CSRF layer"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_02_account_admin_and_org_routes_refuse_anonymous_callers(pool: PgPool) {
    let app = App::new(pool).await;
    let mut anonymous_ok = Vec::new();
    for (method, path) in documented(&app).await {
        let protected = path.starts_with("/v1/me")
            || path.starts_with("/v1/orgs")
            || (path.starts_with("/v1/admin/") && !path.starts_with("/v1/admin/enrollment/"));
        if !protected {
            continue;
        }
        let mut request =
            TestRequest::new(method.parse().unwrap(), &concrete(&path)).header("origin", ORIGIN);
        if is_state_changing(&method) {
            request = request.json(&json!({}));
        }
        let res = app.send(request).await;
        if res.status != StatusCode::UNAUTHORIZED {
            anonymous_ok.push(format!("{method} {path} -> {} {}", res.status, res.text()));
        }
    }
    assert!(
        anonymous_ok.is_empty(),
        "protected routes that do not answer 401 to an anonymous caller: {anonymous_ok:#?}"
    );
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `.route("/v1/…")` / `.route("/.well-known/…")` literal of every
/// crate's `src`, with its parameter names erased.
fn routed_paths() -> BTreeSet<String> {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(crates).unwrap() {
        rust_files(&entry.unwrap().path().join("src"), &mut files);
    }
    let mut out = BTreeSet::new();
    for file in files {
        let source = std::fs::read_to_string(&file).unwrap();
        // Unit-test modules mount throw-away routes.
        let production = source.split("#[cfg(test)]").next().unwrap_or_default();
        let mut rest = production;
        while let Some((_, after)) = rest.split_once(".route(") {
            rest = after;
            if let Some(body) = rest.trim_start().strip_prefix('"')
                && let Some((literal, _)) = body.split_once('"')
                && (literal.starts_with("/v1/") || literal.starts_with("/.well-known/"))
            {
                out.insert(erase(literal));
            }
        }
    }
    out
}

fn erase(path: &str) -> String {
    path.split('/')
        .map(|s| if s.starts_with('{') { "{}" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_09_every_routed_path_is_documented(pool: PgPool) {
    let app = App::new(pool).await;
    let documented: BTreeSet<String> = documented(&app)
        .await
        .into_iter()
        .map(|(_, p)| erase(&p))
        .collect();
    let routed = routed_paths();
    assert!(
        routed.contains("/v1/admin/enrollment/verify") && routed.contains("/v1/orgs/{}"),
        "the source scan found too little; is the parser broken? {routed:?}"
    );
    let undocumented: Vec<_> = routed.difference(&documented).collect();
    assert!(
        undocumented.is_empty(),
        "routed but missing from the OpenAPI document: {undocumented:?}"
    );
}

#[test]
fn ops_02_concrete_paths_fill_every_parameter() {
    assert_eq!(
        concrete("/v1/oauth/{provider}/callback"),
        "/v1/oauth/google/callback"
    );
    assert_eq!(
        concrete("/v1/orgs/{org_id}/members/{user_id}"),
        format!("/v1/orgs/{ZERO}/members/{ZERO}")
    );
    let _ = Method::POST;
}
