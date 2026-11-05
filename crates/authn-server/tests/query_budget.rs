#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)] // integration-test crate
//! Query budgets of the hot endpoints (K-70): how many SQL statements one
//! request costs, through the real router and every middleware, with the
//! production rate-limit backend (PostgreSQL).
//!
//! Round trips to PostgreSQL dominate the latency of every endpoint except
//! password login (Argon2id). Counting them is a structural, noise-free
//! regression guard — unlike wall-clock thresholds it never flakes on a
//! busy CI machine. A change that adds a statement to a hot path fails
//! here and must either be justified (raise the budget in the same commit,
//! update `docs/operations/performance.md`) or be removed.

mod common;
mod perf;

use authn_testkit::bench::{QueryLog, count_queries};
use authn_testkit::http::TestResponse;
use axum::http::StatusCode;
use common::App;
use perf::{client_ip, production_shape};
use sqlx::PgPool;

async fn measured(
    app: &App,
    request: authn_testkit::http::TestRequest,
) -> (TestResponse, QueryLog) {
    count_queries(app.send(request)).await
}

fn check(name: &str, log: &QueryLog, budget: usize) {
    println!("{name}: {} statements\n{log}", log.count());
    assert!(
        log.count() <= budget,
        "{name}: {} statements exceed the budget of {budget}:\n{log}",
        log.count()
    );
}

/// The budgets (statements per request, steady state: signing keys
/// cached, API key used within the last minute). Keep in sync with the
/// table in `docs/operations/performance.md`.
mod budget {
    /// Per-IP rate limit + session lookup.
    pub const GET_BEARER: usize = 2;
    /// Per-IP rate limit + session lookup (activity write throttled).
    pub const GET_COOKIE: usize = 2;
    /// Rate limit and session lookup, then profile (user, profile),
    /// password flag, passkey count, MFA status (user, factors, recovery
    /// codes, trusted devices).
    pub const GET_ME: usize = 10;
    /// Two rate limits, family lookup, then one transaction: session and
    /// token locks, retire, insert, link, activity, commit.
    pub const REFRESH: usize = 10;
    /// Per-IP limit, key lookup (owner status joined, last-use write
    /// throttled), per-client limit, session lookup.
    pub const INTROSPECT: usize = 4;
    /// Native password login of a returning user (rate limits, risk,
    /// policy, session, audit chain). Argon2id dominates its latency.
    pub const LOGIN: usize = 42;
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn k_70_query_budget_of_hot_endpoints(pool: PgPool) {
    let app = App::with(pool, |c| production_shape(c, false)).await;
    let users = perf::users(&app, 3).await;

    // Warm-up login (first use of the signing key cache), then the
    // measured login of the returning user from their known network and
    // device (no risk challenge).
    let first = perf::native_login(&app, 0).await;
    let (r, log) = measured(&app, perf::native_login_request(0, perf::user_ip(0, 1))).await;
    r.assert_status(StatusCode::OK);
    assert_eq!(r.json::<serde_json::Value>()["status"], "authenticated");
    check("POST /v1/login/password (native)", &log, budget::LOGIN);
    let tokens = perf::Tokens::from_body(&r.json());
    let _ = first;

    let ip = client_ip(1);
    let (r, log) = measured(&app, perf::bearer_get("/v1/time", &tokens.access, ip)).await;
    r.assert_status(StatusCode::OK);
    check("GET /v1/time (bearer)", &log, budget::GET_BEARER);

    let (r, log) = measured(&app, perf::bearer_get("/v1/me", &tokens.access, ip)).await;
    r.assert_status(StatusCode::OK);
    check("GET /v1/me (bearer)", &log, budget::GET_ME);

    let (r, log) = measured(&app, perf::refresh_request(&tokens.refresh, ip)).await;
    r.assert_status(StatusCode::OK);
    check("POST /v1/token/refresh", &log, budget::REFRESH);

    // Web session cookie (first web login of a user: no risk challenge).
    let mut browser = app.browser();
    let body = browser.login(&app, &perf::email(2), common::PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    let (r, log) = measured(&app, browser.get("/v1/time").peer_ip(client_ip(4))).await;
    r.assert_status(StatusCode::OK);
    check("GET /v1/time (session cookie)", &log, budget::GET_COOKIE);

    // Introspection of an organization token with an API key, steady
    // state (the key's last use was just recorded).
    let (org, key) = perf::org_with_api_key(&app, users[1]).await;
    let owner_tokens = perf::native_login(&app, 1).await;
    let org_tokens = perf::switch_org(&app, &owner_tokens, org, client_ip(2)).await;
    app.send(perf::introspect_request(
        &key,
        &org_tokens.access,
        client_ip(3),
    ))
    .await
    .assert_status(StatusCode::OK);
    let (r, log) = measured(
        &app,
        perf::introspect_request(&key, &org_tokens.access, client_ip(3)),
    )
    .await;
    r.assert_status(StatusCode::OK);
    assert_eq!(r.json::<serde_json::Value>()["active"], true);
    check("POST /v1/token/introspect", &log, budget::INTROSPECT);
}

/// The budget table of `docs/operations/performance.md` states the same
/// numbers as [`budget`] (the documentation is the operators' reference).
#[test]
fn k_70_documented_budgets_match_the_test() {
    let doc = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/operations/performance.md"),
    )
    .unwrap();
    for (row, value) in [
        ("| `GET` kimlik doğrulamalı (bearer) |", budget::GET_BEARER),
        (
            "| `GET` kimlik doğrulamalı (oturum çerezi) |",
            budget::GET_COOKIE,
        ),
        ("| `GET /v1/me` |", budget::GET_ME),
        ("| `POST /v1/token/refresh` |", budget::REFRESH),
        ("| `POST /v1/token/introspect` |", budget::INTROSPECT),
        ("| `POST /v1/login/password` |", budget::LOGIN),
    ] {
        let expected = format!("{row} {value} |");
        assert!(
            doc.lines().any(|l| l.starts_with(&expected)),
            "docs/operations/performance.md has no budget row `{expected}`"
        );
    }
}
