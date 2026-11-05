#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! PRT-12 / TST-02 (wave 3A audit): DNS rebinding against webhook
//! delivery over the full stack. A webhook URL with a public-looking name
//! passes creation (no DNS at that point); at delivery time the name
//! resolves to loopback. The outbox worker — wired with the server's
//! SSRF-safe client (`Ports::http`) and its handlers
//! (`jobs::outbox_handlers`) — must refuse to connect.
//!
//! The resolver is injected (`SsrfSafeHttpClient::with_resolver`): the
//! sandbox has no DNS server under test control, so a real rebinding DNS
//! answer cannot be produced; the code path after resolution is the same.

mod common;

use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;

use authn_protect::outbound::{SsrfSafeHttpClient, StaticResolver};
use common::{App, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn prt_12_webhook_delivery_refuses_a_name_rebound_to_loopback(pool: PgPool) {
    // A local listener that must never see a connection.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let resolver = Arc::new(
        StaticResolver::new().with("hooks.example.com", &[IpAddr::V4(Ipv4Addr::LOCALHOST)]),
    );
    let lookups = resolver.clone();
    let app = App::with_ports(
        pool,
        // Production rule: no private destinations for user-supplied URLs.
        |c| c.protect.outbound.allow_private_networks = false,
        |ports| {
            let mut outbound = authn_testkit::config::test_config().protect.outbound;
            outbound.allow_private_networks = false;
            ports.http = Arc::new(SsrfSafeHttpClient::with_resolver(&outbound, resolver).unwrap());
        },
    )
    .await;
    app.user("owner@example.com").await;
    let mut owner = app.browser();
    let body = owner.login(&app, "owner@example.com", PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    let r = owner
        .send(
            &app,
            owner.post("/v1/orgs", &json!({"name": "Acme", "slug": "acme"})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let org = r.json::<Value>()["id"].as_str().unwrap().to_owned();
    let r = owner
        .send(
            &app,
            owner.post(
                &format!("/v1/orgs/{org}/webhooks"),
                &json!({
                    "url": format!("https://hooks.example.com:{port}/in"),
                    "event_types": ["organization.updated"],
                }),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    // An event for the endpoint.
    let r = owner
        .send(
            &app,
            owner.patch(&format!("/v1/orgs/{org}"), &json!({"name": "Acme Corp"})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());

    // The server's outbox worker with the server's handlers.
    let handlers = authn_server::jobs::outbox_handlers(&app.services).unwrap();
    let worker = app.services.audit.outbox_worker(handlers);
    // Fan-out (domain event → delivery message), then the delivery.
    for _ in 0..5 {
        worker.run_once().await.unwrap();
    }
    let (attempts, succeeded, error): (i64, i64, Option<String>) = sqlx::query_as(
        "SELECT coalesce(sum(attempts), 0)::bigint,          count(*) FILTER (WHERE status = 'succeeded'), max(last_error)          FROM webhook_deliveries",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert!(attempts >= 1, "no webhook delivery was attempted");
    assert_eq!(succeeded, 0, "{error:?}");
    assert!(lookups.lookups() >= 1, "the name was resolved at delivery");
    assert!(
        listener.accept().is_err(),
        "the delivery connected to loopback"
    );
}
