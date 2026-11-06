#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! GeoIP wiring (RSK-05, K-98): `protect.risk.geoip_database` turns on
//! impossible travel in the real login pipeline; a bad file stops the
//! start-up; the reload job swaps in a changed file.

mod common;

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use authn_server::services::open_geoip;
use authn_testkit::mmdb::{MmdbBuilder, city_record};
use axum::http::StatusCode;
use common::{App, Browser, PASSWORD};
use serde_json::{Value, json};
use sqlx::PgPool;

const EMAIL: &str = "traveller@example.com";
const ISTANBUL: &str = "81.214.10.20";
const LONDON: &str = "2.24.10.20";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("authn-server-geoip-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("city.mmdb");
        std::fs::write(
            &path,
            MmdbBuilder::new("Test-City")
                .insert(
                    "81.214.0.0/16",
                    city_record("TR", "Istanbul", 41.0082, 28.9784, 20),
                )
                .insert(
                    "2.24.0.0/16",
                    city_record("GB", "London", 51.5074, -0.1278, 20),
                )
                .build(),
        )
        .unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

async fn login_from(app: &App, browser: &mut Browser, ip: &str) -> (StatusCode, Value) {
    browser.csrf(app).await;
    let request = browser
        .post(
            "/v1/login/password",
            &json!({"email": EMAIL, "password": PASSWORD}),
        )
        .peer_ip(ip.parse::<IpAddr>().unwrap());
    let response = browser.send(app, request).await;
    (response.status, response.json())
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_05_configured_database_blocks_impossible_travel_at_login(pool: PgPool) {
    let fixture = Fixture::new();
    let path = fixture.0.clone();
    let app = App::with(pool, |c| c.protect.risk.geoip_database = Some(path)).await;
    assert!(app.services.geoip.is_some());
    app.user(EMAIL).await;

    let mut browser = app.browser();
    let (status, body) = login_from(&app, &mut browser, ISTANBUL).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "authenticated", "{body}");

    // One hour later from London, same browser: impossible travel → high
    // risk → blocked after the password was verified (RSK-03).
    app.advance(Duration::from_secs(3600));
    let (status, body) = login_from(&app, &mut browser, LONDON).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "suspicious_login_blocked", "{body}");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_05_without_a_database_the_same_trip_is_only_a_new_network(pool: PgPool) {
    let app = App::new(pool).await;
    assert!(app.services.geoip.is_none());
    app.user(EMAIL).await;
    let mut browser = app.browser();
    let (_, body) = login_from(&app, &mut browser, ISTANBUL).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    app.advance(Duration::from_secs(3600));
    let (status, body) = login_from(&app, &mut browser, LONDON).await;
    // Medium risk (new network): a step-up, not a block.
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "challenge_required", "{body}");
}

#[test]
fn rsk_05_unreadable_database_stops_the_start_up() {
    let fixture = Fixture::new();
    let mut config = authn_testkit::config::test_config();
    config.protect.risk.geoip_database = Some(fixture.0.with_file_name("missing.mmdb"));
    assert!(open_geoip(&config).is_err());
    std::fs::write(&fixture.0, b"not a database").unwrap();
    config.protect.risk.geoip_database = Some(fixture.0.clone());
    assert!(open_geoip(&config).is_err());
    config.protect.risk.geoip_database = None;
    assert!(open_geoip(&config).unwrap().is_none());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_05_reload_job_picks_up_a_replaced_database(pool: PgPool) {
    let fixture = Fixture::new();
    let path = fixture.0.clone();
    let app = App::with(pool, |c| c.protect.risk.geoip_database = Some(path)).await;
    assert!(!authn_server::jobs::reload_geoip(&app.services).await);
    std::fs::write(
        &fixture.0,
        MmdbBuilder::new("Test-City-v2")
            .insert(
                "81.214.0.0/16",
                city_record("DE", "Berlin", 52.52, 13.405, 10),
            )
            .build(),
    )
    .unwrap();
    assert!(authn_server::jobs::reload_geoip(&app.services).await);
    let geoip = app.services.geoip.as_ref().unwrap();
    assert_eq!(geoip.info().database_type, "Test-City-v2");
    // A broken replacement keeps the loaded database.
    std::fs::write(&fixture.0, b"partial download").unwrap();
    assert!(!authn_server::jobs::reload_geoip(&app.services).await);
    assert_eq!(geoip.info().database_type, "Test-City-v2");
}
