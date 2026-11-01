#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Profile: ACC-08 (and the display-name part of ACC-03).

mod common;

use authn_core::ports::Clock as _;

use authn_core::id::UserId;
use authn_testkit::http::TestRequest;
use common::Harness;
use http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_08_profile_can_be_read_and_partially_updated(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("pat@example.com").await;
    let app = h.app_as(&h.fresh(user));
    let res = TestRequest::get("/v1/me/profile").send(&app).await;
    res.assert_status(StatusCode::OK);
    let profile: serde_json::Value = res.json();
    assert_eq!(profile["email"], "pat@example.com");
    assert_eq!(profile["email_verified"], true);
    assert_eq!(profile["locale"], "en");
    assert_eq!(profile["time_zone"], "UTC");
    assert_eq!(profile["display_name"], serde_json::Value::Null);

    let res = TestRequest::patch("/v1/me/profile")
        .json(&json!({ "display_name": "  Pat   Doe ", "locale": "tr" }))
        .send(&app)
        .await;
    res.assert_status(StatusCode::OK);
    let updated: serde_json::Value = res.json();
    assert_eq!(updated["display_name"], "Pat Doe");
    assert_eq!(updated["locale"], "tr");
    assert_eq!(updated["time_zone"], "UTC", "absent fields are kept");

    let updated: serde_json::Value = TestRequest::patch("/v1/me/profile")
        .json(&json!({ "time_zone": "america/new_york" }))
        .send(&app)
        .await
        .json();
    assert_eq!(updated["time_zone"], "America/New_York");
    assert_eq!(updated["display_name"], "Pat Doe");

    let cleared: serde_json::Value = TestRequest::patch("/v1/me/profile")
        .json(&json!({ "display_name": null }))
        .send(&app)
        .await
        .json();
    assert_eq!(cleared["display_name"], serde_json::Value::Null);
    assert_eq!(cleared["locale"], "tr");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_08_invalid_profile_values_are_rejected(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("val@example.com").await;
    let app = h.app_as(&h.fresh(user));
    for (body, code) in [
        (
            json!({ "display_name": "\u{0410}dmin" }),
            "invalid_display_name",
        ),
        (json!({ "display_name": "Support" }), "invalid_display_name"),
        (
            json!({ "display_name": "a\u{200B}b" }),
            "invalid_display_name",
        ),
        (
            json!({ "display_name": "x".repeat(65) }),
            "invalid_display_name",
        ),
        (
            json!({ "time_zone": "Europe/Atlantis" }),
            "invalid_time_zone",
        ),
        (json!({ "locale": "de" }), "validation_failed"),
        (json!({ "email": "x@example.com" }), "validation_failed"),
    ] {
        TestRequest::patch("/v1/me/profile")
            .json(&body)
            .send(&app)
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, code);
    }
    let err = TestRequest::patch("/v1/me/profile")
        .json(&json!({ "display_name": "Ivan Иванов" }))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_display_name");
    assert_eq!(err.details.unwrap()["reason"], "mixed_script");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_08_profile_requires_a_writable_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.active_user("ro@example.com").await;
    TestRequest::get("/v1/me/profile")
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let mut read_only = h.fresh(user);
    read_only.impersonation = Some(authn_core::domain::Impersonation {
        admin_user_id: UserId::generate(),
        read_only: true,
        expires_at: h.ports.clock.now() + time::Duration::minutes(5),
    });
    let app = h.app_as(&read_only);
    TestRequest::get("/v1/me/profile")
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
    TestRequest::patch("/v1/me/profile")
        .json(&json!({ "locale": "tr" }))
        .send(&app)
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
}
