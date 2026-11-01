#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Router / OpenAPI contract (ARC-03, ARC-09) for the account endpoints.

mod common;

use authn_account::{AccountApi, AccountService, router};
use authn_testkit::http::{TestRequest, with_request_context};
use axum::Router;
use axum::extract::FromRef;
use axum::routing::get;
use common::Harness;
use http::StatusCode;
use sqlx::PgPool;
use utoipa::OpenApi;

#[test]
fn acc_01_openapi_documents_every_route() {
    let doc = AccountApi::openapi();
    let paths: Vec<&str> = doc.paths.paths.keys().map(String::as_str).collect();
    for expected in [
        "/v1/signup",
        "/v1/email/verification/resend",
        "/v1/email/verify",
        "/v1/email/change/confirm",
        "/v1/email/change/revert",
        "/v1/account/deletion/cancel",
        "/v1/terms",
        "/v1/me",
        "/v1/me/profile",
        "/v1/me/email",
        "/v1/me/email/confirm",
        "/v1/me/email/verification",
        "/v1/me/email/verify",
        "/v1/me/deletion",
        "/v1/me/deletion/cancel",
        "/v1/me/export",
        "/v1/me/consents",
    ] {
        assert!(
            paths.contains(&expected),
            "{expected} missing from {paths:?}"
        );
    }
    let json = serde_json::to_string(&doc).unwrap();
    assert!(
        json.contains("\"format\":\"password\""),
        "passwords are marked"
    );
}

/// An application state like `authn-server`'s `AppState`.
#[derive(Clone)]
struct AppState {
    account: AccountService,
}

impl FromRef<AppState> for AccountService {
    fn from_ref(state: &AppState) -> Self {
        state.account.clone()
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_01_router_merges_with_other_module_routes(pool: PgPool) {
    let h = Harness::new(pool).await;
    // `GET /v1/me` belongs to authn-session (SES-16); `DELETE /v1/me` to us.
    let session_like: Router<AppState> = Router::new().route("/v1/me", get(|| async { "me" }));
    let app = with_request_context(
        router::<AppState>()
            .merge(session_like)
            .with_state(AppState {
                account: h.service.clone(),
            }),
    );
    let res = TestRequest::get("/v1/me").send(&app).await;
    res.assert_status(StatusCode::OK);
    TestRequest::delete("/v1/me")
        .send(&app)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    TestRequest::get("/v1/terms")
        .send(&app)
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn acc_01_errors_use_the_localized_envelope(pool: PgPool) {
    let h = Harness::new(pool).await;
    let err = TestRequest::post("/v1/signup")
        .json(&serde_json::json!({ "email": "nope", "password": common::PASSWORD }))
        .accept_language("tr")
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_email");
    assert_eq!(err.message, "E-posta adresi geçersiz.");
    assert!(err.request_id.is_some());
    TestRequest::post("/v1/signup")
        .body("email=a")
        .header("content-type", "application/x-www-form-urlencoded")
        .send(&h.app())
        .await
        .assert_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
}
