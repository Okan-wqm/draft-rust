//! Reference implementation of the module-router convention (ARC-03).
//!
//! Every module crate follows exactly this shape:
//!
//! 1. A cheap-to-clone *service* struct holding what the handlers need
//!    (ports as `Arc<dyn …>`, pools, config slices).
//! 2. `pub fn router<S>() -> Router<S>` generic over the application state,
//!    bounded by `Service: FromRef<S>`.
//! 3. Handlers extract `State<Service>`; they never see `AppState`.
//! 4. Handlers are documented with `#[utoipa::path]` and errors use the
//!    standard envelope.
//!
//! The server then merges `example::router::<AppState>()` and implements
//! `FromRef<AppState> for TimeService` (see `crate::state`). Tests build
//! the router with any state that satisfies the bound — e.g. a
//! `TimeService` over a `FakeClock` — without a database.

use std::sync::Arc;

use authn_core::ports::Clock;
use axum::Router;
use axum::extract::{FromRef, State};
use axum::routing::get;
use serde::Serialize;
use time::OffsetDateTime;

/// The example module's service: just a clock.
#[derive(Clone)]
pub struct TimeService {
    clock: Arc<dyn Clock>,
}

impl TimeService {
    /// Creates the service.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

/// Response of `GET /v1/time`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TimeResponse {
    /// Current server time (RFC 3339), for client clock-skew detection.
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub server_time: OffsetDateTime,
}

/// The module router.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    TimeService: FromRef<S>,
{
    Router::new().route("/v1/time", get(server_time))
}

/// Returns the server time.
#[utoipa::path(
    get,
    path = "/v1/time",
    tag = "meta",
    responses(
        (status = 200, description = "Current server time", body = TimeResponse),
        (status = "5XX", description = "Server error", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn server_time(
    State(service): State<TimeService>,
) -> authn_core::http::Json<TimeResponse> {
    authn_core::http::Json(TimeResponse {
        server_time: service.clock.now(),
    })
}

#[cfg(test)]
mod tests {
    use authn_testkit::FakeClock;
    use authn_testkit::http::{TestRequest, with_request_context};
    use http::StatusCode;

    use super::*;

    #[tokio::test]
    async fn arc_03_module_router_works_with_any_state_providing_its_service() {
        // The smallest possible state: the service itself (FromRef<T> for T).
        let clock = Arc::new(FakeClock::new());
        let app = with_request_context(router().with_state(TimeService::new(clock.clone())));
        let res = TestRequest::get("/v1/time").send(&app).await;
        res.assert_status(StatusCode::OK);
        let body: serde_json::Value = res.json();
        assert_eq!(body["server_time"], "2026-01-01T00:00:00Z");
        clock.advance(std::time::Duration::from_secs(60));
        let body: serde_json::Value = TestRequest::get("/v1/time").send(&app).await.json();
        assert_eq!(body["server_time"], "2026-01-01T00:01:00Z");
    }
}
