//! Health probes (OPS-05). Unauthenticated, outside `/v1`, and reveal only
//! component states — never versions, hosts or error messages.

use axum::Router;
use axum::extract::{FromRef, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use http::StatusCode;
use serde::Serialize;
use sqlx::PgPool;

/// Dependencies of the probes.
#[derive(Clone)]
pub struct HealthState {
    /// Database pool.
    pub db: PgPool,
}

/// Probe response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    /// `ok` / `ready` / `not_ready`.
    pub status: &'static str,
    /// Database reachable (`ready` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<&'static str>,
    /// Schema matches this binary (`ready` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrations: Option<&'static str>,
}

/// Health routes.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    HealthState: FromRef<S>,
{
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
}

/// Liveness: the process serves HTTP.
#[utoipa::path(get, path = "/health/live", tag = "health",
    responses((status = 200, description = "Alive", body = HealthResponse)))]
pub async fn live() -> Response {
    no_store(
        StatusCode::OK,
        HealthResponse {
            status: "ok",
            database: None,
            migrations: None,
        },
    )
}

/// Readiness: database reachable and schema up to date.
#[utoipa::path(get, path = "/health/ready", tag = "health",
    responses(
        (status = 200, description = "Ready", body = HealthResponse),
        (status = 503, description = "Not ready", body = HealthResponse),
    ))]
pub async fn ready(State(state): State<HealthState>) -> Response {
    let database_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();
    let migrations_ok = if database_ok {
        match authn_store::migration_status(&state.db).await {
            Ok(status) => status.is_up_to_date(),
            Err(err) => {
                tracing::warn!(error = %err, "migration status check failed");
                false
            }
        }
    } else {
        false
    };
    let ready = database_ok && migrations_ok;
    let body = HealthResponse {
        status: if ready { "ready" } else { "not_ready" },
        database: Some(if database_ok { "ok" } else { "unavailable" }),
        migrations: Some(if migrations_ok {
            "up_to_date"
        } else {
            "pending"
        }),
    };
    no_store(
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        body,
    )
}

fn no_store(status: StatusCode, body: HealthResponse) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}
