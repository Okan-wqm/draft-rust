//! Application state and its `FromRef` projections (ARC-03).
//!
//! `AppState` exists only in this crate. Module crates never see it: each
//! exposes `pub fn router<S>() -> Router<S>` and declares the services it
//! needs with `Service: FromRef<S>` bounds. This crate implements those
//! `FromRef<AppState>` conversions when it wires the module in. See
//! `docs/architecture/contracts.md` §"AppState / FromRef".

use std::sync::Arc;

use authn_core::config::AppConfig;
use authn_core::ports::Clock;
use axum::extract::FromRef;
use sqlx::PgPool;

use crate::routes::example::TimeService;
use crate::routes::health::HealthState;

/// Everything the HTTP layer needs. Cheap to clone (all fields are shared).
#[derive(Clone)]
pub struct AppState {
    /// Validated configuration.
    pub config: Arc<AppConfig>,
    /// Database pool.
    pub db: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
}

impl AppState {
    /// Builds the state. Further ports / module services are added here as
    /// the module crates land.
    #[must_use]
    pub fn new(config: Arc<AppConfig>, db: PgPool, clock: Arc<dyn Clock>) -> Self {
        Self { config, db, clock }
    }
}

impl FromRef<AppState> for Arc<AppConfig> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

impl FromRef<AppState> for PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for HealthState {
    fn from_ref(state: &AppState) -> Self {
        HealthState {
            db: state.db.clone(),
        }
    }
}

impl FromRef<AppState> for TimeService {
    fn from_ref(state: &AppState) -> Self {
        TimeService::new(state.clock.clone())
    }
}
