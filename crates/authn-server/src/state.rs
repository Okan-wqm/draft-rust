//! Application state and its `FromRef` projections (ARC-03).
//!
//! `AppState` exists only in this crate. Module crates never see it: each
//! exposes `pub fn router<S>() -> Router<S>` and declares the services it
//! needs with `Service: FromRef<S>` bounds. This crate implements those
//! `FromRef<AppState>` conversions (contracts §15.3).

use std::sync::Arc;

use authn_account::AccountService;
use authn_audit::AuditService;
use authn_core::config::AppConfig;
use authn_core::ports::Clock;
use authn_mfa::MfaService;
use authn_org::OrgService;
use authn_password::PasswordService;
use authn_protect::CaptchaService;
use authn_session::SessionService;
use authn_webauthn::{WebauthnService, WellKnownDocuments};
use axum::extract::FromRef;
use sqlx::PgPool;

use crate::routes::example::TimeService;
use crate::routes::health::HealthState;
use crate::services::Services;

/// Everything the HTTP layer needs. Cheap to clone (all fields are shared).
#[derive(Clone)]
pub struct AppState {
    /// Validated configuration.
    pub config: Arc<AppConfig>,
    /// Database pool.
    pub db: PgPool,
    /// Injected clock (ARC-04).
    pub clock: Arc<dyn Clock>,
    /// Every module service.
    pub services: Services,
}

impl AppState {
    /// The state over built services.
    #[must_use]
    pub fn new(services: Services) -> Self {
        Self {
            config: services.config.clone(),
            db: services.pool.clone(),
            clock: services.clock.clone(),
            services,
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
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

macro_rules! project {
    ($ty:ty, $field:ident) => {
        impl FromRef<AppState> for $ty {
            fn from_ref(state: &AppState) -> Self {
                state.services.$field.clone()
            }
        }
    };
}

project!(SessionService, sessions);
project!(PasswordService, passwords);
project!(AccountService, accounts);
project!(MfaService, mfa);
project!(WebauthnService, webauthn);
project!(OrgService, orgs);
project!(CaptchaService, captcha);
project!(AuditService, audit);

impl FromRef<AppState> for WellKnownDocuments {
    fn from_ref(state: &AppState) -> Self {
        state.services.webauthn.well_known()
    }
}
