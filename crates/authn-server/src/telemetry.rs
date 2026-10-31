//! Structured logging (OPS-03).
//!
//! JSON lines by default. Every request runs inside the `http_request` span
//! created by the request-context middleware, so each log line carries the
//! `request_id`. Never log secrets; mask personal data with
//! `authn_core::redact`.

use authn_core::config::server::{LogFormat, ServerConfig};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::error::ServerError;

/// Installs the global subscriber. `RUST_LOG` overrides `server.log_filter`.
pub fn init(config: &ServerConfig) -> Result<(), ServerError> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_filter))
        .map_err(|e| ServerError::Telemetry(e.to_string()))?;
    let registry = tracing_subscriber::registry().with(filter);
    let result = match config.log_format {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_target(true),
            )
            .try_init(),
        LogFormat::Pretty => registry
            .with(tracing_subscriber::fmt::layer().pretty())
            .try_init(),
    };
    result.map_err(|e| ServerError::Telemetry(e.to_string()))
}
