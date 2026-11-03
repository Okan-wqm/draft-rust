//! CLI / startup errors.

use std::process::ExitCode;

use authn_core::config::ConfigError;
use authn_store::StoreError;

/// Errors surfaced by the CLI. Display output is safe to print: it never
/// contains secrets (configuration problems name keys, not values).
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Configuration missing or invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Database / migration failure.
    #[error("database error: {0}")]
    Store(#[from] StoreError),
    /// Socket / IO failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The database schema does not match this binary.
    #[error("database schema is not up to date ({0}); run `rust-authentication migrate`")]
    SchemaOutdated(String),
    /// A service could not be built or an operation failed.
    #[error("{0}")]
    Startup(authn_core::error::AuthError),
    /// An integrity check failed (audit chain).
    #[error("integrity check failed: {0}")]
    Integrity(String),
    /// Invalid command input (never echoes secrets).
    #[error("invalid input: {0}")]
    Input(String),
    /// Telemetry could not be initialised.
    #[error("telemetry initialisation failed: {0}")]
    Telemetry(String),
}

impl ServerError {
    /// Process exit code (sysexits-style).
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Config(_) => ExitCode::from(78),
            Self::Store(_) | Self::SchemaOutdated(_) | Self::Startup(_) => ExitCode::from(69),
            Self::Input(_) => ExitCode::from(65),
            Self::Io(_) | Self::Telemetry(_) | Self::Integrity(_) => ExitCode::from(1),
        }
    }
}
