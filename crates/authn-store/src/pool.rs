//! Connection pool construction.

use std::str::FromStr;

use authn_core::config::database::DatabaseConfig;
use authn_core::secret::ExposeSecret;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::error::StoreError;

/// `application_name` reported to PostgreSQL.
pub const APPLICATION_NAME: &str = "rust-authentication";

fn connect_options(config: &DatabaseConfig) -> Result<PgConnectOptions, StoreError> {
    // The parse error is dropped on purpose: it may echo the URL, which
    // contains the database password.
    let options = PgConnectOptions::from_str(config.url.expose_secret())
        .map_err(|_| StoreError::Config("database.url is not a valid PostgreSQL URL"))?;
    let statement_timeout_ms = config.statement_timeout.as_millis().to_string();
    Ok(options.application_name(APPLICATION_NAME).options([
        ("statement_timeout", statement_timeout_ms.as_str()),
        ("timezone", "UTC"),
    ]))
}

fn pool_options(config: &DatabaseConfig) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .idle_timeout(Some(config.idle_timeout))
        .max_lifetime(Some(config.max_lifetime))
}

/// Connects eagerly (fails if the database is unreachable).
pub async fn connect(config: &DatabaseConfig) -> Result<PgPool, StoreError> {
    let options = connect_options(config)?;
    pool_options(config)
        .connect_with(options)
        .await
        .map_err(StoreError::from)
}

/// Creates a pool that connects on first use (CLI commands, tests of wiring).
pub fn connect_lazy(config: &DatabaseConfig) -> Result<PgPool, StoreError> {
    let options = connect_options(config)?;
    Ok(pool_options(config).connect_lazy_with(options))
}

#[cfg(test)]
mod tests {
    use authn_core::secret::SecretString;

    use super::*;

    #[test]
    fn invalid_url_error_does_not_echo_credentials() {
        let config = DatabaseConfig::with_url(SecretString::from(
            "postgres://user:hunter2@host:notaport/db".to_owned(),
        ));
        let err = connect_lazy(&config).unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
        assert!(!format!("{err:?}").contains("hunter2"));
    }

    #[tokio::test]
    async fn lazy_pool_builds_without_connecting() {
        let config = DatabaseConfig::with_url(SecretString::from(
            "postgres://user:pw@127.0.0.1:1/db".to_owned(),
        ));
        let pool = connect_lazy(&config).unwrap();
        assert_eq!(pool.size(), 0);
    }
}
