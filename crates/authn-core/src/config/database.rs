//! `[database]` — PostgreSQL pool (owner: authn-store).

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, mins, secs};
use crate::secret::{ExposeSecret, SecretString};

mod defaults {
    use std::time::Duration;

    pub(super) const fn max_connections() -> u32 {
        20
    }
    pub(super) const fn min_connections() -> u32 {
        1
    }
    pub(super) const fn acquire_timeout() -> Duration {
        super::secs(5)
    }
    pub(super) const fn idle_timeout() -> Duration {
        super::mins(10)
    }
    pub(super) const fn max_lifetime() -> Duration {
        super::mins(30)
    }
    pub(super) const fn statement_timeout() -> Duration {
        super::secs(30)
    }
}

/// `[database]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// **Required.** Connection URL (`postgres://user:password@host/db`).
    /// Use `?sslmode=verify-full` outside of local development.
    pub url: SecretString,
    /// Pool size upper bound. Default 20.
    #[serde(default = "defaults::max_connections")]
    pub max_connections: u32,
    /// Connections kept open. Default 1.
    #[serde(default = "defaults::min_connections")]
    pub min_connections: u32,
    /// Wait for a free connection before `service_unavailable`. Default `5s`.
    #[serde(default = "defaults::acquire_timeout", with = "super::duration")]
    pub acquire_timeout: Duration,
    /// Close idle connections after. Default `10m`.
    #[serde(default = "defaults::idle_timeout", with = "super::duration")]
    pub idle_timeout: Duration,
    /// Recycle connections after. Default `30m`.
    #[serde(default = "defaults::max_lifetime", with = "super::duration")]
    pub max_lifetime: Duration,
    /// Server-side `statement_timeout` per connection. Default `30s`.
    #[serde(default = "defaults::statement_timeout", with = "super::duration")]
    pub statement_timeout: Duration,
    /// Apply pending migrations when `serve` starts. Default `false`
    /// (run `rust-authentication migrate` explicitly).
    #[serde(default)]
    pub migrate_on_start: bool,
}

impl DatabaseConfig {
    /// A configuration with defaults for the given URL.
    #[must_use]
    pub fn with_url(url: SecretString) -> Self {
        Self {
            url,
            max_connections: defaults::max_connections(),
            min_connections: defaults::min_connections(),
            acquire_timeout: defaults::acquire_timeout(),
            idle_timeout: defaults::idle_timeout(),
            max_lifetime: defaults::max_lifetime(),
            statement_timeout: defaults::statement_timeout(),
            migrate_on_start: false,
        }
    }

    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        let url = self.url.expose_secret();
        p.require(
            url.starts_with("postgres://") || url.starts_with("postgresql://"),
            "database.url",
            "must be a postgres:// URL",
        );
        p.require(
            (1..=1000).contains(&self.max_connections),
            "database.max_connections",
            "must be between 1 and 1000",
        );
        p.require(
            self.min_connections <= self.max_connections,
            "database.min_connections",
            "must not exceed max_connections",
        );
        p.require_range(
            self.acquire_timeout,
            secs(1),
            mins(5),
            "database.acquire_timeout",
        );
        p.require_range(
            self.statement_timeout,
            secs(1),
            mins(30),
            "database.statement_timeout",
        );
    }
}
