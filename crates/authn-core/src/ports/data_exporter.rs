//! Personal data export (ACC-10). Owner of this file: authn-account
//! (aggregator); every module implements it for its own tables.
//!
//! authn-account collects all registered exporters and builds one
//! machine-readable JSON document `{ "<section>": <value>, … }`. Exporters
//! must never include secrets (hashes, encrypted secrets, token hashes).

use async_trait::async_trait;
use sqlx::PgConnection;

use crate::error::AuthError;
use crate::id::UserId;

/// Exports one module's personal data about a user.
#[async_trait]
pub trait DataExporter: Send + Sync {
    /// Unique, stable section name (`profile`, `sessions`, `mfa`…).
    fn section(&self) -> &'static str;

    /// Returns the user's data of this module as JSON.
    async fn export(
        &self,
        conn: &mut PgConnection,
        user: UserId,
    ) -> Result<serde_json::Value, AuthError>;
}
