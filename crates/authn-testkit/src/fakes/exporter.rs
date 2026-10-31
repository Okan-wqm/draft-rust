use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::id::UserId;
use authn_core::ports::DataExporter;
use sqlx::PgConnection;

/// A `DataExporter` returning a fixed value (for aggregator tests).
#[derive(Debug, Clone)]
pub struct StaticDataExporter {
    /// Section name.
    pub section: &'static str,
    /// Exported value.
    pub value: serde_json::Value,
}

#[async_trait]
impl DataExporter for StaticDataExporter {
    fn section(&self) -> &'static str {
        self.section
    }

    async fn export(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<serde_json::Value, AuthError> {
        Ok(self.value.clone())
    }
}
