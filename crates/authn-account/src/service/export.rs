//! Personal data export (ACC-10): `POST /v1/me/export` (K-58 audit / K-79:
//! not a safe method, so it passes the CSRF checks).
//!
//! Session + step-up (SES-13), never under impersonation, rate limited per
//! user (`account.export_per_user`). All sections (this crate's `account`
//! plus every registered `DataExporter`) are read in **one**
//! `REPEATABLE READ, READ ONLY` transaction, so the document is a
//! consistent snapshot and exporters cannot write. If any exporter fails
//! the whole export fails — a silently incomplete export would violate
//! KVKK art. 11 / GDPR art. 15 & 20.

use authn_core::domain::Principal;
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::ports::{Actor, DataExporter, RateLimitKey, SecurityEventKind};
use serde_json::{Map, Value, json};

use super::{AccountService, actions};
use crate::export::{EXPORT_FORMAT, ts};

impl AccountService {
    /// ACC-10: builds the machine-readable export document of the signed-in
    /// user:
    ///
    /// ```json
    /// { "format": "rust-authentication/personal-data-export/v1",
    ///   "generated_at": "…", "user_id": "…",
    ///   "sections": { "account": { … }, "<module>": … } }
    /// ```
    pub async fn export_data(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
    ) -> Result<Value, AuthError> {
        let user = Self::self_service_user(principal)?;
        self.require_step_up(principal)?;
        self.limit(
            &RateLimitKey::user(actions::EXPORT, user),
            self.config().export_per_user,
        )
        .await?;
        let now = self.now();
        let mut tx = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let mut sections = Map::new();
        let own = &self.inner.own_exporter;
        sections.insert(own.section().to_owned(), own.export(&mut tx, user).await?);
        for exporter in &self.deps().exporters {
            let value = exporter.export(&mut tx, user).await.map_err(|err| {
                tracing::error!(section = exporter.section(), error = %err, "data exporter failed");
                err
            })?;
            sections.insert(exporter.section().to_owned(), value);
        }
        tx.commit().await?;
        let section_names: Vec<String> = sections.keys().cloned().collect();
        let document = json!({
            "format": EXPORT_FORMAT,
            "generated_at": ts(Some(now)),
            "user_id": user,
            "sections": sections,
        });
        self.deps()
            .audit
            .record(
                self.event(SecurityEventKind::AccountDataExported, ctx)
                    .with_actor(Actor::User(user))
                    .with_subject(user)
                    .with_meta("sections", section_names),
            )
            .await?;
        metrics::counter!("authn_account_data_exports_total").increment(1);
        Ok(document)
    }
}
