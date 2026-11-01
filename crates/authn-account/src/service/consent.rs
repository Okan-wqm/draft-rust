//! Consent records (ACC-11).
//!
//! * Published versions come from `account.terms` and are inserted at
//!   start-up by [`AccountService::sync_terms_versions`]; a published
//!   version is never modified. The current version of a document is its
//!   latest one whose `published_at` has passed.
//! * Acceptance is stored with time, client IP and user agent
//!   (`consents`, unique per user and version).
//! * [`AccountService::terms_requirements`] tells the login flow (SES-22)
//!   which documents must be accepted before a full session is issued.

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{TermsVersionId, UserId};
use authn_core::ports::{Actor, SecurityEventKind};

use super::AccountService;
use crate::model::{ConsentView, TermsAcceptance, TermsVersionView};
use crate::repo::{ConsentRepository, TermsRepository, TermsVersionRecord};

impl From<TermsVersionRecord> for TermsVersionView {
    fn from(v: TermsVersionRecord) -> Self {
        Self {
            id: v.id,
            document: v.document,
            version: v.version,
            url: v.url,
            published_at: v.published_at,
            requires_reacceptance: v.requires_reacceptance,
        }
    }
}

impl AccountService {
    /// Inserts the versions of `account.terms` that are not in the database
    /// yet (call at start-up). Returns how many were inserted.
    pub async fn sync_terms_versions(&self) -> Result<usize, AuthError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut inserted = 0;
        for terms in &self.config().terms {
            let record = TermsVersionRecord {
                id: TermsVersionId::generate(),
                document: terms.document,
                version: terms.version.clone(),
                url: terms.url.clone(),
                published_at: terms.published_at,
                requires_reacceptance: terms.requires_reacceptance,
            };
            if TermsRepository::insert_if_missing(tx.conn(), &record, now).await? {
                inserted += 1;
            } else if let Some(existing) =
                TermsRepository::find(tx.conn(), terms.document, &terms.version).await?
                && (existing.url != record.url
                    || existing.published_at != record.published_at
                    || existing.requires_reacceptance != record.requires_reacceptance)
            {
                tracing::warn!(
                    document = terms.document.as_str(),
                    version = %terms.version,
                    "published terms version differs from configuration; published versions are immutable"
                );
            }
        }
        tx.commit().await?;
        Ok(inserted)
    }

    /// The current version of every document (public).
    pub async fn current_terms(&self) -> Result<Vec<TermsVersionView>, AuthError> {
        Ok(TermsRepository::current(self.pool(), self.now())
            .await?
            .into_iter()
            .map(TermsVersionView::from)
            .collect())
    }

    /// The current versions `user` must (re-)accept before a full session
    /// (SES-22 `accept_terms`):
    /// * `account.require_terms_acceptance` and the user never accepted any
    ///   version of the document, or
    /// * `account.reaccept_terms_on_new_version`, the current version is
    ///   flagged `requires_reacceptance` and the user accepted an older
    ///   version only.
    pub async fn terms_requirements(
        &self,
        user: UserId,
    ) -> Result<Vec<TermsVersionView>, AuthError> {
        let current = TermsRepository::current(self.pool(), self.now()).await?;
        if current.is_empty() {
            return Ok(Vec::new());
        }
        let consents = ConsentRepository::for_user(self.pool(), user).await?;
        let config = self.config();
        Ok(current
            .into_iter()
            .filter(|version| {
                if consents.iter().any(|c| c.terms_version_id == version.id) {
                    return false;
                }
                let accepted_any = consents.iter().any(|c| c.document == version.document);
                (config.require_terms_acceptance && !accepted_any)
                    || (config.reaccept_terms_on_new_version
                        && version.requires_reacceptance
                        && accepted_any)
            })
            .map(TermsVersionView::from)
            .collect())
    }

    /// The signed-in user's acceptances.
    pub async fn consents(&self, principal: &Principal) -> Result<Vec<ConsentView>, AuthError> {
        let user = principal.require_user()?;
        Ok(ConsentRepository::for_user(self.pool(), user)
            .await?
            .into_iter()
            .map(|c| ConsentView {
                document: c.document,
                version: c.version,
                accepted_at: c.accepted_at,
            })
            .collect())
    }

    /// ACC-11: the signed-in user accepts current document versions.
    pub async fn record_consent(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        accepted: &[TermsAcceptance],
    ) -> Result<(), AuthError> {
        let user = Self::self_service_user(principal)?;
        self.accept_terms(ctx, user, accepted).await
    }

    /// ACC-11 / SES-22: records acceptances for `user` (the login flow calls
    /// this when completing the `accept_terms` required action). Only
    /// current versions are accepted (`terms_version_not_current`).
    pub async fn accept_terms(
        &self,
        ctx: &RequestContext,
        user: UserId,
        accepted: &[TermsAcceptance],
    ) -> Result<(), AuthError> {
        if accepted.is_empty() || accepted.len() > 8 {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_context("1 to 8 acceptances expected"));
        }
        let now = self.now();
        let current = TermsRepository::current(self.pool(), now).await?;
        let mut versions = Vec::new();
        for acceptance in accepted {
            let Some(version) = current
                .iter()
                .find(|v| v.document == acceptance.document && v.version == acceptance.version)
            else {
                return Err(AuthError::new(codes::account::TERMS_VERSION_NOT_CURRENT));
            };
            versions.push(version);
        }
        let mut tx = self.begin().await?;
        crate::lifecycle::lock_user(&mut tx, user).await?;
        for version in versions {
            if ConsentRepository::record(
                tx.conn(),
                user,
                version.id,
                now,
                Some(ctx.client_ip),
                ctx.user_agent.as_deref(),
            )
            .await?
            {
                tx.audit(
                    self.event(SecurityEventKind::TermsAccepted, ctx)
                        .with_actor(Actor::User(user))
                        .with_subject(user)
                        .with_resource("terms_version", version.id)
                        .with_meta("document", version.document.as_str())
                        .with_meta("version", version.version.clone()),
                );
            }
        }
        tx.commit().await
    }
}
