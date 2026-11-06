//! Periodic re-verification of verified domains (ORG-13, K-97).
//!
//! ORG-06 proves control of a domain once; domains change hands. A
//! background job ([`OrgService::reverify_due_domains`], authn-server,
//! every few minutes on every instance) re-checks the TXT record of every
//! verified domain once per `org.domain_reverification.interval`:
//!
//! 1. **Claim** (one statement, no transaction kept open): due verified
//!    domains are selected `FOR UPDATE SKIP LOCKED` and their
//!    `last_checked_at` is moved to now, so no other instance checks them
//!    in this interval. An instance dying mid-run only delays those
//!    domains by one interval.
//! 2. **Look up** the record with **no connection held** (bounded by
//!    `org.dns_timeout`), one domain after the other.
//! 3. **Record** the outcome in a short transaction (organization row lock,
//!    the order auto-join uses), only if the domain is still the same
//!    verified domain (same id, same verification value) **and still this
//!    run's claim** (a lookup that outlived the interval, after another
//!    run claimed the domain again, is not counted twice):
//!    * `present` — the value is published: both counters reset;
//!    * `absent` — **definitive absence**: NXDOMAIN, no TXT data, or TXT
//!      records none of which is the value. `check_failures + 1`;
//!    * `inconclusive` — resolver failure (SERVFAIL, refused, network
//!      error) or timeout: does **not** count as absence;
//!      `check_inconclusive + 1`.
//!
//!    At `failure_threshold` absences in a row — or `inconclusive_limit`
//!    inconclusive checks in a row, so a domain whose DNS never answers
//!    (for instance because its new owner makes the record's name fail on
//!    purpose) cannot keep auto-join forever — the domain becomes `failed`:
//!    `verified_at`, `auto_join` and `sso_required` are cleared (auto-join
//!    stops at once), `unverified_at` is set, `org.domain_unverified` is
//!    audited (`Actor::System`) and every active member allowed to manage
//!    the organization's domains (`domains:manage`) is notified
//!    (`org_domain_unverified`), all in that transaction. The organization
//!    verifies the domain again through the normal ORG-06 flow.

use authn_core::domain::{EmailAddress, Locale};
use authn_core::error::AuthError;
use authn_core::id::{OrgDomainId, OrgId, UserId};
use authn_core::ports::{
    Actor, Notification, NotificationKind, Recipient, SecurityEvent, SecurityEventKind,
};
use serde::Serialize;
use sqlx::PgConnection;

use super::domains::contains_value;
use super::{OrgService, lock_org};
use crate::permission::Permission;

/// Most administrators notified per unverified domain.
const MAX_RECIPIENTS: i64 = 50;

/// Outcome of one DNS check of a verified domain (ORG-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainCheckOutcome {
    /// The verification value is published.
    Present,
    /// The record is definitively absent (NXDOMAIN, no data, other values).
    Absent,
    /// The resolver failed or timed out: nothing is known.
    Inconclusive,
}

impl DomainCheckOutcome {
    /// Stable value (`org_domains.last_check_outcome`, metrics, audit).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// What one run of [`OrgService::reverify_due_domains`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ReverificationReport {
    /// Domains claimed and checked.
    pub checked: u32,
    /// Checks that found the record.
    pub present: u32,
    /// Checks that found the record definitively absent.
    pub absent: u32,
    /// Inconclusive checks (resolver error, timeout).
    pub inconclusive: u32,
    /// Domains that lost their verification in this run.
    pub unverified: u32,
}

#[derive(Debug, sqlx::FromRow)]
struct Claimed {
    id: OrgDomainId,
    org_id: OrgId,
    domain: String,
    verification_value: String,
    /// The claim (`last_checked_at` as stored): the outcome is recorded
    /// only while it is still this claim.
    last_checked_at: time::OffsetDateTime,
}

#[derive(Debug, sqlx::FromRow)]
struct Counters {
    check_failures: i32,
    check_inconclusive: i32,
}

impl OrgService {
    /// Re-checks the TXT record of verified domains whose last check is
    /// older than `org.domain_reverification.interval` (at most
    /// `batch_size` per run) and takes the verification away after too
    /// many consecutive definitive absences (module docs). Safe on several
    /// instances. Does nothing when the job is disabled.
    pub async fn reverify_due_domains(&self) -> Result<ReverificationReport, AuthError> {
        let settings = self.config().domain_reverification;
        let mut report = ReverificationReport::default();
        if !settings.enabled {
            return Ok(report);
        }
        let now = self.now();
        let cutoff = now - settings.interval;
        let claimed: Vec<Claimed> = sqlx::query_as(
            "UPDATE org_domains d SET last_checked_at = $1 \
             FROM (SELECT id FROM org_domains \
                   WHERE status = 'verified' AND (last_checked_at IS NULL OR last_checked_at <= $2) \
                   ORDER BY last_checked_at NULLS FIRST, id LIMIT $3 \
                   FOR UPDATE SKIP LOCKED) due \
             WHERE d.id = due.id \
             RETURNING d.id, d.org_id, d.domain, d.verification_value, d.last_checked_at",
        )
        .bind(now)
        .bind(cutoff)
        .bind(i64::from(settings.batch_size))
        .fetch_all(self.pool())
        .await?;
        for domain in claimed {
            // No connection is held during the lookup.
            let outcome = self
                .check_domain(&domain.domain, &domain.verification_value)
                .await;
            report.checked += 1;
            match outcome {
                DomainCheckOutcome::Present => report.present += 1,
                DomainCheckOutcome::Absent => report.absent += 1,
                DomainCheckOutcome::Inconclusive => report.inconclusive += 1,
            }
            crate::metrics::domain_reverification(outcome.as_str());
            if self.record_check(&domain, outcome).await? {
                report.unverified += 1;
            }
        }
        if report.checked > 0 {
            tracing::info!(
                checked = report.checked,
                absent = report.absent,
                inconclusive = report.inconclusive,
                unverified = report.unverified,
                "domain re-verification run"
            );
        }
        Ok(report)
    }

    /// One lookup, classified. Only an answer is `Present` / `Absent`; an
    /// error or a timeout is `Inconclusive` (never absence).
    async fn check_domain(&self, domain: &str, expected: &str) -> DomainCheckOutcome {
        // Fully qualified: no search-domain expansion.
        let name = format!("{}.", self.verification_record_name(domain));
        let lookup = self.deps().dns.lookup_txt(&name);
        match tokio::time::timeout(self.config().dns_timeout, lookup).await {
            Ok(Ok(records)) if contains_value(&records, expected) => DomainCheckOutcome::Present,
            Ok(Ok(_)) => DomainCheckOutcome::Absent,
            Ok(Err(err)) => {
                tracing::warn!(
                    code = err.code().code(),
                    "domain re-verification lookup failed"
                );
                DomainCheckOutcome::Inconclusive
            }
            Err(_) => {
                tracing::warn!("domain re-verification lookup timed out");
                DomainCheckOutcome::Inconclusive
            }
        }
    }

    /// Records `outcome` for a claimed domain; returns whether the domain
    /// lost its verification.
    async fn record_check(
        &self,
        claimed: &Claimed,
        outcome: DomainCheckOutcome,
    ) -> Result<bool, AuthError> {
        let settings = self.config().domain_reverification;
        let mut tx = self.begin().await?;
        lock_org(&mut tx, claimed.org_id).await?;
        // Still the same verified domain, and still our claim? (removed,
        // re-added or already unverified meanwhile, or the lookup outlived
        // the interval and another run claimed and checked the domain
        // again: nothing to record — one claim, one counted check)
        let current: Option<Counters> = sqlx::query_as(
            "SELECT check_failures, check_inconclusive FROM org_domains \
             WHERE id = $1 AND org_id = $2 AND verification_value = $3 AND status = 'verified' \
               AND last_checked_at = $4 \
             FOR UPDATE",
        )
        .bind(claimed.id)
        .bind(claimed.org_id)
        .bind(&claimed.verification_value)
        .bind(claimed.last_checked_at)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current) = current else {
            tx.rollback().await?;
            return Ok(false);
        };
        let (failures, inconclusive) = match outcome {
            DomainCheckOutcome::Present => (0, 0),
            DomainCheckOutcome::Absent => (current.check_failures.saturating_add(1), 0),
            DomainCheckOutcome::Inconclusive => (
                current.check_failures,
                current.check_inconclusive.saturating_add(1),
            ),
        };
        let threshold = i32::try_from(settings.failure_threshold).unwrap_or(i32::MAX);
        let limit = i32::try_from(settings.inconclusive_limit).unwrap_or(i32::MAX);
        let reason = if failures >= threshold {
            Some(DomainCheckOutcome::Absent)
        } else if inconclusive >= limit {
            Some(DomainCheckOutcome::Inconclusive)
        } else {
            None
        };
        let now = self.now();
        let Some(reason) = reason else {
            sqlx::query(
                "UPDATE org_domains SET check_failures = $2, check_inconclusive = $3, \
                   last_check_outcome = $4 WHERE id = $1",
            )
            .bind(claimed.id)
            .bind(failures)
            .bind(inconclusive)
            .bind(outcome.as_str())
            .execute(&mut *tx)
            .await?;
            authn_store::commit(tx).await?;
            return Ok(false);
        };
        sqlx::query(
            "UPDATE org_domains SET status = 'failed', verified_at = NULL, auto_join = false, \
               sso_required = false, check_failures = $2, check_inconclusive = $3, \
               last_check_outcome = $4, unverified_at = $5 WHERE id = $1",
        )
        .bind(claimed.id)
        .bind(failures)
        .bind(inconclusive)
        .bind(outcome.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let consecutive = match reason {
            DomainCheckOutcome::Inconclusive => inconclusive,
            _ => failures,
        };
        let event = SecurityEvent::new(SecurityEventKind::OrgDomainUnverified, now)
            .with_actor(Actor::System)
            .with_org(claimed.org_id)
            .with_resource("org_domain", claimed.id)
            .with_meta("domain", claimed.domain.clone())
            .with_meta("reason", reason.as_str())
            .with_meta("consecutive_checks", consecutive)
            .with_meta("priority", "high");
        self.audit_in_tx(&mut tx, event).await?;
        let notified = self.notify_domain_admins(&mut tx, claimed, now).await?;
        authn_store::commit(tx).await?;
        crate::metrics::domain_unverified(reason.as_str());
        tracing::warn!(
            org = %claimed.org_id,
            domain_id = %claimed.id,
            reason = reason.as_str(),
            notified,
            "verified domain lost its verification (re-verification)"
        );
        Ok(true)
    }

    /// Queues an `org_domain_unverified` notice to every active member of
    /// an active account whose role may manage the domains (bounded).
    async fn notify_domain_admins(
        &self,
        conn: &mut PgConnection,
        claimed: &Claimed,
        at: time::OffsetDateTime,
    ) -> Result<u32, AuthError> {
        let org_name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
            .bind(claimed.org_id)
            .fetch_one(&mut *conn)
            .await?;
        let recipients: Vec<(UserId, Option<String>)> = sqlx::query_as(
            "SELECT u.id, u.email FROM memberships m JOIN users u ON u.id = m.user_id \
             WHERE m.org_id = $1 AND m.status = 'active' AND u.status = 'active' \
               AND u.email IS NOT NULL \
               AND EXISTS (SELECT 1 FROM role_permissions rp \
                           WHERE rp.role_id = m.role_id AND rp.permission = $2) \
             ORDER BY m.created_at, m.id LIMIT $3",
        )
        .bind(claimed.org_id)
        .bind(Permission::DomainsManage.as_str())
        .bind(MAX_RECIPIENTS)
        .fetch_all(&mut *conn)
        .await?;
        let mut sent = 0;
        for (user, email) in recipients {
            let Some(email) = email.and_then(|e| EmailAddress::parse(&e).ok()) else {
                continue;
            };
            let notification = Notification {
                recipient: Recipient {
                    email,
                    user_id: Some(user),
                    display_name: None,
                },
                locale: Locale::default(),
                kind: NotificationKind::OrgDomainUnverified {
                    org_name: org_name.clone(),
                    domain: claimed.domain.clone(),
                    at,
                },
            };
            self.deps()
                .notifier
                .notify_in_tx(&mut *conn, notification)
                .await?;
            sent += 1;
        }
        Ok(sent)
    }
}
