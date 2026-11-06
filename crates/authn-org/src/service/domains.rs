//! Domain verification and auto-join (ORG-06).
//!
//! * A domain is proven by publishing the random value
//!   `authn-verification=<43 base64url chars>` as a TXT record at
//!   `<org.domain_verification_label>.<domain>` (fully qualified lookup; no
//!   search-domain expansion). The DNS lookup runs **outside** any
//!   transaction (no locks held during network I/O), is bounded by
//!   `org.dns_timeout` and rate-limited per organization.
//! * Domains are normalized like e-mail domains (IDNA / punycode, homograph
//!   rejection), so the proven domain is exactly the one compared with
//!   users' verified addresses.
//! * A domain can be verified by one organization only (unique index);
//!   the first verification wins.
//! * Auto-join (`auto_join = true`, verified domains only): a user whose
//!   **verified** address belongs exactly to the domain (no subdomains)
//!   becomes a `member` — through [`OrgService::auto_join_verified_domains`],
//!   called by authn-session after login / by the server after e-mail
//!   verification. Users who were removed from the organization or left it
//!   are never re-added automatically (`org_auto_join_exclusions`, cleared
//!   only by accepting an invitation).
//! * `sso_required` is stored for Phase 2 (enterprise SSO) and not enforced
//!   yet.
//! * Verified domains are re-checked periodically (ORG-13, K-97,
//!   [`OrgService::reverify_due_domains`]): only a **definitive absence**
//!   of the record counts towards losing the verification; resolver errors
//!   are counted separately.

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgDomainId, OrgId, UserId};
use authn_core::ports::{Actor, DomainEventKind, RateLimitKey, SecurityEvent, SecurityEventKind};
use authn_crypto::token::OpaqueToken;
use authn_store::{UserRecord, UserRepository};
use serde::Deserialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;

use super::members::lock_member_of_user;
use super::orgs::insert_membership;
use super::{OrgService, actions, lock_org, on_unique};
use crate::model::{DomainStatus, OrgDomain};
use crate::permission::{MEMBER_ROLE_ID, Permission};
use crate::validate;

/// Prefix of the TXT record value.
pub const VERIFICATION_VALUE_PREFIX: &str = "authn-verification=";
/// At most this many TXT strings are inspected per lookup.
const MAX_TXT_RECORDS: usize = 64;

/// Body of `POST /v1/orgs/{org_id}/domains`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddDomain {
    /// The domain (Unicode or punycode; normalized).
    pub domain: String,
}

/// Body of `PATCH /v1/orgs/{org_id}/domains/{domain_id}`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateDomain {
    /// Auto-join users with a verified address of this domain (verified
    /// domains only).
    pub auto_join: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct DomainRow {
    id: OrgDomainId,
    domain: String,
    verification_value: String,
    status: DomainStatus,
    auto_join: bool,
    sso_required: bool,
    last_checked_at: Option<OffsetDateTime>,
    verified_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    check_failures: i32,
    check_inconclusive: i32,
    last_check_outcome: Option<String>,
    unverified_at: Option<OffsetDateTime>,
}

macro_rules! domain_columns {
    () => {
        "id, domain, verification_value, status, auto_join, sso_required, last_checked_at, \
         verified_at, created_at, check_failures, check_inconclusive, last_check_outcome, \
         unverified_at"
    };
}

impl OrgService {
    fn domain_from_row(&self, row: DomainRow) -> OrgDomain {
        OrgDomain {
            id: row.id,
            verification_record_name: self.verification_record_name(&row.domain),
            domain: row.domain,
            status: row.status,
            auto_join: row.auto_join,
            sso_required: row.sso_required,
            verification_value: row.verification_value,
            last_checked_at: row.last_checked_at,
            verified_at: row.verified_at,
            created_at: row.created_at,
            consecutive_absent_checks: u32::try_from(row.check_failures).unwrap_or(0),
            consecutive_inconclusive_checks: u32::try_from(row.check_inconclusive).unwrap_or(0),
            last_check_outcome: row.last_check_outcome,
            unverified_at: row.unverified_at,
        }
    }

    /// `<label>.<domain>` (without the trailing dot).
    #[must_use]
    pub fn verification_record_name(&self, domain: &str) -> String {
        format!("{}.{domain}", self.config().domain_verification_label)
    }

    /// Lists the organization's domains (`domains:read`).
    pub async fn list_domains(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
    ) -> Result<Vec<OrgDomain>, AuthError> {
        self.authorize(ctx, principal, Permission::DomainsRead, org)
            .await?;
        let sql = concat!(
            "SELECT ",
            domain_columns!(),
            " FROM org_domains WHERE org_id = $1 ORDER BY created_at, id"
        );
        let rows = sqlx::query_as::<_, DomainRow>(sql)
            .bind(org)
            .fetch_all(self.pool())
            .await?;
        Ok(rows.into_iter().map(|r| self.domain_from_row(r)).collect())
    }

    /// Adds a domain to verify (`domains:manage`).
    pub async fn add_domain(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        input: AddDomain,
    ) -> Result<OrgDomain, AuthError> {
        let domain = validate::domain(&input.domain)?;
        let (mut tx, _auth) = self
            .begin_write(ctx, principal, Permission::DomainsManage, org)
            .await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM org_domains WHERE org_id = $1")
            .bind(org)
            .fetch_one(&mut *tx)
            .await?;
        if count >= i64::from(self.config().limits.domains) {
            return Err(AuthError::new(codes::org::ORG_LIMIT_REACHED));
        }
        let value = format!(
            "{VERIFICATION_VALUE_PREFIX}{}",
            OpaqueToken::generate()?.expose()
        );
        let id = OrgDomainId::generate();
        let sql = concat!(
            "INSERT INTO org_domains (id, org_id, domain, verification_value, status, created_at) \
             VALUES ($1, $2, $3, $4, 'pending', $5) RETURNING ",
            domain_columns!()
        );
        let row = sqlx::query_as::<_, DomainRow>(sql)
            .bind(id)
            .bind(org)
            .bind(&domain)
            .bind(&value)
            .bind(self.now())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                on_unique(
                    e,
                    "org_domains_org_domain_key",
                    codes::org::ORG_DOMAIN_EXISTS,
                )
            })?;
        let event = self
            .event(SecurityEventKind::OrgDomainAdded, ctx, principal, Some(org))
            .with_resource("org_domain", id)
            .with_meta("domain", row.domain.clone());
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(self.domain_from_row(row))
    }

    /// Checks the TXT record and marks the domain verified (`domains:manage`).
    pub async fn verify_domain(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        domain_id: OrgDomainId,
    ) -> Result<OrgDomain, AuthError> {
        self.authorize(ctx, principal, Permission::DomainsManage, org)
            .await?;
        let sql = concat!(
            "SELECT ",
            domain_columns!(),
            " FROM org_domains WHERE org_id = $1 AND id = $2"
        );
        let row = sqlx::query_as::<_, DomainRow>(sql)
            .bind(org)
            .bind(domain_id)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if row.status == DomainStatus::Verified {
            return Ok(self.domain_from_row(row));
        }
        self.rate_limit(
            RateLimitKey::org(actions::DOMAIN_CHECK, org),
            self.config().domain_checks_per_org,
        )
        .await?;
        let found = self
            .txt_record_present(&row.domain, &row.verification_value)
            .await?;

        let (mut tx, _auth) = self
            .begin_write(ctx, principal, Permission::DomainsManage, org)
            .await?;
        // The domain may have been removed or re-created meanwhile.
        let current = sqlx::query_as::<_, DomainRow>(concat!(
            "SELECT ",
            domain_columns!(),
            " FROM org_domains WHERE org_id = $1 AND id = $2 FOR UPDATE"
        ))
        .bind(org)
        .bind(domain_id)
        .fetch_optional(&mut *tx)
        .await?
        .filter(|c| c.verification_value == row.verification_value)
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let now = self.now();
        let claimed_elsewhere: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM org_domains WHERE domain = $1 AND status = 'verified' \
             AND org_id <> $2)",
        )
        .bind(&current.domain)
        .bind(org)
        .fetch_one(&mut *tx)
        .await?;
        let (status, outcome) = if !found {
            (
                DomainStatus::Failed,
                Err(codes::org::ORG_DOMAIN_VERIFICATION_FAILED),
            )
        } else if claimed_elsewhere {
            (DomainStatus::Failed, Err(codes::org::ORG_DOMAIN_CLAIMED))
        } else {
            (DomainStatus::Verified, Ok(()))
        };
        let verified_at = (status == DomainStatus::Verified).then_some(now);
        let sql = concat!(
            "UPDATE org_domains SET status = $3, last_checked_at = $4, verified_at = $5, \
               check_failures = 0, check_inconclusive = 0, \
               last_check_outcome = CASE WHEN $3 = 'verified' THEN 'present' ELSE 'absent' END, \
               unverified_at = CASE WHEN $3 = 'verified' THEN NULL ELSE unverified_at END \
             WHERE org_id = $1 AND id = $2 RETURNING ",
            domain_columns!()
        );
        let updated = sqlx::query_as::<_, DomainRow>(sql)
            .bind(org)
            .bind(domain_id)
            .bind(status)
            .bind(now)
            .bind(verified_at)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                on_unique(
                    e,
                    "org_domains_verified_domain_idx",
                    codes::org::ORG_DOMAIN_CLAIMED,
                )
            })?;
        if outcome.is_ok() {
            let event = self
                .event(
                    SecurityEventKind::OrgDomainVerified,
                    ctx,
                    principal,
                    Some(org),
                )
                .with_resource("org_domain", domain_id)
                .with_meta("domain", updated.domain.clone());
            self.audit_in_tx(&mut tx, event).await?;
        }
        authn_store::commit(tx).await?;
        crate::metrics::domain_check(outcome.is_ok());
        match outcome {
            Ok(()) => Ok(self.domain_from_row(updated)),
            Err(code) => Err(AuthError::new(code)),
        }
    }

    /// Turns auto-join on or off (`domains:manage`; verified domains only).
    pub async fn update_domain(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        domain_id: OrgDomainId,
        input: UpdateDomain,
    ) -> Result<OrgDomain, AuthError> {
        let (mut tx, _auth) = self
            .begin_write(ctx, principal, Permission::DomainsManage, org)
            .await?;
        let current = sqlx::query_as::<_, DomainRow>(concat!(
            "SELECT ",
            domain_columns!(),
            " FROM org_domains WHERE org_id = $1 AND id = $2 FOR UPDATE"
        ))
        .bind(org)
        .bind(domain_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        if input.auto_join && current.status != DomainStatus::Verified {
            return Err(AuthError::new(codes::org::ORG_DOMAIN_NOT_VERIFIED));
        }
        let sql = concat!(
            "UPDATE org_domains SET auto_join = $3 WHERE org_id = $1 AND id = $2 RETURNING ",
            domain_columns!()
        );
        let updated = sqlx::query_as::<_, DomainRow>(sql)
            .bind(org)
            .bind(domain_id)
            .bind(input.auto_join)
            .fetch_one(&mut *tx)
            .await?;
        let event = self
            .event(
                SecurityEventKind::OrgPolicyChanged,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("org_domain", domain_id)
            .with_meta("auto_join", input.auto_join);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await?;
        Ok(self.domain_from_row(updated))
    }

    /// Removes a domain (`domains:manage`).
    pub async fn delete_domain(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        org: OrgId,
        domain_id: OrgDomainId,
    ) -> Result<(), AuthError> {
        let (mut tx, _auth) = self
            .begin_write(ctx, principal, Permission::DomainsManage, org)
            .await?;
        let deleted = sqlx::query("DELETE FROM org_domains WHERE org_id = $1 AND id = $2")
            .bind(org)
            .bind(domain_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if deleted == 0 {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        }
        let event = self
            .event(
                SecurityEventKind::OrgDomainRemoved,
                ctx,
                principal,
                Some(org),
            )
            .with_resource("org_domain", domain_id);
        self.audit_in_tx(&mut tx, event).await?;
        authn_store::commit(tx).await
    }

    /// Auto-join (ORG-06): adds `user` as `member` to every active
    /// organization with a verified, auto-join domain equal to the domain
    /// of the user's **verified** address. Returns the joined
    /// organizations. Idempotent (existing memberships, also suspended
    /// ones, are left untouched).
    pub async fn auto_join_verified_domains(&self, user: UserId) -> Result<Vec<OrgId>, AuthError> {
        let Some(record) = UserRepository::find_by_id(self.pool(), user).await? else {
            return Ok(Vec::new());
        };
        self.auto_join_verified_domains_of(&record).await
    }

    /// [`Self::auto_join_verified_domains`] for an account row the caller
    /// read in this request (K-128: the login reads it under its row lock
    /// just before; the address and its verification are taken from it).
    pub async fn auto_join_verified_domains_of(
        &self,
        record: &UserRecord,
    ) -> Result<Vec<OrgId>, AuthError> {
        let user = record.id;
        if !record.is_email_verified() {
            return Ok(Vec::new());
        }
        let Some(domain) = record
            .email_normalized
            .as_deref()
            .and_then(|e| e.rsplit_once('@'))
            .map(|(_, d)| d.to_owned())
        else {
            return Ok(Vec::new());
        };
        let candidates: Vec<OrgId> = sqlx::query_scalar(
            "SELECT d.org_id FROM org_domains d JOIN organizations o ON o.id = d.org_id \
             WHERE d.domain = $1 AND d.status = 'verified' AND d.auto_join \
             AND o.status = 'active' \
             AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.org_id = d.org_id AND m.user_id = $2) \
             AND NOT EXISTS (SELECT 1 FROM org_auto_join_exclusions x \
                             WHERE x.org_id = d.org_id AND x.user_id = $2)",
        )
        .bind(&domain)
        .bind(user)
        .fetch_all(self.pool())
        .await?;
        let mut joined = Vec::new();
        for org in candidates {
            let mut tx = self.begin().await?;
            lock_org(&mut tx, org).await?;
            if self.auto_join_one(&mut tx, org, user, &domain).await? {
                authn_store::commit(tx).await?;
                joined.push(org);
            }
        }
        Ok(joined)
    }

    async fn auto_join_one(
        &self,
        conn: &mut PgConnection,
        org: OrgId,
        user: UserId,
        domain: &str,
    ) -> Result<bool, AuthError> {
        // Re-check under the organization lock (removal / leaving records
        // an exclusion in the same lock order).
        let still: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM org_domains d JOIN organizations o ON o.id = d.org_id \
             WHERE d.org_id = $1 AND d.domain = $2 AND d.status = 'verified' AND d.auto_join \
             AND o.status = 'active') \
             AND NOT EXISTS (SELECT 1 FROM org_auto_join_exclusions x \
                             WHERE x.org_id = $1 AND x.user_id = $3)",
        )
        .bind(org)
        .bind(domain)
        .bind(user)
        .fetch_one(&mut *conn)
        .await?;
        if !still || lock_member_of_user(&mut *conn, org, user).await?.is_some() {
            return Ok(false);
        }
        let now = self.now();
        insert_membership(&mut *conn, org, user, MEMBER_ROLE_ID, None, now).await?;
        self.publish(
            &mut *conn,
            DomainEventKind::MemberAdded,
            org,
            Some(user),
            serde_json::json!({ "org_id": org, "user_id": user, "role": "member", "via": "domain" }),
        )
        .await?;
        let event = SecurityEvent::new(SecurityEventKind::MemberAdded, now)
            .with_actor(Actor::System)
            .with_org(org)
            .with_subject(user)
            .with_meta("reason", "domain_auto_join");
        self.audit_in_tx(conn, event).await?;
        Ok(true)
    }

    async fn txt_record_present(&self, domain: &str, expected: &str) -> Result<bool, AuthError> {
        // Fully qualified: no search-domain expansion.
        let name = format!("{}.", self.verification_record_name(domain));
        let lookup = self.deps().dns.lookup_txt(&name);
        let records = tokio::time::timeout(self.config().dns_timeout, lookup)
            .await
            .map_err(|_| {
                AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                    .with_context("dns lookup timed out")
            })??;
        Ok(contains_value(&records, expected))
    }
}

/// Whether one of the (first [`MAX_TXT_RECORDS`]) TXT strings is exactly
/// `expected` (constant time per comparison).
pub(crate) fn contains_value(records: &[String], expected: &str) -> bool {
    records
        .iter()
        .take(MAX_TXT_RECORDS)
        .any(|r| authn_core::secret::constant_time_eq(r.trim().as_bytes(), expected.as_bytes()))
}
