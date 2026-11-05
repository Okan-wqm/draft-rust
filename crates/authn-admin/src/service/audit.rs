//! Audit log query, export and chain verification (ADM-07).
//!
//! Platform-wide listing through `authn_audit::list_events` (keyset pages,
//! newest first), enriched with the justification stored by this crate
//! (ADM-08). Exports are bounded (`AdminSettings::audit_export_max_events`)
//! and need a justification; they are audited themselves, as are chain
//! verifications.

use std::collections::HashMap;

use authn_audit::query::AuditEventQuery;
use authn_audit::{AuditEventDetail, AuditEventFilter, ChainAnchor, ChainReport};
use authn_core::domain::{Page, PageRequest};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, UserId};
use authn_core::ports::SecurityEventKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::limits::Limit;
use super::{AdminService, meta};
use crate::guard::AdminCaller;
use crate::reason::Justification;
use crate::store;

/// Filters of the admin audit listing / export.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct AdminAuditFilter {
    /// Page size, 1–100 (default 20). Ignored by the export.
    pub limit: Option<u32>,
    /// Cursor from the previous page / export.
    pub cursor: Option<String>,
    /// Exact event kind, e.g. `admin.action`.
    pub kind: Option<String>,
    /// Kind category (first segment), e.g. `admin`, `login`.
    pub category: Option<String>,
    /// `success` or `failure`.
    pub outcome: Option<String>,
    /// Events performed by this user.
    pub actor_user_id: Option<UserId>,
    /// Events about this user.
    pub subject_user_id: Option<UserId>,
    /// Events of this organization.
    pub org_id: Option<OrgId>,
    /// Events about this resource type.
    pub resource_type: Option<String>,
    /// Events at or after this instant (RFC 3339).
    pub since: Option<String>,
    /// Events before this instant (RFC 3339).
    pub until: Option<String>,
}

impl AdminAuditFilter {
    fn into_filter(self) -> Result<(AuditEventFilter, PageRequest), AuthError> {
        let (mut filter, page) = AuditEventQuery {
            limit: self.limit,
            cursor: self.cursor,
            kind: self.kind,
            category: self.category,
            outcome: self.outcome,
            actor_user_id: self.actor_user_id,
            resource_type: self.resource_type,
            since: self.since,
            until: self.until,
        }
        .into_filter()?;
        filter.subject_user = self.subject_user_id;
        filter.org_id = self.org_id;
        Ok((filter, page))
    }
}

/// An audit event as the platform admin sees it: every stored field plus
/// the justification of admin actions.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminAuditEvent {
    /// The stored event.
    #[serde(flatten)]
    pub event: AuditEventDetail,
    /// Justification of an admin action (ADM-08), while retained.
    pub justification: Option<String>,
}

/// A bounded export of matching events (newest first).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditExport {
    /// The events.
    pub events: Vec<AdminAuditEvent>,
    /// Pass as `cursor` to continue; absent when the export is complete.
    pub next_cursor: Option<String>,
}

/// A chain position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VerifiedAnchor {
    /// Sequence number (`0` = before the first event).
    pub seq: i64,
    /// Hash at that position (lowercase hex, 64 characters).
    pub hash: String,
}

impl From<ChainAnchor> for VerifiedAnchor {
    fn from(a: ChainAnchor) -> Self {
        Self {
            seq: a.seq,
            hash: a.hash_hex(),
        }
    }
}

impl VerifiedAnchor {
    /// Parses an externally kept anchor.
    pub fn into_anchor(self) -> Result<ChainAnchor, AuthError> {
        let invalid = || {
            AuthError::new(codes::common::VALIDATION_FAILED)
                .with_details(serde_json::json!({ "field": "anchor" }))
        };
        if self.seq < 0 {
            return Err(invalid());
        }
        let hash = decode_hex32(&self.hash).ok_or_else(invalid)?;
        Ok(ChainAnchor {
            seq: self.seq,
            hash,
        })
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let hi = hex_digit(*pair.first()?)?;
        let lo = hex_digit(*pair.get(1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Result of a chain verification (AUD-02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ChainVerification {
    /// No defect found.
    pub intact: bool,
    /// Where verification started.
    pub start: VerifiedAnchor,
    /// Last event verified successfully.
    pub last_verified: VerifiedAnchor,
    /// Events verified.
    pub events_verified: u64,
    /// The stored chain head.
    pub head: VerifiedAnchor,
    /// Sequence number of the first defect.
    pub broken_at_seq: Option<i64>,
    /// The first defect (`hash_mismatch`, `prev_hash_mismatch`, …).
    pub problem: Option<String>,
}

impl From<ChainReport> for ChainVerification {
    fn from(r: ChainReport) -> Self {
        Self {
            intact: r.is_intact(),
            start: r.start.into(),
            last_verified: r.last_verified.into(),
            events_verified: r.events_verified,
            head: r.head.into(),
            broken_at_seq: r.broken.map(|b| b.seq),
            problem: r.broken.map(|b| b.problem.as_str().to_owned()),
        }
    }
}

impl AdminService {
    async fn with_justifications(
        &self,
        events: Vec<AuditEventDetail>,
    ) -> Result<Vec<AdminAuditEvent>, AuthError> {
        let ids: Vec<Uuid> = events.iter().map(|e| e.id.as_uuid()).collect();
        let mut reasons: HashMap<Uuid, String> = store::reasons_for(self.pool(), &ids)
            .await?
            .into_iter()
            .collect();
        Ok(events
            .into_iter()
            .map(|event| {
                let justification = reasons.remove(&event.id.as_uuid());
                AdminAuditEvent {
                    event,
                    justification,
                }
            })
            .collect())
    }

    /// Lists audit events platform-wide (ADM-07).
    pub async fn query_audit(
        &self,
        _caller: &AdminCaller,
        query: AdminAuditFilter,
    ) -> Result<Page<AdminAuditEvent>, AuthError> {
        let (filter, page) = query.into_filter()?;
        let listed = authn_audit::list_events(self.pool(), &filter, &page).await?;
        Ok(Page {
            items: self.with_justifications(listed.items).await?,
            next_cursor: listed.next_cursor,
        })
    }

    /// Exports up to `audit_export_max_events` matching events (ADM-07).
    /// The export is audited with its justification.
    pub async fn export_audit(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        query: AdminAuditFilter,
        reason: &Justification,
    ) -> Result<AuditExport, AuthError> {
        let (filter, first) = query.into_filter()?;
        let max = usize::try_from(self.settings().audit_export_max_events).unwrap_or(usize::MAX);
        let mut cursor = first.cursor;
        let mut events: Vec<AuditEventDetail> = Vec::new();
        loop {
            let page = PageRequest {
                limit: Some(authn_core::domain::MAX_PAGE_LIMIT),
                cursor: cursor.take(),
            };
            let listed = authn_audit::list_events(self.pool(), &filter, &page).await?;
            let done = listed.next_cursor.is_none();
            events.extend(listed.items);
            cursor = listed.next_cursor;
            if done || events.len() >= max {
                break;
            }
        }
        if events.len() > max {
            events.truncate(max);
            cursor = events.last().map(|e| {
                authn_core::domain::Cursor {
                    sort_key: time_to_micros(e.occurred_at),
                    id: e.id.as_uuid(),
                }
                .encode()
            });
        }
        let mut tx = self.begin().await?;
        self.record_action(
            &mut tx,
            ctx,
            caller,
            SecurityEventKind::AdminAction,
            "audit_exported",
            filter.subject_user,
            Some(reason),
            meta([
                ("events_exported", Value::from(events.len())),
                ("complete", Value::from(cursor.is_none())),
            ]),
        )
        .await?;
        authn_store::commit(tx).await?;
        Ok(AuditExport {
            events: self.with_justifications(events).await?,
            next_cursor: cursor,
        })
    }

    /// Verifies the hash chain (AUD-02, ADM-07): from the retention start,
    /// or from an externally kept anchor. The verification is audited.
    ///
    /// K-09: the per-admin budget `audit_verify_per_admin` applies, and at
    /// most **one** verification runs at a time across every instance (a
    /// lease in `admin_operation_leases`, taken and released with single
    /// statements — no connection is held while the chain is read). A
    /// second concurrent request answers `429 rate_limited`.
    ///
    /// K-65: the lease uses the database clock and is renewed by a
    /// heartbeat every third of `audit_verify_lease` while the chain is
    /// read, so a verification longer than the lease never lets a second
    /// one start; `audit_verify_lease` only bounds how long a **dead**
    /// holder blocks others. If the lease is lost anyway (renewals failed
    /// until it expired and another instance took it), the verification is
    /// aborted (`409 conflict`) instead of overlapping.
    pub async fn verify_audit_chain(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        anchor: Option<VerifiedAnchor>,
    ) -> Result<ChainVerification, AuthError> {
        const LEASE: &str = "audit_chain_verification";
        let anchor = anchor.map(VerifiedAnchor::into_anchor).transpose()?;
        self.check_audit_verify(caller, ctx).await?;
        let holder = Uuid::now_v7();
        let ttl = self.settings().audit_verify_lease;
        if !store::acquire_lease(self.pool(), LEASE, holder, ttl).await? {
            return Err(self
                .throttled(
                    caller,
                    ctx,
                    "audit_chain_verified",
                    Limit::AuditVerifyRunning,
                    ttl.min(std::time::Duration::from_secs(60)),
                )
                .await);
        }
        let verification = async {
            match anchor {
                Some(a) => authn_audit::verify_chain_from(self.pool(), a).await,
                None => authn_audit::verify_chain(self.pool()).await,
            }
        };
        let verified = tokio::select! {
            verified = verification => verified,
            lost = self.lease_heartbeat(LEASE, holder, ttl) => Err(lost),
        };
        if let Err(err) = store::release_lease(self.pool(), LEASE, holder).await {
            // The lease expires on its own.
            tracing::warn!(error = %err, "could not release the chain verification lease");
        }
        let report = verified?;
        let verification = ChainVerification::from(report);
        let mut tx = self.begin().await?;
        self.record_action(
            &mut tx,
            ctx,
            caller,
            SecurityEventKind::AdminAction,
            "audit_chain_verified",
            None,
            None,
            meta([
                ("intact", Value::from(verification.intact)),
                ("events_verified", Value::from(verification.events_verified)),
            ]),
        )
        .await?;
        authn_store::commit(tx).await?;
        Ok(verification)
    }
}

impl AdminService {
    /// K-65: renews the lease `name` of `holder` every `ttl / 3` until it is
    /// lost; returns the error to abort with. A failed renewal is retried
    /// at the next beat; two failures in a row (the lease may expire before
    /// the next one) count as lost.
    async fn lease_heartbeat(
        &self,
        name: &'static str,
        holder: Uuid,
        ttl: std::time::Duration,
    ) -> AuthError {
        let beat = (ttl / 3).max(std::time::Duration::from_millis(50));
        let mut failures = 0_u32;
        loop {
            tokio::time::sleep(beat).await;
            match store::renew_lease(self.pool(), name, holder, ttl).await {
                Ok(true) => failures = 0,
                Ok(false) => {
                    tracing::error!(lease = name, "operation lease lost; aborting");
                    break;
                }
                Err(err) => {
                    failures += 1;
                    tracing::warn!(lease = name, error = %err, "operation lease renewal failed");
                    if failures >= 2 {
                        break;
                    }
                }
            }
        }
        AuthError::new(codes::common::CONFLICT)
            .with_context("the operation lease was lost; another instance may be running it")
    }
}

/// Same cursor encoding as `authn_audit::query` (Unix microseconds).
fn time_to_micros(t: time::OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adm_07_anchor_parsing_is_strict() {
        let hex = "ab".repeat(32);
        let anchor = VerifiedAnchor {
            seq: 3,
            hash: hex.clone(),
        }
        .into_anchor()
        .unwrap();
        assert_eq!(anchor.hash, [0xab; 32]);
        assert_eq!(VerifiedAnchor::from(anchor).hash, hex);
        for (seq, hash) in [
            (-1, "ab".repeat(32)),
            (1, "ab".repeat(31)),
            (1, "zz".repeat(32)),
            (1, "é".repeat(32)),
        ] {
            assert!(VerifiedAnchor { seq, hash }.into_anchor().is_err());
        }
    }

    #[test]
    fn adm_07_filter_validation_reuses_audit_rules() {
        let subject = UserId::generate();
        let (filter, _) = AdminAuditFilter {
            kind: Some("admin.action".into()),
            subject_user_id: Some(subject),
            ..AdminAuditFilter::default()
        }
        .into_filter()
        .unwrap();
        assert_eq!(filter.subject_user, Some(subject));
        assert_eq!(filter.kind, Some(SecurityEventKind::AdminAction));
        let err = AdminAuditFilter {
            kind: Some("admin.nope".into()),
            ..AdminAuditFilter::default()
        }
        .into_filter()
        .unwrap_err();
        assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
    }
}
