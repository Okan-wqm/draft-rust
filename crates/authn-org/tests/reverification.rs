#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-13 (K-97): periodic re-verification of verified domains. Only a
//! definitive absence of the TXT record counts; resolver errors and
//! timeouts are counted apart; after the configured number of consecutive
//! absences the domain loses its verification, auto-join stops, the
//! organization's domain administrators are notified and the change is
//! audited. Several instances never check one domain twice per interval.

mod common;

use std::time::Duration;

use authn_core::id::{OrgDomainId, OrgId, UserId};
use authn_core::ports::{NotificationKind, SecurityEventKind};
use authn_org::model::{DomainStatus, OrgDomain};
use authn_org::permission::BuiltinRole;
use authn_org::service::domains::{AddDomain, UpdateDomain};
use authn_org::service::reverify::ReverificationReport;
use common::{Harness, MEMBER_ROLE_ID};
use sqlx::PgPool;

const RECORD: &str = "_authn-verification.acme.example";
const DAY: Duration = Duration::from_secs(86_400);

struct Setup {
    h: Harness,
    owner: UserId,
    org: OrgId,
    domain: OrgDomain,
}

async fn setup(pool: PgPool, tweak: impl FnOnce(&mut authn_org::OrgServiceSettings)) -> Setup {
    let h = Harness::with(pool, tweak).await;
    let owner = h.user("alice@example.com").await;
    let org = h.org(owner, "acme").await;
    let domain = h
        .service
        .add_domain(
            &h.ctx(),
            &h.fresh(owner),
            org,
            AddDomain {
                domain: "acme.example".into(),
            },
        )
        .await
        .unwrap();
    h.ports.dns.add_txt(RECORD, &domain.verification_value);
    h.service
        .verify_domain(&h.ctx(), &h.fresh(owner), org, domain.id)
        .await
        .unwrap();
    h.service
        .update_domain(
            &h.ctx(),
            &h.fresh(owner),
            org,
            domain.id,
            UpdateDomain { auto_join: true },
        )
        .await
        .unwrap();
    Setup {
        h,
        owner,
        org,
        domain,
    }
}

impl Setup {
    async fn current(&self) -> OrgDomain {
        self.h
            .service
            .list_domains(&self.h.ctx(), &self.h.fresh(self.owner), self.org)
            .await
            .unwrap()
            .into_iter()
            .find(|d| d.id == self.domain.id)
            .unwrap()
    }

    /// One interval later, one job run.
    async fn next_run(&self) -> ReverificationReport {
        self.h.advance(DAY + Duration::from_secs(1));
        self.h.service.reverify_due_domains().await.unwrap()
    }

    fn unverified_notices(&self) -> Vec<(String, String, String)> {
        self.h
            .ports
            .notifier
            .recorded()
            .into_iter()
            .filter_map(|n| match n.kind {
                NotificationKind::OrgDomainUnverified {
                    org_name, domain, ..
                } => Some((n.recipient.email.as_str().to_owned(), org_name, domain)),
                _ => None,
            })
            .collect()
    }
}

/// ORG-13: after `failure_threshold` (3) consecutive definitive absences
/// the domain becomes `failed`, auto-join stops at once, the change is
/// audited and the domain administrators (not plain members) are notified.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_13_definitive_absence_unverifies_the_domain_and_stops_auto_join(pool: PgPool) {
    let s = setup(pool, |_| {}).await;
    let admin = s.h.user("admin@example.com").await;
    let admin_role = BuiltinRole::Admin.id();
    s.h.add_member(s.org, admin, admin_role).await;
    let member = s.h.user("member@example.com").await;
    s.h.add_member(s.org, member, MEMBER_ROLE_ID).await;

    // Still published: nothing changes.
    let report = s.next_run().await;
    assert_eq!((report.checked, report.present), (1, 1));
    assert_eq!(
        s.current().await.last_check_outcome.as_deref(),
        Some("present")
    );

    // The domain changes hands: the record disappears (NXDOMAIN / NODATA).
    s.h.ports.dns.remove_txt(RECORD);
    for expected in 1..=2_u32 {
        let report = s.next_run().await;
        assert_eq!((report.absent, report.unverified), (1, 0));
        let d = s.current().await;
        assert_eq!(d.status, DomainStatus::Verified);
        assert!(d.auto_join);
        assert_eq!(d.consecutive_absent_checks, expected);
        assert_eq!(d.last_check_outcome.as_deref(), Some("absent"));
    }
    // A user of the domain still joins before the threshold.
    let early = s.h.user("early@acme.example").await;
    assert_eq!(
        s.h.service.auto_join_verified_domains(early).await.unwrap(),
        vec![s.org]
    );
    assert!(s.unverified_notices().is_empty());

    let report = s.next_run().await;
    assert_eq!((report.absent, report.unverified), (1, 1));
    let d = s.current().await;
    assert_eq!(d.status, DomainStatus::Failed);
    assert!(!d.auto_join && !d.sso_required);
    assert!(d.verified_at.is_none());
    assert_eq!(d.unverified_at, Some(s.h.now()));
    assert_eq!(d.consecutive_absent_checks, 3);

    // Auto-join stopped.
    let late = s.h.user("late@acme.example").await;
    assert!(
        s.h.service
            .auto_join_verified_domains(late)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(s.h.membership_of(s.org, late).await.is_none());

    // Audited once, as the system, with the reason.
    let events =
        s.h.ports
            .audit
            .of_kind(SecurityEventKind::OrgDomainUnverified);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].org_id, Some(s.org));
    assert_eq!(events[0].metadata["reason"], "absent");
    assert_eq!(events[0].metadata["consecutive_checks"], 3);
    assert_eq!(events[0].metadata["domain"], "acme.example");

    // Owner and admin (domains:manage) are told; the plain member is not.
    let mut notified: Vec<String> = s.unverified_notices().into_iter().map(|n| n.0).collect();
    notified.sort();
    assert_eq!(notified, vec!["admin@example.com", "alice@example.com"]);
    assert!(s.unverified_notices().iter().all(|n| n.2 == "acme.example"));

    // Failed domains are no longer re-checked.
    let report = s.next_run().await;
    assert_eq!(report.checked, 0);
}

/// ORG-13: resolver failures (SERVFAIL, refused) and timeouts are
/// inconclusive: they never count as absence, keep the domain verified and
/// leave the absence counter alone; only a long streak of them
/// (`inconclusive_limit`) takes the verification away.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_13_resolver_errors_are_not_absence(pool: PgPool) {
    let s = setup(pool, |settings| {
        settings.org.dns_timeout = Duration::from_millis(200);
        settings.org.domain_reverification.inconclusive_limit = 6;
    })
    .await;
    s.h.ports.dns.remove_txt(RECORD);
    // One real absence first.
    assert_eq!(s.next_run().await.absent, 1);

    s.h.ports.dns.set_failing(true);
    for _ in 0..3 {
        let report = s.next_run().await;
        assert_eq!((report.inconclusive, report.unverified), (1, 0));
    }
    s.h.ports.dns.set_failing(false);
    s.h.ports.dns.set_hanging(true);
    for _ in 0..2 {
        let report = s.next_run().await;
        assert_eq!((report.inconclusive, report.unverified), (1, 0));
    }
    let d = s.current().await;
    assert_eq!(
        d.status,
        DomainStatus::Verified,
        "errors never count as absence"
    );
    assert!(d.auto_join);
    assert_eq!(d.consecutive_absent_checks, 1, "absence counter untouched");
    assert_eq!(d.consecutive_inconclusive_checks, 5);
    assert_eq!(d.last_check_outcome.as_deref(), Some("inconclusive"));
    assert!(s.unverified_notices().is_empty());

    // The sixth inconclusive check in a row: a domain whose DNS never
    // answers does not keep auto-join forever.
    let report = s.next_run().await;
    assert_eq!(report.unverified, 1);
    let d = s.current().await;
    assert_eq!(d.status, DomainStatus::Failed);
    let events =
        s.h.ports
            .audit
            .of_kind(SecurityEventKind::OrgDomainUnverified);
    assert_eq!(events[0].metadata["reason"], "inconclusive");
    assert_eq!(events[0].metadata["consecutive_checks"], 6);
}

/// ORG-13: only *consecutive* absences count — a check that finds the
/// record resets both counters; a record with another value is absence.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_13_a_found_record_resets_the_counters(pool: PgPool) {
    let s = setup(pool, |_| {}).await;
    s.h.ports.dns.remove_txt(RECORD);
    s.h.ports
        .dns
        .add_txt(RECORD, "authn-verification=someone-else");
    s.next_run().await;
    s.next_run().await;
    assert_eq!(s.current().await.consecutive_absent_checks, 2);
    s.h.ports.dns.add_txt(RECORD, &s.domain.verification_value);
    assert_eq!(s.next_run().await.present, 1);
    let d = s.current().await;
    assert_eq!(
        (
            d.consecutive_absent_checks,
            d.consecutive_inconclusive_checks
        ),
        (0, 0)
    );
    s.h.ports.dns.remove_txt(RECORD);
    s.next_run().await;
    s.next_run().await;
    assert_eq!(s.current().await.status, DomainStatus::Verified);
}

/// ORG-13: a domain is checked once per interval, and two instances
/// running the job at the same time never check one domain twice.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_13_each_domain_is_checked_once_per_interval_across_instances(pool: PgPool) {
    let s = setup(pool, |_| {}).await;
    // More verified domains (other organizations).
    let mut ids: Vec<OrgDomainId> = vec![s.domain.id];
    for i in 0..9 {
        let owner = s.h.user(&format!("owner{i}@example.com")).await;
        let org = s.h.org(owner, &format!("org-{i}")).await;
        let d =
            s.h.service
                .add_domain(
                    &s.h.ctx(),
                    &s.h.fresh(owner),
                    org,
                    AddDomain {
                        domain: format!("d{i}.example"),
                    },
                )
                .await
                .unwrap();
        s.h.ports.dns.add_txt(
            &format!("_authn-verification.d{i}.example"),
            &d.verification_value,
        );
        s.h.service
            .verify_domain(&s.h.ctx(), &s.h.fresh(owner), org, d.id)
            .await
            .unwrap();
        ids.push(d.id);
    }
    // Not due yet.
    assert_eq!(s.h.service.reverify_due_domains().await.unwrap().checked, 0);
    s.h.advance(DAY + Duration::from_secs(1));
    let other_instance = s.h.with_rate_limiter(s.h.ports.rate_limiter.clone());
    let (a, b) = tokio::join!(
        s.h.service.reverify_due_domains(),
        other_instance.reverify_due_domains()
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.checked + b.checked, 10, "{a:?} {b:?}");
    assert_eq!(a.present + b.present, 10);
    // Done for this interval, on every instance.
    assert_eq!(s.h.service.reverify_due_domains().await.unwrap().checked, 0);
    assert_eq!(
        other_instance.reverify_due_domains().await.unwrap().checked,
        0
    );
    assert_eq!(ids.len(), 10);
}

/// ORG-13 (audit, wave 11): a lookup that outlives its claim — a large
/// batch of slow lookups can take longer than the interval, and another
/// instance then claims and checks the same domain again — records
/// nothing. Before, both outcomes were counted, so a domain could reach
/// `failure_threshold` in fewer intervals than configured.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_13_a_check_that_outlived_its_claim_is_not_counted(pool: PgPool) {
    let s = setup(pool, |settings| {
        settings.org.dns_timeout = Duration::from_millis(1500);
    })
    .await;
    s.h.advance(DAY + Duration::from_secs(1));
    s.h.ports.dns.set_hanging(true);
    let slow = s.h.with_rate_limiter(s.h.ports.rate_limiter.clone());
    let takeover = async {
        // The slow instance has claimed the domain and waits for DNS.
        tokio::time::sleep(Duration::from_millis(400)).await;
        // An interval later, another run claims it again and finds the
        // record definitively absent.
        s.h.advance(DAY + Duration::from_secs(1));
        s.h.ports.dns.set_hanging(false);
        s.h.ports.dns.remove_txt(RECORD);
        s.h.service.reverify_due_domains().await
    };
    let (stale, fresh) = tokio::join!(slow.reverify_due_domains(), takeover);
    let (stale, fresh) = (stale.unwrap(), fresh.unwrap());
    assert_eq!(fresh.absent, 1, "{fresh:?}");
    assert_eq!(stale.inconclusive, 1, "{stale:?}");
    let d = s.current().await;
    assert_eq!(
        (
            d.consecutive_absent_checks,
            d.consecutive_inconclusive_checks,
            d.last_check_outcome.as_deref()
        ),
        (1, 0, Some("absent")),
        "only the current claim's outcome is recorded"
    );
}

/// ORG-13: the batch size bounds one run.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_13_batch_size_bounds_one_run(pool: PgPool) {
    let s = setup(pool, |settings| {
        settings.org.domain_reverification.batch_size = 1;
    })
    .await;
    let owner = s.h.user("bob@example.com").await;
    let org = s.h.org(owner, "other").await;
    let d =
        s.h.service
            .add_domain(
                &s.h.ctx(),
                &s.h.fresh(owner),
                org,
                AddDomain {
                    domain: "other.example".into(),
                },
            )
            .await
            .unwrap();
    s.h.ports
        .dns
        .add_txt("_authn-verification.other.example", &d.verification_value);
    s.h.service
        .verify_domain(&s.h.ctx(), &s.h.fresh(owner), org, d.id)
        .await
        .unwrap();
    assert_eq!(s.next_run().await.checked, 1);
    assert_eq!(s.h.service.reverify_due_domains().await.unwrap().checked, 1);
    assert_eq!(s.h.service.reverify_due_domains().await.unwrap().checked, 0);
}

/// ORG-13: switched off, the job does nothing.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_13_the_job_can_be_switched_off(pool: PgPool) {
    let s = setup(pool, |settings| {
        settings.org.domain_reverification.enabled = false;
    })
    .await;
    s.h.ports.dns.remove_txt(RECORD);
    for _ in 0..5 {
        assert_eq!(s.next_run().await, ReverificationReport::default());
    }
    assert_eq!(s.current().await.status, DomainStatus::Verified);
}

/// ORG-13: a domain that lost its verification is verified again through
/// the normal ORG-06 flow; its re-verification state is reset.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_13_an_unverified_domain_can_be_verified_again(pool: PgPool) {
    let s = setup(pool, |settings| {
        settings.org.domain_reverification.failure_threshold = 1;
    })
    .await;
    s.h.ports.dns.remove_txt(RECORD);
    assert_eq!(s.next_run().await.unverified, 1);
    assert_eq!(s.current().await.status, DomainStatus::Failed);

    s.h.ports.dns.add_txt(RECORD, &s.domain.verification_value);
    let again =
        s.h.service
            .verify_domain(&s.h.ctx(), &s.h.fresh(s.owner), s.org, s.domain.id)
            .await
            .unwrap();
    assert_eq!(again.status, DomainStatus::Verified);
    assert_eq!(again.unverified_at, None);
    assert_eq!(again.consecutive_absent_checks, 0);
    assert!(
        !again.auto_join,
        "auto-join is switched on again explicitly"
    );
}
