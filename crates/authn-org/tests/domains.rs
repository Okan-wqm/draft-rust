#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-06: domain verification over DNS TXT and auto-join.

mod common;

use std::time::Duration;

use authn_core::error::codes;
use authn_core::ports::SecurityEventKind;
use authn_org::model::DomainStatus;
use authn_org::service::domains::{AddDomain, UpdateDomain};
use common::{Harness, MEMBER_ROLE_ID};
use sqlx::PgPool;

fn add(domain: &str) -> AddDomain {
    AddDomain {
        domain: domain.into(),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_06_domain_is_verified_through_the_txt_record(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let domain = h
        .service
        .add_domain(&h.ctx(), &h.fresh(alice), org, add("Acme.Example."))
        .await
        .unwrap();
    assert_eq!(domain.domain, "acme.example");
    assert_eq!(domain.status, DomainStatus::Pending);
    assert_eq!(
        domain.verification_record_name,
        "_authn-verification.acme.example"
    );
    assert!(domain.verification_value.starts_with("authn-verification="));
    assert_eq!(
        domain.verification_value.len(),
        "authn-verification=".len() + 43
    );

    // No record yet → failed (and retryable).
    let err = h
        .service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_DOMAIN_VERIFICATION_FAILED);
    // A record with a different value does not count.
    h.ports.dns.add_txt(
        "_authn-verification.acme.example",
        "authn-verification=someone-else",
    );
    let err = h
        .service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_DOMAIN_VERIFICATION_FAILED);
    h.ports.dns.add_txt(
        "_authn-verification.acme.example",
        &domain.verification_value,
    );
    let verified = h
        .service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap();
    assert_eq!(verified.status, DomainStatus::Verified);
    assert!(verified.verified_at.is_some());
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OrgDomainVerified)
            .len(),
        1
    );
    // Idempotent.
    h.service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_06_a_domain_belongs_to_one_organization(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let mallory = h.user("mallory@example.com").await;
    let org = h.org(alice, "acme").await;
    let evil = h.org(mallory, "evil").await;
    let mine = h
        .service
        .add_domain(&h.ctx(), &h.fresh(alice), org, add("acme.example"))
        .await
        .unwrap();
    let err = h
        .service
        .add_domain(&h.ctx(), &h.fresh(alice), org, add("ACME.example"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_DOMAIN_EXISTS);
    h.ports
        .dns
        .add_txt("_authn-verification.acme.example", &mine.verification_value);
    h.service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, mine.id)
        .await
        .unwrap();
    // Mallory claims the same domain; even with her own record published
    // the first verification wins.
    let theirs = h
        .service
        .add_domain(&h.ctx(), &h.fresh(mallory), evil, add("acme.example"))
        .await
        .unwrap();
    h.ports.dns.add_txt(
        "_authn-verification.acme.example",
        &theirs.verification_value,
    );
    let err = h
        .service
        .verify_domain(&h.ctx(), &h.fresh(mallory), evil, theirs.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_DOMAIN_CLAIMED);
    // Mallory's own value never verifies Alice's entry either.
    assert_ne!(mine.verification_value, theirs.verification_value);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_06_auto_join_requires_verification_and_matches_exact_verified_addresses(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let domain = h
        .service
        .add_domain(&h.ctx(), &h.fresh(alice), org, add("acme.example"))
        .await
        .unwrap();
    let err = h
        .service
        .update_domain(
            &h.ctx(),
            &h.fresh(alice),
            org,
            domain.id,
            UpdateDomain { auto_join: true },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_DOMAIN_NOT_VERIFIED);
    h.ports.dns.add_txt(
        "_authn-verification.acme.example",
        &domain.verification_value,
    );
    h.service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap();
    let updated = h
        .service
        .update_domain(
            &h.ctx(),
            &h.fresh(alice),
            org,
            domain.id,
            UpdateDomain { auto_join: true },
        )
        .await
        .unwrap();
    assert!(updated.auto_join);

    let employee = h.user("dev@acme.example").await;
    let unverified = h.unverified_user("intern@acme.example").await;
    let subdomain = h.user("dev@eu.acme.example").await;
    let lookalike = h.user("dev@acme.example.evil.test").await;
    assert_eq!(
        h.service
            .auto_join_verified_domains(employee)
            .await
            .unwrap(),
        vec![org]
    );
    let (_, role, _) = h.membership_of(org, employee).await.unwrap();
    assert_eq!(role, MEMBER_ROLE_ID);
    // Idempotent.
    assert!(
        h.service
            .auto_join_verified_domains(employee)
            .await
            .unwrap()
            .is_empty()
    );
    for user in [unverified, subdomain, lookalike] {
        assert!(
            h.service
                .auto_join_verified_domains(user)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(h.membership_of(org, user).await.is_none());
    }
    // Turning auto-join off stops it.
    h.service
        .update_domain(
            &h.ctx(),
            &h.fresh(alice),
            org,
            domain.id,
            UpdateDomain { auto_join: false },
        )
        .await
        .unwrap();
    let late = h.user("late@acme.example").await;
    assert!(
        h.service
            .auto_join_verified_domains(late)
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_06_dns_failures_and_check_budget(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.org.domain_checks_per_org =
            authn_core::ports::RateLimitPolicy::new(2, Duration::from_secs(3600));
    })
    .await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let domain = h
        .service
        .add_domain(&h.ctx(), &h.fresh(alice), org, add("acme.example"))
        .await
        .unwrap();
    h.ports.dns.set_failing(true);
    let err = h
        .service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
    h.ports.dns.set_failing(false);
    let err = h
        .service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_DOMAIN_VERIFICATION_FAILED);
    let err = h
        .service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_06_invalid_domains_limits_and_removal(pool: PgPool) {
    let h = Harness::with(pool, |s| s.org.limits.domains = 1).await;
    let alice = h.user("alice@example.com").await;
    let viewer = h.user("viewer@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, viewer, common::VIEWER_ROLE_ID).await;
    for bad in [
        "localhost",
        "1.2.3.4",
        "exаmple.com",
        "https://acme.example",
        "a@b.example",
    ] {
        let err = h
            .service
            .add_domain(&h.ctx(), &h.fresh(alice), org, add(bad))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::VALIDATION_FAILED, "{bad}");
    }
    let domain = h
        .service
        .add_domain(&h.ctx(), &h.fresh(alice), org, add("bücher.example"))
        .await
        .unwrap();
    assert_eq!(domain.domain, "xn--bcher-kva.example");
    let err = h
        .service
        .add_domain(&h.ctx(), &h.fresh(alice), org, add("second.example"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_LIMIT_REACHED);
    // Viewers read, but cannot manage.
    assert_eq!(
        h.service
            .list_domains(&h.ctx(), &h.fresh(viewer), org)
            .await
            .unwrap()
            .len(),
        1
    );
    let err = h
        .service
        .delete_domain(&h.ctx(), &h.fresh(viewer), org, domain.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
    h.service
        .delete_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap();
    let err = h
        .service
        .delete_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::NOT_FOUND);
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OrgDomainRemoved)
            .len(),
        1
    );
}

/// Security review: domain auto-join re-added a removed member (or one who
/// left) at the next login, so removal and leaving did not stick for users
/// of a verified auto-join domain.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_02_org_06_auto_join_never_undoes_a_removal_or_a_departure(pool: PgPool) {
    use authn_org::service::invitations::CreateInvitation;

    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let domain = h
        .service
        .add_domain(&h.ctx(), &h.fresh(alice), org, add("acme.example"))
        .await
        .unwrap();
    h.ports.dns.add_txt(
        "_authn-verification.acme.example",
        &domain.verification_value,
    );
    h.service
        .verify_domain(&h.ctx(), &h.fresh(alice), org, domain.id)
        .await
        .unwrap();
    h.service
        .update_domain(
            &h.ctx(),
            &h.fresh(alice),
            org,
            domain.id,
            UpdateDomain { auto_join: true },
        )
        .await
        .unwrap();
    // Adding the domain is audited with its own event kind.
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::OrgDomainAdded)
            .len(),
        1
    );
    let fired = h.user("fired@acme.example").await;
    let quitter = h.user("quitter@acme.example").await;
    for user in [fired, quitter] {
        assert_eq!(
            h.service.auto_join_verified_domains(user).await.unwrap(),
            vec![org]
        );
    }

    // Removed by an administrator → not re-added at the next login.
    let (membership, _, _) = h.membership_of(org, fired).await.unwrap();
    h.service
        .remove_member(&h.ctx(), &h.fresh(alice), org, membership)
        .await
        .unwrap();
    assert!(
        h.service
            .auto_join_verified_domains(fired)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(h.membership_of(org, fired).await.is_none());

    // Left voluntarily → stays out as well.
    h.service
        .leave_organization(&h.ctx(), &h.fresh(quitter), org)
        .await
        .unwrap();
    assert!(
        h.service
            .auto_join_verified_domains(quitter)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(h.membership_of(org, quitter).await.is_none());

    // Only an explicit invitation brings the user back.
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            CreateInvitation {
                email: "fired@acme.example".into(),
                role_id: MEMBER_ROLE_ID,
            },
        )
        .await
        .unwrap();
    let token = h.invitation_token("fired@acme.example");
    h.service
        .accept_invitation(&h.ctx(), &h.fresh(fired), &common::secret(&token))
        .await
        .unwrap();
    assert!(h.membership_of(org, fired).await.is_some());

    // The exclusion is part of the user's data export.
    let mut conn = h.pool.acquire().await.unwrap();
    let export =
        authn_core::ports::DataExporter::export(&authn_org::OrgDataExporter, &mut conn, quitter)
            .await
            .unwrap();
    assert_eq!(export["auto_join_exclusions"][0]["org_id"], org.to_string());
    assert_eq!(export["auto_join_exclusions"][0]["reason"], "left");
}
