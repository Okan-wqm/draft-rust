#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ORG-05: invitations.

mod common;

use std::time::Duration;

use authn_core::domain::PageRequest;
use authn_core::error::codes;
use authn_core::ports::{NotificationKind, SecurityEventKind};
use authn_org::model::InvitationStatus;
use authn_org::service::invitations::CreateInvitation;
use authn_testkit::http::TestRequest;
use common::{ADMIN_ROLE_ID, Harness, MEMBER_ROLE_ID, OWNER_ROLE_ID, secret, token_json};
use http::StatusCode;
use sqlx::PgPool;

fn invite(email: &str, role: authn_core::id::RoleId) -> CreateInvitation {
    CreateInvitation {
        email: email.into(),
        role_id: role,
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_invitation_flow_end_to_end(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let invitation = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("Bob@Example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    assert_eq!(invitation.status, InvitationStatus::Pending);
    assert_eq!(
        invitation.expires_at,
        h.now() + Duration::from_secs(7 * 86_400)
    );
    let sent = h.ports.notifier.with_template("invitation");
    assert_eq!(sent.len(), 1);
    let NotificationKind::Invitation {
        org_name, token, ..
    } = &sent[0].kind
    else {
        panic!("wrong notification");
    };
    assert_eq!(org_name, "Org acme");
    // Only the SHA-256 of the 256-bit token is stored.
    assert_eq!(token.len(), 43);
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM invitations WHERE id = $1")
        .bind(invitation.id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(
        stored,
        authn_crypto::sha256(token.expose().as_bytes()).to_vec()
    );
    // The audit trail never carries the token or the address.
    let audited = h.ports.audit.of_kind(SecurityEventKind::InvitationCreated);
    let text = serde_json::to_string(&audited).unwrap();
    assert!(!text.contains(token.expose()) && !text.contains("bob@"));

    let bob = h.user("bob@example.com").await;
    let preview = h
        .service
        .preview_invitation(&h.fresh(bob), &secret(token.expose()))
        .await
        .unwrap();
    assert!(preview.email_matches);
    assert_eq!(preview.email_masked, "B***@example.com");
    let joined = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(token.expose()))
        .await
        .unwrap();
    assert_eq!(joined.organization.id, org);
    assert_eq!(joined.role.key, "member");
    let (_, role, _) = h.membership_of(org, bob).await.unwrap();
    assert_eq!(role, MEMBER_ROLE_ID);
    assert_eq!(
        h.ports
            .audit
            .of_kind(SecurityEventKind::InvitationAccepted)
            .len(),
        1
    );
    // Single use.
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(token.expose()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_accepting_requires_the_invited_verified_address(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bob@example.com", ADMIN_ROLE_ID),
        )
        .await
        .unwrap();
    let token = h.invitation_token("bob@example.com");
    // An attacker who intercepted the token, signed in as someone else.
    let mallory = h.user("mallory@example.com").await;
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(mallory), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_INVITATION_EMAIL_MISMATCH);
    assert!(h.membership_of(org, mallory).await.is_none());
    let preview = h
        .service
        .preview_invitation(&h.fresh(mallory), &secret(&token))
        .await
        .unwrap();
    assert!(!preview.email_matches);
    assert!(!preview.email_masked.contains("bob"), "address masked");
    // The right address, not verified yet.
    let bob = h.unverified_user("bob@example.com").await;
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_EMAIL_VERIFICATION_REQUIRED);
    // The failed attempts did not consume the invitation.
    let mut conn = h.pool.acquire().await.unwrap();
    authn_store::UserRepository::mark_email_verified(&mut conn, bob, h.now())
        .await
        .unwrap();
    h.service
        .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(&token))
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_expired_revoked_and_garbage_tokens_are_indistinguishable(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let carol = h.user("carol@example.com").await;
    let org = h.org(alice, "acme").await;
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bob@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let bob_token = h.invitation_token("bob@example.com");
    let carol_inv = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("carol@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let carol_token = h.invitation_token("carol@example.com");
    h.service
        .revoke_invitation(&h.ctx(), &h.fresh(alice), org, carol_inv.id)
        .await
        .unwrap();
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(carol), &secret(&carol_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);

    h.advance(Duration::from_secs(7 * 86_400 + 1));
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(&bob_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    for garbage in ["", "x", &"A".repeat(43), &"A".repeat(5000)] {
        let err = h
            .service
            .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(garbage))
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    }
    // The listing shows the expired one as expired.
    let list = h
        .service
        .list_invitations(&h.ctx(), &h.fresh(alice), org, &PageRequest::default())
        .await
        .unwrap();
    let statuses: Vec<_> = list.items.iter().map(|i| i.status).collect();
    assert!(statuses.contains(&InvitationStatus::Expired));
    assert!(statuses.contains(&InvitationStatus::Revoked));
    // A new invitation for the expired address is possible.
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bob@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_resend_rotates_the_token_and_is_rate_limited(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    let inv = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bob@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let first = h.invitation_token("bob@example.com");
    let resent = h
        .service
        .resend_invitation(&h.ctx(), &h.fresh(alice), org, inv.id)
        .await
        .unwrap();
    assert_eq!(resent.send_count, 2);
    let second = h.invitation_token("bob@example.com");
    assert_ne!(first, second);
    // Cooldown per invitation.
    let err = h
        .service
        .resend_invitation(&h.ctx(), &h.fresh(alice), org, inv.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    // The old token is dead, the new one works.
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(&first))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    h.service
        .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(&second))
        .await
        .unwrap();
    // Accepted invitations cannot be re-sent or revoked.
    h.advance(Duration::from_secs(120));
    let err = h
        .service
        .resend_invitation(&h.ctx(), &h.fresh(alice), org, inv.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::CONFLICT);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_send_budget_per_org(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.org.invitation_sends_per_org =
            authn_core::ports::RateLimitPolicy::new(2, Duration::from_secs(3600));
    })
    .await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    for i in 0..2 {
        h.service
            .create_invitation(
                &h.ctx(),
                &h.fresh(alice),
                org,
                invite(&format!("u{i}@example.com"), MEMBER_ROLE_ID),
            )
            .await
            .unwrap();
    }
    let err = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("u9@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_duplicates_members_and_escalation_are_refused(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let admin = h.user("admin@example.com").await;
    let org = h.org(alice, "acme").await;
    h.add_member(org, admin, ADMIN_ROLE_ID).await;
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bob@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let err = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("BOB@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_INVITATION_PENDING);
    let err = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("admin@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ALREADY_MEMBER);
    // An existing account that is not a member is invited like any other
    // address: nothing reveals that the account exists.
    h.user("exists@example.com").await;
    let existing = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("exists@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let fresh = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("nobody@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    assert_eq!(existing.status, fresh.status);
    // Admins cannot invite owners.
    let err = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(admin),
            org,
            invite("carol@example.com", OWNER_ROLE_ID),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::org::ORG_ROLE_ESCALATION);
    let err = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("not an address", MEMBER_ROLE_ID),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::VALIDATION_FAILED);
    // Members without members:invite cannot even list invitations.
    let member = h.user("member@example.com").await;
    h.add_member(org, member, MEMBER_ROLE_ID).await;
    let err = h
        .service
        .list_invitations(&h.ctx(), &h.fresh(member), org, &PageRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::FORBIDDEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_concurrent_acceptance_creates_exactly_one_membership(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bob@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let token = h.invitation_token("bob@example.com");
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let service = h.service.clone();
        let ctx = h.ctx();
        let p = h.fresh(bob);
        let t = secret(&token);
        tasks.push(tokio::spawn(async move {
            service.accept_invitation(&ctx, &p, &t).await
        }));
    }
    let mut ok = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM memberships WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(bob)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_http_accept_and_preview_attempts_are_rate_limited(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.org.token_attempts_per_user =
            authn_core::ports::RateLimitPolicy::new(3, Duration::from_secs(3600));
    })
    .await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bob@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let app = h.app_as(h.fresh(bob));
    for _ in 0..3 {
        TestRequest::post("/v1/invitations/accept")
            .json(&token_json(&"B".repeat(43)))
            .send(&app)
            .await
            .assert_error(StatusCode::BAD_REQUEST, "invalid_or_expired_token");
    }
    let res = TestRequest::post("/v1/invitations/accept")
        .json(&token_json(&h.invitation_token("bob@example.com")))
        .send(&app)
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(res.header("retry-after").is_some());
    // Wrong body types never echo the value.
    let res = TestRequest::post("/v1/invitations/preview")
        .json(&serde_json::json!({"token": 12345}))
        .send(&app)
        .await;
    res.assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    assert!(!res.text().contains("12345"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_pending_deletion_invalidates_invitations(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let org = h.org(alice, "acme").await;
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bob@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let token = h.invitation_token("bob@example.com");
    h.service
        .schedule_deletion(&h.ctx(), &h.fresh(alice), org)
        .await
        .unwrap();
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(bob), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_04_org_05_invitations_of_a_demoted_or_removed_inviter_are_revoked(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let rogue = h.user("rogue@example.com").await;
    let accomplice = h.user("accomplice@example.com").await;
    let org = h.org(alice, "acme").await;
    let rogue_m = h.add_member(org, rogue, ADMIN_ROLE_ID).await;
    // A rogue admin invites an accomplice as admin, then gets demoted.
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(rogue),
            org,
            invite("accomplice@example.com", ADMIN_ROLE_ID),
        )
        .await
        .unwrap();
    let token = h.invitation_token("accomplice@example.com");
    h.service
        .update_member(
            &h.ctx(),
            &h.fresh(alice),
            org,
            rogue_m,
            authn_org::service::members::UpdateMember {
                role_id: Some(MEMBER_ROLE_ID),
                status: None,
            },
        )
        .await
        .unwrap();
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(accomplice), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    assert!(h.membership_of(org, accomplice).await.is_none());
}

/// Security review: removing permissions from a custom role revoked its
/// holders' sessions but not the invitations they had sent, so a pending
/// invitation still granted a role its sender could no longer grant.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_04_org_05_role_reduction_revokes_invitations_of_its_holders(pool: PgPool) {
    use authn_org::permission::BILLING_ROLE_ID;
    use authn_org::service::roles::{CreateRole, UpdateRole};

    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let recruiter = h.user("recruiter@example.com").await;
    let invitee = h.user("invitee@example.com").await;
    let bystander = h.user("bystander@example.com").await;
    let org = h.org(alice, "acme").await;
    let perms = |list: &[&str]| list.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
    let role = h
        .service
        .create_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            CreateRole {
                key: "recruiter".into(),
                name: "Recruiter".into(),
                description: None,
                permissions: perms(&[
                    "org:read",
                    "members:read",
                    "members:invite",
                    "billing:read",
                    "billing:manage",
                ]),
            },
        )
        .await
        .unwrap();
    h.add_member(org, recruiter, role.id).await;
    // The recruiter may grant `billing` (org:read, billing:read/manage).
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(recruiter),
            org,
            invite("invitee@example.com", BILLING_ROLE_ID),
        )
        .await
        .unwrap();
    let token = h.invitation_token("invitee@example.com");
    // An invitation of another sender is not affected.
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("bystander@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let other_token = h.invitation_token("bystander@example.com");
    // The owner takes `billing:manage` away from the role.
    h.service
        .update_role(
            &h.ctx(),
            &h.fresh(alice),
            org,
            role.id,
            UpdateRole {
                permissions: Some(perms(&[
                    "org:read",
                    "members:read",
                    "members:invite",
                    "billing:read",
                ])),
                ..UpdateRole::default()
            },
        )
        .await
        .unwrap();
    let err = h
        .service
        .accept_invitation(&h.ctx(), &h.fresh(invitee), &secret(&token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::INVALID_OR_EXPIRED_TOKEN);
    assert!(h.membership_of(org, invitee).await.is_none());
    h.service
        .accept_invitation(&h.ctx(), &h.fresh(bystander), &secret(&other_token))
        .await
        .unwrap();
}

/// Security review: the per-invitation resend cooldown was bypassed by
/// revoking the invitation and inviting the same address again, so one
/// organization could mail a victim up to its whole hourly budget.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_05_revoke_and_reinvite_cannot_bomb_one_address(pool: PgPool) {
    let h = Harness::with(pool, |s| {
        s.org.invitation_sends_per_recipient =
            authn_core::ports::RateLimitPolicy::new(2, Duration::from_secs(86_400));
    })
    .await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let other_org = h.org(alice, "globex").await;
    for _ in 0..2 {
        let inv = h
            .service
            .create_invitation(
                &h.ctx(),
                &h.fresh(alice),
                org,
                invite("victim@example.com", MEMBER_ROLE_ID),
            )
            .await
            .unwrap();
        h.service
            .revoke_invitation(&h.ctx(), &h.fresh(alice), org, inv.id)
            .await
            .unwrap();
    }
    let sent_before = h.ports.notifier.recorded().len();
    let err = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("victim@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
    assert_eq!(h.ports.notifier.recorded().len(), sent_before);
    // Other addresses and other organizations keep their own budgets.
    h.service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("someone@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let pending = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            other_org,
            invite("victim@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    // Resends count against the same budget.
    h.advance(Duration::from_secs(120));
    h.service
        .resend_invitation(&h.ctx(), &h.fresh(alice), other_org, pending.id)
        .await
        .unwrap();
    h.advance(Duration::from_secs(120));
    let err = h
        .service
        .resend_invitation(&h.ctx(), &h.fresh(alice), other_org, pending.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::RATE_LIMITED);
}

/// Security review: granting `owner` through `update_member` required
/// step-up, but inviting an address as `owner` (and re-sending such an
/// invitation) did not — a stale owner session could mint a new owner.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn org_04_org_05_owner_invitations_require_step_up(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let org = h.org(alice, "acme").await;
    let err = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.stale(alice),
            org,
            invite("partner@example.com", OWNER_ROLE_ID),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    assert!(
        h.ports
            .notifier
            .recorded()
            .iter()
            .all(|n| { n.recipient.email.as_str() != "partner@example.com" })
    );
    // Other roles need no step-up.
    h.service
        .create_invitation(
            &h.ctx(),
            &h.stale(alice),
            org,
            invite("staff@example.com", MEMBER_ROLE_ID),
        )
        .await
        .unwrap();
    let inv = h
        .service
        .create_invitation(
            &h.ctx(),
            &h.fresh(alice),
            org,
            invite("partner@example.com", OWNER_ROLE_ID),
        )
        .await
        .unwrap();
    h.advance(Duration::from_secs(120));
    let err = h
        .service
        .resend_invitation(&h.ctx(), &h.stale(alice), org, inv.id)
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::STEP_UP_REQUIRED);
    h.service
        .resend_invitation(&h.ctx(), &h.fresh(alice), org, inv.id)
        .await
        .unwrap();
}
