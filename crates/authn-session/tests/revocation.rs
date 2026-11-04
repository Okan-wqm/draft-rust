#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Revocation (SES-15 port semantics), the session list (SES-11) and
//! logout (SES-12).

mod common;

use std::sync::Arc;

use authn_core::id::SessionId;
use authn_core::ports::{
    DomainEventKind, RevocationReason, RevokeOptions, SecurityEventKind, SessionRevoker,
};
use authn_session::cookies::SESSION_COOKIE;
use authn_testkit::http::TestRequest;
use common::{Harness, set_cookie};
use http::StatusCode;
use sqlx::PgPool;

async fn trusted_devices(h: &Harness, user: authn_core::id::UserId) -> i64 {
    h.count(
        "SELECT count(*) FROM trusted_devices WHERE user_id = $1 AND revoked_at IS NULL",
        user.as_uuid(),
    )
    .await
}

async fn live(h: &Harness, session: SessionId) -> bool {
    !common::session_row(&h.pool, session).await.0
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_revoke_all_for_user_with_trusted_devices_in_the_callers_transaction(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let web = h.web_login(user).await;
    let native = h.native_login(user).await;
    h.mfa
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trusted_devices(&h, user).await, 1);
    let revoker: Arc<dyn SessionRevoker> = Arc::new(h.revoker.clone());

    // Rolled back: nothing changes (ARC-06).
    let mut tx = h.service.begin().await.unwrap();
    let n = revoker
        .revoke_all_for_user(
            &mut tx,
            user,
            RevocationReason::PasswordReset,
            RevokeOptions {
                also_trusted_devices: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(n, 2);
    tx.rollback().await.unwrap();
    assert!(live(&h, web.session_id).await && live(&h, native.session_id).await);
    assert_eq!(trusted_devices(&h, user).await, 1);

    // Committed: sessions, refresh families and trusted devices go together.
    let mut tx = h.service.begin().await.unwrap();
    revoker
        .revoke_all_for_user(
            &mut tx,
            user,
            RevocationReason::PasswordReset,
            RevokeOptions {
                also_trusted_devices: true,
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(!live(&h, web.session_id).await && !live(&h, native.session_id).await);
    assert_eq!(
        h.revoked_reason(web.session_id).await.as_deref(),
        Some("password_reset")
    );
    assert_eq!(trusted_devices(&h, user).await, 0);
    assert_eq!(
        h.count(
            "SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL",
            native.session_id.as_uuid()
        )
        .await,
        0
    );
    // The very next request is rejected.
    let res = h.send(h.web_get("/v1/me", &web)).await;
    res.assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    let events = h.ports.audit.of_kind(SecurityEventKind::SessionsRevoked);
    let event = events.last().unwrap();
    assert_eq!(event.metadata["reason"], "password_reset");
    assert_eq!(event.metadata["sessions"], 2);
    assert_eq!(event.metadata["trusted_devices"], 1);

    // Without the flag, trusted devices stay.
    let _again = h.web_login(user).await;
    h.mfa
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    let mut tx = h.service.begin().await.unwrap();
    revoker
        .revoke_all_for_user(
            &mut tx,
            user,
            RevocationReason::AdminAction,
            RevokeOptions::default(),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(trusted_devices(&h, user).await, 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_revoke_all_except_keeps_exactly_one(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let other = h.user("bob@example.com").await;
    let keep = h.web_login(user).await;
    let a = h.web_login(user).await;
    let b = h.native_login(user).await;
    let foreign = h.web_login(other).await;
    let mut tx = h.service.begin().await.unwrap();
    let n = h
        .revoker
        .revoke_all_except(
            &mut tx,
            user,
            keep.session_id,
            RevocationReason::PasswordChanged,
            RevokeOptions::default(),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 2);
    assert!(live(&h, keep.session_id).await);
    assert!(!live(&h, a.session_id).await && !live(&h, b.session_id).await);
    assert!(
        live(&h, foreign.session_id).await,
        "other users are untouched"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_org_scoped_revocation_and_domain_events(pool: PgPool) {
    let h = Harness::new(pool).await;
    let owner = h.user("owner@example.com").await;
    let member = h.user("member@example.com").await;
    let org = h.org(owner, "acme").await;
    let other_org = h.org(owner, "globex").await;
    h.add_member(org, member).await;
    h.add_member(other_org, member).await;
    let mut in_org = h.request(member, h.web_channel());
    in_org.org = Some(h.verified_org(member, org).await);
    let in_org = common::web_of(h.establish(in_org).await);
    let mut elsewhere = h.request(member, authn_session::ClientChannel::Native);
    elsewhere.org = Some(h.verified_org(member, other_org).await);
    let elsewhere = common::native_of(h.establish(elsewhere).await);
    let personal = h.web_login(member).await;
    let mut owner_in_org = h.request(owner, h.web_channel());
    owner_in_org.org = Some(h.verified_org(owner, org).await);
    let owner_in_org = common::web_of(h.establish(owner_in_org).await);

    let mut tx = h.service.begin().await.unwrap();
    let n = h
        .revoker
        .revoke_for_user_in_org(&mut tx, member, org, RevocationReason::MembershipRemoved)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 1);
    assert!(!live(&h, in_org.session_id).await);
    assert!(live(&h, elsewhere.session_id).await && live(&h, personal.session_id).await);
    assert!(live(&h, owner_in_org.session_id).await);
    let revoked_events: Vec<_> = h
        .ports
        .events
        .recorded()
        .into_iter()
        .filter(|e| e.kind == DomainEventKind::SessionRevoked)
        .collect();
    assert_eq!(revoked_events.len(), 1);
    assert_eq!(revoked_events[0].org_id, Some(org));
    assert_eq!(revoked_events[0].data["reason"], "membership_removed");

    let mut tx = h.service.begin().await.unwrap();
    let n = h
        .revoker
        .revoke_all_for_org(&mut tx, org, RevocationReason::OrgPolicyChanged)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 1);
    assert!(!live(&h, owner_in_org.session_id).await);
    assert!(live(&h, elsewhere.session_id).await);

    let mut tx = h.service.begin().await.unwrap();
    assert!(
        h.revoker
            .revoke_everything(&mut tx, RevocationReason::Emergency)
            .await
            .unwrap()
            >= 2
    );
    tx.commit().await.unwrap();
    assert!(!live(&h, elsewhere.session_id).await && !live(&h, personal.session_id).await);
    assert_eq!(
        h.revoked_reason(personal.session_id).await.as_deref(),
        Some("emergency")
    );
    // Every RevocationReason fits the stored format.
    for reason in RevocationReason::ALL {
        let user = h
            .user(&format!(
                "{}@example.com",
                reason.as_str().replace('_', "-")
            ))
            .await;
        let s = h.web_login(user).await;
        let mut tx = h.service.begin().await.unwrap();
        assert!(
            h.revoker
                .revoke_session(&mut tx, s.session_id, *reason)
                .await
                .unwrap()
        );
        assert!(
            !h.revoker
                .revoke_session(&mut tx, s.session_id, *reason)
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        assert_eq!(
            h.revoked_reason(s.session_id).await.as_deref(),
            Some(reason.as_str())
        );
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_11_session_list_masks_ip_and_marks_the_current_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let current = h.web_login(user).await;
    let phone = h.native_login(user).await;
    let other_user = h.user("bob@example.com").await;
    let foreign = h.web_login(other_user).await;
    let res = h.send(h.web_get("/v1/me/sessions", &current)).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: serde_json::Value = res.json();
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    let me = sessions.iter().find(|s| s["current"] == true).unwrap();
    assert_eq!(me["id"], current.session_id.to_string());
    assert_eq!(me["ip"], "203.0.113.x");
    assert_eq!(me["device"], "Firefox on Linux");
    assert_eq!(me["client_kind"], "web");
    assert!(
        sessions
            .iter()
            .any(|s| s["id"] == phone.session_id.to_string())
    );
    assert!(
        !body.to_string().contains("203.0.113.10"),
        "full IP never listed"
    );
    assert!(!body.to_string().contains(&foreign.session_id.to_string()));

    // Revoking another user's session: 404, nothing happens (IDOR).
    h.send(
        TestRequest::delete(&format!("/v1/me/sessions/{}", foreign.session_id))
            .cookie(SESSION_COOKIE, &current.cookie)
            .header("origin", common::ORIGIN)
            .header("x-csrf-token", &current.csrf),
    )
    .await
    .assert_error(StatusCode::NOT_FOUND, "not_found");
    assert!(live(&h, foreign.session_id).await);
    // CSRF applies to DELETE as well.
    h.send(
        TestRequest::delete(&format!("/v1/me/sessions/{}", phone.session_id))
            .cookie(SESSION_COOKIE, &current.cookie)
            .header("origin", common::ORIGIN),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    // Revoking one's own other session.
    let res = h
        .send(
            TestRequest::delete(&format!("/v1/me/sessions/{}", phone.session_id))
                .cookie(SESSION_COOKIE, &current.cookie)
                .header("origin", common::ORIGIN)
                .header("x-csrf-token", &current.csrf),
        )
        .await;
    res.assert_status(StatusCode::NO_CONTENT);
    assert!(
        res.header("clear-site-data").is_none(),
        "not the current session"
    );
    assert_eq!(
        h.revoked_reason(phone.session_id).await.as_deref(),
        Some("user_request")
    );
    // Revoking the current session logs out.
    let res = h
        .send(
            TestRequest::delete(&format!("/v1/me/sessions/{}", current.session_id))
                .cookie(SESSION_COOKIE, &current.cookie)
                .header("origin", common::ORIGIN)
                .header("x-csrf-token", &current.csrf),
        )
        .await;
    res.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(res.header("clear-site-data"), Some("\"cookies\""));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_11_revoke_others_keeps_the_current_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let current = h.web_login(user).await;
    let other_web = h.web_login(user).await;
    let other_native = h.native_login(user).await;
    h.mfa
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    let res = h
        .send(h.web_post("/v1/me/sessions/revoke-others", &current))
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<serde_json::Value>()["revoked"], 2);
    assert!(live(&h, current.session_id).await);
    assert!(!live(&h, other_web.session_id).await && !live(&h, other_native.session_id).await);
    assert_eq!(trusted_devices(&h, user).await, 0);
    h.send(h.web_get("/v1/me", &current))
        .await
        .assert_status(StatusCode::OK);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_12_logout_revokes_clears_cookie_and_site_data(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    let other = h.web_login(user).await;
    // CSRF: a cross-site logout is refused.
    h.send(
        TestRequest::post("/v1/logout")
            .cookie(SESSION_COOKIE, &login.cookie)
            .header("origin", "https://evil.example")
            .header("x-csrf-token", &login.csrf),
    )
    .await
    .assert_error(StatusCode::FORBIDDEN, "csrf_failed");
    let res = h.send(h.web_post("/v1/logout", &login)).await;
    res.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(res.header("clear-site-data"), Some("\"cookies\""));
    let cookies = res.set_cookies();
    let cleared = set_cookie(&cookies, SESSION_COOKIE).unwrap();
    assert!(
        cleared.contains("Max-Age=0") && cleared.contains("Secure") && cleared.contains("HttpOnly")
    );
    assert_eq!(
        h.revoked_reason(login.session_id).await.as_deref(),
        Some("logout")
    );
    assert!(live(&h, other.session_id).await, "only the current session");
    // The old cookie is dead even if a client keeps sending it.
    h.send(h.web_post("/v1/logout", &login))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    assert_eq!(h.ports.audit.of_kind(SecurityEventKind::Logout).len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_12_logout_everywhere_revokes_all_sessions_and_trusted_devices(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let login = h.web_login(user).await;
    let native = h.native_login(user).await;
    h.mfa
        .trust_device(&h.ctx(), user, true)
        .await
        .unwrap()
        .unwrap();
    let res = h.send(h.web_post("/v1/logout/all", &login)).await;
    res.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(res.header("clear-site-data"), Some("\"cookies\""));
    assert!(!live(&h, login.session_id).await && !live(&h, native.session_id).await);
    assert_eq!(trusted_devices(&h, user).await, 0);
    // Native logout with the bearer token only revokes that session.
    let a = h.native_login(user).await;
    let b = h.native_login(user).await;
    let res = h
        .send(TestRequest::post("/v1/logout").bearer(&a.access))
        .await;
    res.assert_status(StatusCode::NO_CONTENT);
    assert!(res.header("clear-site-data").is_none());
    assert!(!live(&h, a.session_id).await && live(&h, b.session_id).await);
    // Unauthenticated logout.
    h.send(TestRequest::post("/v1/logout"))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_cleanup_job_purges_ended_sessions(pool: PgPool) {
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let ended = h.native_login(user).await;
    let alive = h.web_login(user).await;
    let mut tx = h.service.begin().await.unwrap();
    h.revoker
        .revoke_session(&mut tx, ended.session_id, RevocationReason::Logout)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    h.advance(std::time::Duration::from_secs(31 * 86_400));
    let _keep_alive = alive;
    let report = h.service.purge_expired(1000).await.unwrap();
    assert!(report.sessions >= 1);
    assert_eq!(
        h.count(
            "SELECT count(*) FROM sessions WHERE id = $1",
            ended.session_id.as_uuid()
        )
        .await,
        0
    );
    assert_eq!(
        h.count(
            "SELECT count(*) FROM refresh_tokens WHERE session_id = $1",
            ended.session_id.as_uuid()
        )
        .await,
        0
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_11_personal_data_export_lists_sessions_without_secrets(pool: PgPool) {
    use authn_core::ports::DataExporter;
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let web = h.web_login(user).await;
    let native = h.native_login(user).await;
    let exporter = authn_session::SessionDataExporter;
    assert_eq!(exporter.section(), "sessions");
    let mut conn = h.pool.acquire().await.unwrap();
    let export = exporter.export(&mut conn, user).await.unwrap();
    let text = export.to_string();
    assert!(text.contains(&web.session_id.to_string()));
    assert!(text.contains(&native.session_id.to_string()));
    assert!(!text.contains(&web.cookie) && !text.contains(&native.refresh));
    assert!(!text.contains(&native.access));
}

// --- security review regressions -------------------------------------------

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_user_wide_revocation_closes_pending_logins(pool: PgPool) {
    use authn_session::ChallengeKind;
    let h = Harness::new(pool).await;
    let user = h.user("alice@example.com").await;
    let bystander = h.user("bob@example.com").await;
    let (_, theirs) = h
        .pending_challenge(bystander, ChallengeKind::Login, None)
        .await;
    let revoke_all = |reason: RevocationReason| {
        let h = &h;
        async move {
            let mut tx = h.service.begin().await.unwrap();
            h.revoker
                .revoke_all_for_user(&mut tx, user, reason, RevokeOptions::default())
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    };

    // A password change keeps the pending login: the SES-22 required
    // actions (password change, e-mail verification) revoke with this
    // reason from inside the login they complete.
    let (_, pending) = h.pending_challenge(user, ChallengeKind::Login, None).await;
    revoke_all(RevocationReason::PasswordChanged).await;
    assert!(h.challenge_open(&pending, ChallengeKind::Login).await);

    // A login started with the old password cannot finish after a reset,
    // a suspension or "this wasn't me".
    for reason in [
        RevocationReason::PasswordReset,
        RevocationReason::AccountSuspended,
        RevocationReason::NotMe,
    ] {
        let (_, pending) = h.pending_challenge(user, ChallengeKind::Login, None).await;
        revoke_all(reason).await;
        assert!(
            !h.challenge_open(&pending, ChallengeKind::Login).await,
            "{reason:?} left a pending login open"
        );
    }

    // "Sign out other sessions" ends pending logins elsewhere but keeps a
    // step-up bound to the session that stays.
    let login = h.web_login(user).await;
    let (_, pending) = h.pending_challenge(user, ChallengeKind::Login, None).await;
    let (_, step_up) = h
        .pending_challenge(user, ChallengeKind::StepUp, Some(login.session_id))
        .await;
    h.send(h.web_post("/v1/me/sessions/revoke-others", &login))
        .await
        .assert_status(StatusCode::OK);
    assert!(!h.challenge_open(&pending, ChallengeKind::Login).await);
    assert!(h.challenge_open(&step_up, ChallengeKind::StepUp).await);

    // Other users are untouched.
    assert!(h.challenge_open(&theirs, ChallengeKind::Login).await);
}

/// ADM-06 / K-10: the emergency revocation can keep one session (the
/// calling admin's); everything else — other users, the admin's other
/// sessions, impersonations started from the kept session, pending logins —
/// ends in the caller's transaction.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_06_revoke_everything_except_keeps_exactly_one_session(pool: PgPool) {
    let h = Harness::new(pool).await;
    let admin = h.user("admin@example.com").await;
    let alice = h.user("alice@example.com").await;
    let kept = h.web_login(admin).await;
    let other_admin_session = h.native_login(admin).await;
    let alice_web = h.web_login(alice).await;
    let alice_native = h.native_login(alice).await;

    // Rolled back: nothing changes.
    let mut tx = h.service.begin().await.unwrap();
    let n = h
        .revoker
        .revoke_everything_except(&mut tx, kept.session_id, RevocationReason::Emergency)
        .await
        .unwrap();
    assert_eq!(n, 3);
    tx.rollback().await.unwrap();
    assert!(live(&h, alice_web.session_id).await);

    let mut tx = h.service.begin().await.unwrap();
    h.revoker
        .revoke_everything_except(&mut tx, kept.session_id, RevocationReason::Emergency)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(live(&h, kept.session_id).await);
    for gone in [
        other_admin_session.session_id,
        alice_web.session_id,
        alice_native.session_id,
    ] {
        assert!(!live(&h, gone).await);
        assert_eq!(h.revoked_reason(gone).await.as_deref(), Some("emergency"));
    }
    // The kept cookie still authenticates.
    h.send(TestRequest::get("/v1/me").cookie(SESSION_COOKIE, &kept.cookie))
        .await
        .assert_status(StatusCode::OK);
    h.send(TestRequest::get("/v1/me").cookie(SESSION_COOKIE, &alice_web.cookie))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

/// K-03 support (SOC-06): `is_session_active_in` answers on the caller's
/// connection — live own session yes; another user's, revoked, expired,
/// impersonation and suspended-owner sessions no.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn soc_06_k03_session_liveness_on_the_callers_connection(pool: PgPool) {
    let h = Harness::new(pool).await;
    let alice = h.user("alice@example.com").await;
    let bob = h.user("bob@example.com").await;
    let web = h.web_login(alice).await;
    let other = h.web_login(alice).await;
    let mut tx = h.service.begin().await.unwrap();
    let now = h.now();
    assert!(
        authn_session::is_session_active_in(&mut tx, web.session_id, alice, now)
            .await
            .unwrap()
    );
    assert!(
        !authn_session::is_session_active_in(&mut tx, web.session_id, bob, now)
            .await
            .unwrap()
    );
    assert!(
        !authn_session::is_session_active_in(&mut tx, SessionId::generate(), alice, now)
            .await
            .unwrap()
    );
    h.revoker
        .revoke_session(&mut tx, other.session_id, RevocationReason::Logout)
        .await
        .unwrap();
    assert!(
        !authn_session::is_session_active_in(&mut tx, other.session_id, alice, now)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(alice)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        !authn_session::is_session_active_in(&mut tx, web.session_id, alice, now)
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();
    // Expired.
    h.advance(std::time::Duration::from_secs(40 * 24 * 3600));
    let mut conn = h.pool.acquire().await.unwrap();
    assert!(
        !authn_session::is_session_active_in(&mut conn, web.session_id, alice, h.now())
            .await
            .unwrap()
    );
    // Impersonation sessions never count.
    let admin = h.user("admin@example.com").await;
    h.make_admin(admin).await;
    h.establish(h.request(admin, h.web_channel())).await;
    let issued = authn_core::ports::SessionIssuer::start_impersonation(
        &h.service,
        &h.ctx(),
        authn_core::ports::ImpersonationRequest {
            admin_user_id: admin,
            target_user_id: bob,
            read_only: true,
            ttl: std::time::Duration::from_secs(600),
            reason: "Support".into(),
        },
    )
    .await
    .unwrap();
    assert!(
        !authn_session::is_session_active_in(&mut conn, issued.session_id, bob, h.now())
            .await
            .unwrap()
    );
}
