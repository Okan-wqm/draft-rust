//! Every fake behaves as documented and is usable as a trait object.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use std::sync::Arc;
use std::time::Duration;

use authn_core::domain::{
    AuthMethodRef, ClientKind, EmailAddress, FactorKind, Locale, LoginMethod, PhoneNumber,
};
use authn_core::http::RequestContext;
use authn_core::id::{OrgId, SessionId, UserId};
use authn_core::ports::*;
use authn_core::secret::{SecretString, SensitiveString};
use authn_testkit::fakes::{
    AllowAllRateLimiter, DenyAllRateLimiter, RevocationCall, StaticDataExporter,
};
use authn_testkit::{FakeClock, TestPorts};
use http::StatusCode;
use sqlx::PgPool;
use time::OffsetDateTime;

fn ctx() -> RequestContext {
    RequestContext::system(Locale::En)
}

#[tokio::test]
async fn prt_01_in_memory_rate_limiter_counts_and_resets_with_fake_clock() {
    let ports = TestPorts::new();
    let limiter: Arc<dyn RateLimiter> = ports.rate_limiter.clone();
    let key = RateLimitKey::account("login", "alice@example.com");
    let policy = RateLimitPolicy::new(3, Duration::from_secs(60));
    for expected_remaining in [2, 1, 0] {
        let d = limiter.check(&key, policy, 1).await.unwrap();
        assert!(d.allowed);
        assert_eq!(d.remaining, expected_remaining);
    }
    let denied = limiter.check(&key, policy, 1).await.unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.retry_after, Some(Duration::from_secs(60)));
    assert!(denied.into_result().is_err());
    assert!(!limiter.peek(&key, policy).await.unwrap().allowed);

    ports.clock.advance(Duration::from_secs(61));
    assert!(limiter.check(&key, policy, 1).await.unwrap().allowed);
    limiter.reset(&key).await.unwrap();
    assert_eq!(ports.rate_limiter.used(&key), 0);

    let allow: Arc<dyn RateLimiter> = Arc::new(AllowAllRateLimiter);
    assert!(allow.check(&key, policy, 100).await.unwrap().allowed);
    let deny: Arc<dyn RateLimiter> = Arc::new(DenyAllRateLimiter::default());
    let err = deny
        .check(&key, policy, 1)
        .await
        .unwrap()
        .into_result()
        .unwrap_err();
    assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn aud_01_recording_fakes_capture_calls() {
    let ports = TestPorts::new();
    let audit: Arc<dyn AuditSink> = ports.audit.clone();
    audit
        .record(
            SecurityEvent::new(SecurityEventKind::LoginFailed, ports.clock.now())
                .failed("wrong_password"),
        )
        .await
        .unwrap();
    assert_eq!(ports.audit.of_kind(SecurityEventKind::LoginFailed).len(), 1);
    assert_eq!(ports.audit.take().len(), 1);
    assert!(ports.audit.recorded().is_empty());

    let notifier: Arc<dyn Notifier> = ports.notifier.clone();
    notifier
        .notify(Notification {
            recipient: Recipient {
                email: EmailAddress::parse("bob@example.com").unwrap(),
                user_id: None,
                display_name: None,
            },
            locale: Locale::Tr,
            kind: NotificationKind::MfaFactorAdded {
                factor: FactorKind::Totp,
                at: ports.clock.now(),
            },
        })
        .await
        .unwrap();
    assert_eq!(ports.notifier.with_template("mfa_factor_added").len(), 1);
    assert!(ports.notifier.last().is_some());

    let sms: Arc<dyn SmsSender> = ports.sms.clone();
    assert!(sms.is_configured());
    let receipt = sms
        .send(&SmsMessage {
            to: PhoneNumber::parse("+905551112233").unwrap(),
            body: SensitiveString::new("123456"),
        })
        .await
        .unwrap();
    assert!(receipt.provider_message_id.is_some());
    ports.sms.set_configured(false);
    assert!(!sms.is_configured());

    let email: Arc<dyn EmailTransport> = ports.email.clone();
    ports.email.set_failing(true);
    let msg = EmailMessage {
        to: EmailAddress::parse("c@example.com").unwrap(),
        to_name: None,
        subject: "s".into(),
        text_body: "t".into(),
        html_body: None,
        outbox_id: None,
    };
    assert!(email.send(&msg).await.is_err());
    ports.email.set_failing(false);
    email.send(&msg).await.unwrap();
    assert_eq!(ports.email.recorded().len(), 1);
}

#[tokio::test]
async fn prt_05_captcha_risk_password_dns_geo_http_fakes() {
    let ports = TestPorts::new();
    let captcha: Arc<dyn CaptchaVerifier> = ports.captcha.clone();
    let cctx = CaptchaContext {
        action: "login",
        ip: "203.0.113.1".parse().unwrap(),
    };
    assert_eq!(
        captcha.verify("pass", &cctx).await.unwrap(),
        CaptchaVerdict::Passed
    );
    assert_eq!(
        captcha.verify("nope", &cctx).await.unwrap(),
        CaptchaVerdict::Failed
    );
    ports.captcha.force(Some(CaptchaVerdict::Unavailable));
    assert_eq!(
        captcha.verify("pass", &cctx).await.unwrap(),
        CaptchaVerdict::Unavailable
    );

    let risk: Arc<dyn RiskEvaluator> = ports.risk.clone();
    let input = RiskInput::from_context(
        &ctx(),
        Some(UserId::generate()),
        LoginMethod::Password,
        ports.clock.now(),
    );
    assert_eq!(risk.evaluate(&input).await.unwrap().level, RiskLevel::Low);
    ports.risk.set(RiskAssessment {
        level: RiskLevel::High,
        reasons: vec![RiskReason::NewDevice],
    });
    assert_eq!(risk.evaluate(&input).await.unwrap().level, RiskLevel::High);
    risk.record_successful_login(&input).await.unwrap();
    assert_eq!(ports.risk.evaluated().len(), 2);
    assert_eq!(ports.risk.successes().len(), 1);

    let breach: Arc<dyn BreachedPasswordChecker> = ports.breached_passwords.clone();
    ports.breached_passwords.add_breached("password123456");
    let pw = SecretString::from("password123456".to_owned());
    assert!(matches!(
        breach.check(&pw).await.unwrap(),
        BreachStatus::Breached { .. }
    ));
    ports.breached_passwords.set_unavailable(true);
    assert_eq!(breach.check(&pw).await.unwrap(), BreachStatus::Unknown);

    let validator: Arc<dyn PasswordValidator> = ports.password_validator.clone();
    let short = validator
        .validate(
            &SecretString::from("short".to_owned()),
            &PasswordContext::default(),
        )
        .await
        .unwrap();
    assert!(!short.is_acceptable());
    let ok = validator
        .validate(
            &SecretString::from("a perfectly long passphrase".to_owned()),
            &PasswordContext::default(),
        )
        .await
        .unwrap();
    assert!(ok.is_acceptable());

    let dns: Arc<dyn DnsTxtResolver> = ports.dns.clone();
    ports
        .dns
        .add_txt("_authn-verification.Example.com.", "token-1");
    assert_eq!(
        dns.lookup_txt("_authn-verification.example.com")
            .await
            .unwrap(),
        vec!["token-1"]
    );
    assert!(
        dns.lookup_txt("missing.example.com")
            .await
            .unwrap()
            .is_empty()
    );
    ports.dns.set_failing(true);
    assert!(
        dns.lookup_txt("_authn-verification.example.com")
            .await
            .is_err()
    );

    let geo: Arc<dyn GeoIpLookup> = ports.geoip.clone();
    assert!(
        geo.lookup("203.0.113.1".parse().unwrap())
            .await
            .unwrap()
            .is_none()
    );

    let http: Arc<dyn HttpClient> = ports.http.clone();
    ports.http.respond(
        http::Method::GET,
        "https://api.example.com/x?y=1",
        StatusCode::OK,
        "hello",
    );
    let url = url::Url::parse("https://api.example.com/x?y=1").unwrap();
    let res = http
        .execute(OutboundRequest::get(url.clone(), OutboundTarget::Trusted))
        .await
        .unwrap();
    assert_eq!(res.body, b"hello");
    let other = url::Url::parse("https://api.example.com/other").unwrap();
    assert!(
        http.execute(OutboundRequest::get(other, OutboundTarget::UserSupplied))
            .await
            .is_err()
    );
    assert_eq!(ports.http.requests().len(), 2);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ses_15_session_revoker_and_issuer_fakes(pool: PgPool) {
    let ports = TestPorts::new();
    let mut conn = pool.acquire().await.unwrap();
    let revoker: Arc<dyn SessionRevoker> = ports.session_revoker.clone();
    let user = UserId::generate();
    let keep = SessionId::generate();
    let n = revoker
        .revoke_all_except(
            &mut conn,
            user,
            keep,
            RevocationReason::PasswordChanged,
            RevokeOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(n, 1);
    revoker
        .revoke_all_for_org(
            &mut conn,
            OrgId::generate(),
            RevocationReason::OrgPolicyChanged,
        )
        .await
        .unwrap();
    assert!(matches!(
        ports.session_revoker.calls()[0],
        RevocationCall::AllExcept(u, k, RevocationReason::PasswordChanged, _) if u == user && k == keep
    ));

    let issuer: Arc<dyn SessionIssuer> = ports.session_issuer.clone();
    let outcome = issuer
        .complete_primary_authentication(
            &ctx(),
            PrimaryAuthentication {
                user_id: user,
                method: LoginMethod::Social,
                amr: vec![AuthMethodRef::Fed],
                client: ClientKind::Native,
                remember_me: false,
                shared_device: false,
                requested_org: None,
                provider_asserted_mfa: false,
            },
        )
        .await
        .unwrap();
    let LoginOutcome::Authenticated(session) = outcome.clone() else {
        panic!("expected session")
    };
    assert!(session.refresh_token.is_some() && session.session_token.is_none());
    assert_eq!(ports.session_issuer.logins().len(), 1);
    let response = issuer.login_response(outcome, None);
    assert_eq!(response.status(), StatusCode::OK);

    let exporter: Arc<dyn DataExporter> = Arc::new(StaticDataExporter {
        section: "profile",
        value: serde_json::json!({"a": 1}),
    });
    assert_eq!(exporter.section(), "profile");
    assert_eq!(exporter.export(&mut conn, user).await.unwrap()["a"], 1);

    // The migrator applied the full schema.
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables WHERE table_name = 'users'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tables, 1);
}

#[test]
fn arc_04_fake_clock_is_a_clock() {
    let clock: Arc<dyn Clock> = Arc::new(FakeClock::at(OffsetDateTime::UNIX_EPOCH));
    assert_eq!(clock.now(), OffsetDateTime::UNIX_EPOCH);
}
