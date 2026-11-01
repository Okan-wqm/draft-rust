#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Risk evaluation and alerts (RSK-01 … RSK-04) with PostgreSQL.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::protect::RiskConfig;
use authn_core::domain::{AccountStatus, EmailAddress, Locale, LoginMethod};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{
    Clock, GeoIpLookup, GeoLocation, NotificationKind, RateLimitKey, RateLimiter, Recipient,
    RiskAssessment, RiskEvaluator, RiskInput, RiskLevel, RiskReason, SecurityEventKind,
};
use authn_core::secret::SensitiveString;
use authn_crypto::kdf::KeyRing;
use authn_protect::KeyHasher;
use authn_protect::rate_limit::MemoryRateLimiter;
use authn_protect::risk::{
    AnonymizingNetworks, DefaultRiskEvaluator, FAILURE_ACTION, NotMeTokenIssuer, RiskAlerts,
};
use authn_store::{NewUser, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::fakes::FakeGeoIp;
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

const LAPTOP: &str = "laptop-device-000000001";
const PHONE: &str = "phone-device-0000000001";
const HOME: &str = "198.51.100.10";
const ISTANBUL_IP: &str = "198.51.100.10";
const LONDON_IP: &str = "203.0.113.20";
const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

struct Fixture {
    ports: TestPorts,
    limiter: Arc<dyn RateLimiter>,
    pool: PgPool,
    hasher: KeyHasher,
}

impl Fixture {
    fn new(pool: &PgPool) -> Self {
        let ports = TestPorts::new();
        let hasher = KeyHasher::new(&KeyRing::derive(&[6_u8; 32]).unwrap()).unwrap();
        let limiter: Arc<dyn RateLimiter> =
            Arc::new(MemoryRateLimiter::new(ports.clock.clone(), hasher.clone()));
        Self {
            ports,
            limiter,
            pool: pool.clone(),
            hasher,
        }
    }

    fn evaluator(&self, geoip: Option<Arc<dyn GeoIpLookup>>) -> DefaultRiskEvaluator {
        DefaultRiskEvaluator::new(
            self.pool.clone(),
            self.hasher.clone(),
            self.limiter.clone(),
            &RiskConfig::default(),
            geoip,
        )
        .unwrap()
    }

    fn alerts(&self, evaluator: DefaultRiskEvaluator) -> RiskAlerts {
        RiskAlerts::new(
            evaluator,
            self.ports.notifier.clone(),
            self.ports.audit.clone(),
            self.limiter.clone(),
            self.ports.clock.clone(),
        )
    }

    async fn user(&self, email: &str) -> UserId {
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id: UserId::generate(),
                email: EmailAddress::parse(email).unwrap(),
                status: AccountStatus::Active,
                created_at: self.ports.clock.now(),
            },
        )
        .await
        .unwrap()
        .id
    }

    fn input(&self, user: UserId, ip: &str, device: Option<&str>) -> RiskInput {
        RiskInput {
            user_id: Some(user),
            ip: ip.parse().unwrap(),
            user_agent: Some(FIREFOX.to_owned()),
            device_id: device.map(str::to_owned),
            at: self.ports.clock.now(),
            method: LoginMethod::Password,
        }
    }
}

fn reasons(a: &RiskAssessment) -> Vec<RiskReason> {
    a.reasons.clone()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_01_known_context_is_low_risk_and_input_comes_from_the_request(pool: PgPool) {
    let f = Fixture::new(&pool);
    let user = f.user("a@example.com").await;
    let evaluator = f.evaluator(None);
    let mut ctx = RequestContext::system(Locale::En);
    ctx.client_ip = HOME.parse().unwrap();
    ctx.device_id = Some(LAPTOP.to_owned());
    ctx.user_agent = Some(FIREFOX.to_owned());
    let input =
        RiskInput::from_context(&ctx, Some(user), LoginMethod::Password, f.ports.clock.now());
    // First login ever: no baseline, no novelty signals.
    assert_eq!(
        evaluator.evaluate(&input).await.unwrap(),
        RiskAssessment::low()
    );
    evaluator.record_successful_login(&input).await.unwrap();
    assert_eq!(
        evaluator.evaluate(&input).await.unwrap(),
        RiskAssessment::low()
    );
    // Same /24, other host: still a known network.
    let same_net = f.input(user, "198.51.100.200", Some(LAPTOP));
    assert_eq!(
        evaluator.evaluate(&same_net).await.unwrap(),
        RiskAssessment::low()
    );
    // Stored device ids are keyed hashes, never the raw id.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT device_hash FROM known_devices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), 32);
    assert!(!String::from_utf8_lossy(&stored).contains("laptop"));
    let name: String = sqlx::query_scalar("SELECT device_name FROM known_devices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(name, "Firefox on Linux");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_02_new_device_new_network_and_failures_raise_the_level(pool: PgPool) {
    let f = Fixture::new(&pool);
    let user = f.user("b@example.com").await;
    let evaluator = f.evaluator(None);
    evaluator
        .record_successful_login(&f.input(user, HOME, Some(LAPTOP)))
        .await
        .unwrap();

    let new_device = evaluator
        .evaluate(&f.input(user, HOME, Some(PHONE)))
        .await
        .unwrap();
    assert_eq!(reasons(&new_device), vec![RiskReason::NewDevice]);
    assert_eq!(new_device.level, RiskLevel::Medium);

    let no_device_id = evaluator
        .evaluate(&f.input(user, HOME, None))
        .await
        .unwrap();
    assert_eq!(reasons(&no_device_id), vec![RiskReason::NewDevice]);

    let elsewhere = evaluator
        .evaluate(&f.input(user, "192.0.2.77", Some(PHONE)))
        .await
        .unwrap();
    assert_eq!(
        reasons(&elsewhere),
        vec![RiskReason::NewDevice, RiskReason::NewNetwork]
    );
    assert_eq!(elsewhere.level, RiskLevel::Medium);

    // IPv6 networks are compared at /48.
    evaluator
        .record_successful_login(&f.input(user, "2001:db8:1:2::1", Some(LAPTOP)))
        .await
        .unwrap();
    let v6 = evaluator
        .evaluate(&f.input(user, "2001:db8:1:ffff::9", Some(LAPTOP)))
        .await
        .unwrap();
    assert_eq!(v6, RiskAssessment::low());

    // Failure velocity (5 per hour by default).
    for _ in 0..5 {
        f.limiter
            .check(
                &RateLimitKey::user(FAILURE_ACTION, user),
                evaluator.failure_policy(),
                1,
            )
            .await
            .unwrap();
    }
    let attacked = evaluator
        .evaluate(&f.input(user, "192.0.2.77", Some(PHONE)))
        .await
        .unwrap();
    assert_eq!(
        reasons(&attacked),
        vec![
            RiskReason::NewDevice,
            RiskReason::NewNetwork,
            RiskReason::RecentFailures
        ]
    );
    assert_eq!(attacked.level, RiskLevel::High);

    // Passkeys prove possession: novelty and failures are not counted.
    let mut passkey = f.input(user, "192.0.2.77", Some(PHONE));
    passkey.method = LoginMethod::Passkey;
    assert_eq!(
        evaluator.evaluate(&passkey).await.unwrap(),
        RiskAssessment::low()
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_02_ip_failures_and_anonymizing_networks(pool: PgPool) {
    let f = Fixture::new(&pool);
    let user = f.user("c@example.com").await;
    let evaluator = f
        .evaluator(None)
        .with_anonymizing_networks(AnonymizingNetworks::parse("185.220.101.0/24\n").unwrap());
    evaluator
        .record_successful_login(&f.input(user, HOME, Some(LAPTOP)))
        .await
        .unwrap();
    let tor = evaluator
        .evaluate(&f.input(user, "185.220.101.33", Some(LAPTOP)))
        .await
        .unwrap();
    assert_eq!(
        reasons(&tor),
        vec![RiskReason::NewNetwork, RiskReason::AnonymizingNetwork]
    );
    assert_eq!(tor.level, RiskLevel::High);

    // Many failures from one IP (credential stuffing across accounts).
    for _ in 0..5 {
        f.limiter
            .check(
                &RateLimitKey::ip(FAILURE_ACTION, "198.51.100.99".parse().unwrap()),
                evaluator.failure_policy(),
                1,
            )
            .await
            .unwrap();
    }
    let stuffing = evaluator
        .evaluate(&f.input(user, "198.51.100.99", Some(LAPTOP)))
        .await
        .unwrap();
    assert_eq!(reasons(&stuffing), vec![RiskReason::RecentFailures]);

    // Disabled evaluation is always low.
    let disabled = DefaultRiskEvaluator::new(
        pool.clone(),
        f.hasher.clone(),
        f.limiter.clone(),
        &RiskConfig {
            enabled: false,
            ..RiskConfig::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(
        disabled
            .evaluate(&f.input(user, "185.220.101.33", None))
            .await
            .unwrap(),
        RiskAssessment::low()
    );
}

fn geoip() -> Arc<FakeGeoIp> {
    let geo = Arc::new(FakeGeoIp::default());
    geo.insert(
        ISTANBUL_IP.parse().unwrap(),
        GeoLocation {
            country_code: Some("TR".to_owned()),
            city: Some("İstanbul".to_owned()),
            latitude: Some(41.0082),
            longitude: Some(28.9784),
            accuracy_km: Some(20),
        },
    );
    geo.insert(
        LONDON_IP.parse().unwrap(),
        GeoLocation {
            country_code: Some("gb".to_owned()),
            city: Some("London\u{0}\n".to_owned()),
            latitude: Some(51.5074),
            longitude: Some(-0.1278),
            accuracy_km: Some(20),
        },
    );
    geo
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_02_impossible_travel_requires_a_geoip_provider(pool: PgPool) {
    let f = Fixture::new(&pool);
    let user = f.user("d@example.com").await;
    let geo = geoip();
    let with_geo = f.evaluator(Some(geo.clone()));
    let without_geo = f.evaluator(None);
    with_geo
        .record_successful_login(&f.input(user, ISTANBUL_IP, Some(LAPTOP)))
        .await
        .unwrap();
    f.ports.clock.advance(Duration::from_secs(3600));
    let london = f.input(user, LONDON_IP, Some(LAPTOP));
    let assessed = with_geo.evaluate(&london).await.unwrap();
    assert!(reasons(&assessed).contains(&RiskReason::ImpossibleTravel));
    assert_eq!(assessed.level, RiskLevel::High);
    assert!(
        !reasons(&without_geo.evaluate(&london).await.unwrap())
            .contains(&RiskReason::ImpossibleTravel)
    );
    // Plausible after enough time.
    f.ports.clock.advance(Duration::from_secs(6 * 3600));
    let later = f.input(user, LONDON_IP, Some(LAPTOP));
    assert!(
        !reasons(&with_geo.evaluate(&later).await.unwrap()).contains(&RiskReason::ImpossibleTravel)
    );
}

#[derive(Default)]
struct FakeNotMe {
    issued: AtomicUsize,
    fail: bool,
}

#[async_trait]
impl NotMeTokenIssuer for FakeNotMe {
    async fn issue_not_me_token(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
        _now: OffsetDateTime,
    ) -> Result<SensitiveString, AuthError> {
        if self.fail {
            return Err(AuthError::internal("token store down"));
        }
        let n = self.issued.fetch_add(1, Ordering::SeqCst);
        Ok(SensitiveString::new(format!("not-me-token-{n}")))
    }
}

fn recipient(user: UserId) -> Recipient {
    Recipient {
        email: EmailAddress::parse("owner@example.com").unwrap(),
        user_id: Some(user),
        display_name: None,
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_04_new_device_login_sends_notification_with_not_me_token(pool: PgPool) {
    let f = Fixture::new(&pool);
    let user = f.user("e@example.com").await;
    let alerts = f.alerts(f.evaluator(Some(geoip())));
    let not_me = FakeNotMe::default();
    let ctx = RequestContext::system(Locale::Tr);

    // First login after sign-up: recorded, no alert.
    let first = alerts
        .on_successful_login(
            &f.input(user, ISTANBUL_IP, Some(LAPTOP)),
            recipient(user),
            Locale::Tr,
            &not_me,
            &ctx,
        )
        .await
        .unwrap();
    assert!(first.novelty.first_login && !first.notified);
    // Same device again: no alert.
    let again = alerts
        .on_successful_login(
            &f.input(user, ISTANBUL_IP, Some(LAPTOP)),
            recipient(user),
            Locale::Tr,
            &not_me,
            &ctx,
        )
        .await
        .unwrap();
    assert!(!again.notified && !again.novelty.new_device);
    assert!(f.ports.notifier.recorded().is_empty());

    // New device: alert with masked IP, location, device and token.
    f.ports.clock.advance(Duration::from_secs(86_400));
    let new = alerts
        .on_successful_login(
            &f.input(user, LONDON_IP, Some(PHONE)),
            recipient(user),
            Locale::Tr,
            &not_me,
            &ctx,
        )
        .await
        .unwrap();
    assert!(new.notified && new.novelty.new_device && new.novelty.new_network);
    let sent = f.ports.notifier.with_template("new_device_login");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].locale, Locale::Tr);
    let NotificationKind::NewDeviceLogin {
        device,
        approximate_location,
        ip_masked,
        at,
        not_me_token,
    } = &sent[0].kind
    else {
        panic!("wrong kind")
    };
    assert_eq!(device, "Firefox on Linux");
    assert_eq!(approximate_location.as_deref(), Some("London, GB"));
    assert_eq!(ip_masked, "203.0.113.x");
    assert_eq!(*at, f.ports.clock.now());
    assert_eq!(not_me_token.expose(), "not-me-token-0");
    let audited = f.ports.audit.of_kind(SecurityEventKind::NewDeviceLogin);
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].subject_user, Some(user));
    assert!(!format!("{audited:?}").contains("not-me-token"));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_04_alert_and_device_record_commit_together(pool: PgPool) {
    let f = Fixture::new(&pool);
    let user = f.user("f@example.com").await;
    let alerts = f.alerts(f.evaluator(None));
    let ctx = RequestContext::system(Locale::En);
    alerts
        .on_successful_login(
            &f.input(user, HOME, Some(LAPTOP)),
            recipient(user),
            Locale::En,
            &FakeNotMe::default(),
            &ctx,
        )
        .await
        .unwrap();
    let failing = FakeNotMe {
        fail: true,
        ..FakeNotMe::default()
    };
    assert!(
        alerts
            .on_successful_login(
                &f.input(user, HOME, Some(PHONE)),
                recipient(user),
                Locale::En,
                &failing,
                &ctx
            )
            .await
            .is_err()
    );
    // Rolled back: the phone is still unknown, so the next login alerts.
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM known_devices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(devices, 1);
    let retry = alerts
        .on_successful_login(
            &f.input(user, HOME, Some(PHONE)),
            recipient(user),
            Locale::En,
            &FakeNotMe::default(),
            &ctx,
        )
        .await
        .unwrap();
    assert!(retry.notified);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn rsk_03_blocked_login_is_audited_and_notified_without_mail_bombing(pool: PgPool) {
    let f = Fixture::new(&pool);
    let user = f.user("g@example.com").await;
    let alerts = f.alerts(f.evaluator(None));
    let ctx = RequestContext::system(Locale::En);
    let assessment = RiskAssessment {
        level: RiskLevel::High,
        reasons: vec![RiskReason::ImpossibleTravel],
    };
    for _ in 0..3 {
        let err = alerts
            .on_blocked_login(
                &f.input(user, LONDON_IP, Some(PHONE)),
                &assessment,
                recipient(user),
                Locale::En,
                &ctx,
            )
            .await;
        assert_eq!(err.code(), codes::protect::SUSPICIOUS_LOGIN_BLOCKED);
    }
    assert_eq!(
        f.ports
            .notifier
            .with_template("suspicious_login_blocked")
            .len(),
        1
    );
    let events = f.ports.audit.of_kind(SecurityEventKind::RiskHighBlocked);
    assert_eq!(events.len(), 3);
    assert_eq!(
        events[0].metadata["reasons"],
        serde_json::json!(["impossible_travel"])
    );
}
