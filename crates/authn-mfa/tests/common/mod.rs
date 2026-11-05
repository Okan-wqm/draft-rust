//! Shared harness of the authn-mfa integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_core::domain::{
    AccountStatus, AuthMethodRef, EmailAddress, Impersonation, Locale, PhoneNumber, Principal,
    PrincipalCredential, Subject,
};
use authn_core::error::AuthError;
use authn_core::http::RequestContext;
use authn_core::id::{ChallengeId, FactorId, RequestId, SessionId, UserId};
use authn_core::ports::{Clock, NotificationKind, SmsNotification, SmsNotificationKind};
use authn_core::secret::SecretString;
use authn_crypto::CryptoServices;
use authn_crypto::totp::{Totp, TotpParams, TotpSecret};
use authn_mfa::{
    FactorProof, MfaPolicySource, MfaService, MfaServiceDeps, MfaServiceSettings, OrgMfaPolicy,
    VerifiedFactor, router,
};
use authn_store::{NewUser, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::fakes::RecordingNotifier;
use authn_testkit::http::with_request_context;
use axum::{Extension, Router};
use sqlx::{PgConnection, PgPool};

/// Mutable organization policy / passkey count.
#[derive(Debug, Default)]
pub struct TestPolicySource {
    pub org: Mutex<Option<OrgMfaPolicy>>,
    pub webauthn: AtomicU32,
}

impl TestPolicySource {
    pub fn require_mfa(&self) {
        *self.org.lock().unwrap() = Some(OrgMfaPolicy {
            mfa_required: true,
            ..OrgMfaPolicy::default()
        });
    }
}

#[async_trait]
impl MfaPolicySource for TestPolicySource {
    async fn org_policy_for_user(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<Option<OrgMfaPolicy>, AuthError> {
        Ok(self.org.lock().unwrap().clone())
    }

    async fn webauthn_factor_count(
        &self,
        _conn: &mut PgConnection,
        _user: UserId,
    ) -> Result<u32, AuthError> {
        Ok(self.webauthn.load(Ordering::SeqCst))
    }
}

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub crypto: CryptoServices,
    pub service: MfaService,
    pub settings: MfaServiceSettings,
    pub notifier: Arc<RecordingNotifier>,
    pub policy: Arc<TestPolicySource>,
}

/// A step-up-fresh TOTP factor and its secret.
pub struct TotpFactor {
    pub id: FactorId,
    pub secret: TotpSecret,
    pub recovery_codes: Vec<String>,
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut MfaServiceSettings)) -> Self {
        authn_testkit::init_tracing();
        let config = authn_testkit::config::test_config();
        let crypto = CryptoServices::from_config(&config.crypto).await.unwrap();
        let ports = TestPorts::new();
        let mut settings = MfaServiceSettings::from_app_config(&config);
        settings.mfa.sms.allowed_country_codes = vec!["90".to_owned(), "1".to_owned()];
        tweak(&mut settings);
        Self::build(pool, ports, crypto, settings)
    }

    fn build(
        pool: PgPool,
        ports: TestPorts,
        crypto: CryptoServices,
        settings: MfaServiceSettings,
    ) -> Self {
        let notifier = Arc::new(RecordingNotifier::default());
        let policy = Arc::new(TestPolicySource::default());
        let deps = MfaServiceDeps {
            pool: pool.clone(),
            clock: ports.clock.clone(),
            keys: crypto.keys.clone(),
            otp: crypto.otp.clone(),
            envelopes: crypto.envelopes.clone(),
            rate_limiter: ports.rate_limiter.clone(),
            notifier: notifier.clone(),
            audit: ports.audit.clone(),
            sms: Some(ports.sms.clone()),
            policy_source: policy.clone(),
        };
        let service = MfaService::new(deps, settings.clone()).unwrap();
        Self {
            pool,
            ports,
            crypto,
            service,
            settings,
            notifier,
            policy,
        }
    }

    /// The same harness with another rate limiter.
    pub fn with_rate_limiter(
        &self,
        limiter: Arc<dyn authn_core::ports::RateLimiter>,
    ) -> MfaService {
        let deps = MfaServiceDeps {
            pool: self.pool.clone(),
            clock: self.ports.clock.clone(),
            keys: self.crypto.keys.clone(),
            otp: self.crypto.otp.clone(),
            envelopes: self.crypto.envelopes.clone(),
            rate_limiter: limiter,
            notifier: self.notifier.clone(),
            audit: self.ports.audit.clone(),
            sms: Some(self.ports.sms.clone()),
            policy_source: self.policy.clone(),
        };
        MfaService::new(deps, self.settings.clone()).unwrap()
    }

    pub fn now(&self) -> time::OffsetDateTime {
        self.ports.clock.now()
    }

    pub fn advance(&self, by: Duration) {
        self.ports.clock.advance(by);
    }

    pub async fn user(&self, email: &str) -> UserId {
        let id = UserId::generate();
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status: AccountStatus::Active,
                created_at: self.now(),
            },
        )
        .await
        .unwrap();
        id
    }

    pub async fn make_admin(&self, user: UserId) {
        sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
            .bind(user)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    /// A login challenge row (owned by authn-session; fixture only).
    pub async fn challenge(&self, user: UserId) -> ChallengeId {
        let id = ChallengeId::generate();
        let token_hash = authn_crypto::sha256(id.to_string().as_bytes());
        sqlx::query(
            "INSERT INTO auth_challenges (id, kind, user_id, token_hash, client_kind, created_at, \
             expires_at) VALUES ($1, 'login', $2, $3, 'web', $4, $5)",
        )
        .bind(id)
        .bind(user)
        .bind(token_hash.as_slice())
        .bind(self.now())
        .bind(self.now() + Duration::from_secs(3600))
        .execute(&self.pool)
        .await
        .unwrap();
        id
    }

    /// A session principal that authenticated `auth_age` ago.
    pub fn principal(&self, user: UserId, auth_age: Duration) -> Principal {
        Principal {
            subject: Subject::User { user_id: user },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: vec![AuthMethodRef::Pwd],
            acr: None,
            auth_time: Some(self.now() - auth_age),
            scopes: vec![],
            impersonation: None,
            is_platform_admin: false,
            login_method: None,
            mfa_factors: Vec::new(),
        }
    }

    /// A step-up-fresh principal.
    pub fn fresh(&self, user: UserId) -> Principal {
        self.principal(user, Duration::from_secs(5))
    }

    pub fn impersonated(&self, user: UserId, read_only: bool) -> Principal {
        let mut p = self.fresh(user);
        p.impersonation = Some(Impersonation {
            admin_user_id: UserId::generate(),
            read_only,
            expires_at: self.now() + Duration::from_secs(900),
        });
        p
    }

    pub fn ctx(&self) -> RequestContext {
        self.ctx_from("203.0.113.10".parse().unwrap())
    }

    pub fn ctx_from(&self, ip: IpAddr) -> RequestContext {
        RequestContext {
            request_id: RequestId::generate(),
            client_ip: ip,
            peer_ip: ip,
            user_agent: Some("Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0".to_owned()),
            device_id: None,
            locale: Locale::En,
        }
    }

    pub fn app(&self) -> Router {
        with_request_context(router().with_state(self.service.clone()))
    }

    pub fn app_as(&self, principal: Principal) -> Router {
        with_request_context(
            router()
                .with_state(self.service.clone())
                .layer(Extension(principal)),
        )
    }

    /// Enrolls and confirms a TOTP factor; returns its id and secret.
    pub async fn enroll_totp(&self, user: UserId) -> TotpFactor {
        let enrollment = self
            .service
            .begin_totp_enrollment(&self.ctx(), &self.fresh(user), Some("Phone".into()))
            .await
            .unwrap();
        let secret = TotpSecret::from_base32(&enrollment.provisioning.secret_base32).unwrap();
        let code = self.totp_code(&secret, 0);
        let confirmed = self
            .service
            .confirm_enrollment(
                &self.ctx(),
                &self.fresh(user),
                enrollment.factor.id,
                &secret_str(&code),
            )
            .await
            .unwrap();
        // Leave the confirmation step behind so the next code is fresh.
        self.advance(Duration::from_secs(30));
        TotpFactor {
            id: enrollment.factor.id,
            secret,
            recovery_codes: confirmed
                .recovery_codes
                .map(|c| c.codes.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default(),
        }
    }

    /// The TOTP code for the current time shifted by `step_offset` steps.
    pub fn totp_code(&self, secret: &TotpSecret, step_offset: i64) -> String {
        let totp = Totp::new(TotpParams::default()).unwrap();
        let step = totp.time_step(self.now()).unwrap();
        let step = u64::try_from(i64::try_from(step).unwrap() + step_offset).unwrap();
        totp.code_for_step(secret, step).unwrap().to_string()
    }

    /// Enrolls and confirms the e-mail factor.
    pub async fn enroll_email(&self, user: UserId) -> FactorId {
        let delivery = self
            .service
            .begin_email_enrollment(&self.ctx(), &self.fresh(user))
            .await
            .unwrap();
        let code = self.last_email_code();
        self.service
            .confirm_enrollment(
                &self.ctx(),
                &self.fresh(user),
                delivery.factor_id,
                &secret_str(&code),
            )
            .await
            .unwrap();
        // Leave the resend cooldown behind.
        self.advance(Duration::from_secs(61));
        delivery.factor_id
    }

    /// Enrolls and confirms an SMS factor for `phone`.
    pub async fn enroll_sms(&self, user: UserId, phone: &str) -> FactorId {
        let delivery = self
            .service
            .begin_sms_enrollment(&self.ctx(), &self.fresh(user), phone, None)
            .await
            .unwrap();
        let code = self.last_sms_code();
        self.service
            .confirm_enrollment(
                &self.ctx(),
                &self.fresh(user),
                delivery.factor_id,
                &secret_str(&code),
            )
            .await
            .unwrap();
        self.advance(Duration::from_secs(61));
        delivery.factor_id
    }

    pub fn last_email_code(&self) -> String {
        let sent = self.notifier.with_template("mfa_email_code");
        match &sent.last().expect("mfa e-mail code sent").kind {
            NotificationKind::MfaEmailCode { code, .. } => code.expose().to_owned(),
            other => panic!("unexpected {other:?}"),
        }
    }

    pub fn last_sms(&self) -> SmsNotification {
        self.notifier.last_sms().expect("sms sent")
    }

    pub fn last_sms_code(&self) -> String {
        match &self.last_sms().kind {
            SmsNotificationKind::MfaSmsCode { code, .. }
            | SmsNotificationKind::PhoneVerification { code, .. } => code.expose().to_owned(),
        }
    }

    pub async fn verify(
        &self,
        user: UserId,
        challenge: Option<ChallengeId>,
        proof: FactorProof,
    ) -> Result<VerifiedFactor, AuthError> {
        self.service
            .verify_factor(&self.ctx(), user, challenge, proof)
            .await
    }

    pub async fn verify_totp(&self, user: UserId, code: &str) -> Result<VerifiedFactor, AuthError> {
        self.verify(
            user,
            None,
            FactorProof::Totp {
                code: secret_str(code),
                factor_id: None,
            },
        )
        .await
    }

    pub async fn count(&self, sql: &'static str, user: UserId) -> i64 {
        let (n,): (i64,) = sqlx::query_as(sql)
            .bind(user)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        n
    }
}

pub fn secret_str(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

pub fn phone(value: &str) -> PhoneNumber {
    PhoneNumber::parse(value).unwrap()
}

/// A wrong code that differs from `code` in every digit.
pub fn wrong(code: &str) -> String {
    code.chars()
        .map(|c| char::from(b'0' + ((u8::try_from(c).unwrap() - b'0' + 5) % 10)))
        .collect()
}
