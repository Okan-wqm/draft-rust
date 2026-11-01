#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! NTF-01 / NTF-03 / NTF-04: the outbox notifier and the deliverer against
//! a real PostgreSQL database.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::AppConfig;
use authn_core::domain::{EmailAddress, Locale, PhoneNumber};
use authn_core::error::AuthError;
use authn_core::id::{OutboxMessageId, UserId};
use authn_core::ports::{
    Clock, EmailTransport, Notification, NotificationKind, Notifier, RateLimitDecision,
    RateLimitKey, RateLimitPolicy, RateLimiter, Recipient, SmsNotification, SmsNotificationKind,
    SmsSender,
};
use authn_core::secret::SensitiveString;
use authn_crypto::envelope::{EnvKeyProvider, EnvelopeCipher, KekId};
use authn_crypto::secret::SecretKey;
use authn_notify::email::InjectedFailure;
use authn_notify::{
    DeliveryFailure, DeliveryRequest, DisabledSmsSender, EMAIL_TOPIC, MemoryEmailTransport,
    MemorySmsSender, NotificationDeliverer, OutboxNotifier, SMS_TOPIC, TemplateRenderer,
};
use authn_testkit::TestPorts;
use authn_testkit::config::test_config;
use serde_json::{Value, json};
use sqlx::PgPool;

const TOKEN: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";
const CODE: &str = "468024";

struct Fixture {
    pool: PgPool,
    ports: TestPorts,
    config: AppConfig,
    notifier: OutboxNotifier,
    deliverer: NotificationDeliverer,
    email: Arc<MemoryEmailTransport>,
    sms: Arc<MemorySmsSender>,
}

fn cipher(config: &AppConfig) -> EnvelopeCipher {
    EnvelopeCipher::from_config(&config.crypto).unwrap()
}

fn clock(ports: &TestPorts) -> Arc<dyn Clock> {
    ports.clock.clone()
}

impl Fixture {
    fn new(pool: PgPool) -> Self {
        let ports = TestPorts::new();
        let config = test_config();
        let email = Arc::new(MemoryEmailTransport::new());
        let sms = Arc::new(MemorySmsSender::new());
        let notifier = OutboxNotifier::new(pool.clone(), cipher(&config), clock(&ports))
            .with_max_attempts(config.notify.max_attempts);
        let deliverer = Self::deliverer_with(&config, &ports, email.clone(), sms.clone());
        Self {
            pool,
            ports,
            config,
            notifier,
            deliverer,
            email,
            sms,
        }
    }

    fn deliverer_with(
        config: &AppConfig,
        ports: &TestPorts,
        email: Arc<dyn EmailTransport>,
        sms: Arc<dyn SmsSender>,
    ) -> NotificationDeliverer {
        NotificationDeliverer::new(
            cipher(config),
            Arc::new(TemplateRenderer::from_config(config).unwrap()),
            email,
            sms,
            clock(ports),
        )
    }

    fn now(&self) -> time::OffsetDateTime {
        self.ports.clock.now()
    }

    fn password_reset(&self, locale: Locale) -> Notification {
        Notification {
            recipient: Recipient {
                email: EmailAddress::parse("alice@example.com").unwrap(),
                user_id: Some(UserId::generate()),
                display_name: Some("Alice Örnek".to_owned()),
            },
            locale,
            kind: NotificationKind::PasswordReset {
                token: SensitiveString::new(TOKEN),
                code: Some(SensitiveString::new(CODE)),
                expires_at: self.now() + Duration::from_secs(30 * 60),
            },
        }
    }

    fn magic_link(&self) -> Notification {
        Notification {
            recipient: Recipient {
                email: EmailAddress::parse("bob@example.com").unwrap(),
                user_id: None,
                display_name: None,
            },
            locale: Locale::En,
            kind: NotificationKind::MagicLink {
                token: SensitiveString::new(TOKEN),
                expires_at: self.now() + Duration::from_secs(15 * 60),
            },
        }
    }

    fn sms(&self) -> SmsNotification {
        SmsNotification {
            to: PhoneNumber::parse("+905551112233").unwrap(),
            user_id: None,
            locale: Locale::Tr,
            kind: SmsNotificationKind::MfaSmsCode {
                code: SensitiveString::new(CODE),
                expires_at: self.now() + Duration::from_secs(600),
            },
        }
    }

    async fn rows(&self) -> Vec<Row> {
        sqlx::query_as(
            "SELECT id, topic, payload, sealed_payload, status, max_attempts \
             FROM outbox ORDER BY created_at, id",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn deliver(&self, row: &Row) -> Result<(), DeliveryFailure> {
        self.deliverer.deliver(row.request()).await
    }
}

#[derive(sqlx::FromRow)]
struct Row {
    id: OutboxMessageId,
    topic: String,
    payload: sqlx::types::Json<Value>,
    sealed_payload: Option<Vec<u8>>,
    status: String,
    max_attempts: i32,
}

impl Row {
    fn request(&self) -> DeliveryRequest<'_> {
        DeliveryRequest {
            id: self.id,
            topic: &self.topic,
            payload: &self.payload.0,
            sealed_payload: self.sealed_payload.as_deref(),
            attempt: 1,
            max_attempts: 10,
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_01_notify_enqueues_one_sealed_outbox_row(pool: PgPool) {
    let f = Fixture::new(pool);
    let notification = f.password_reset(Locale::Tr);
    let user_id = notification.recipient.user_id.unwrap();
    f.notifier.notify(notification).await.unwrap();

    let rows = f.rows().await;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.topic, EMAIL_TOPIC);
    assert_eq!(row.status, "pending");
    assert_eq!(
        row.max_attempts,
        i32::try_from(f.config.notify.max_attempts).unwrap()
    );
    assert_eq!(
        row.payload.0,
        json!({
            "v": 1,
            "channel": "email",
            "template": "password_reset",
            "locale": "tr",
            "user_id": user_id.to_string(),
            "recipient": "a***@example.com",
        })
    );
    // Nothing secret or personal in clear text at rest.
    let payload_text = row.payload.0.to_string();
    let sealed = row.sealed_payload.as_deref().unwrap();
    for secret in [TOKEN, CODE, "alice@example.com", "Alice Örnek"] {
        assert!(!payload_text.contains(secret), "{secret} in payload");
        assert!(
            !contains(sealed, secret.as_bytes()),
            "{secret} in sealed payload"
        );
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_01_notify_in_tx_commits_and_rolls_back_with_the_caller(pool: PgPool) {
    let f = Fixture::new(pool);
    let mut tx = f.pool.begin().await.unwrap();
    f.notifier
        .notify_in_tx(&mut tx, f.password_reset(Locale::En))
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert!(f.rows().await.is_empty(), "rolled back with the caller");

    let mut tx = f.pool.begin().await.unwrap();
    f.notifier
        .notify_in_tx(&mut tx, f.password_reset(Locale::En))
        .await
        .unwrap();
    f.notifier.notify_sms_in_tx(&mut tx, f.sms()).await.unwrap();
    tx.commit().await.unwrap();
    let topics: Vec<String> = f.rows().await.into_iter().map(|r| r.topic).collect();
    assert_eq!(topics, [EMAIL_TOPIC, SMS_TOPIC]);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_03_delivery_unseals_renders_and_sends(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier
        .notify(f.password_reset(Locale::Tr))
        .await
        .unwrap();
    let rows = f.rows().await;
    f.deliver(&rows[0]).await.unwrap();

    let sent = f.email.messages();
    assert_eq!(sent.len(), 1);
    let message = &sent[0];
    assert_eq!(message.to.as_str(), "alice@example.com");
    assert_eq!(message.to_name.as_deref(), Some("Alice Örnek"));
    assert_eq!(message.subject, "Şifrenizi sıfırlayın");
    assert_eq!(message.outbox_id, Some(rows[0].id), "Message-ID seed");
    let link = format!("https://auth.test.example/reset-password#token={TOKEN}");
    assert!(message.text_body.contains(&link), "{}", message.text_body);
    assert!(message.text_body.contains(CODE));
    assert!(message.text_body.contains("30 dakika boyunca"));
    assert!(message.html_body.as_deref().unwrap().contains(TOKEN));
    // EmailMessage's Debug never shows the bodies.
    let debug = format!("{message:?}");
    assert!(!debug.contains(TOKEN) && !debug.contains(CODE));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_03_redelivery_keeps_the_same_message_id(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier.notify(f.magic_link()).await.unwrap();
    let rows = f.rows().await;
    f.deliver(&rows[0]).await.unwrap();
    f.deliver(&rows[0]).await.unwrap();
    let ids: Vec<_> = f.email.messages().iter().map(|m| m.outbox_id).collect();
    assert_eq!(ids, [Some(rows[0].id), Some(rows[0].id)]);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_01_sealed_payload_is_bound_to_its_outbox_row(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier
        .notify(f.password_reset(Locale::En))
        .await
        .unwrap();
    f.notifier
        .notify(f.password_reset(Locale::En))
        .await
        .unwrap();
    let rows = f.rows().await;
    // Copy-paste: row A's sealed payload presented as row B's.
    let mut swapped = rows[1].request();
    swapped.sealed_payload = rows[0].sealed_payload.as_deref();
    assert_eq!(
        f.deliverer.deliver(swapped).await.unwrap_err(),
        DeliveryFailure::Permanent {
            reason: "sealed payload cannot be opened"
        }
    );
    // Tampering with any byte fails as well.
    let mut tampered = rows[0].sealed_payload.clone().unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut request = rows[0].request();
    request.sealed_payload = Some(&tampered);
    assert!(
        !f.deliverer
            .deliver(request)
            .await
            .unwrap_err()
            .is_retryable()
    );
    // A missing sealed payload is permanent too.
    let mut request = rows[0].request();
    request.sealed_payload = None;
    assert!(
        !f.deliverer
            .deliver(request)
            .await
            .unwrap_err()
            .is_retryable()
    );
    assert!(f.email.messages().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_03_payload_must_match_topic_and_template(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier
        .notify(f.password_reset(Locale::En))
        .await
        .unwrap();
    f.notifier.notify_sms(f.sms()).await.unwrap();
    let rows = f.rows().await;
    let email_row = &rows[0];
    let sms_row = &rows[1];

    let cases: Vec<(DeliveryRequest<'_>, &str)> = vec![
        (
            DeliveryRequest {
                topic: "notification.push",
                ..email_row.request()
            },
            "unknown notification topic",
        ),
        (
            DeliveryRequest {
                topic: SMS_TOPIC,
                ..email_row.request()
            },
            "payload does not match topic",
        ),
        (
            DeliveryRequest {
                topic: EMAIL_TOPIC,
                payload: &email_row.payload.0,
                ..sms_row.request()
            },
            "payload does not match topic",
        ),
    ];
    for (request, reason) in cases {
        assert_eq!(
            f.deliverer.deliver(request).await.unwrap_err(),
            DeliveryFailure::Permanent { reason }
        );
    }
    let mut renamed = email_row.payload.0.clone();
    renamed["template"] = json!("magic_link");
    let request = DeliveryRequest {
        payload: &renamed,
        ..email_row.request()
    };
    assert_eq!(
        f.deliverer.deliver(request).await.unwrap_err(),
        DeliveryFailure::Permanent {
            reason: "payload does not match template"
        }
    );
    for bad in [json!({"v": 2}), json!("x"), json!({})] {
        let mut payload = email_row.payload.0.clone();
        if bad.is_object() && bad.get("v").is_some() {
            payload["v"] = json!(2);
        } else {
            payload = bad;
        }
        let request = DeliveryRequest {
            payload: &payload,
            ..email_row.request()
        };
        assert!(
            !f.deliverer
                .deliver(request)
                .await
                .unwrap_err()
                .is_retryable()
        );
    }
    assert!(f.email.messages().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_03_unknown_sealing_key_is_retried(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier.notify(f.magic_link()).await.unwrap();
    let rows = f.rows().await;
    let other_keys = EnvelopeCipher::new(Arc::new(
        EnvKeyProvider::new(
            "other-kek",
            [(
                KekId::new("other-kek").unwrap(),
                SecretKey::from_bytes([9; 32]),
            )],
        )
        .unwrap(),
    ));
    let deliverer = NotificationDeliverer::new(
        other_keys,
        Arc::new(TemplateRenderer::from_config(&f.config).unwrap()),
        f.email.clone(),
        f.sms.clone(),
        clock(&f.ports),
    );
    let failure = deliverer.deliver(rows[0].request()).await.unwrap_err();
    assert!(failure.is_retryable(), "{failure:?}");
    assert_eq!(failure.reason(), "sealing key unavailable");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_03_expired_links_and_codes_are_not_delivered(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier.notify(f.magic_link()).await.unwrap();
    f.notifier.notify_sms(f.sms()).await.unwrap();
    // A security notice without expiry is still delivered late.
    let mut alert = f.password_reset(Locale::En);
    alert.kind = NotificationKind::PasswordChanged {
        at: f.now(),
        ip_masked: Some("203.0.113.x".to_owned()),
        device: None,
    };
    f.notifier.notify(alert).await.unwrap();
    f.ports.clock.advance(Duration::from_secs(16 * 60));
    let rows = f.rows().await;
    for row in &rows[..2] {
        assert_eq!(
            f.deliver(row).await.unwrap_err(),
            DeliveryFailure::Permanent {
                reason: "expired before delivery"
            }
        );
    }
    f.deliver(&rows[2]).await.unwrap();
    assert_eq!(f.email.messages().len(), 1);
    assert!(f.sms.messages().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_03_transport_failures_are_classified_for_the_outbox(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier.notify(f.magic_link()).await.unwrap();
    let rows = f.rows().await;
    f.email.fail_next(InjectedFailure::Temporary);
    let failure = f.deliver(&rows[0]).await.unwrap_err();
    assert!(failure.is_retryable());
    assert_eq!(failure.reason(), "temporary delivery failure");
    f.email.fail_next(InjectedFailure::Permanent);
    assert_eq!(
        f.deliver(&rows[0]).await.unwrap_err(),
        DeliveryFailure::Permanent {
            reason: "rejected by the provider"
        }
    );
    f.deliver(&rows[0]).await.unwrap();
    assert_eq!(f.email.messages().len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_03_retry_after_from_the_transport_is_kept(pool: PgPool) {
    struct SlowDown;
    #[async_trait]
    impl EmailTransport for SlowDown {
        async fn send(&self, _: &authn_core::ports::EmailMessage) -> Result<(), AuthError> {
            Err(
                AuthError::new(authn_core::error::codes::common::SERVICE_UNAVAILABLE)
                    .with_retry_after(Duration::from_secs(120)),
            )
        }
    }
    let f = Fixture::new(pool);
    f.notifier.notify(f.magic_link()).await.unwrap();
    let rows = f.rows().await;
    let deliverer = Fixture::deliverer_with(&f.config, &f.ports, Arc::new(SlowDown), f.sms.clone());
    assert_eq!(
        deliverer.deliver(rows[0].request()).await.unwrap_err(),
        DeliveryFailure::Retry {
            reason: "temporary delivery failure",
            retry_after: Some(Duration::from_secs(120)),
        }
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_04_sms_notifications_go_through_the_outbox(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier.notify_sms(f.sms()).await.unwrap();
    let rows = f.rows().await;
    assert_eq!(rows[0].topic, SMS_TOPIC);
    assert_eq!(rows[0].payload.0["recipient"], "+90*******233");
    assert_eq!(rows[0].payload.0["template"], "mfa_sms_code");
    let sealed = rows[0].sealed_payload.as_deref().unwrap();
    assert!(!contains(sealed, CODE.as_bytes()));
    assert!(!contains(
        rows[0].payload.0.to_string().as_bytes(),
        b"5551112233"
    ));

    f.deliver(&rows[0]).await.unwrap();
    let sent = f.sms.messages();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to.as_str(), "+905551112233");
    let body = sent[0].body.expose();
    assert!(body.contains(CODE), "{body}");
    assert!(body.ends_with("@auth.test.example #468024"), "{body}");
    assert!(!format!("{:?}", sent[0]).contains(CODE));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_04_sms_without_provider_is_dead_lettered(pool: PgPool) {
    let f = Fixture::new(pool);
    f.notifier.notify_sms(f.sms()).await.unwrap();
    let rows = f.rows().await;
    let deliverer = Fixture::deliverer_with(
        &f.config,
        &f.ports,
        f.email.clone(),
        Arc::new(DisabledSmsSender),
    );
    assert_eq!(
        deliverer.deliver(rows[0].request()).await.unwrap_err(),
        DeliveryFailure::Permanent {
            reason: "no SMS provider configured"
        }
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_01_recipient_limit_drops_bombing_silently_but_never_security_alerts(pool: PgPool) {
    let f = Fixture::new(pool);
    let notifier = f.notifier.clone().with_recipient_limit(
        f.ports.rate_limiter.clone(),
        RateLimitPolicy::new(2, Duration::from_secs(3600)),
    );
    for _ in 0..5 {
        // Always Ok: an error would reveal that the address has an account.
        notifier.notify(f.magic_link()).await.unwrap();
    }
    assert_eq!(f.rows().await.len(), 2);
    let mut alert = f.magic_link();
    alert.kind = NotificationKind::NewDeviceLogin {
        device: "Firefox on Linux".to_owned(),
        approximate_location: None,
        ip_masked: "203.0.113.x".to_owned(),
        at: f.now(),
        not_me_token: SensitiveString::new(TOKEN),
    };
    notifier.notify(alert).await.unwrap();
    assert_eq!(
        f.rows().await.len(),
        3,
        "security alerts are never throttled"
    );
    for _ in 0..3 {
        notifier.notify_sms(f.sms()).await.unwrap();
    }
    assert_eq!(f.rows().await.len(), 5, "SMS limited per number");
}

/// Security review: `victim+1@…`, `victim+2@…` reach the same inbox and
/// must share its budget.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_01_recipient_limit_cannot_be_bypassed_with_plus_addressing(pool: PgPool) {
    let f = Fixture::new(pool);
    let notifier = f.notifier.clone().with_recipient_limit(
        f.ports.rate_limiter.clone(),
        RateLimitPolicy::new(2, Duration::from_secs(3600)),
    );
    for address in [
        "victim@example.com",
        "Victim+1@example.com",
        "victim+2@EXAMPLE.com",
        "victim+bomb+3@example.com",
    ] {
        let mut n = f.magic_link();
        n.recipient.email = EmailAddress::parse(address).unwrap();
        notifier.notify(n).await.unwrap();
    }
    assert_eq!(f.rows().await.len(), 2, "one inbox, one budget");
    // A different mailbox keeps its own budget.
    let mut other = f.magic_link();
    other.recipient.email = EmailAddress::parse("victimother@example.com").unwrap();
    notifier.notify(other).await.unwrap();
    assert_eq!(f.rows().await.len(), 3);
}

/// Security review: cheap, unauthenticated kinds (registration notices,
/// phone verifications aimed at someone else's number) must not exhaust
/// the budget of the victim's sign-in and second-factor codes (lock-out).
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_01_cheap_kinds_cannot_starve_sign_in_and_mfa_codes(pool: PgPool) {
    let f = Fixture::new(pool);
    let notifier = f.notifier.clone().with_recipient_limit(
        f.ports.rate_limiter.clone(),
        RateLimitPolicy::new(2, Duration::from_secs(3600)),
    );
    let victim = |kind: NotificationKind| Notification {
        recipient: Recipient {
            email: EmailAddress::parse("victim@example.com").unwrap(),
            user_id: Some(UserId::generate()),
            display_name: None,
        },
        locale: Locale::En,
        kind,
    };
    for _ in 0..5 {
        notifier
            .notify(victim(NotificationKind::RegistrationAttempt))
            .await
            .unwrap();
    }
    assert_eq!(f.rows().await.len(), 2, "registration notices are limited");
    let expires_at = f.now() + Duration::from_secs(600);
    for kind in [
        NotificationKind::MfaEmailCode {
            code: SensitiveString::new(CODE),
            expires_at,
        },
        NotificationKind::LoginCode {
            code: SensitiveString::new(CODE),
            expires_at,
        },
        NotificationKind::MagicLink {
            token: SensitiveString::new(TOKEN),
            expires_at,
        },
        NotificationKind::PasswordReset {
            token: SensitiveString::new(TOKEN),
            code: None,
            expires_at,
        },
    ] {
        let template = kind.template_name();
        notifier.notify(victim(kind)).await.unwrap();
        assert!(
            f.rows()
                .await
                .iter()
                .any(|row| row.payload.0["template"] == template),
            "{template} must not be starved by registration notices"
        );
    }

    let mut verification = f.sms();
    verification.kind = SmsNotificationKind::PhoneVerification {
        code: SensitiveString::new(CODE),
        expires_at,
    };
    for _ in 0..5 {
        notifier.notify_sms(verification.clone()).await.unwrap();
    }
    let sms_rows = |rows: &[Row]| rows.iter().filter(|r| r.topic == SMS_TOPIC).count();
    assert_eq!(sms_rows(&f.rows().await), 2);
    notifier.notify_sms(f.sms()).await.unwrap();
    assert_eq!(
        sms_rows(&f.rows().await),
        3,
        "the SMS second factor is not starved by phone verifications"
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_01_recipient_limit_fails_open_when_the_limiter_is_down(pool: PgPool) {
    struct Broken;
    #[async_trait]
    impl RateLimiter for Broken {
        async fn check(
            &self,
            _: &RateLimitKey,
            _: RateLimitPolicy,
            _: u32,
        ) -> Result<RateLimitDecision, AuthError> {
            Err(AuthError::internal("limiter down"))
        }
        async fn peek(
            &self,
            _: &RateLimitKey,
            _: RateLimitPolicy,
        ) -> Result<RateLimitDecision, AuthError> {
            Err(AuthError::internal("limiter down"))
        }
        async fn reset(&self, _: &RateLimitKey) -> Result<(), AuthError> {
            Ok(())
        }
    }
    let f = Fixture::new(pool);
    let notifier = f.notifier.clone().with_recipient_limit(
        Arc::new(Broken),
        RateLimitPolicy::new(1, Duration::from_secs(60)),
    );
    notifier.notify(f.magic_link()).await.unwrap();
    notifier.notify(f.magic_link()).await.unwrap();
    assert_eq!(f.rows().await.len(), 2);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_01_malformed_secrets_are_refused_at_enqueue(pool: PgPool) {
    let f = Fixture::new(pool);
    let mut bad_token = f.magic_link();
    bad_token.kind = NotificationKind::MagicLink {
        token: SensitiveString::new("https://evil.example/?t=AAAAAAAAAAAAAAAA"),
        expires_at: f.now() + Duration::from_secs(60),
    };
    assert!(f.notifier.notify(bad_token).await.is_err());
    let mut bad_code = f.magic_link();
    bad_code.kind = NotificationKind::LoginCode {
        code: SensitiveString::new("12345\n"),
        expires_at: f.now() + Duration::from_secs(60),
    };
    assert!(f.notifier.notify(bad_code).await.is_err());
    let mut bad_sms = f.sms();
    bad_sms.kind = SmsNotificationKind::PhoneVerification {
        code: SensitiveString::new("abcdef"),
        expires_at: f.now() + Duration::from_secs(60),
    };
    assert!(f.notifier.notify_sms(bad_sms).await.is_err());
    assert!(f.rows().await.is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ntf_02_hostile_values_survive_the_whole_pipeline_safely(pool: PgPool) {
    let f = Fixture::new(pool);
    let notification = Notification {
        recipient: Recipient {
            email: EmailAddress::parse("carol@example.com").unwrap(),
            user_id: None,
            display_name: Some("Carol\r\nBcc: evil@example.com <script>".to_owned()),
        },
        locale: Locale::En,
        kind: NotificationKind::Invitation {
            org_name: "Acme https://evil.example\u{202E}".to_owned(),
            inviter_name: Some("{{ link }}".to_owned()),
            token: SensitiveString::new(TOKEN),
            expires_at: f.now() + Duration::from_secs(86_400),
        },
    };
    f.notifier.notify(notification).await.unwrap();
    let rows = f.rows().await;
    f.deliver(&rows[0]).await.unwrap();
    let message = f.email.messages().pop().unwrap();
    assert!(!message.subject.contains(['\r', '\n', '\u{202E}']));
    assert!(!message.to_name.as_deref().unwrap().contains(['\r', '\n']));
    assert!(!message.text_body.contains("https://evil"));
    assert!(message.text_body.contains("{{ link }} has invited you"));
    assert!(!message.html_body.as_deref().unwrap().contains("<script>"));
}
