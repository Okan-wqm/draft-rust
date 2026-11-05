#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Organization webhooks: management API, fan-out, signed SSRF-safe
//! delivery, retries, history, redelivery, auto-disable (AUD-07).

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_audit::webhooks::{WebhookDeliverer, rewrap_webhook_secrets};
use authn_audit::{AuditPermission, OutboxHandlers, OutboxWorker};
use authn_core::config::audit::AuditConfig;
use authn_core::config::common::VersionedKey;
use authn_core::config::crypto::KekConfig;
use authn_core::error::{AuthError, codes};
use authn_core::id::{OrgId, ServiceAccountId, UserId};
use authn_core::ports::{
    AuditSink, Clock, DomainEvent, DomainEventKind, EventPublisher, HttpClient, OutboundRequest,
    OutboundResponse, OutboundTarget,
};
use authn_crypto::envelope::EnvelopeCipher;
use authn_crypto::webhook::{SignedHeaders, WebhookSecret, verify};
use authn_testkit::http::TestRequest;
use common::{
    Harness, create_org, create_user, impersonated, service_account_principal, user_principal,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;

const URL: &str = "https://hooks.example.com/authn";

/// `Ok((status, retry-after, body))` or a transport error.
type Scripted = Result<(u16, Option<&'static str>, &'static str), ()>;

/// An `HttpClient` returning scripted responses (default 200) and recording
/// every request.
#[derive(Default)]
struct ScriptedHttp {
    script: Mutex<Vec<Scripted>>,
    requests: Mutex<Vec<OutboundRequest>>,
}

impl ScriptedHttp {
    fn push(&self, status: u16) {
        self.script.lock().unwrap().push(Ok((status, None, "")));
    }

    fn push_full(&self, status: u16, retry_after: Option<&'static str>, body: &'static str) {
        self.script
            .lock()
            .unwrap()
            .push(Ok((status, retry_after, body)));
    }

    fn push_transport_error(&self) {
        self.script.lock().unwrap().push(Err(()));
    }

    fn requests(&self) -> Vec<OutboundRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpClient for ScriptedHttp {
    async fn execute(&self, request: OutboundRequest) -> Result<OutboundResponse, AuthError> {
        self.requests.lock().unwrap().push(request);
        let next = {
            let mut script = self.script.lock().unwrap();
            if script.is_empty() {
                Ok((200, None, ""))
            } else {
                script.remove(0)
            }
        };
        match next {
            Ok((status, retry_after, body)) => {
                let mut headers = HeaderMap::new();
                if let Some(v) = retry_after {
                    headers.insert("retry-after", HeaderValue::from_static(v));
                }
                Ok(OutboundResponse {
                    status: StatusCode::from_u16(status).unwrap(),
                    headers,
                    body: body.as_bytes().to_vec(),
                })
            }
            Err(()) => Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)),
        }
    }
}

struct Setup {
    h: Harness,
    http: Arc<ScriptedHttp>,
    worker: OutboxWorker,
    org: OrgId,
    admin: UserId,
}

impl Setup {
    async fn new(pool: PgPool) -> Self {
        Self::with_config(pool, &AuditConfig::default()).await
    }

    async fn with_config(pool: PgPool, config: &AuditConfig) -> Self {
        let h = Harness::with_config(pool.clone(), config);
        let http = Arc::new(ScriptedHttp::default());
        let worker = h
            .service
            .outbox_worker(h.service.outbox_handlers(http.clone()).unwrap());
        let org = create_org(&pool).await;
        let admin = create_user(&pool).await;
        h.policy.grant_user(
            admin,
            org,
            &[
                AuditPermission::WebhooksRead,
                AuditPermission::WebhooksManage,
            ],
        );
        Self {
            h,
            http,
            worker,
            org,
            admin,
        }
    }

    fn admin_app(&self) -> axum::Router {
        self.h
            .app(Some(user_principal(self.admin, Some(self.h.now()))))
    }

    async fn create(&self, url: &str, types: &[&str]) -> (Value, String) {
        let res = TestRequest::post(&format!("/v1/orgs/{}/webhooks", self.org))
            .json(&json!({"url": url, "event_types": types, "description": "CRM sync"}))
            .send(&self.admin_app())
            .await;
        res.assert_status(StatusCode::CREATED);
        assert_eq!(res.header("cache-control"), Some("no-store"));
        let body: Value = res.json();
        let secret = body["secret"].as_str().unwrap().to_owned();
        (body["endpoint"].clone(), secret)
    }

    async fn publish(&self, kind: DomainEventKind, org: OrgId) -> DomainEvent {
        let mut event = DomainEvent::new(kind, self.h.now(), json!({"role": "member"}));
        event.org_id = Some(org);
        event.user_id = Some(self.admin);
        let mut tx = self.h.pool.begin().await.unwrap();
        self.h
            .service
            .event_publisher()
            .publish(&mut tx, event.clone())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        event
    }

    /// Runs the worker until nothing is due.
    async fn drain(&self) {
        while self.worker.run_once().await.unwrap().claimed > 0 {}
    }

    async fn deliveries(&self) -> Vec<(String, i32, Option<i32>, Option<String>)> {
        sqlx::query_as(
            "SELECT status, attempts, response_status, last_error FROM webhook_deliveries \
             ORDER BY created_at, id",
        )
        .fetch_all(&self.h.pool)
        .await
        .unwrap()
    }
}

fn signed_headers(request: &OutboundRequest) -> SignedHeaders {
    let get = |name: &str| {
        request
            .headers
            .get(name)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    };
    SignedHeaders {
        id: get("webhook-id"),
        timestamp: get("webhook-timestamp"),
        signature: get("webhook-signature"),
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_create_returns_the_secret_once_and_stores_only_ciphertext(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (endpoint, secret) = s.create(URL, &["member.added", "user.created"]).await;
    assert!(secret.starts_with("whsec_"));
    WebhookSecret::parse(&secret).unwrap();
    assert_eq!(endpoint["url"], URL);
    assert_eq!(endpoint["status"], "active");
    assert_eq!(
        endpoint["event_types"],
        json!(["member.added", "user.created"])
    );

    let stored: Vec<String> =
        sqlx::query_scalar("SELECT row_to_json(t)::text FROM webhook_endpoints t")
            .fetch_all(&pool)
            .await
            .unwrap();
    let stored = stored.join("\n");
    let key_b64 = secret.trim_start_matches("whsec_");
    assert!(!stored.contains(key_b64), "secret stored in clear text");

    // Listing and reading never return the secret.
    for uri in [
        format!("/v1/orgs/{}/webhooks", s.org),
        format!(
            "/v1/orgs/{}/webhooks/{}",
            s.org,
            endpoint["id"].as_str().unwrap()
        ),
    ] {
        let res = TestRequest::get(&uri).send(&s.admin_app()).await;
        res.assert_status(StatusCode::OK);
        assert!(!res.text().contains("whsec_"), "{}", res.text());
    }
    // Audited, without the URL (it may carry a capability) or the secret.
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM audit_events t WHERE kind = 'webhook.endpoint_created'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audit.len(), 1);
    assert!(!audit[0].contains("hooks.example.com") && !audit[0].contains(key_b64));
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_unsafe_urls_and_unknown_event_types_are_rejected(pool: PgPool) {
    let s = Setup::new(pool).await;
    let app = s.admin_app();
    for url in [
        "http://hooks.example.com/",
        "https://127.0.0.1/",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/",
        "https://localhost/",
        "https://user:pass@hooks.example.com/",
        "https://metadata.google.internal/",
    ] {
        TestRequest::post(&format!("/v1/orgs/{}/webhooks", s.org))
            .json(&json!({"url": url, "event_types": ["user.created"]}))
            .send(&app)
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "webhook_url_invalid");
    }
    for types in [json!([]), json!(["user.pwned"]), json!(["*"])] {
        TestRequest::post(&format!("/v1/orgs/{}/webhooks", s.org))
            .json(&json!({"url": URL, "event_types": types}))
            .send(&app)
            .await
            .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
    TestRequest::post(&format!("/v1/orgs/{}/webhooks", s.org))
        .json(&json!({"url": URL, "event_types": ["user.created"], "secret": "mine"}))
        .send(&app)
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_management_requires_permission_step_up_and_write_access(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let now = s.h.now();
    let body = json!({"url": URL, "event_types": ["user.created"]});
    let uri = format!("/v1/orgs/{}/webhooks", s.org);

    let stranger = create_user(&pool).await;
    TestRequest::post(&uri)
        .json(&body)
        .send(&s.h.app(Some(user_principal(stranger, Some(now)))))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");

    let reader = create_user(&pool).await;
    s.h.policy
        .grant_user(reader, s.org, &[AuditPermission::WebhooksRead]);
    TestRequest::get(&uri)
        .send(&s.h.app(Some(user_principal(reader, Some(now)))))
        .await
        .assert_status(StatusCode::OK);
    TestRequest::post(&uri)
        .json(&body)
        .send(&s.h.app(Some(user_principal(reader, Some(now)))))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");

    // Stale authentication → step-up.
    let stale = user_principal(s.admin, Some(now - Duration::from_secs(3600)));
    TestRequest::post(&uri)
        .json(&body)
        .send(&s.h.app(Some(stale)))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    // Read-only impersonation never writes.
    let support = create_user(&pool).await;
    let ro = impersonated(user_principal(s.admin, Some(now)), support, true);
    TestRequest::post(&uri)
        .json(&body)
        .send(&s.h.app(Some(ro)))
        .await
        .assert_error(StatusCode::FORBIDDEN, "forbidden");
    // Machine credential of the organization with the permission.
    let sa = ServiceAccountId::generate();
    s.h.policy
        .grant_service_account(sa, s.org, &[AuditPermission::WebhooksManage]);
    TestRequest::post(&uri)
        .json(&body)
        .send(&s.h.app(Some(service_account_principal(sa, s.org))))
        .await
        .assert_status(StatusCode::CREATED);
    TestRequest::post(&uri)
        .json(&body)
        .send(&s.h.app(None))
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "unauthenticated");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_endpoint_limit_holds_under_concurrent_creation(pool: PgPool) {
    let mut config = AuditConfig::default();
    config.webhooks.max_endpoints_per_org = 3;
    let s = Setup::with_config(pool.clone(), &config).await;
    let app = s.admin_app();
    let mut tasks = Vec::new();
    for i in 0..8 {
        let app = app.clone();
        let uri = format!("/v1/orgs/{}/webhooks", s.org);
        tasks.push(tokio::spawn(async move {
            TestRequest::post(&uri)
                .json(&json!({"url": format!("https://hooks{i}.example.com/"), "event_types": ["user.created"]}))
                .send(&app)
                .await
                .status
        }));
    }
    let mut created = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::CREATED => created += 1,
            StatusCode::CONFLICT => {}
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!(created, 3);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_endpoints")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 3);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_endpoints_of_other_tenants_are_not_found(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (endpoint, _) = s.create(URL, &["user.created"]).await;
    let id = endpoint["id"].as_str().unwrap();
    let org_b = create_org(&pool).await;
    let admin_b = create_user(&pool).await;
    s.h.policy.grant_user(
        admin_b,
        org_b,
        &[
            AuditPermission::WebhooksRead,
            AuditPermission::WebhooksManage,
        ],
    );
    let app_b = s.h.app(Some(user_principal(admin_b, Some(s.h.now()))));
    // Through its own organization path (IDOR) and through org A's path.
    for org in [org_b.to_string(), s.org.to_string()] {
        for req in [
            TestRequest::get(&format!("/v1/orgs/{org}/webhooks/{id}")),
            TestRequest::patch(&format!("/v1/orgs/{org}/webhooks/{id}"))
                .json(&json!({"url": "https://attacker.example.net/"})),
            TestRequest::delete(&format!("/v1/orgs/{org}/webhooks/{id}")),
            TestRequest::post(&format!("/v1/orgs/{org}/webhooks/{id}/rotate-secret")),
            TestRequest::get(&format!("/v1/orgs/{org}/webhooks/{id}/deliveries")),
        ] {
            req.send(&app_b)
                .await
                .assert_error(StatusCode::NOT_FOUND, "not_found");
        }
    }
    let url: String = sqlx::query_scalar("SELECT url FROM webhook_endpoints")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(url, URL);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_events_are_fanned_out_signed_and_sent_to_user_supplied_targets(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (_, secret) = s.create(URL, &["member.added"]).await;
    let other_org = create_org(&pool).await;
    let event = s.publish(DomainEventKind::MemberAdded, s.org).await;
    // Not subscribed / other tenant: nothing is sent.
    s.publish(DomainEventKind::UserCreated, s.org).await;
    s.publish(DomainEventKind::MemberAdded, other_org).await;
    s.drain().await;

    let requests = s.http.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.url.as_str(), URL);
    assert_eq!(
        request.target,
        OutboundTarget::UserSupplied,
        "SSRF-protected path"
    );
    assert_eq!(request.timeout, Some(Duration::from_secs(10)));
    assert_eq!(
        request.headers.get("content-type").unwrap(),
        "application/json"
    );
    let headers = signed_headers(request);
    assert_eq!(headers.id, event.id.to_string(), "webhook-id = event id");
    let body = request.body.clone().unwrap();
    let secret = WebhookSecret::parse(&secret).unwrap();
    verify(
        std::slice::from_ref(&secret),
        &headers,
        &body,
        s.h.now(),
        300,
    )
    .unwrap();
    let stranger = WebhookSecret::generate().unwrap();
    assert!(verify(&[stranger], &headers, &body, s.h.now(), 300).is_err());
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["type"], "member.added");
    assert_eq!(payload["id"], event.id.to_string());
    assert_eq!(payload["organization_id"], s.org.to_string());
    assert_eq!(payload["data"]["role"], "member");

    assert_eq!(
        s.deliveries().await,
        vec![("succeeded".to_owned(), 1, Some(200), None)]
    );
    let last_success: Option<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT last_success_at FROM webhook_endpoints")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(last_success, Some(s.h.now()));
    // Re-running the fan-out for the same event never duplicates deliveries.
    sqlx::query(
        "UPDATE outbox SET status = 'pending', delivered_at = NULL WHERE topic = 'domain_event'",
    )
    .execute(&pool)
    .await
    .unwrap();
    s.drain().await;
    assert_eq!(s.http.requests().len(), 1);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_secret_rotation_signs_with_both_secrets_during_the_overlap(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (endpoint, old) = s.create(URL, &["member.added"]).await;
    let id = endpoint["id"].as_str().unwrap().to_owned();
    let res = TestRequest::post(&format!("/v1/orgs/{}/webhooks/{id}/rotate-secret", s.org))
        .send(&s.admin_app())
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let body: Value = res.json();
    let new = body["secret"].as_str().unwrap().to_owned();
    assert_ne!(new, old);
    assert!(body["endpoint"]["previous_secret_expires_at"].is_string());

    s.publish(DomainEventKind::MemberAdded, s.org).await;
    s.drain().await;
    let request = s.http.requests().pop().unwrap();
    let headers = signed_headers(&request);
    assert_eq!(headers.signature.split(' ').count(), 2);
    let payload = request.body.unwrap();
    for secret in [&old, &new] {
        verify(
            &[WebhookSecret::parse(secret).unwrap()],
            &headers,
            &payload,
            s.h.now(),
            300,
        )
        .unwrap();
    }

    // After the overlap only the new secret signs.
    s.h.ports.clock.advance(Duration::from_secs(25 * 3600));
    s.publish(DomainEventKind::MemberAdded, s.org).await;
    s.drain().await;
    let request = s.http.requests().pop().unwrap();
    let headers = signed_headers(&request);
    assert_eq!(headers.signature.split(' ').count(), 1);
    let payload = request.body.unwrap();
    assert!(
        verify(
            &[WebhookSecret::parse(&old).unwrap()],
            &headers,
            &payload,
            s.h.now(),
            300
        )
        .is_err()
    );

    // Immediate rotation (suspected leak) drops the previous secret at once.
    let res = TestRequest::post(&format!(
        "/v1/orgs/{}/webhooks/{id}/rotate-secret?immediate=true",
        s.org
    ))
    .send(&s.h.app(Some(user_principal(s.admin, Some(s.h.now())))))
    .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["endpoint"]["previous_secret_expires_at"], Value::Null);
    let rotations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE kind = 'webhook.secret_rotated'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rotations, 2);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_failed_deliveries_are_retried_recorded_and_redeliverable(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (endpoint, _) = s.create(URL, &["member.added"]).await;
    let endpoint_id = endpoint["id"].as_str().unwrap().to_owned();
    s.http
        .push_full(500, None, "stack trace with secret-echo-123");
    s.publish(DomainEventKind::MemberAdded, s.org).await;
    s.drain().await;
    assert_eq!(
        s.deliveries().await,
        vec![(
            "failed".to_owned(),
            1,
            Some(500),
            Some("http_status_500".to_owned())
        )]
    );
    // The receiver's body is never stored anywhere.
    let everything: Vec<String> = sqlx::query_scalar(
        "SELECT row_to_json(t)::text FROM webhook_deliveries t \
         UNION ALL SELECT row_to_json(o)::text FROM outbox o",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!everything.join("\n").contains("secret-echo"));
    // The retry is scheduled with the webhook backoff (1 min base).
    let available_at: time::OffsetDateTime =
        sqlx::query_scalar("SELECT available_at FROM outbox WHERE topic = 'webhook.delivery'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let delay = available_at - s.h.now();
    assert!(
        delay >= time::Duration::seconds(30) && delay <= time::Duration::seconds(60),
        "{delay}"
    );

    s.h.ports.clock.advance(Duration::from_secs(61));
    s.drain().await;
    assert_eq!(
        s.deliveries().await,
        vec![("succeeded".to_owned(), 2, Some(200), None)]
    );

    // History listing.
    let history_uri = format!("/v1/orgs/{}/webhooks/{endpoint_id}/deliveries", s.org);
    let body: Value = TestRequest::get(&history_uri)
        .send(&s.admin_app())
        .await
        .json();
    let delivery_id = body["items"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(body["items"][0]["status"], "succeeded");
    assert_eq!(body["items"][0]["attempts"], 2);
    assert_eq!(body["items"][0]["payload"]["type"], "member.added");

    // Manual redelivery of a finished delivery.
    let redeliver = format!(
        "/v1/orgs/{}/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver",
        s.org
    );
    let res = TestRequest::post(&redeliver).send(&s.admin_app()).await;
    res.assert_status(StatusCode::ACCEPTED);
    assert_eq!(res.json::<Value>()["status"], "pending");
    TestRequest::post(&redeliver)
        .send(&s.admin_app())
        .await
        .assert_error(StatusCode::CONFLICT, "webhook_delivery_in_progress");
    let sent_before = s.http.requests().len();
    s.drain().await;
    assert_eq!(s.http.requests().len(), sent_before + 1);
    let last = s.http.requests().pop().unwrap();
    assert_eq!(
        signed_headers(&last).id,
        body["items"][0]["event_id"].as_str().unwrap()
    );
    assert_eq!(s.deliveries().await[0].1, 3);
    // Unknown delivery / other endpoint: 404.
    TestRequest::post(&format!(
        "/v1/orgs/{}/webhooks/{endpoint_id}/deliveries/{}/redeliver",
        s.org,
        uuid::Uuid::now_v7()
    ))
    .send(&s.admin_app())
    .await
    .assert_error(StatusCode::NOT_FOUND, "not_found");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_exhausted_retries_end_in_the_dead_state_and_honour_retry_after(pool: PgPool) {
    let mut config = AuditConfig::default();
    config.webhooks.max_attempts = 2;
    let s = Setup::with_config(pool.clone(), &config).await;
    s.create(URL, &["member.added"]).await;
    s.http.push_full(429, Some("600"), "");
    s.http.push_transport_error();
    s.publish(DomainEventKind::MemberAdded, s.org).await;
    s.drain().await;
    let available_at: time::OffsetDateTime =
        sqlx::query_scalar("SELECT available_at FROM outbox WHERE topic = 'webhook.delivery'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        available_at - s.h.now() >= time::Duration::seconds(600),
        "Retry-After honoured"
    );
    s.h.ports.clock.advance(Duration::from_secs(601));
    s.drain().await;
    let rows = s.deliveries().await;
    assert_eq!(rows[0].0, "dead");
    assert_eq!(rows[0].1, 2);
    assert_eq!(
        rows[0].3.as_deref(),
        Some("transport_error:service_unavailable")
    );
    let status: String =
        sqlx::query_scalar("SELECT status FROM outbox WHERE topic = 'webhook.delivery'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "dead");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_sustained_failures_disable_the_endpoint(pool: PgPool) {
    let mut config = AuditConfig::default();
    config.webhooks.disable_after_failures = 3;
    config.webhooks.disable_after = Duration::from_secs(3600);
    config.webhooks.max_attempts = 1;
    let s = Setup::with_config(pool.clone(), &config).await;
    let (endpoint, _) = s.create(URL, &["member.added"]).await;
    let id = endpoint["id"].as_str().unwrap().to_owned();
    for _ in 0..4 {
        s.http.push(503);
        s.publish(DomainEventKind::MemberAdded, s.org).await;
        s.drain().await;
        s.h.ports.clock.advance(Duration::from_secs(1800));
    }
    let (status, reason, failures): (String, Option<String>, i32) = sqlx::query_as(
        "SELECT status, disabled_reason, consecutive_failures FROM webhook_endpoints",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "disabled");
    assert_eq!(reason.as_deref(), Some("consecutive_failures"));
    // Failures at 0, 30 and 60 minutes: the third one reaches both
    // thresholds; the fourth event finds no active endpoint.
    assert_eq!(failures, 3);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE kind = 'webhook.endpoint_auto_disabled' AND actor_type = 'system'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);

    // A disabled endpoint is not called and new events are not queued for it.
    let sent = s.http.requests().len();
    s.publish(DomainEventKind::MemberAdded, s.org).await;
    s.drain().await;
    assert_eq!(s.http.requests().len(), sent);
    let dead_letter_redeliver = sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM webhook_deliveries ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    TestRequest::post(&format!(
        "/v1/orgs/{}/webhooks/{id}/deliveries/{dead_letter_redeliver}/redeliver",
        s.org
    ))
    .send(&s.admin_app())
    .await
    .assert_error(StatusCode::CONFLICT, "webhook_endpoint_disabled");

    // Re-enabling (step-up) resets the failure streak.
    let res = TestRequest::patch(&format!("/v1/orgs/{}/webhooks/{id}", s.org))
        .json(&json!({"enabled": true}))
        .send(&s.admin_app())
        .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["status"], "active");
    assert_eq!(body["consecutive_failures"], 0);
    assert_eq!(body["disabled_reason"], Value::Null);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_update_and_delete_endpoint(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (endpoint, _) = s.create(URL, &["member.added"]).await;
    let id = endpoint["id"].as_str().unwrap().to_owned();
    let uri = format!("/v1/orgs/{}/webhooks/{id}", s.org);
    // A sensitive change (URL) with stale authentication needs step-up; a
    // description change does not.
    let stale = s.h.app(Some(user_principal(
        s.admin,
        Some(s.h.now() - Duration::from_secs(7200)),
    )));
    TestRequest::patch(&uri)
        .json(&json!({"url": "https://other.example.com/in"}))
        .send(&stale)
        .await
        .assert_error(StatusCode::UNAUTHORIZED, "step_up_required");
    let res = TestRequest::patch(&uri)
        .json(&json!({"description": ""}))
        .send(&stale)
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<Value>()["description"], Value::Null);
    let res = TestRequest::patch(&uri)
        .json(&json!({"url": "https://other.example.com/in", "event_types": ["user.deleted"], "enabled": false}))
        .send(&s.admin_app())
        .await;
    res.assert_status(StatusCode::OK);
    let body: Value = res.json();
    assert_eq!(body["url"], "https://other.example.com/in");
    assert_eq!(body["event_types"], json!(["user.deleted"]));
    assert_eq!(body["status"], "disabled");
    assert_eq!(body["disabled_reason"], "manual");
    TestRequest::patch(&uri)
        .json(&json!({"url": "https://10.0.0.1/"}))
        .send(&s.admin_app())
        .await
        .assert_error(StatusCode::UNPROCESSABLE_ENTITY, "webhook_url_invalid");

    TestRequest::delete(&uri)
        .send(&s.admin_app())
        .await
        .assert_status(StatusCode::NO_CONTENT);
    TestRequest::get(&uri)
        .send(&s.admin_app())
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM audit_events WHERE kind LIKE 'webhook.%' ORDER BY seq",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        kinds,
        vec![
            "webhook.endpoint_created",
            "webhook.endpoint_updated",
            "webhook.endpoint_updated",
            "webhook.endpoint_deleted"
        ]
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_deleting_an_endpoint_drops_pending_deliveries(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (endpoint, _) = s.create(URL, &["member.added"]).await;
    s.publish(DomainEventKind::MemberAdded, s.org).await;
    // Fan-out only (one batch): the delivery message is pending.
    s.worker.run_once().await.unwrap();
    let id = endpoint["id"].as_str().unwrap();
    TestRequest::delete(&format!("/v1/orgs/{}/webhooks/{id}", s.org))
        .send(&s.admin_app())
        .await
        .assert_status(StatusCode::NO_CONTENT);
    s.drain().await;
    assert!(s.http.requests().is_empty());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_kek_rotation_rewraps_secrets_without_changing_them(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (_, secret) = s.create(URL, &["member.added"]).await;
    let mut crypto = authn_testkit::config::test_config().crypto;
    crypto.keks.push(KekConfig {
        id: "test-kek-2".into(),
        key: authn_core::secret::SecretString::from(
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=".to_owned(),
        ),
    });
    crypto.current_kek_id = "test-kek-2".into();
    let _: Option<VersionedKey> = None;
    let rotated = EnvelopeCipher::from_config(&crypto).unwrap();
    assert_eq!(rewrap_webhook_secrets(&pool, &rotated).await.unwrap(), 1);
    assert_eq!(rewrap_webhook_secrets(&pool, &rotated).await.unwrap(), 0);
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT secret_ciphertext FROM webhook_endpoints")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!rotated.needs_rewrap(&sealed).unwrap());

    // Deliveries with the rotated key ring still sign with the same secret.
    let deliverer = WebhookDeliverer::new(
        pool.clone(),
        s.h.clock(),
        rotated,
        s.http.clone() as Arc<dyn HttpClient>,
        s.h.service.sink(),
        s.h.config.webhooks,
    );
    let handlers =
        s.h.service
            .outbox_handlers(s.http.clone())
            .unwrap()
            .register("webhook", Arc::new(deliverer))
            .unwrap();
    let worker = OutboxWorker::new(
        pool.clone(),
        s.h.clock() as Arc<dyn Clock>,
        handlers,
        s.h.config.outbox,
    );
    s.publish(DomainEventKind::MemberAdded, s.org).await;
    while worker.run_once().await.unwrap().claimed > 0 {}
    let request = s.http.requests().pop().unwrap();
    verify(
        &[WebhookSecret::parse(&secret).unwrap()],
        &signed_headers(&request),
        &request.body.unwrap(),
        s.h.now(),
        300,
    )
    .unwrap();
    let _ = OutboxHandlers::new();
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_07_webhook_changes_and_redeliveries_are_rate_limited_per_org(pool: PgPool) {
    let mut config = AuditConfig::default();
    config.rate_limits.webhook_write =
        authn_core::ports::RateLimitPolicy::new(2, Duration::from_secs(3600));
    let s = Setup::with_config(pool.clone(), &config).await;
    s.create(URL, &["member.added"]).await;
    s.create("https://hooks2.example.com/", &["member.added"])
        .await;
    let res = TestRequest::post(&format!("/v1/orgs/{}/webhooks", s.org))
        .json(&json!({"url": "https://hooks3.example.com/", "event_types": ["user.created"]}))
        .send(&s.admin_app())
        .await;
    res.assert_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    assert!(res.header("retry-after").is_some());
    // Unauthorized callers never consume the organization's budget.
    let stranger = create_user(&pool).await;
    TestRequest::post(&format!("/v1/orgs/{}/webhooks", s.org))
        .json(&json!({"url": URL, "event_types": ["user.created"]}))
        .send(&s.h.app(Some(user_principal(stranger, Some(s.h.now())))))
        .await
        .assert_error(StatusCode::NOT_FOUND, "not_found");
}

// --- K-58: no user id of an erased account survives in the history -------

async fn publish_for(s: &Setup, kind: DomainEventKind, user: UserId) -> DomainEvent {
    let mut event = DomainEvent::new(kind, s.h.now(), json!({ "user_id": user }));
    event.org_id = Some(s.org);
    event.user_id = Some(user);
    let mut tx = s.h.pool.begin().await.unwrap();
    s.h.service
        .event_publisher()
        .publish(&mut tx, event.clone())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    event
}

/// Rows of the outbox and the delivery history that still mention `user`.
async fn mentions(pool: &PgPool, user: UserId) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT 'outbox:' || status || ':' || topic FROM outbox o \
         WHERE row_to_json(o)::text LIKE '%' || $1 || '%' \
         UNION ALL SELECT 'delivery:' || status || ':' || event_type FROM webhook_deliveries d \
         WHERE row_to_json(d)::text LIKE '%' || $1 || '%' ORDER BY 1",
    )
    .bind(user.to_string())
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_06_k58_delivered_outbox_messages_keep_no_personal_data(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    s.create(URL, &["member.added"]).await;
    let user = create_user(&pool).await;
    publish_for(&s, DomainEventKind::MemberAdded, user).await;
    s.drain().await;
    let delivered: Vec<Value> =
        sqlx::query_scalar("SELECT payload FROM outbox WHERE status = 'delivered'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        delivered.len(),
        2,
        "domain event + webhook delivery message"
    );
    for payload in &delivered {
        assert!(payload.get("user_id").is_none(), "{payload}");
        assert!(payload.get("data").is_none(), "{payload}");
    }
    // The delivery history of a live user keeps its payload (receivers'
    // operators need it; redelivery works).
    assert_eq!(
        mentions(&pool, user).await,
        vec!["delivery:succeeded:member.added"]
    );
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_k58_erasure_scrubs_the_outbox_and_redacts_the_webhook_history(pool: PgPool) {
    let s = Setup::new(pool.clone()).await;
    let (endpoint, _) = s
        .create(URL, &["member.added", "member.removed", "user.deleted"])
        .await;
    let endpoint_id = endpoint["id"].as_str().unwrap().to_owned();
    let victim = create_user(&pool).await;
    let bystander = create_user(&pool).await;
    // A finished delivery, an unfinished one (the receiver failed once)
    // and a dead-letter message of the victim; a bystander's delivery.
    publish_for(&s, DomainEventKind::MemberAdded, victim).await;
    publish_for(&s, DomainEventKind::MemberAdded, bystander).await;
    s.drain().await;
    s.http.push_full(500, None, "");
    publish_for(&s, DomainEventKind::MemberRemoved, victim).await;
    s.drain().await;
    sqlx::query(
        "INSERT INTO outbox (id, topic, payload, status, attempts, max_attempts, available_at, \
         created_at) VALUES ($1, 'notification.email', $2, 'dead', 10, 10, $3, $3)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(json!({ "v": 1, "user_id": victim, "recipient": "v***@example.com" }))
    .bind(s.h.now())
    .execute(&pool)
    .await
    .unwrap();
    let finished_id: String = sqlx::query_scalar(
        "SELECT id::text FROM webhook_deliveries WHERE event_type = 'member.added' \
         AND subject_user_id = $1",
    )
    .bind(victim)
    .fetch_one(&pool)
    .await
    .unwrap();

    // The erasure transaction (authn-account ACC-09): `user.deleted`, then
    // the pseudonymisation.
    let mut tx = pool.begin().await.unwrap();
    let mut deleted = DomainEvent::new(
        DomainEventKind::UserDeleted,
        s.h.now(),
        json!({ "user_id": victim }),
    );
    deleted.org_id = Some(s.org);
    deleted.user_id = Some(victim);
    s.h.service
        .event_publisher()
        .publish(&mut tx, deleted)
        .await
        .unwrap();
    s.h.service
        .sink()
        .pseudonymize_subject(&mut tx, victim)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Finished rows: scrubbed at once. Unfinished ones still carry the id
    // until they are delivered.
    let redacted: Value =
        sqlx::query_scalar("SELECT payload FROM webhook_deliveries WHERE id::text = $1")
            .bind(&finished_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(redacted["redacted"], true);
    assert_eq!(redacted["type"], "member.added");
    assert!(redacted.get("user_id").is_none() && redacted.get("data").is_none());
    assert_eq!(
        mentions(&pool, victim).await,
        vec![
            "delivery:failed:member.removed",
            "outbox:pending:domain_event",
        ]
    );

    // Receivers still get every event, `user.deleted` included...
    s.h.ports.clock.advance(Duration::from_secs(61));
    s.drain().await;
    let sent: Vec<Value> = s
        .http
        .requests()
        .iter()
        .map(|r| serde_json::from_slice(r.body.as_ref().unwrap()).unwrap())
        .collect();
    assert!(
        sent.iter()
            .any(|b| b["type"] == "user.deleted" && b["user_id"] == victim.to_string())
    );
    assert!(sent.iter().any(|b| b["type"] == "member.removed"));
    // ... and afterwards nothing mentions the erased account any more; the
    // bystander's history is untouched.
    assert_eq!(mentions(&pool, victim).await, Vec::<String>::new());
    assert_eq!(
        mentions(&pool, bystander).await,
        vec!["delivery:succeeded:member.added"]
    );

    // A redacted delivery cannot be sent again.
    TestRequest::post(&format!(
        "/v1/orgs/{}/webhooks/{endpoint_id}/deliveries/{finished_id}/redeliver",
        s.org
    ))
    .send(&s.admin_app())
    .await
    .assert_error(StatusCode::NOT_FOUND, "not_found");
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn aud_05_k58_deliveries_that_die_after_the_erasure_are_redacted(pool: PgPool) {
    let mut config = AuditConfig::default();
    config.webhooks.max_attempts = 1;
    let s = Setup::with_config(pool.clone(), &config).await;
    s.create(URL, &["user.deleted"]).await;
    let victim = create_user(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let mut deleted = DomainEvent::new(
        DomainEventKind::UserDeleted,
        s.h.now(),
        json!({ "user_id": victim }),
    );
    deleted.org_id = Some(s.org);
    deleted.user_id = Some(victim);
    s.h.service
        .event_publisher()
        .publish(&mut tx, deleted)
        .await
        .unwrap();
    s.h.service
        .sink()
        .pseudonymize_subject(&mut tx, victim)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    s.http.push_full(500, None, "");
    s.drain().await;
    assert_eq!(s.deliveries().await[0].0, "dead");
    assert_eq!(mentions(&pool, victim).await, Vec::<String>::new());
}
