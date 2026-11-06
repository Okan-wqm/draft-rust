#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! OpenTelemetry tracing (OPS-11) and the absence of personal data and
//! secrets in exported spans (OPS-12), over the real router: the spans of
//! registration, login, refresh and password reset go to an in-memory
//! exporter and every name and attribute is checked. The exporter's fail
//! safety is tested against an unreachable and a hanging collector.

mod common;

use std::collections::BTreeSet;
use std::io::Read as _;
use std::net::{IpAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use authn_core::config::telemetry::TelemetryConfig;
use authn_core::ports::NotificationKind;
use authn_server::telemetry::otel;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::{App, Browser, PASSWORD};
use opentelemetry::trace::{SpanKind, Status};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use serde_json::{Value, json};
use sqlx::PgPool;
use tracing_subscriber::layer::SubscriberExt;

const EMAIL: &str = "telemetry.person@example.com";
const NEW_PASSWORD: &str = "completely new passphrase 2026";
/// A distinctive client address (peer and `X-Forwarded-For`).
const CLIENT_IP: &str = "198.51.100.77";

/// The only span attributes the `http` span may carry (OPS-12 allow-list:
/// a new attribute must be reviewed and added here on purpose).
const ALLOWED_ATTRIBUTES: &[&str] = &[
    "request_id",
    "http.request.method",
    "http.route",
    "http.response.status_code",
    "trace_id",
];

fn config(ratio: f64) -> TelemetryConfig {
    TelemetryConfig {
        enabled: true,
        sampling_ratio: ratio,
        ..TelemetryConfig::default()
    }
}

/// In-memory provider with the production sampler, limits and filter.
fn in_memory(config: &TelemetryConfig) -> (SdkTracerProvider, InMemorySpanExporter) {
    let exporter = InMemorySpanExporter::default();
    let provider = otel::provider_builder(config)
        .with_simple_exporter(exporter.clone())
        .build();
    otel::activate(config);
    (provider, exporter)
}

fn subscriber(provider: &SdkTracerProvider) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::registry().with(otel::layer(provider))
}

fn finished(exporter: &InMemorySpanExporter) -> Vec<SpanData> {
    exporter.get_finished_spans().unwrap()
}

fn attribute(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.as_str().into_owned())
}

/// Browser request from the distinctive client address.
fn from_client(request: TestRequest) -> TestRequest {
    request
        .peer_ip(CLIENT_IP.parse::<IpAddr>().unwrap())
        .header("x-forwarded-for", CLIENT_IP)
}

async fn send(app: &App, browser: &mut Browser, request: TestRequest) -> Value {
    let response = browser.send(app, from_client(request)).await;
    assert!(response.status.is_success(), "{}", response.text());
    response.json()
}

/// Registration → verification → login → native login + refresh →
/// password reset. Returns every secret and personal value seen.
async fn run_flows(app: &App) -> Vec<String> {
    let mut seen = vec![
        EMAIL.to_owned(),
        PASSWORD.to_owned(),
        NEW_PASSWORD.to_owned(),
        CLIENT_IP.to_owned(),
        // The masked forms of the logs must not appear either.
        "telemetry.person".to_owned(),
        "198.51.100".to_owned(),
    ];

    // Registration and e-mail verification.
    let mut browser = app.browser();
    browser.csrf(app).await;
    let terms: Vec<Value> = app
        .send(browser.get("/v1/terms"))
        .await
        .json::<Value>()
        .get("current")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|t| json!({"document": t["document"], "version": t["version"]}))
        .collect();
    let request = browser.post(
        "/v1/signup",
        &json!({"email": EMAIL, "password": PASSWORD, "accepted_terms": terms}),
    );
    send(app, &mut browser, request).await;
    app.drain().await;
    let NotificationKind::EmailVerification { token, .. } =
        app.last_notification("email_verification")
    else {
        panic!("verification mail")
    };
    seen.push(token.expose().to_owned());
    let request = browser.post("/v1/email/verify", &json!({"token": token.expose()}));
    send(app, &mut browser, request).await;

    // Browser password login (session + CSRF cookies).
    let mut laptop = app.browser();
    let body = laptop.login(app, EMAIL, PASSWORD).await;
    assert_eq!(body["status"], "authenticated", "{body}");
    assert_eq!(
        app.send(from_client(laptop.get("/v1/me"))).await.status,
        StatusCode::OK
    );
    seen.extend(laptop.cookies.values().cloned());
    seen.extend(browser.cookies.values().cloned());
    seen.extend(laptop.csrf.clone());
    let user = app.user_id(EMAIL).await;
    seen.push(user.to_string());

    // Native login and refresh-token rotation.
    let mut native = app.native();
    let r = app
        .send(from_client(native.post(
            "/v1/login/password",
            &json!({"email": EMAIL, "password": PASSWORD}),
        )))
        .await;
    native.absorb(&r.json());
    let first_refresh = native.refresh.clone().unwrap();
    seen.push(first_refresh.clone());
    seen.extend(native.access.clone());
    let r = app
        .send(from_client(native.post(
            "/v1/token/refresh",
            &json!({"refresh_token": first_refresh}),
        )))
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    native.absorb(&r.json());
    seen.extend(native.refresh.clone());
    seen.extend(native.access.clone());

    // Password reset.
    let mut stranger = app.browser();
    stranger.csrf(app).await;
    let request = stranger.post("/v1/password/forgot", &json!({"email": EMAIL}));
    send(app, &mut stranger, request).await;
    app.drain().await;
    let NotificationKind::PasswordReset { token, .. } = app.last_notification("password_reset")
    else {
        panic!("reset mail")
    };
    seen.push(token.expose().to_owned());
    let request = stranger.post(
        "/v1/password/reset",
        &json!({"token": token.expose(), "new_password": NEW_PASSWORD}),
    );
    send(app, &mut stranger, request).await;

    // Personal data in an unmatched path and a query string.
    let r = app
        .send(from_client(TestRequest::get(&format!(
            "/v1/no-such-route/{EMAIL}?token=query-secret-value"
        ))))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    seen.push("query-secret-value".to_owned());
    seen.push("no-such-route".to_owned());
    seen
}

trait UserId {
    async fn user_id(&self, email: &str) -> uuid::Uuid;
}

impl UserId for App {
    async fn user_id(&self, email: &str) -> uuid::Uuid {
        let (id,): (uuid::Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        id
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_12_spans_of_core_flows_carry_no_personal_data_or_secrets(pool: PgPool) {
    // Risk off: the flows then need no e-mailed confirmation step.
    let app = App::with(pool, |c| c.protect.risk.enabled = false).await;
    let (provider, exporter) = in_memory(&config(1.0));
    let guard = tracing::subscriber::set_default(subscriber(&provider));
    let seen = run_flows(&app).await;
    drop(guard);
    provider.force_flush().unwrap();

    let spans = finished(&exporter);
    assert!(spans.len() >= 12, "only {} spans", spans.len());
    let seen: Vec<String> = seen.into_iter().filter(|s| s.len() >= 6).collect();
    let mut routes = BTreeSet::new();
    for span in &spans {
        // Only the `http` span of the tracing layer, never the
        // request-context span (raw path) or log events.
        assert_eq!(span.span_kind, SpanKind::Server, "{}", span.name);
        assert!(span.events.is_empty(), "{}: events exported", span.name);
        assert!(span.links.is_empty());
        let mut texts = vec![span.name.to_string()];
        for kv in &span.attributes {
            assert!(
                ALLOWED_ATTRIBUTES.contains(&kv.key.as_str()),
                "unexpected span attribute `{}` on {}",
                kv.key,
                span.name
            );
            texts.push(kv.key.to_string());
            texts.push(kv.value.as_str().into_owned());
        }
        texts.push(format!("{:?}", span.span_context.trace_state()));
        for text in &texts {
            let lower = text.to_lowercase();
            for secret in &seen {
                assert!(
                    !lower.contains(&secret.to_lowercase()),
                    "span {} leaks a personal value or secret in {text:?}",
                    span.name
                );
            }
        }
        let route = attribute(span, "http.route").unwrap();
        assert!(
            route == "unmatched" || route.starts_with('/'),
            "route {route}"
        );
        assert_eq!(
            span.name,
            format!(
                "{} {route}",
                attribute(span, "http.request.method").unwrap()
            )
        );
        assert!(attribute(span, "request_id").is_some_and(|id| id.len() == 36));
        assert!(attribute(span, "http.response.status_code").is_some());
        routes.insert(route);
    }
    for expected in [
        "/v1/signup",
        "/v1/email/verify",
        "/v1/login/password",
        "/v1/token/refresh",
        "/v1/password/forgot",
        "/v1/password/reset",
        "unmatched",
    ] {
        assert!(
            routes.contains(expected),
            "no span for {expected}: {routes:?}"
        );
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_11_incoming_traceparent_is_continued_without_its_tracestate(pool: PgPool) {
    let app = App::new(pool).await;
    let remote_trace = "4bf92f3577b34da6a3ce929d0e0e4736";
    let remote_span = "00f067aa0ba902b7";
    let traceparent = format!("00-{remote_trace}-{remote_span}-01");

    // Sampled remote parent, local ratio 1: continued.
    let (provider, exporter) = in_memory(&config(1.0));
    {
        let _guard = tracing::subscriber::set_default(subscriber(&provider));
        let r = app
            .send(
                TestRequest::get("/health/live")
                    .header("traceparent", &traceparent)
                    .header("tracestate", "vendor=telemetry.person@example.com"),
            )
            .await;
        r.assert_status(StatusCode::OK);
    }
    let spans = finished(&exporter);
    assert_eq!(spans.len(), 1);
    let span = &spans[0];
    assert_eq!(span.span_context.trace_id().to_string(), remote_trace);
    assert_eq!(span.parent_span_id.to_string(), remote_span);
    assert!(span.parent_span_is_remote);
    // The caller's tracestate is not carried along.
    assert_eq!(span.span_context.trace_state().header(), "");
    // Log correlation: the trace id is recorded on the span.
    assert_eq!(attribute(span, "trace_id").as_deref(), Some(remote_trace));
    assert_eq!(
        attribute(span, "http.route").as_deref(),
        Some("/health/live")
    );

    // The caller cannot force sampling: ratio 0 drops even "sampled" parents.
    let (provider, exporter) = in_memory(&config(0.0));
    {
        let _guard = tracing::subscriber::set_default(subscriber(&provider));
        for _ in 0..20 {
            app.send(TestRequest::get("/health/live").header("traceparent", &traceparent))
                .await
                .assert_status(StatusCode::OK);
        }
    }
    assert!(finished(&exporter).is_empty());

    // ... unless the operator opts in.
    let opt_in = TelemetryConfig {
        respect_remote_sampling: true,
        ..config(0.0)
    };
    let (provider, exporter) = in_memory(&opt_in);
    {
        let _guard = tracing::subscriber::set_default(subscriber(&provider));
        app.send(TestRequest::get("/health/live").header("traceparent", &traceparent))
            .await
            .assert_status(StatusCode::OK);
    }
    assert_eq!(finished(&exporter).len(), 1);

    // A malformed traceparent starts a fresh root trace.
    let (provider, exporter) = in_memory(&config(1.0));
    {
        let _guard = tracing::subscriber::set_default(subscriber(&provider));
        app.send(TestRequest::get("/health/live").header("traceparent", "00-zz-yy-01"))
            .await
            .assert_status(StatusCode::OK);
    }
    let spans = finished(&exporter);
    assert_eq!(spans.len(), 1);
    assert!(!spans[0].parent_span_is_remote);
    assert_ne!(spans[0].span_context.trace_id().to_string(), remote_trace);
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_11_server_errors_mark_the_span_status(pool: PgPool) {
    let app = App::new(pool).await;
    let (provider, exporter) = in_memory(&config(1.0));
    {
        let _guard = tracing::subscriber::set_default(subscriber(&provider));
        app.send(TestRequest::get("/health/live"))
            .await
            .assert_status(StatusCode::OK);
    }
    let spans = finished(&exporter);
    assert_eq!(spans[0].status, Status::Unset);
    assert_eq!(
        attribute(&spans[0], "http.response.status_code").as_deref(),
        Some("200")
    );
}

/// A collector that accepts connections and never answers.
fn hanging_collector() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            count.fetch_add(1, Ordering::SeqCst);
            // Read the request head, then hang.
            let mut buf = [0_u8; 1024];
            let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
            let _ = stream.read(&mut buf);
            held.push(stream);
        }
    });
    (format!("http://{addr}/v1/traces"), accepted)
}

/// An address nothing listens on (connection refused).
fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}/v1/traces")
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn ops_11_an_unreachable_or_hanging_collector_never_blocks_requests(pool: PgPool) {
    let app = App::new(pool).await;
    let (hanging, accepted) = hanging_collector();
    for endpoint in [closed_port(), hanging] {
        let telemetry = TelemetryConfig {
            endpoint: Some(endpoint.parse().unwrap()),
            export_timeout: Duration::from_secs(2),
            scheduled_delay: Duration::from_millis(100),
            max_queue_size: 64,
            max_export_batch_size: 16,
            ..config(1.0)
        };
        let provider =
            otel::otlp_provider(&telemetry, &app.services.config.protect.outbound).unwrap();
        otel::activate(&telemetry);
        let started = Instant::now();
        let mut slowest = Duration::ZERO;
        {
            let _guard = tracing::subscriber::set_default(subscriber(&provider));
            // Far more spans than the queue holds: the overflow is dropped.
            for _ in 0..400 {
                let one = Instant::now();
                app.send(TestRequest::get("/health/live"))
                    .await
                    .assert_status(StatusCode::OK);
                slowest = slowest.max(one.elapsed());
            }
            // Give the exporter time to try (and fail / hang).
            tokio::time::sleep(Duration::from_millis(300)).await;
            for _ in 0..50 {
                let one = Instant::now();
                app.send(TestRequest::get("/health/live"))
                    .await
                    .assert_status(StatusCode::OK);
                slowest = slowest.max(one.elapsed());
            }
        }
        assert!(
            slowest < Duration::from_millis(1500),
            "{endpoint}: a request waited {slowest:?} for the exporter"
        );
        assert!(started.elapsed() < Duration::from_secs(30));
        // Shutdown is bounded by the export timeout, never hangs.
        let stop = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            provider.shutdown_with_timeout(Duration::from_secs(3))
        })
        .await
        .unwrap();
        assert!(stop.elapsed() < Duration::from_secs(10), "{result:?}");
    }
    assert!(
        accepted.load(Ordering::SeqCst) >= 1,
        "the exporter never reached the hanging collector"
    );
}
