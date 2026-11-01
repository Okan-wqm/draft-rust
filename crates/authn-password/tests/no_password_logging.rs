#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! PWD-05 (and AUD-03 / OPS-03): passwords, tokens and codes never reach the
//! logs. A process-wide `tracing` subscriber captures every span and event
//! at TRACE level (this file is its own test binary, so installing the
//! global subscriber cannot interfere with other tests).

mod common;

use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use authn_testkit::http::TestRequest;
use common::{Harness, STRONG};
use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<String>>);

struct Writer<'a>(&'a mut String);

impl Visit for Writer<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

struct CaptureSubscriber {
    out: Capture,
    next_id: AtomicU64,
}

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, span: &Attributes<'_>) -> Id {
        let mut out = self.out.0.lock().unwrap();
        span.record(&mut Writer(&mut out));
        out.push('\n');
        Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed))
    }
    fn record(&self, _: &Id, values: &Record<'_>) {
        let mut out = self.out.0.lock().unwrap();
        values.record(&mut Writer(&mut out));
        out.push('\n');
    }
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut out = self.out.0.lock().unwrap();
        out.push_str(event.metadata().target());
        out.push(' ');
        event.record(&mut Writer(&mut out));
        out.push('\n');
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn capture() -> Capture {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    CAPTURE
        .get_or_init(|| {
            let out = Capture::default();
            tracing::subscriber::set_global_default(CaptureSubscriber {
                out: out.clone(),
                next_id: AtomicU64::new(1),
            })
            .expect("first global subscriber of this test binary");
            out
        })
        .clone()
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_05_passwords_tokens_and_codes_never_appear_in_logs(pool: sqlx::PgPool) {
    let logs = capture();
    let h = Harness::new(pool).await;
    let user = h.user("logs@example.com", Some(STRONG)).await;
    let app = h.app();
    let secrets = [
        "Mysecret pass phrase 0451",
        "hunter2hunter2hunter2",
        "987654321123",
    ];
    // Live check: acceptable, weak, and a body with a type error that serde
    // would quote.
    for body in [
        json!({"password": secrets[0]}),
        json!({"password": secrets[1], "email": "logs@example.com"}),
        json!({"password": 987_654_321_123_u64}),
    ] {
        TestRequest::post("/v1/password/check")
            .json(&body)
            .send(&app)
            .await;
    }
    // Change with a wrong current password, reset with policy violations and
    // a full successful reset.
    let principal_app = h.app_as(h.principal(user, std::time::Duration::from_secs(5)));
    TestRequest::post("/v1/me/password/change")
        .json(&json!({"current_password": secrets[1], "new_password": secrets[0]}))
        .send(&principal_app)
        .await;
    let (token, code) = h.forgot("logs@example.com").await;
    let code = code.unwrap();
    TestRequest::post("/v1/password/reset")
        .json(&json!({"token": token, "new_password": secrets[1]}))
        .send(&app)
        .await;
    TestRequest::post("/v1/password/reset")
        .json(&json!({"email": "logs@example.com", "code": code, "new_password": "short"}))
        .send(&app)
        .await;
    TestRequest::post("/v1/password/reset")
        .json(&json!({"token": token, "new_password": "brand new strong phrase 7781"}))
        .send(&app)
        .await
        .assert_status(http::StatusCode::OK);

    let captured = logs.0.lock().unwrap().clone();
    assert!(!captured.is_empty(), "the subscriber saw the request logs");
    // (The 6-digit code is not searched for: six digits can legitimately
    // occur in ids and durations. It travels in the same bodies as the
    // secrets checked here.)
    for secret in secrets
        .iter()
        .copied()
        .chain([token.as_str(), "brand new strong phrase"])
    {
        assert!(
            !captured.contains(secret),
            "secret leaked into logs: {secret}\n{captured}"
        );
    }
}
