#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! NTF-04: the generic HTTP SMS provider through the `HttpClient` port.
#![cfg(feature = "sms")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::notify::{SmsConfig, SmsProviderKind};
use authn_core::domain::PhoneNumber;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{
    HttpClient, OutboundRequest, OutboundResponse, OutboundTarget, SmsMessage, SmsSender,
};
use authn_core::secret::{SecretString, SensitiveString};
use authn_notify::HttpSmsSender;
use authn_testkit::fakes::FakeHttpClient;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{Value, json};

const URL: &str = "https://sms.example.com/v1/send";
const API_KEY: &str = "sk_live_super_secret_sms_key";

fn config() -> SmsConfig {
    SmsConfig {
        provider: SmsProviderKind::Http,
        http_url: Some(URL.to_owned()),
        http_api_key: Some(SecretString::from(API_KEY.to_owned())),
        sender_id: Some("AUTHN".to_owned()),
        http_message_id_pointer: Some("/data/id".to_owned()),
        timeout: Duration::from_secs(7),
        ..SmsConfig::default()
    }
}

fn message(text: &str) -> SmsMessage {
    SmsMessage {
        to: PhoneNumber::parse("+905551112233").unwrap(),
        body: SensitiveString::new(text),
    }
}

/// Answers every request with a fixed status / headers and records them.
struct Canned {
    status: StatusCode,
    headers: HeaderMap,
    fail: bool,
    requests: Mutex<Vec<OutboundRequest>>,
}

impl Canned {
    fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            fail: false,
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl HttpClient for Canned {
    async fn execute(&self, request: OutboundRequest) -> Result<OutboundResponse, AuthError> {
        self.requests.lock().unwrap().push(request);
        if self.fail {
            return Err(AuthError::new(codes::common::SERVICE_UNAVAILABLE)
                .with_context("connection refused"));
        }
        Ok(OutboundResponse {
            status: self.status,
            headers: self.headers.clone(),
            body: br#"{"error":"echo of +905551112233"}"#.to_vec(),
        })
    }
}

#[tokio::test]
async fn ntf_04_http_provider_receives_a_json_request_with_the_secret_auth_header() {
    let http = Arc::new(FakeHttpClient::default());
    http.respond_json(
        Method::POST,
        URL,
        StatusCode::OK,
        &json!({"data": {"id": "msg-42"}}),
    );
    let sender = HttpSmsSender::from_config(&config(), http.clone()).unwrap();
    assert!(sender.is_configured());
    let text = "Kod: 468024 \"tırnak\" {{to}} \\\n@auth.test.example #468024";
    let receipt = sender.send(&message(text)).await.unwrap();
    assert_eq!(receipt.provider_message_id.as_deref(), Some("msg-42"));

    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.url.as_str(), URL);
    assert_eq!(request.target, OutboundTarget::Trusted);
    assert_eq!(request.timeout, Some(Duration::from_secs(7)));
    assert!(request.max_response_bytes.is_some());
    let auth = request.headers.get("authorization").unwrap();
    assert_eq!(auth, &format!("Bearer {API_KEY}"));
    assert!(auth.is_sensitive());
    assert_eq!(
        request.headers.get("content-type").unwrap(),
        "application/json"
    );
    let body: Value = serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"to": "+905551112233", "text": text, "from": "AUTHN"})
    );
    // Neither the key nor the code shows up in Debug output.
    let debug = format!("{request:?} {sender:?}");
    assert!(
        !debug.contains(API_KEY) && !debug.contains("468024"),
        "{debug}"
    );
}

#[tokio::test]
async fn ntf_04_custom_auth_header_and_body_template() {
    let http = Arc::new(FakeHttpClient::default());
    http.respond(Method::POST, URL, StatusCode::ACCEPTED, "");
    let mut config = config();
    config.http_auth_header = "x-api-key".to_owned();
    config.http_auth_scheme = String::new();
    config.http_body_template =
        r#"{"messages":[{"destination":"{{to}}","content":{"text":"{{text}}"}}],"originator":"{{sender_id}}"}"#
            .to_owned();
    config.http_message_id_pointer = None;
    let sender = HttpSmsSender::from_config(&config, http.clone()).unwrap();
    let receipt = sender.send(&message("123456 is your code")).await.unwrap();
    assert_eq!(receipt.provider_message_id, None);
    let request = &http.requests()[0];
    assert_eq!(request.headers.get("x-api-key").unwrap(), API_KEY);
    assert!(request.headers.get("authorization").is_none());
    let body: Value = serde_json::from_slice(request.body.as_deref().unwrap()).unwrap();
    assert_eq!(body["messages"][0]["destination"], "+905551112233");
    assert_eq!(
        body["messages"][0]["content"]["text"],
        "123456 is your code"
    );
    assert_eq!(body["originator"], "AUTHN");
}

#[tokio::test]
async fn ntf_04_provider_responses_are_classified_for_retry() {
    let cases = [
        (
            StatusCode::TOO_MANY_REQUESTS,
            codes::common::SERVICE_UNAVAILABLE,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            codes::common::SERVICE_UNAVAILABLE,
        ),
        (StatusCode::BAD_GATEWAY, codes::common::SERVICE_UNAVAILABLE),
        (
            StatusCode::REQUEST_TIMEOUT,
            codes::common::SERVICE_UNAVAILABLE,
        ),
        (StatusCode::BAD_REQUEST, codes::notify::DELIVERY_REJECTED),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            codes::notify::DELIVERY_REJECTED,
        ),
        (StatusCode::FORBIDDEN, codes::notify::DELIVERY_REJECTED),
    ];
    for (status, expected) in cases {
        let http = Arc::new(Canned::new(status));
        let sender = HttpSmsSender::from_config(&config(), http).unwrap();
        let err = sender.send(&message("123456")).await.unwrap_err();
        assert_eq!(err.code(), expected, "{status}");
        // Provider response bodies never reach the error.
        assert!(!format!("{err:?}").contains("5551112233"));
    }
}

#[tokio::test]
async fn ntf_04_retry_after_is_honoured_and_capped() {
    for (header, expected) in [("30", 30), ("999999", 3600)] {
        let mut canned = Canned::new(StatusCode::TOO_MANY_REQUESTS);
        canned
            .headers
            .insert("retry-after", HeaderValue::from_static(header));
        let sender = HttpSmsSender::from_config(&config(), Arc::new(canned)).unwrap();
        let err = sender.send(&message("123456")).await.unwrap_err();
        assert_eq!(err.retry_after(), Some(Duration::from_secs(expected)));
    }
}

#[tokio::test]
async fn ntf_04_transport_errors_are_retryable() {
    let mut canned = Canned::new(StatusCode::OK);
    canned.fail = true;
    let sender = HttpSmsSender::from_config(&config(), Arc::new(canned)).unwrap();
    let err = sender.send(&message("123456")).await.unwrap_err();
    assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn ntf_04_invalid_bodies_are_never_sent() {
    let http = Arc::new(Canned::new(StatusCode::OK));
    let sender = HttpSmsSender::from_config(&config(), http.clone()).unwrap();
    for body in ["", "code 123456\r\nX-Injected: 1", &"x".repeat(1601)] {
        let err = sender.send(&message(body)).await.unwrap_err();
        assert_eq!(err.code(), codes::notify::DELIVERY_REJECTED);
    }
    assert!(http.requests.lock().unwrap().is_empty());
}

#[test]
fn ntf_04_e164_numbers_only() {
    for bad in [
        "05551112233",
        "+90 555 111 22 33",
        "+0123456789",
        "tel:+905551112233",
    ] {
        assert!(PhoneNumber::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn ntf_04_http_provider_configuration_is_checked_at_startup() {
    let http: Arc<dyn HttpClient> = Arc::new(FakeHttpClient::default());
    let mut plain_http = config();
    plain_http.http_url = Some("http://sms.example.com/send".to_owned());
    let mut header_injection = config();
    header_injection.http_api_key = Some(SecretString::from("key\r\nX-Evil: 1".to_owned()));
    let mut no_key = config();
    no_key.http_api_key = None;
    let mut bad_template = config();
    bad_template.http_body_template = "[\"{{to}}\"]".to_owned();
    for (name, config) in [
        ("plain http", plain_http),
        ("CRLF in key", header_injection),
        ("missing key", no_key),
        ("non-object template", bad_template),
    ] {
        let err = HttpSmsSender::from_config(&config, http.clone()).unwrap_err();
        assert!(
            !err.to_string().contains("key\r\n"),
            "{name}: secret leaked"
        );
    }
}
