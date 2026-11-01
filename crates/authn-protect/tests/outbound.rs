#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! SSRF-safe outbound HTTP against local mock servers (PRT-12, TST-02 SSRF).
//! No external network is used (TST-08): names resolve through a static
//! table.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use authn_core::config::protect::OutboundHttpConfig;
use authn_core::error::codes;
use authn_core::ports::{HttpClient, OutboundRequest, OutboundTarget};
use authn_protect::outbound::{SsrfSafeHttpClient, StaticResolver};
use http::StatusCode;
use url::Url;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LOCALHOST: &str = "127.0.0.1";

fn config(allow_private: bool) -> OutboundHttpConfig {
    OutboundHttpConfig {
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        max_response_bytes: 1024,
        allow_private_networks: allow_private,
    }
}

fn client(allow_private: bool, resolver: Arc<StaticResolver>) -> SsrfSafeHttpClient {
    SsrfSafeHttpClient::with_resolver(&config(allow_private), resolver).unwrap()
}

fn localhost() -> IpAddr {
    LOCALHOST.parse().unwrap()
}

fn get(url: &str, target: OutboundTarget) -> OutboundRequest {
    OutboundRequest::get(Url::parse(url).unwrap(), target)
}

#[tokio::test]
async fn prt_12_user_supplied_url_resolving_to_loopback_is_refused_without_connecting() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let port = server.address().port();
    let resolver = Arc::new(StaticResolver::new().with("rebind.test", &[localhost()]));
    let client = client(false, resolver.clone());

    // Name resolving to loopback.
    let err = client
        .execute(get(
            &format!("https://rebind.test:{port}/hook"),
            OutboundTarget::UserSupplied,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::protect::OUTBOUND_DESTINATION_NOT_ALLOWED);
    assert_eq!(resolver.lookups(), 1, "exactly one resolution");

    // IP literals never reach the resolver and are refused up front.
    for url in [
        format!("https://127.0.0.1:{port}/hook"),
        format!("https://[::ffff:127.0.0.1]:{port}/hook"),
        format!("https://2130706433:{port}/hook"),
        format!("http://127.0.0.1:{port}/hook"),
        "https://169.254.169.254/latest/meta-data/iam/".to_owned(),
    ] {
        let err = client
            .execute(get(&url, OutboundTarget::UserSupplied))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            codes::protect::OUTBOUND_DESTINATION_NOT_ALLOWED,
            "{url}"
        );
    }
    assert_eq!(resolver.lookups(), 1);
    // `expect(0)` is verified when the server drops.
}

#[tokio::test]
async fn prt_12_connection_is_pinned_to_the_vetted_resolution() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(202).set_body_string("accepted"))
        .expect(1)
        .mount(&server)
        .await;
    let port = server.address().port();
    // `pinned.test` exists only in our resolver: reaching the mock proves the
    // connector used the vetted answer and did not resolve again elsewhere.
    let resolver = Arc::new(StaticResolver::new().with("pinned.test", &[localhost()]));
    let client = client(true, resolver.clone());
    let mut request = OutboundRequest::post(
        Url::parse(&format!("http://pinned.test:{port}/hook")).unwrap(),
        b"{}".to_vec(),
        OutboundTarget::UserSupplied,
    );
    request
        .headers
        .insert(http::header::HOST, "internal.admin".parse().unwrap());
    let response = client.execute(request).await.unwrap();
    assert_eq!(response.status, StatusCode::ACCEPTED);
    assert_eq!(response.body, b"accepted");
    assert_eq!(resolver.lookups(), 1);
    let received = server.received_requests().await.unwrap();
    let host = received[0].headers.get("host").unwrap().to_str().unwrap();
    assert_eq!(
        host,
        format!("pinned.test:{port}"),
        "caller Host header dropped"
    );
}

#[tokio::test]
async fn prt_12_redirects_are_not_followed() {
    let internal = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&internal)
        .await;
    let public = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/admin", internal.uri()).as_str()),
        )
        .mount(&public)
        .await;
    let resolver = Arc::new(StaticResolver::new());
    for target in [OutboundTarget::Trusted, OutboundTarget::UserSupplied] {
        let response = client(true, resolver.clone())
            .execute(get(&format!("{}/start", public.uri()), target))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::FOUND);
        assert!(response.headers.get("location").is_some());
    }
}

#[tokio::test]
async fn prt_12_response_size_is_capped() {
    let server = MockServer::start().await;
    Mock::given(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 4096]))
        .mount(&server)
        .await;
    Mock::given(path("/small"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 512]))
        .mount(&server)
        .await;
    let client = client(true, Arc::new(StaticResolver::new()));
    let err = client
        .execute(get(
            &format!("{}/big", server.uri()),
            OutboundTarget::Trusted,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
    let ok = client
        .execute(get(
            &format!("{}/small", server.uri()),
            OutboundTarget::Trusted,
        ))
        .await
        .unwrap();
    assert_eq!(ok.body.len(), 512);
    // A per-request override cannot be used to read more than asked.
    let mut request = get(&format!("{}/small", server.uri()), OutboundTarget::Trusted);
    request.max_response_bytes = Some(100);
    assert!(client.execute(request).await.is_err());
}

#[tokio::test]
async fn prt_12_slow_responses_time_out() {
    let server = MockServer::start().await;
    Mock::given(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&server)
        .await;
    let client = client(true, Arc::new(StaticResolver::new()));
    let mut request = get(&format!("{}/slow", server.uri()), OutboundTarget::Trusted);
    request.timeout = Some(Duration::from_millis(200));
    let started = std::time::Instant::now();
    let err = client.execute(request).await.unwrap_err();
    assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(err.context(), Some("outbound request timed out"));
}

#[tokio::test]
async fn prt_12_trusted_targets_may_be_internal_and_keep_headers() {
    let server = MockServer::start().await;
    Mock::given(path("/range/ABCDE"))
        .and(header_exists("add-padding"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;
    // Even with the development switch off, operator-configured endpoints
    // (e.g. an internal SMS gateway) are reachable.
    let client = client(false, Arc::new(StaticResolver::new()));
    let mut request = get(
        &format!("{}/range/ABCDE", server.uri()),
        OutboundTarget::Trusted,
    );
    request
        .headers
        .insert("add-padding", "true".parse().unwrap());
    let response = client.execute(request).await.unwrap();
    assert_eq!(response.body, b"ok");
}

#[tokio::test]
async fn prt_12_errors_never_contain_the_url_query() {
    let client = client(false, Arc::new(StaticResolver::new()));
    let err = client
        .execute(get(
            "https://unknown.test/hook?token=s3cr3t",
            OutboundTarget::UserSupplied,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::common::SERVICE_UNAVAILABLE);
    let debug = format!("{err:?} {err}");
    assert!(!debug.contains("s3cr3t"), "{debug}");
}
