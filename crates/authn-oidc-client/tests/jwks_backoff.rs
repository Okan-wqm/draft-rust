#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-16 (SOC-03): JWKS download failures back off per URL — during a
//! provider outage a flood of verifications does not become a flood of
//! requests to the provider.

mod common;

use std::time::Duration;

use authn_core::ports::OutboundTarget;
use authn_oidc_client::jwks::{JWKS_BACKOFF_MAX, JwksCache};
use authn_testkit::config::TestConfigBuilder;
use common::{KEY_A, public_jwk};
use serde_json::json;
use time::OffsetDateTime;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client() -> authn_protect::outbound::SsrfSafeHttpClient {
    authn_core::tls::install_crypto_provider();
    let config = TestConfigBuilder::new().build();
    authn_protect::outbound::SsrfSafeHttpClient::new(&config.protect.outbound).unwrap()
}

async fn mount_outage(server: &MockServer) {
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503))
        .mount(server)
        .await;
}

async fn mount_keys(server: &MockServer) {
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "keys": [public_jwk(KEY_A, "key-a")] })),
        )
        .mount(server)
        .await;
}

async fn hits(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

#[tokio::test]
async fn soc_03_jwks_outage_backs_off_exponentially() {
    let server = MockServer::start().await;
    let url = Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let http = client();
    let cache = JwksCache::new(Duration::from_secs(3600), Duration::from_secs(60));
    let t0 = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let at = |secs: i64| t0 + time::Duration::seconds(secs);
    let key = |now| cache.key(&http, &url, OutboundTarget::Trusted, "key-a", now);

    mount_outage(&server).await;
    // First failure: one request, then 5 s without any request.
    let err = key(at(0)).await.unwrap_err();
    assert!(err.is(authn_core::error::codes::common::SERVICE_UNAVAILABLE));
    assert_eq!(hits(&server).await, 1);
    for s in [1, 2, 4] {
        assert!(key(at(s)).await.is_err());
    }
    assert_eq!(hits(&server).await, 1, "backing off: no request");
    // After 5 s: one more attempt, then 10 s of quiet.
    assert!(key(at(5)).await.is_err());
    assert_eq!(hits(&server).await, 2);
    assert!(key(at(14)).await.is_err());
    assert_eq!(hits(&server).await, 2);
    // After 10 s more: third attempt, the wait doubles again (20 s).
    assert!(key(at(15)).await.is_err());
    assert_eq!(hits(&server).await, 3);
    assert!(key(at(34)).await.is_err());
    assert_eq!(hits(&server).await, 3);

    // The provider recovers: the next allowed attempt succeeds and resets
    // the backoff.
    mount_keys(&server).await;
    assert!(key(at(35)).await.unwrap().is_some());
    assert_eq!(hits(&server).await, 1);
    // Cached: no request for a known kid.
    assert!(key(at(36)).await.unwrap().is_some());
    assert_eq!(hits(&server).await, 1);
}

#[tokio::test]
async fn soc_03_jwks_backoff_is_bounded_and_keeps_stale_keys() {
    let server = MockServer::start().await;
    let url = Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let http = client();
    let ttl = Duration::from_secs(600);
    let cache = JwksCache::new(ttl, Duration::from_secs(60));
    let t0 = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let at = |secs: i64| t0 + time::Duration::seconds(secs);
    let key = |now| cache.key(&http, &url, OutboundTarget::Trusted, "key-a", now);

    mount_keys(&server).await;
    assert!(key(at(0)).await.unwrap().is_some());
    mount_outage(&server).await;

    // The cache is stale (ttl passed) and the provider is down: the stale
    // key still verifies, and during the backoff no request is made.
    let mut now = 700;
    assert!(key(at(now)).await.unwrap().is_some());
    assert_eq!(hits(&server).await, 1);
    assert!(key(at(now + 1)).await.unwrap().is_some());
    assert_eq!(hits(&server).await, 1);

    // Many failures: the wait never exceeds JWKS_BACKOFF_MAX.
    let max = i64::try_from(JWKS_BACKOFF_MAX.as_secs()).unwrap();
    for _ in 0..12 {
        now += max;
        assert!(key(at(now)).await.unwrap().is_some());
    }
    assert_eq!(hits(&server).await, 13, "one attempt per maximal backoff");
}
