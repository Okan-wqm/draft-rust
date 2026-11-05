#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-16 (SOC-03): JWKS download failures back off per URL — during a
//! provider outage a flood of verifications does not become a flood of
//! requests to the provider. K-61: stale keys are used only for a bounded
//! time.

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

/// K-61 (SOC-03): during a JWKS outage cached keys are used only until
/// they are `jwks_max_staleness` old; afterwards verification fails closed
/// with the stable `service_unavailable` code, and works again as soon as
/// the provider answers.
#[tokio::test]
async fn soc_03_k61_stale_keys_expire_after_the_max_staleness() {
    let server = MockServer::start().await;
    let url = Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let http = client();
    let cache = JwksCache::new(Duration::from_secs(600), Duration::from_secs(60))
        .with_max_staleness(Duration::from_secs(3 * 3600));
    let t0 = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let at = |secs: i64| t0 + time::Duration::seconds(secs);
    let key = |now| cache.key(&http, &url, OutboundTarget::Trusted, "key-a", now);

    mount_keys(&server).await;
    assert!(key(at(0)).await.unwrap().is_some());
    mount_outage(&server).await;
    // Within the bound: the stale key verifies (outage tolerance) — both
    // on a failed download and while backing off.
    assert!(key(at(2 * 3600)).await.unwrap().is_some());
    assert!(key(at(2 * 3600 + 1)).await.unwrap().is_some());
    assert!(key(at(3 * 3600)).await.unwrap().is_some());
    // Beyond it: fail closed, on a failed download and during the backoff.
    let err = key(at(3 * 3600 + 400)).await.unwrap_err();
    assert!(err.is(authn_core::error::codes::common::SERVICE_UNAVAILABLE));
    let err = key(at(3 * 3600 + 401)).await.unwrap_err();
    assert!(err.is(authn_core::error::codes::common::SERVICE_UNAVAILABLE));
    // The provider recovers: fresh keys verify again.
    mount_keys(&server).await;
    assert!(key(at(4 * 3600)).await.unwrap().is_some());

    // The bound is never below the cache lifetime.
    let floor = JwksCache::new(Duration::from_secs(600), Duration::from_secs(60))
        .with_max_staleness(Duration::from_secs(1));
    assert!(format!("{floor:?}").contains("max_staleness: 600s"));
}

/// K-61: the default bound is 24 hours.
#[tokio::test]
async fn soc_03_k61_default_max_staleness_is_a_day() {
    let server = MockServer::start().await;
    let url = Url::parse(&format!("{}/jwks", server.uri())).unwrap();
    let http = client();
    let cache = JwksCache::new(Duration::from_secs(600), Duration::from_secs(60));
    let t0 = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let at = |secs: i64| t0 + time::Duration::seconds(secs);
    let key = |now| cache.key(&http, &url, OutboundTarget::Trusted, "key-a", now);
    mount_keys(&server).await;
    assert!(key(at(0)).await.unwrap().is_some());
    mount_outage(&server).await;
    assert!(key(at(23 * 3600)).await.unwrap().is_some());
    assert!(key(at(24 * 3600 + 1000)).await.is_err());
}
