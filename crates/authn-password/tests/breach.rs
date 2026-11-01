#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! PWD-03: HIBP Pwned Passwords range API (k-anonymity, `Add-Padding`),
//! padded responses, outages and the offline list — through the
//! `HttpClient` port fake.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::password::BreachCheckConfig;
use authn_core::error::AuthError;
use authn_core::ports::{
    BreachStatus, BreachedPasswordChecker, HttpClient, OutboundRequest, OutboundResponse,
    OutboundTarget,
};
use authn_core::secret::SecretString;
use authn_password::{HibpBreachChecker, OfflineBreachList};
use authn_testkit::fakes::FakeHttpClient;
use http::{Method, StatusCode};

const BASE: &str = "https://api.pwnedpasswords.com/range/";
// SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
const PREFIX: &str = "5BAA6";
const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

fn padded_body(hit: Option<u64>) -> String {
    // A realistic padded answer: real entries, padding entries (count 0)
    // and CRLF line endings.
    let mut body = String::new();
    for i in 0..400_u32 {
        body.push_str(&format!("{:035X}:{}\r\n", u128::from(i) * 7919, i % 50 + 1));
    }
    if let Some(count) = hit {
        body.push_str(&format!("{SUFFIX}:{count}\r\n"));
    }
    for i in 0..400_u32 {
        body.push_str(&format!("F{:034X}:0\r\n", u128::from(i) * 104_729));
    }
    body
}

fn checker(http: Arc<FakeHttpClient>) -> HibpBreachChecker {
    HibpBreachChecker::new(http, Some(BASE), Duration::from_secs(3), None).unwrap()
}

fn pw(value: &str) -> SecretString {
    SecretString::from(value)
}

#[tokio::test]
async fn pwd_03_only_the_five_character_prefix_is_sent_with_padding() {
    let http = Arc::new(FakeHttpClient::default());
    http.respond(
        Method::GET,
        &format!("{BASE}{PREFIX}"),
        StatusCode::OK,
        padded_body(Some(9_545_824)),
    );
    let status = checker(http.clone()).check(&pw("password")).await.unwrap();
    assert_eq!(
        status,
        BreachStatus::Breached {
            occurrences: 9_545_824
        }
    );
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, Method::GET);
    assert_eq!(request.url.as_str(), format!("{BASE}{PREFIX}"));
    assert!(request.url.query().is_none());
    assert!(!request.url.as_str().contains(SUFFIX));
    assert_eq!(request.url.path(), "/range/5BAA6");
    assert_eq!(request.headers["add-padding"], "true");
    assert!(request.headers.contains_key(http::header::USER_AGENT));
    assert!(request.body.is_none());
    assert_eq!(request.target, OutboundTarget::Trusted);
    assert_eq!(request.timeout, Some(Duration::from_secs(3)));
    assert!(request.max_response_bytes.is_some());
}

#[tokio::test]
async fn pwd_03_padding_entries_and_absent_suffixes_are_not_breaches() {
    let http = Arc::new(FakeHttpClient::default());
    http.respond(
        Method::GET,
        &format!("{BASE}{PREFIX}"),
        StatusCode::OK,
        padded_body(None),
    );
    assert_eq!(
        checker(http.clone()).check(&pw("password")).await.unwrap(),
        BreachStatus::NotFound
    );
    // Our own suffix listed as padding (count 0) is still not a breach.
    http.respond(
        Method::GET,
        &format!("{BASE}{PREFIX}"),
        StatusCode::OK,
        format!("{}{SUFFIX}:0\r\n", padded_body(None)),
    );
    assert_eq!(
        checker(http).check(&pw("password")).await.unwrap(),
        BreachStatus::NotFound
    );
}

#[tokio::test]
async fn pwd_03_outages_and_bad_answers_yield_unknown() {
    // No canned response: the fake fails like a timeout / connection error.
    let http = Arc::new(FakeHttpClient::default());
    assert_eq!(
        checker(http.clone()).check(&pw("password")).await.unwrap(),
        BreachStatus::Unknown
    );
    for (status, body) in [
        (StatusCode::INTERNAL_SERVER_ERROR, "oops".to_owned()),
        (StatusCode::TOO_MANY_REQUESTS, String::new()),
        (StatusCode::OK, "<html>captive portal</html>".to_owned()),
        (StatusCode::OK, String::new()),
    ] {
        http.respond(Method::GET, &format!("{BASE}{PREFIX}"), status, body);
        assert_eq!(
            checker(http.clone()).check(&pw("password")).await.unwrap(),
            BreachStatus::Unknown,
            "{status}"
        );
    }
}

#[tokio::test]
async fn pwd_03_disabled_hibp_makes_no_request() {
    let http = Arc::new(FakeHttpClient::default());
    let config = BreachCheckConfig {
        enabled: false,
        ..BreachCheckConfig::default()
    };
    let checker = HibpBreachChecker::from_config(&config, http.clone()).unwrap();
    assert_eq!(
        checker.check(&pw("password")).await.unwrap(),
        BreachStatus::NotFound
    );
    assert!(http.requests().is_empty());
}

#[tokio::test]
async fn pwd_03_offline_list_is_consulted_first_and_loaded_from_file() {
    let dir = std::env::temp_dir().join(format!("authn-password-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("breached.txt");
    std::fs::write(
        &file,
        "# local corpus\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:12\n\
         7c4a8d09ca3762af61e59520943dc26494f8941b\n",
    )
    .unwrap();
    let http = Arc::new(FakeHttpClient::default());
    let config = BreachCheckConfig {
        enabled: true,
        hibp_range_url: BASE.to_owned(),
        timeout: Duration::from_secs(1),
        fail_open: true,
        offline_list_file: Some(file.clone()),
    };
    let checker = HibpBreachChecker::from_config(&config, http.clone()).unwrap();
    assert_eq!(
        checker.check(&pw("password")).await.unwrap(),
        BreachStatus::Breached { occurrences: 12 }
    );
    assert_eq!(
        checker.check(&pw("123456")).await.unwrap(),
        BreachStatus::Breached { occurrences: 1 }
    );
    assert!(http.requests().is_empty(), "offline hits never go online");

    // Malformed or missing files fail fast at start-up (ARC-07).
    std::fs::write(&file, "not-a-hash\n").unwrap();
    assert!(HibpBreachChecker::from_config(&config, http.clone()).is_err());
    let missing = BreachCheckConfig {
        offline_list_file: Some(dir.join("missing.txt")),
        ..config
    };
    assert!(HibpBreachChecker::from_config(&missing, http).is_err());
    std::fs::remove_dir_all(dir).unwrap();

    let list = OfflineBreachList::parse("").unwrap();
    assert!(list.is_empty());
}

#[tokio::test]
async fn pwd_03_checker_debug_reveals_no_configuration_secrets_or_hashes() {
    let checker = checker(Arc::new(FakeHttpClient::default()));
    let debug = format!("{checker:?}");
    assert!(debug.contains("hibp_enabled: true"), "{debug}");
    assert!(!debug.contains(PREFIX));
}

/// An HTTP client that ignores the timeout and hangs.
struct HangingClient;

#[async_trait]
impl HttpClient for HangingClient {
    async fn execute(&self, _request: OutboundRequest) -> Result<OutboundResponse, AuthError> {
        tokio::time::sleep(Duration::from_secs(600)).await;
        Err(AuthError::internal("unreachable"))
    }
}

#[tokio::test]
async fn pwd_03_hanging_service_times_out_to_unknown() {
    let checker = HibpBreachChecker::new(
        Arc::new(HangingClient),
        Some(BASE),
        Duration::from_millis(50),
        None,
    )
    .unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        checker.check(&pw("password")).await.unwrap(),
        BreachStatus::Unknown
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

mod properties {
    use authn_password::OfflineBreachList;
    use authn_password::breach::{SUFFIX_LEN, lookup_in_range_response};
    use proptest::prelude::*;

    proptest! {
        // Same invariants as fuzz/fuzz_targets/hibp_range_parse.rs (TST-03).
        #[test]
        fn pwd_03_range_and_offline_parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let split = data.iter().position(|b| *b == b'\n').unwrap_or(data.len());
            let (suffix, body) = data.split_at(split);
            let suffix = String::from_utf8_lossy(suffix);
            if let Ok(Some(count)) = lookup_in_range_response(body, &suffix) {
                prop_assert!(count > 0);
                prop_assert_eq!(suffix.len(), SUFFIX_LEN);
            }
            if let Ok(text) = std::str::from_utf8(&data)
                && let Ok(list) = OfflineBreachList::parse(text)
            {
                prop_assert!(list.len() <= text.lines().count());
            }
        }

        #[test]
        fn pwd_03_listed_suffix_is_always_found(
            suffix in "[0-9A-F]{35}",
            count in 1_u64..u64::MAX,
            noise in proptest::collection::vec("[0-9a-f]{35}:[0-9]{1,6}", 0..50),
        ) {
            let mut body = noise.join("\r\n");
            body.push_str(&format!("\r\n{}:{count}\r\n", suffix.to_ascii_lowercase()));
            prop_assert_eq!(lookup_in_range_response(body.as_bytes(), &suffix), Ok(Some(count)));
        }
    }
}
