//! Breached-password lookup (PWD-03): the [`BreachedPasswordChecker`] port
//! implementation.
//!
//! * **HIBP Pwned Passwords range API (k-anonymity).** The candidate's
//!   SHA-1 is computed locally; only the first 5 hex characters leave the
//!   process (`GET <hibp_range_url><PREFIX>`), with `Add-Padding: true` so
//!   the response size does not reveal the prefix bucket. The response
//!   (`SUFFIX:COUNT` lines) is scanned locally; padding entries carry count
//!   `0` and are ignored. The request goes through the [`HttpClient`] port as
//!   an operator-configured [`OutboundTarget::Trusted`] destination with the
//!   configured timeout and a response-size cap.
//! * **Offline list (optional).** A file of SHA-1 hashes (one per line,
//!   `HASH` or `HASH:COUNT`, `#` comments) loaded once at start-up into a
//!   sorted array; looked up first, without network.
//! * **Unavailability.** Any network error, timeout, non-200 status or
//!   unparseable body yields [`BreachStatus::Unknown`]; the policy then
//!   applies the configured fail mode (see [`crate::policy`]).
//!
//! Neither the password, its hash nor the prefix is ever logged.

use std::fmt;
use std::io::BufRead as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::password::BreachCheckConfig;
use authn_core::error::AuthError;
use authn_core::ports::{
    BreachStatus, BreachedPasswordChecker, HttpClient, OutboundRequest, OutboundTarget,
};
use authn_core::secret::{ExposeSecret, SecretString};
use http::{HeaderValue, StatusCode, header};
use sha1::Digest as _;
use url::Url;
use zeroize::Zeroizing;

use crate::metrics;

/// Characters of the SHA-1 hex digest sent to HIBP.
pub const PREFIX_LEN: usize = 5;
/// Characters of the SHA-1 hex digest compared locally.
pub const SUFFIX_LEN: usize = 35;
/// Response-size cap for one range query. Padded responses are ~40 KiB.
pub const MAX_RANGE_RESPONSE_BYTES: usize = 512 * 1024;
/// `User-Agent` sent to HIBP (required by the API).
const USER_AGENT: &str = "rust-authentication-password-check";

/// Why a range response could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RangeResponseError {
    /// The body exceeds [`MAX_RANGE_RESPONSE_BYTES`].
    #[error("range response too large")]
    TooLarge,
    /// The body is not UTF-8.
    #[error("range response is not UTF-8")]
    NotUtf8,
    /// The body contains no well-formed `SUFFIX:COUNT` line (a real padded
    /// response always has hundreds).
    #[error("range response has no entries")]
    NoEntries,
}

/// Scans a range-API body for `suffix` (35 hex characters, any case).
///
/// Returns the occurrence count when the suffix is listed with a count
/// above zero; padding entries (count `0`) and malformed lines are ignored.
/// The comparison of each line is constant-time.
pub fn lookup_in_range_response(
    body: &[u8],
    suffix: &str,
) -> Result<Option<u64>, RangeResponseError> {
    if body.len() > MAX_RANGE_RESPONSE_BYTES {
        return Err(RangeResponseError::TooLarge);
    }
    let text = std::str::from_utf8(body).map_err(|_| RangeResponseError::NotUtf8)?;
    let wanted = suffix.as_bytes();
    let mut entries = 0_usize;
    let mut found: Option<u64> = None;
    for line in text.lines() {
        let Some((candidate, count)) = line.trim().split_once(':') else {
            continue;
        };
        let candidate = candidate.trim().as_bytes();
        if candidate.len() != SUFFIX_LEN || !candidate.iter().all(u8::is_ascii_hexdigit) {
            continue;
        }
        let Ok(count) = count.trim().parse::<u64>() else {
            continue;
        };
        entries += 1;
        if count > 0 && wanted.len() == SUFFIX_LEN && ascii_ci_ct_eq(candidate, wanted) {
            found = Some(found.map_or(count, |c| c.max(count)));
        }
    }
    if entries == 0 {
        return Err(RangeResponseError::NoEntries);
    }
    Ok(found)
}

/// Constant-time, ASCII case-insensitive equality of equal-length slices.
fn ascii_ci_ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x.to_ascii_uppercase() ^ y.to_ascii_uppercase();
    }
    a.len() == b.len() && diff == 0
}

/// Uppercase hex SHA-1 of the (already normalized) password.
fn sha1_hex(password: &str) -> Zeroizing<String> {
    let digest: [u8; 20] = sha1::Sha1::digest(password.as_bytes()).into();
    let digest = Zeroizing::new(digest);
    Zeroizing::new(data_encoding::HEXUPPER.encode(digest.as_slice()))
}

/// Why the offline list could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OfflineListError {
    /// The file cannot be read.
    #[error("offline breach list cannot be read")]
    Unreadable,
    /// A line is neither a comment, blank, `HASH` nor `HASH:COUNT`.
    #[error("offline breach list line {line} is malformed")]
    Malformed {
        /// 1-based line number (the content is never echoed).
        line: usize,
    },
}

/// Sorted in-memory set of breached SHA-1 hashes with occurrence counts.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OfflineBreachList {
    entries: Vec<([u8; 20], u64)>,
}

impl fmt::Debug for OfflineBreachList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfflineBreachList")
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl OfflineBreachList {
    /// Parses the list format: one SHA-1 hex digest per line (any case),
    /// optionally followed by `:COUNT`; blank lines and `#` comments are
    /// skipped; entries with count `0` are ignored.
    pub fn parse(text: &str) -> Result<Self, OfflineListError> {
        Self::from_lines(text.lines().map(|l| Ok(l.to_owned())))
    }

    /// Loads the list from a file (fail-fast at start-up, ARC-07).
    pub fn load(path: &Path) -> Result<Self, OfflineListError> {
        let file = std::fs::File::open(path).map_err(|_| OfflineListError::Unreadable)?;
        let reader = std::io::BufReader::new(file);
        Self::from_lines(
            reader
                .lines()
                .map(|l| l.map_err(|_| OfflineListError::Unreadable)),
        )
    }

    fn from_lines(
        lines: impl Iterator<Item = Result<String, OfflineListError>>,
    ) -> Result<Self, OfflineListError> {
        let mut entries: Vec<([u8; 20], u64)> = Vec::new();
        for (index, line) in lines.enumerate() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let malformed = OfflineListError::Malformed { line: index + 1 };
            let (hash, count) = match trimmed.split_once(':') {
                Some((hash, count)) => (
                    hash.trim(),
                    count.trim().parse::<u64>().map_err(|_| malformed.clone())?,
                ),
                None => (trimmed, 1),
            };
            let decoded = data_encoding::HEXUPPER_PERMISSIVE
                .decode(hash.as_bytes())
                .map_err(|_| malformed.clone())?;
            let digest: [u8; 20] = decoded.try_into().map_err(|_| malformed)?;
            if count > 0 {
                entries.push((digest, count));
            }
        }
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        entries.dedup_by(|later, earlier| later.0 == earlier.0);
        Ok(Self { entries })
    }

    /// Number of distinct hashes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Occurrence count of a SHA-1 digest, if listed.
    #[must_use]
    pub fn occurrences(&self, digest: &[u8; 20]) -> Option<u64> {
        self.entries
            .binary_search_by(|(hash, _)| hash.cmp(digest))
            .ok()
            .and_then(|i| self.entries.get(i))
            .map(|(_, count)| *count)
    }

    fn lookup_hex(&self, hex: &str) -> Option<u64> {
        let decoded = Zeroizing::new(data_encoding::HEXUPPER.decode(hex.as_bytes()).ok()?);
        let digest: [u8; 20] = decoded.as_slice().try_into().ok()?;
        self.occurrences(&digest)
    }
}

/// HIBP + offline-list breach checker (PWD-03).
#[derive(Clone)]
pub struct HibpBreachChecker {
    http: Arc<dyn HttpClient>,
    range_base: Option<Url>,
    timeout: Duration,
    offline: Option<Arc<OfflineBreachList>>,
}

impl fmt::Debug for HibpBreachChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HibpBreachChecker")
            .field("hibp_enabled", &self.range_base.is_some())
            .field("timeout", &self.timeout)
            .field("offline", &self.offline)
            .finish_non_exhaustive()
    }
}

impl HibpBreachChecker {
    /// Builds the checker from `[password.breach_check]`; loads the offline
    /// list (fail-fast on an unreadable or malformed file).
    pub fn from_config(
        config: &BreachCheckConfig,
        http: Arc<dyn HttpClient>,
    ) -> Result<Self, AuthError> {
        let range_base = if config.enabled {
            Some(range_base_url(&config.hibp_range_url)?)
        } else {
            None
        };
        let offline = match &config.offline_list_file {
            Some(path) => Some(Arc::new(OfflineBreachList::load(path).map_err(|err| {
                AuthError::internal("password.breach_check.offline_list_file is invalid")
                    .with_source(err)
            })?)),
            None => None,
        };
        Ok(Self {
            http,
            range_base,
            timeout: config.timeout,
            offline,
        })
    }

    /// Builds the checker from its parts. `range_url = None` disables HIBP.
    pub fn new(
        http: Arc<dyn HttpClient>,
        range_url: Option<&str>,
        timeout: Duration,
        offline: Option<OfflineBreachList>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            http,
            range_base: range_url.map(range_base_url).transpose()?,
            timeout,
            offline: offline.map(Arc::new),
        })
    }

    async fn query_hibp(&self, base: &Url, hex: &str) -> BreachStatus {
        let (Some(prefix), Some(suffix)) = (hex.get(..PREFIX_LEN), hex.get(PREFIX_LEN..)) else {
            return BreachStatus::Unknown;
        };
        let Ok(url) = base.join(prefix) else {
            return BreachStatus::Unknown;
        };
        let mut request = OutboundRequest::get(url, OutboundTarget::Trusted);
        request.timeout = Some(self.timeout);
        request.max_response_bytes = Some(MAX_RANGE_RESPONSE_BYTES);
        request
            .headers
            .insert("add-padding", HeaderValue::from_static("true"));
        request
            .headers
            .insert(header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
        request
            .headers
            .insert(header::ACCEPT, HeaderValue::from_static("text/plain"));

        // The port enforces the timeout; the outer one is defence in depth
        // against an implementation that ignores it.
        let response = match tokio::time::timeout(self.timeout, self.http.execute(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                tracing::warn!(error.code = err.code().code(), "HIBP range request failed");
                metrics::breach_check("hibp", "unavailable");
                return BreachStatus::Unknown;
            }
            Err(_) => {
                tracing::warn!("HIBP range request timed out");
                metrics::breach_check("hibp", "unavailable");
                return BreachStatus::Unknown;
            }
        };
        if response.status != StatusCode::OK {
            tracing::warn!(
                status = response.status.as_u16(),
                "HIBP range request answered with an unexpected status"
            );
            metrics::breach_check("hibp", "unavailable");
            return BreachStatus::Unknown;
        }
        match lookup_in_range_response(&response.body, suffix) {
            Ok(Some(occurrences)) => {
                metrics::breach_check("hibp", "breached");
                BreachStatus::Breached { occurrences }
            }
            Ok(None) => {
                metrics::breach_check("hibp", "not_found");
                BreachStatus::NotFound
            }
            Err(err) => {
                tracing::warn!(error = %err, "HIBP range response unusable");
                metrics::breach_check("hibp", "unavailable");
                BreachStatus::Unknown
            }
        }
    }
}

/// Validates the configured base URL and makes sure it ends with `/` so
/// `join(prefix)` appends instead of replacing the last segment.
fn range_base_url(raw: &str) -> Result<Url, AuthError> {
    let mut url = Url::parse(raw).map_err(|err| {
        AuthError::internal("password.breach_check.hibp_range_url is invalid").with_source(err)
    })?;
    if url.cannot_be_a_base()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AuthError::internal(
            "password.breach_check.hibp_range_url must be a plain base URL",
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

#[async_trait]
impl BreachedPasswordChecker for HibpBreachChecker {
    async fn check(&self, password: &SecretString) -> Result<BreachStatus, AuthError> {
        let hex = sha1_hex(password.expose_secret());
        if let Some(list) = &self.offline {
            if let Some(occurrences) = list.lookup_hex(&hex) {
                metrics::breach_check("offline", "breached");
                return Ok(BreachStatus::Breached { occurrences });
            }
            metrics::breach_check("offline", "not_found");
        }
        match &self.range_base {
            Some(base) => Ok(self.query_hibp(base, &hex).await),
            None => Ok(BreachStatus::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    const PASSWORD_SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn pwd_03_sha1_known_answer_and_split() {
        let hex = sha1_hex("password");
        assert_eq!(hex.as_str(), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(hex.get(..PREFIX_LEN), Some("5BAA6"));
        assert_eq!(hex.get(PREFIX_LEN..), Some(PASSWORD_SUFFIX));
    }

    #[test]
    fn pwd_03_padded_response_is_parsed_and_zero_counts_ignored() {
        let body = format!(
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{PASSWORD_SUFFIX}:3861493\r\n\
             00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n"
        );
        assert_eq!(
            lookup_in_range_response(body.as_bytes(), PASSWORD_SUFFIX),
            Ok(Some(3_861_493))
        );
        // Lowercase in the response, uppercase locally.
        let lower = format!("{}:2\n", PASSWORD_SUFFIX.to_ascii_lowercase());
        assert_eq!(
            lookup_in_range_response(lower.as_bytes(), PASSWORD_SUFFIX),
            Ok(Some(2))
        );
        // A padding entry for our suffix (count 0) is not a hit.
        let padding = format!("{PASSWORD_SUFFIX}:0\r\n");
        assert_eq!(
            lookup_in_range_response(padding.as_bytes(), PASSWORD_SUFFIX),
            Ok(None)
        );
    }

    #[test]
    fn pwd_03_malformed_responses_are_rejected() {
        assert_eq!(
            lookup_in_range_response(b"", PASSWORD_SUFFIX),
            Err(RangeResponseError::NoEntries)
        );
        assert_eq!(
            lookup_in_range_response(b"<html>error</html>", PASSWORD_SUFFIX),
            Err(RangeResponseError::NoEntries)
        );
        assert_eq!(
            lookup_in_range_response(&[0xff, 0xfe, b':', b'1'], PASSWORD_SUFFIX),
            Err(RangeResponseError::NotUtf8)
        );
        let huge = vec![b'A'; MAX_RANGE_RESPONSE_BYTES + 1];
        assert_eq!(
            lookup_in_range_response(&huge, PASSWORD_SUFFIX),
            Err(RangeResponseError::TooLarge)
        );
        // Bad lines are skipped, good ones still count.
        let mixed = format!("garbage\nZZ:1\n{PASSWORD_SUFFIX}:x\n{PASSWORD_SUFFIX}:7\n");
        assert_eq!(
            lookup_in_range_response(mixed.as_bytes(), PASSWORD_SUFFIX),
            Ok(Some(7))
        );
    }

    #[test]
    fn pwd_03_offline_list_parses_and_finds_hashes() {
        let text = "# comment\n\n5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:42\n\
                    7C4A8D09CA3762AF61E59520943DC26494F8941B\n\
                    0000000000000000000000000000000000000000:0\n";
        let list = OfflineBreachList::parse(text).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list.lookup_hex(&sha1_hex("password")), Some(42));
        assert_eq!(list.lookup_hex(&sha1_hex("123456")), Some(1));
        assert_eq!(list.lookup_hex(&sha1_hex("correct horse")), None);
        assert_eq!(
            OfflineBreachList::parse("ok\n").unwrap_err(),
            OfflineListError::Malformed { line: 1 }
        );
        assert_eq!(
            OfflineBreachList::parse("# x\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:abc")
                .unwrap_err(),
            OfflineListError::Malformed { line: 2 }
        );
        assert!(
            !format!("{:?}", OfflineListError::Malformed { line: 3 }).contains("5BAA"),
            "errors never echo content"
        );
    }

    #[test]
    fn pwd_03_base_url_is_normalized() {
        assert_eq!(
            range_base_url("https://api.pwnedpasswords.com/range")
                .unwrap()
                .join("ABCDE")
                .unwrap()
                .as_str(),
            "https://api.pwnedpasswords.com/range/ABCDE"
        );
        assert!(range_base_url("https://u:p@example.com/range/").is_err());
        assert!(range_base_url("https://example.com/range/?x=1").is_err());
        assert!(range_base_url("not a url").is_err());
    }
}
