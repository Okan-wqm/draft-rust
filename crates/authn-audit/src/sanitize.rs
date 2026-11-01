//! Structural enforcement of AUD-03: secrets, credentials and personal data
//! never reach the audit log, even when a producer makes a mistake.
//!
//! Producers may only put *codes and identifiers* into `reason`,
//! `resource` and `metadata`. Everything else is replaced by
//! [`REDACTED`] before the event is hashed and stored, and a warning naming
//! only the key and the rule (never the value) is logged.
//!
//! Metadata grammar accepted unchanged:
//! * at most [`MAX_ENTRIES`] entries per object, nesting depth ≤
//!   [`MAX_DEPTH`], arrays ≤ [`MAX_ENTRIES`] items;
//! * keys `^[a-z][a-z0-9_]{0,63}$` whose `_`-separated segments are not on
//!   the secret / personal-data deny list (`password`, `token`, `otp`,
//!   `code`, `email`, `ip`, `phone`, `name`, …; a final `key` segment);
//! * keys that merely *contain* an unambiguous secret word (`newpassword`,
//!   `clientsecret`, `accesstoken`, …) are redacted as well;
//! * values: `null`, booleans, integers (`i64`/`u64`), and strings of at most
//!   128 printable ASCII characters (no whitespace) that do not look like an
//!   e-mail address, IP address, phone number, numeric code (≥ 4 digits),
//!   JWT / webhook secret, or a high-entropy token.
//!
//! UUID strings are normalized to lowercase; the sink then replaces those
//! that are user ids by the user's pseudonym (AUD-05). An identifier
//! *embedded* in a longer string (`UserId(…)`, `urn:uuid:…`, `{…}`, a run of
//! ≥ 32 hex digits) cannot be pseudonymised reliably and would stay in the
//! immutable chain forever, so such strings — and reason codes or keys that
//! contain one — are refused as well.

use std::net::IpAddr;

use serde_json::{Map, Value};
use uuid::Uuid;

/// Replacement for redacted values.
pub const REDACTED: &str = "[REDACTED]";
/// Maximum entries per object / items per array.
pub const MAX_ENTRIES: usize = 32;
/// Maximum nesting depth of metadata (the top-level object is depth 1).
pub const MAX_DEPTH: usize = 3;
/// Maximum characters of a metadata string.
pub const MAX_STRING_CHARS: usize = 128;
/// Maximum characters of a stored user agent (schema limit).
pub const MAX_USER_AGENT_CHARS: usize = 512;
/// Maximum characters of a resource id (schema limit).
pub const MAX_RESOURCE_ID_CHARS: usize = 128;
/// Key under which the number of dropped (unrepresentable) keys is stored.
pub const DROPPED_KEYS_ENTRY: &str = "redacted_entries";

/// `_`-separated key segments that name secrets or personal data.
const FORBIDDEN_SEGMENTS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "otp",
    "totp",
    "hotp",
    "code",
    "pin",
    "cookie",
    "authorization",
    "bearer",
    "pepper",
    "private",
    "salt",
    "hash",
    "signature",
    "seed",
    "jwt",
    "email",
    "mail",
    "phone",
    "msisdn",
    "ip",
    "ua",
    "useragent",
    "address",
    "name",
    "lat",
    "lng",
    "lon",
    "latitude",
    "longitude",
    "ssn",
    "pass",
    "pw",
    "passcode",
    "credential",
    "credentials",
    "apikey",
    "cvv",
    "iban",
];

/// Words that name a secret or personal data wherever they appear in a key
/// (catches concatenations such as `newpassword`, `clientsecret`,
/// `accesstoken`, `useremail`).
const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "passcode",
    "secret",
    "token",
    "cookie",
    "bearer",
    "authorization",
    "credential",
    "pepper",
    "privatekey",
    "apikey",
    "jwt",
    "email",
    "phone",
    "useragent",
];

/// Why a value was redacted (logged; never contains the value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionRule {
    /// Key names a secret or personal data.
    ForbiddenKey,
    /// Key is not a snake_case identifier (dropped).
    InvalidKey,
    /// String longer than allowed.
    TooLong,
    /// Non-printable or non-ASCII characters, or whitespace (free text).
    FreeText,
    /// Looks like an e-mail address.
    Email,
    /// Looks like an IP address.
    IpAddress,
    /// Looks like a phone number.
    PhoneNumber,
    /// Digits only (OTP / PIN / code).
    NumericCode,
    /// JWT, webhook secret or another known secret format.
    KnownSecretFormat,
    /// High-entropy token.
    TokenLike,
    /// Floating-point number (no canonical form).
    NonInteger,
    /// Nested too deeply.
    TooDeep,
    /// Too many entries.
    TooManyEntries,
    /// An identifier (UUID, long hex run) embedded in a longer string: it
    /// may be a user id that cannot be pseudonymised (AUD-05).
    EmbeddedIdentifier,
    /// More identifiers than the sink checks per event (fail closed).
    TooManyIdentifiers,
}

impl RedactionRule {
    /// Stable name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForbiddenKey => "forbidden_key",
            Self::InvalidKey => "invalid_key",
            Self::TooLong => "too_long",
            Self::FreeText => "free_text",
            Self::Email => "email",
            Self::IpAddress => "ip_address",
            Self::PhoneNumber => "phone_number",
            Self::NumericCode => "numeric_code",
            Self::KnownSecretFormat => "known_secret_format",
            Self::TokenLike => "token_like",
            Self::NonInteger => "non_integer",
            Self::TooDeep => "too_deep",
            Self::TooManyEntries => "too_many_entries",
            Self::EmbeddedIdentifier => "embedded_identifier",
            Self::TooManyIdentifiers => "too_many_identifiers",
        }
    }
}

/// One redaction: where (a key path without values) and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redaction {
    /// Key path such as `device.os` or `scopes[2]`.
    pub path: String,
    /// The rule that triggered.
    pub rule: RedactionRule,
}

/// Result of [`sanitize_metadata`].
#[derive(Debug, Clone, PartialEq)]
pub struct SanitizedMetadata {
    /// The safe metadata object.
    pub metadata: Map<String, Value>,
    /// What was redacted.
    pub redactions: Vec<Redaction>,
}

/// Whether `s` is a snake_case identifier of at most `max` bytes
/// (`^[a-z][a-z0-9_]{0,max-1}$`).
#[must_use]
pub fn is_identifier(s: &str, max: usize) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Whether a metadata key names a secret or personal data.
#[must_use]
pub fn is_forbidden_key(key: &str) -> bool {
    if key.contains("user_agent") || key.contains("api_key") && !key.ends_with("_id") {
        return true;
    }
    if FORBIDDEN_SUBSTRINGS.iter().any(|word| key.contains(word)) {
        return true;
    }
    let segments: Vec<&str> = key.split('_').collect();
    if segments.last() == Some(&"key") {
        return true;
    }
    segments.iter().any(|s| FORBIDDEN_SEGMENTS.contains(s))
}

/// Outcome of checking one string value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringCheck {
    /// Acceptable as is.
    Keep,
    /// A UUID, normalized to lowercase hyphenated form.
    Uuid(Uuid),
}

/// Minimum length of a run of hexadecimal digits treated as an embedded
/// identifier (a UUID in "simple" form has 32).
const EMBEDDED_HEX_RUN: usize = 32;

/// Whether `bytes` is a hyphenated UUID (`8-4-4-4-12` hex digits).
fn is_hyphenated_uuid(bytes: &[u8]) -> bool {
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Whether `value` contains an identifier that is not the whole value: a
/// hyphenated UUID anywhere inside a longer string, or a run of at least 32
/// hexadecimal digits (a UUID in simple form, a hex digest or token).
///
/// Such strings cannot be pseudonymised reliably (`UserId(…)`,
/// `urn:uuid:…`, `{…}`, `user_<simple uuid>`) and are refused.
#[must_use]
pub fn contains_embedded_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() == 36 && is_hyphenated_uuid(bytes) {
        return false;
    }
    let mut run = 0_usize;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= EMBEDDED_HEX_RUN {
                return true;
            }
        } else {
            run = 0;
        }
        if *byte == b'-'
            && index >= 8
            && let Some(window) = bytes.get(index - 8..index + 28)
            && is_hyphenated_uuid(window)
        {
            return true;
        }
    }
    false
}

/// Checks a metadata / resource-id string against the value grammar.
pub fn check_string(value: &str) -> Result<StringCheck, RedactionRule> {
    if value.len() == 36
        && let Ok(uuid) = Uuid::try_parse(value)
    {
        return Ok(StringCheck::Uuid(uuid));
    }
    if value.chars().count() > MAX_STRING_CHARS {
        return Err(RedactionRule::TooLong);
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(RedactionRule::FreeText);
    }
    if value.contains('@') {
        return Err(RedactionRule::Email);
    }
    let lower = value.to_ascii_lowercase();
    if value.starts_with("eyJ")
        || lower.starts_with("whsec_")
        || lower.starts_with("bearer")
        || lower.starts_with("basic")
        || lower.contains("password=")
        || lower.contains("token=")
        || lower.contains("secret=")
    {
        return Err(RedactionRule::KnownSecretFormat);
    }
    if value.parse::<IpAddr>().is_ok() || looks_like_ip_with_port(value) {
        return Err(RedactionRule::IpAddress);
    }
    if let Some(rest) = value.strip_prefix('+')
        && rest.len() >= 7
        && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    {
        return Err(RedactionRule::PhoneNumber);
    }
    if value.len() >= 4 && value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RedactionRule::NumericCode);
    }
    if looks_like_token(value) {
        return Err(RedactionRule::TokenLike);
    }
    if contains_embedded_identifier(value) {
        return Err(RedactionRule::EmbeddedIdentifier);
    }
    Ok(StringCheck::Keep)
}

fn looks_like_ip_with_port(value: &str) -> bool {
    value.rsplit_once(':').is_some_and(|(host, port)| {
        !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok()
    })
}

/// High-entropy token heuristic: base64 / base64url / hex alphabets with a
/// character mix that identifiers and codes do not have.
fn looks_like_token(value: &str) -> bool {
    if value.len() < 16 {
        return false;
    }
    let token_alphabet = value.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-' | b'.' | b'~')
    });
    if !token_alphabet {
        return false;
    }
    let upper = value.bytes().any(|b| b.is_ascii_uppercase());
    let lower = value.bytes().any(|b| b.is_ascii_lowercase());
    let digit = value.bytes().any(|b| b.is_ascii_digit());
    let hex_only = value.bytes().all(|b| b.is_ascii_hexdigit());
    (upper && digit) || (upper && lower && value.len() >= 20) || (hex_only && value.len() >= 32)
}

/// Sanitizes a metadata object (see the module documentation).
#[must_use]
pub fn sanitize_metadata(input: Map<String, Value>) -> SanitizedMetadata {
    let mut redactions = Vec::new();
    let metadata = sanitize_object(input, "", 1, &mut redactions);
    SanitizedMetadata {
        metadata,
        redactions,
    }
}

fn join_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

fn sanitize_object(
    input: Map<String, Value>,
    prefix: &str,
    depth: usize,
    redactions: &mut Vec<Redaction>,
) -> Map<String, Value> {
    let mut out = Map::new();
    let mut dropped: u64 = 0;
    for (key, value) in input {
        if !is_identifier(&key, 64) || contains_embedded_identifier(&key) {
            dropped += 1;
            redactions.push(Redaction {
                path: join_path(prefix, "<invalid>"),
                rule: RedactionRule::InvalidKey,
            });
            continue;
        }
        let path = join_path(prefix, &key);
        if out.len() >= MAX_ENTRIES {
            dropped += 1;
            redactions.push(Redaction {
                path,
                rule: RedactionRule::TooManyEntries,
            });
            continue;
        }
        if is_forbidden_key(&key) {
            redactions.push(Redaction {
                path,
                rule: RedactionRule::ForbiddenKey,
            });
            out.insert(key, Value::String(REDACTED.to_owned()));
            continue;
        }
        let value = sanitize_value(value, &path, depth, redactions);
        out.insert(key, value);
    }
    if dropped > 0 && depth == 1 {
        out.insert(DROPPED_KEYS_ENTRY.to_owned(), Value::from(dropped));
    }
    out
}

fn sanitize_value(
    value: Value,
    path: &str,
    depth: usize,
    redactions: &mut Vec<Redaction>,
) -> Value {
    let mut redact = |rule: RedactionRule| {
        redactions.push(Redaction {
            path: path.to_owned(),
            rule,
        });
        Value::String(REDACTED.to_owned())
    };
    match value {
        Value::Null | Value::Bool(_) => value,
        Value::Number(ref n) => {
            if n.is_i64() || n.is_u64() {
                value
            } else {
                redact(RedactionRule::NonInteger)
            }
        }
        Value::String(s) => match check_string(&s) {
            Ok(StringCheck::Keep) => Value::String(s),
            Ok(StringCheck::Uuid(uuid)) => Value::String(uuid.hyphenated().to_string()),
            Err(rule) => redact(rule),
        },
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return redact(RedactionRule::TooDeep);
            }
            if items.len() > MAX_ENTRIES {
                return redact(RedactionRule::TooManyEntries);
            }
            Value::Array(
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, item)| {
                        sanitize_value(item, &format!("{path}[{i}]"), depth + 1, redactions)
                    })
                    .collect(),
            )
        }
        Value::Object(map) => {
            if depth >= MAX_DEPTH {
                return redact(RedactionRule::TooDeep);
            }
            Value::Object(sanitize_object(map, path, depth + 1, redactions))
        }
    }
}

/// Every canonical UUID string inside `value` (already normalized by
/// [`sanitize_metadata`]).
pub fn collect_uuids(value: &Value, out: &mut Vec<Uuid>) {
    match value {
        Value::String(s) if s.len() == 36 => {
            if let Ok(uuid) = Uuid::try_parse(s) {
                out.push(uuid);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| collect_uuids(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_uuids(v, out)),
        _ => {}
    }
}

/// Whether a metadata key names a reference to a user: `user`, `users`,
/// `owner`, `owners` or a key ending in `user_id(s)` / `owner_id(s)`
/// (`removed_user_id`, `previous_owner`, `target_user_ids`).
#[must_use]
pub fn is_user_reference_key(key: &str) -> bool {
    let last = key.rsplit('_').next().unwrap_or(key);
    matches!(last, "user" | "users" | "owner" | "owners")
        || ["user_id", "user_ids", "owner_id", "owner_ids"]
            .iter()
            .any(|suffix| key == *suffix || key.ends_with(&format!("_{suffix}")))
}

/// Every canonical UUID string stored under a user-reference key (see
/// [`is_user_reference_key`]), directly or inside an array. The sink
/// pseudonymises these even when the account no longer exists.
pub fn collect_user_reference_uuids(value: &Value, out: &mut Vec<Uuid>) {
    fn under_user_key(value: &Value, out: &mut Vec<Uuid>) {
        match value {
            Value::String(s) if s.len() == 36 => {
                if let Ok(uuid) = Uuid::try_parse(s) {
                    out.push(uuid);
                }
            }
            Value::Array(items) => items.iter().for_each(|v| under_user_key(v, out)),
            _ => {}
        }
    }
    match value {
        Value::Array(items) => items
            .iter()
            .for_each(|v| collect_user_reference_uuids(v, out)),
        Value::Object(map) => {
            for (key, item) in map {
                if is_user_reference_key(key) {
                    under_user_key(item, out);
                }
                collect_user_reference_uuids(item, out);
            }
        }
        _ => {}
    }
}

/// Rewrites every canonical UUID string inside `value`: `f` returns the
/// replacement text, or `None` to keep the UUID.
pub fn rewrite_uuids(value: &mut Value, f: &mut dyn FnMut(Uuid) -> Option<String>) {
    match value {
        Value::String(s) if s.len() == 36 => {
            if let Ok(uuid) = Uuid::try_parse(s)
                && let Some(replacement) = f(uuid)
            {
                *s = replacement;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| rewrite_uuids(v, f)),
        Value::Object(map) => map.values_mut().for_each(|v| rewrite_uuids(v, f)),
        _ => {}
    }
}

/// Replaces UUID strings found in `replacements` (user id → pseudonym).
pub fn replace_uuids(value: &mut Value, replacements: &[(Uuid, Uuid)]) {
    rewrite_uuids(value, &mut |uuid| {
        replacements
            .iter()
            .find(|(from, _)| *from == uuid)
            .map(|(_, pseudonym)| pseudonym.hyphenated().to_string())
    });
}

/// A stored reason code: valid codes pass, anything else (free text!)
/// becomes `invalid_reason`.
#[must_use]
pub fn sanitize_reason(reason: Option<String>) -> (Option<String>, bool) {
    match reason {
        None => (None, false),
        Some(r) if is_identifier(&r, 64) && !contains_embedded_identifier(&r) => (Some(r), false),
        Some(_) => (Some("invalid_reason".to_owned()), true),
    }
}

/// Invisible formatting characters that can spoof how a string is shown
/// (bidirectional overrides / isolates, zero-width characters, BOM, soft
/// hyphen).
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// Control and invisible formatting characters (bidi overrides, zero-width
/// characters) removed — the user agent is shown back to users and
/// organization admins (AUD-04) — truncated to [`MAX_USER_AGENT_CHARS`].
#[must_use]
pub fn sanitize_user_agent(user_agent: Option<String>) -> Option<String> {
    let ua = user_agent?;
    let cleaned: String = ua
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_format(*c))
        .take(MAX_USER_AGENT_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sanitize(value: Value) -> SanitizedMetadata {
        let Value::Object(map) = value else {
            panic!("object expected")
        };
        sanitize_metadata(map)
    }

    #[test]
    fn aud_03_identifiers_and_ids_are_kept() {
        let id = Uuid::now_v7();
        let out = sanitize(json!({
            "method": "password",
            "factor": "totp",
            "from": "active",
            "to": "suspended",
            "kind": "session.revoked_bulk",
            "permission": "members:invite",
            "count": 3,
            "negative": -7,
            "enabled": true,
            "nothing": null,
            "session_id": id.to_string(),
            "api_key_id": id.to_string(),
            "scopes": ["read", "write"],
            "at": "2026-01-01T00:00:00Z",
            "host": "hooks.example.com",
            "rule_version": "v2_2026",
        }));
        assert!(out.redactions.is_empty(), "{:?}", out.redactions);
        assert_eq!(out.metadata["method"], "password");
        assert_eq!(out.metadata["session_id"], id.to_string());
    }

    #[test]
    fn aud_03_secret_and_pii_keys_are_redacted() {
        for key in [
            "password",
            "new_password",
            "reset_token",
            "otp",
            "code",
            "recovery_code",
            "email",
            "old_email",
            "ip",
            "client_ip",
            "user_agent",
            "phone",
            "display_name",
            "api_key",
            "private_key",
            "signing_key",
            "webhook_secret",
            "cookie",
            "authorization",
        ] {
            let out = sanitize(json!({ key: "harmless" }));
            assert_eq!(out.metadata[key], REDACTED, "{key}");
            assert_eq!(out.redactions[0].rule, RedactionRule::ForbiddenKey, "{key}");
        }
    }

    #[test]
    fn aud_03_secret_and_pii_values_are_redacted_whatever_the_key() {
        let cases = [
            ("alice@example.com", RedactionRule::Email),
            ("203.0.113.7", RedactionRule::IpAddress),
            ("2001:db8::1", RedactionRule::IpAddress),
            ("203.0.113.7:8443", RedactionRule::IpAddress),
            ("+905551234567", RedactionRule::PhoneNumber),
            ("123456", RedactionRule::NumericCode),
            (
                "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxIn0.c2ln",
                RedactionRule::KnownSecretFormat,
            ),
            (
                "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
                RedactionRule::KnownSecretFormat,
            ),
            (
                "Kq3vX9_2mZ-8pLw0aBcD1eFgH2iJkLmN3oPqRsTuV4w",
                RedactionRule::TokenLike,
            ),
            ("JBSWY3DPEHPK3PXP", RedactionRule::TokenLike),
            (
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                RedactionRule::TokenLike,
            ),
            ("my password is hunter2", RedactionRule::FreeText),
            ("Ayşe", RedactionRule::FreeText),
            ("line\nbreak", RedactionRule::FreeText),
            ("x", RedactionRule::TooLong),
        ];
        for (value, rule) in cases {
            let value = if rule == RedactionRule::TooLong {
                "a".repeat(MAX_STRING_CHARS + 1)
            } else {
                value.to_owned()
            };
            let out = sanitize(json!({ "detail": value }));
            assert_eq!(out.metadata["detail"], REDACTED, "{value}");
            assert_eq!(out.redactions[0].rule, rule, "{value}");
        }
    }

    #[test]
    fn aud_03_structure_limits() {
        let out = sanitize(json!({
            "ratio": 1.5,
            "Bad Key": "x",
            "nested": {"level2": {"level3": {"level4": 1}}},
            "list": (0..40).collect::<Vec<i32>>(),
        }));
        assert_eq!(out.metadata["ratio"], REDACTED);
        assert!(!out.metadata.contains_key("Bad Key"));
        assert_eq!(out.metadata[DROPPED_KEYS_ENTRY], 1);
        assert_eq!(out.metadata["nested"]["level2"]["level3"], REDACTED);
        assert_eq!(out.metadata["list"], REDACTED);
        let many: Map<String, Value> = (0..40).map(|i| (format!("k{i}"), json!(i))).collect();
        let out = sanitize_metadata(many);
        assert_eq!(out.metadata.len(), MAX_ENTRIES + 1);
    }

    #[test]
    fn aud_03_uuids_are_normalized_collected_and_replaced() {
        let user = Uuid::now_v7();
        let pseudonym = Uuid::now_v7();
        let out = sanitize(json!({
            "target_user_id": user.hyphenated().to_string().to_uppercase(),
            "list": [user.to_string()],
        }));
        assert!(out.redactions.is_empty());
        let mut value = Value::Object(out.metadata);
        let mut found = Vec::new();
        collect_uuids(&value, &mut found);
        assert_eq!(found, vec![user, user]);
        replace_uuids(&mut value, &[(user, pseudonym)]);
        assert_eq!(value["target_user_id"], pseudonym.to_string());
        assert_eq!(value["list"][0], pseudonym.to_string());
    }

    /// Security review: keys that concatenate a secret word are redacted.
    #[test]
    fn aud_03_concatenated_secret_key_names_are_redacted() {
        for key in [
            "newpassword",
            "oldpasswd",
            "clientsecret",
            "accesstoken",
            "refreshtoken",
            "useremail",
            "userphone",
            "sessioncookie",
            "apikey",
            "dbcredentials",
            "passcode",
            "pass",
            "pw",
        ] {
            let out = sanitize(json!({ key: "hunter2" }));
            assert_eq!(out.metadata[key], REDACTED, "{key}");
            assert_eq!(out.redactions[0].rule, RedactionRule::ForbiddenKey, "{key}");
        }
        for key in ["description_changed", "ship_count", "typed_value", "kind"] {
            assert!(!is_forbidden_key(key), "{key}");
        }
    }

    /// Security review: a user id embedded in a longer string cannot be
    /// pseudonymised and must never reach the chain (AUD-05).
    #[test]
    fn aud_05_embedded_identifiers_are_refused() {
        let id = Uuid::now_v7();
        let embedded = [
            format!("UserId({id})"),
            format!("urn:uuid:{id}"),
            format!("{{{id}}}"),
            format!("user/{id}/sessions"),
            format!("x{}", id.simple()),
            format!("sha256:{}", "ab".repeat(32)),
        ];
        for value in &embedded {
            assert!(contains_embedded_identifier(value), "{value}");
            let out = sanitize(json!({ "detail": value }));
            assert_eq!(out.metadata["detail"], REDACTED, "{value}");
            assert_eq!(
                out.redactions[0].rule,
                RedactionRule::EmbeddedIdentifier,
                "{value}"
            );
        }
        // A plain UUID is fine (the sink pseudonymises user ids).
        assert!(!contains_embedded_identifier(&id.to_string()));
        assert_eq!(check_string(&id.to_string()), Ok(StringCheck::Uuid(id)));
        assert!(!contains_embedded_identifier("0192f3a4-1b2c"));
        assert!(!contains_embedded_identifier("2026-01-01T00:00:00Z"));
        // Reason codes and keys carrying one are refused too.
        let reason = format!("user_{}", id.simple());
        assert_eq!(
            sanitize_reason(Some(reason.clone())),
            (Some("invalid_reason".into()), true)
        );
        let out = sanitize(json!({ reason.clone(): 1 }));
        assert!(!out.metadata.contains_key(&reason));
        assert_eq!(out.redactions[0].path, "<invalid>");
    }

    #[test]
    fn aud_05_user_reference_keys() {
        for key in [
            "user",
            "users",
            "owner",
            "previous_owner",
            "user_id",
            "removed_user_id",
            "target_user_ids",
            "owner_id",
        ] {
            assert!(is_user_reference_key(key), "{key}");
        }
        for key in ["owner_org_id", "membership_id", "user_count", "session_id"] {
            assert!(!is_user_reference_key(key), "{key}");
        }
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let c = Uuid::now_v7();
        let mut found = Vec::new();
        collect_user_reference_uuids(
            &json!({
                "removed_user_id": a.to_string(),
                "nested": {"target_user_ids": [b.to_string()]},
                "membership_id": c.to_string(),
            }),
            &mut found,
        );
        found.sort_unstable();
        let mut expected = vec![a, b];
        expected.sort_unstable();
        assert_eq!(found, expected);
    }

    /// Security review: bidi overrides / zero-width characters in a user
    /// agent shown back to users and admins could spoof the display.
    #[test]
    fn aud_04_user_agent_spoofing_characters_are_removed() {
        let ua = "Mozilla/5.0 \u{202e}cod.exe\u{202c} \u{200b}Safari\u{feff}\u{2066}x\u{2069}";
        let cleaned = sanitize_user_agent(Some(ua.to_owned())).unwrap();
        assert_eq!(cleaned, "Mozilla/5.0 cod.exe Safarix");
    }

    #[test]
    fn aud_03_reason_and_user_agent() {
        assert_eq!(
            sanitize_reason(Some("wrong_password".into())),
            (Some("wrong_password".into()), false)
        );
        assert_eq!(
            sanitize_reason(Some("user typed hunter2".into())),
            (Some("invalid_reason".into()), true)
        );
        assert_eq!(sanitize_reason(None), (None, false));
        let ua = format!("Mozilla\u{0}/5.0 {}", "x".repeat(600));
        let cleaned = sanitize_user_agent(Some(ua)).unwrap();
        assert!(!cleaned.contains('\u{0}'));
        assert_eq!(cleaned.chars().count(), MAX_USER_AGENT_CHARS);
        assert_eq!(sanitize_user_agent(Some("  ".into())), None);
    }
}
