//! E-mail address newtype with baseline normalization (ACC-03).
//!
//! Ownership: the baseline lives here so every crate can accept and compare
//! addresses consistently; `authn-account` owns ACC-03 and may harden the
//! rules (additively, via a contract change request) — e.g. disposable domain
//! lists (ACC-12) are *policy* and stay in `authn-account`.
//!
//! Normalization pipeline:
//! 1. Reject input larger than [`MAX_EMAIL_INPUT_BYTES`] before any work.
//! 2. Unicode NFKC, then trim leading/trailing whitespace.
//! 3. Exactly one `@`; split into local part and domain.
//! 4. Local part: 1–64 bytes of RFC 5322 `dot-atom` characters; non-ASCII
//!    characters (RFC 6531) are accepted only if UTS #39 marks them as
//!    allowed in identifiers (rejects zero-width, bidi controls, symbols…).
//!    Quoted local parts and comments are not supported.
//! 5. Domain: no trailing dot, converted with UTS #46 / IDNA to its ASCII
//!    (punycode) lowercase form using STD3 rules; at least two labels, each
//!    1–63 LDH characters, total ≤ 253, the TLD must contain a letter (this
//!    also rejects IPv4 literals); address literals (`[…]`) are rejected.
//! 6. Whole address ≤ 254 bytes.
//!
//! Hardening owned by `authn-account` (ACC-03, homograph / spoofing
//! defences):
//!
//! * **Mixed scripts:** a non-ASCII local part, and every label of an
//!   internationalized domain (checked on its Unicode form), must satisfy
//!   the UTS #39 *moderately restrictive* profile: one script, or Latin plus
//!   one other recommended script that is not Cyrillic or Greek (Han +
//!   Hiragana/Katakana, Han + Hangul are fine). `pаypal@example.com` with a
//!   Cyrillic `а`, or `alice@exаmple.com`, are rejected.
//! * **Combining-mark runs:** more than two consecutive combining marks
//!   (after NFKC) are rejected ("Zalgo" text hides the base letter).
//! * **Special-use names:** the never-deliverable RFC 6761 TLDs
//!   `localhost` and `invalid` are rejected.
//! * The lowercased form is NFKC-normalized again, so
//!   [`EmailAddress::normalized`] is a fixed point of the pipeline.
//!
//! [`EmailAddress::as_str`] is the canonical form (`local@ascii-domain`, local
//! case preserved); [`EmailAddress::normalized`] lowercases the local part
//! too and is the value of the unique `users.email_normalized` column.
//!
//! `EmailAddress` deliberately implements neither `Display` nor a revealing
//! `Debug`: addresses are personal data and must not leak into logs by
//! accident. Use [`EmailAddress::as_str`] where the full value is needed.
//!
//! It can be *bound* as a SQL parameter (`text`), but it intentionally does
//! not implement `sqlx::Decode`: stored addresses are read back as `String`
//! so that a future hardening of the parsing rules can never make existing
//! rows unreadable.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use unicode_security::{GeneralSecurityProfile, RestrictionLevel, RestrictionLevelDetection};

use crate::redact::mask_email;

/// Inputs longer than this many bytes are rejected before normalization.
pub const MAX_EMAIL_INPUT_BYTES: usize = 1024;
const MAX_LOCAL_BYTES: usize = 64;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;
const MAX_ADDRESS_BYTES: usize = 254;
/// Longest accepted run of consecutive combining marks (after NFKC).
const MAX_COMBINING_RUN: usize = 2;
/// RFC 6761 top-level domains that can never receive mail.
const NON_DELIVERABLE_TLDS: &[&str] = &["localhost", "invalid"];

/// Why an e-mail address was rejected. Variants never echo the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmailError {
    /// Empty input (after trimming).
    #[error("e-mail address is empty")]
    Empty,
    /// Input or result exceeds the length limits.
    #[error("e-mail address is too long")]
    TooLong,
    /// Not exactly one `@`.
    #[error("e-mail address must contain exactly one '@'")]
    InvalidAtSign,
    /// The local part is empty, too long or contains invalid characters.
    #[error("e-mail local part is invalid")]
    InvalidLocalPart,
    /// The domain is not a valid internet domain name.
    #[error("e-mail domain is invalid")]
    InvalidDomain,
}

/// A syntactically valid, normalized e-mail address.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EmailAddress {
    address: String,
    normalized: String,
    at: usize,
}

impl EmailAddress {
    /// Parses and normalizes user input (see the module docs for the rules).
    pub fn parse(input: &str) -> Result<Self, EmailError> {
        if input.len() > MAX_EMAIL_INPUT_BYTES {
            return Err(EmailError::TooLong);
        }
        let nfkc: String = input.nfkc().collect();
        let trimmed = nfkc.trim();
        if trimmed.is_empty() {
            return Err(EmailError::Empty);
        }
        let mut parts = trimmed.split('@');
        let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(EmailError::InvalidAtSign);
        };
        validate_local_part(local)?;
        let ascii_domain = normalize_domain(domain)?;

        let address = format!("{local}@{ascii_domain}");
        if address.len() > MAX_ADDRESS_BYTES {
            return Err(EmailError::TooLong);
        }
        let lowered: String = local.to_lowercase().nfkc().collect();
        // Lowercasing can lengthen the local part (`İ` → `i̇`): the
        // uniqueness form must itself be a valid address, or it would not be
        // a fixed point of the pipeline.
        validate_local_part(&lowered)?;
        let normalized = format!("{lowered}@{ascii_domain}");
        if normalized.len() > MAX_ADDRESS_BYTES {
            return Err(EmailError::TooLong);
        }
        Ok(Self {
            at: local.len(),
            address,
            normalized,
        })
    }

    /// Canonical address: NFKC local part (case preserved) `@` ASCII domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.address
    }

    /// Fully lowercased form used for uniqueness and lookups
    /// (`users.email_normalized`).
    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// The local part (before `@`), case preserved.
    #[must_use]
    pub fn local_part(&self) -> &str {
        self.address.get(..self.at).unwrap_or_default()
    }

    /// The ASCII (punycode) lowercase domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        self.address.get(self.at + 1..).unwrap_or_default()
    }

    /// Masked form for logs (`a***@example.com`).
    #[must_use]
    pub fn masked(&self) -> String {
        mask_email(&self.address)
    }

    /// Consumes the value, returning `(address, normalized)`.
    #[must_use]
    pub fn into_parts(self) -> (String, String) {
        (self.address, self.normalized)
    }
}

impl fmt::Debug for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmailAddress({})", self.masked())
    }
}

fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~-".contains(c)
}

fn validate_local_part(local: &str) -> Result<(), EmailError> {
    if local.is_empty() || local.len() > MAX_LOCAL_BYTES {
        return Err(EmailError::InvalidLocalPart);
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(EmailError::InvalidLocalPart);
    }
    let valid = local.chars().all(|c| {
        if c.is_ascii() {
            c == '.' || is_atext(c)
        } else {
            c.identifier_allowed()
        }
    });
    if !valid || has_long_combining_run(local) || !is_script_safe(local) {
        return Err(EmailError::InvalidLocalPart);
    }
    Ok(())
}

/// Whether more than [`MAX_COMBINING_RUN`] combining marks follow each other.
fn has_long_combining_run(s: &str) -> bool {
    let mut run = 0_usize;
    for c in s.chars() {
        if is_combining_mark(c) {
            run += 1;
            if run > MAX_COMBINING_RUN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// UTS #39 restriction-level check of the letters and digits of `s` (ASCII
/// punctuation such as `.`, `+`, `-` is script-neutral and skipped). Pure
/// ASCII is always accepted.
fn is_script_safe(s: &str) -> bool {
    if s.is_ascii() {
        return true;
    }
    let letters: String = s.chars().filter(|c| !c.is_ascii_punctuation()).collect();
    letters
        .as_str()
        .check_restriction_level(RestrictionLevel::ModeratelyRestrictive)
}

fn normalize_domain(domain: &str) -> Result<String, EmailError> {
    if domain.is_empty() || domain.ends_with('.') || domain.starts_with('[') {
        return Err(EmailError::InvalidDomain);
    }
    let ascii = idna::domain_to_ascii_strict(domain).map_err(|_| EmailError::InvalidDomain)?;
    if ascii.is_empty() || ascii.len() > MAX_DOMAIN_BYTES {
        return Err(EmailError::InvalidDomain);
    }
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 {
        return Err(EmailError::InvalidDomain);
    }
    for label in &labels {
        let ldh = label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if label.is_empty()
            || label.len() > MAX_LABEL_BYTES
            || !ldh
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(EmailError::InvalidDomain);
        }
    }
    let tld_has_letter = labels
        .last()
        .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_lowercase()));
    if !tld_has_letter {
        return Err(EmailError::InvalidDomain);
    }
    if labels
        .last()
        .is_some_and(|tld| NON_DELIVERABLE_TLDS.contains(tld))
    {
        return Err(EmailError::InvalidDomain);
    }
    // Homograph defence on the Unicode form of internationalized labels.
    if labels.iter().any(|l| l.starts_with("xn--")) {
        let (unicode, result) = idna::domain_to_unicode(&ascii);
        if result.is_err()
            || unicode
                .split('.')
                .any(|label| has_long_combining_run(label) || !is_script_safe(label))
        {
            return Err(EmailError::InvalidDomain);
        }
    }
    Ok(ascii)
}

impl Serialize for EmailAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.address)
    }
}

impl<'de> Deserialize<'de> for EmailAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl utoipa::PartialSchema for EmailAddress {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .format(Some(utoipa::openapi::SchemaFormat::KnownFormat(
                utoipa::openapi::KnownFormat::Email,
            )))
            .max_length(Some(MAX_ADDRESS_BYTES))
            .into()
    }
}

impl utoipa::ToSchema for EmailAddress {}

impl sqlx::Type<sqlx::Postgres> for EmailAddress {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <&str as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <&str as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for EmailAddress {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn ok(input: &str) -> EmailAddress {
        EmailAddress::parse(input).unwrap_or_else(|e| panic!("{input:?} rejected: {e}"))
    }

    #[test]
    fn acc_03_trims_and_lowercases_domain() {
        let e = ok("  Alice.Smith@Example.COM \t");
        assert_eq!(e.as_str(), "Alice.Smith@example.com");
        assert_eq!(e.normalized(), "alice.smith@example.com");
        assert_eq!(e.local_part(), "Alice.Smith");
        assert_eq!(e.domain(), "example.com");
    }

    #[test]
    fn acc_03_idn_domain_is_converted_to_punycode() {
        let e = ok("kullanici@Örnek.com.tr");
        assert_eq!(e.domain(), "xn--rnek-4qa.com.tr");
        assert_eq!(e.normalized(), "kullanici@xn--rnek-4qa.com.tr");
    }

    #[test]
    fn acc_03_nfkc_is_applied_before_validation() {
        // Full-width characters fold to ASCII under NFKC.
        let e = ok("ＡＬＩ＠ｅｘａｍｐｌｅ．ｃｏｍ");
        assert_eq!(e.as_str(), "ALI@example.com");
        assert_eq!(e.normalized(), "ali@example.com");
    }

    #[test]
    fn acc_03_unicode_local_part_is_lowercased_for_uniqueness() {
        let e = ok("Şükrü@example.com");
        assert_eq!(e.local_part(), "Şükrü");
        assert_eq!(e.normalized(), "şükrü@example.com");
    }

    #[test]
    fn acc_03_rejects_invalid_shapes() {
        let cases = [
            ("", EmailError::Empty),
            ("   ", EmailError::Empty),
            ("no-at-sign.example.com", EmailError::InvalidAtSign),
            ("a@b@example.com", EmailError::InvalidAtSign),
            ("@example.com", EmailError::InvalidLocalPart),
            (".alice@example.com", EmailError::InvalidLocalPart),
            ("alice.@example.com", EmailError::InvalidLocalPart),
            ("al..ice@example.com", EmailError::InvalidLocalPart),
            ("\"quoted\"@example.com", EmailError::InvalidLocalPart),
            ("al ice@example.com", EmailError::InvalidLocalPart),
            ("alice(comment)@example.com", EmailError::InvalidLocalPart),
            ("alice@", EmailError::InvalidDomain),
            ("alice@localhost", EmailError::InvalidDomain),
            ("alice@example.com.", EmailError::InvalidDomain),
            ("alice@[127.0.0.1]", EmailError::InvalidDomain),
            ("alice@127.0.0.1", EmailError::InvalidDomain),
            ("alice@-example.com", EmailError::InvalidDomain),
            ("alice@exa_mple.com", EmailError::InvalidDomain),
            ("alice@example..com", EmailError::InvalidDomain),
        ];
        for (input, expected) in cases {
            assert_eq!(EmailAddress::parse(input), Err(expected), "input {input:?}");
        }
    }

    #[test]
    fn acc_03_rejects_invisible_and_bidi_characters_in_local_part() {
        for input in [
            "ali\u{200B}ce@example.com", // zero width space
            "ali\u{202E}ce@example.com", // right-to-left override
            "ali\u{00AD}ce@example.com", // soft hyphen
            "ali\u{0000}ce@example.com",
        ] {
            assert_eq!(
                EmailAddress::parse(input),
                Err(EmailError::InvalidLocalPart),
                "{input:?}"
            );
        }
    }

    #[test]
    fn acc_03_rejects_mixed_script_local_parts() {
        // Latin "p" + Cyrillic "а" (U+0430) + Latin "ypal".
        assert_eq!(
            EmailAddress::parse("p\u{0430}ypal@example.com"),
            Err(EmailError::InvalidLocalPart)
        );
        // Latin + Greek omicron.
        assert_eq!(
            EmailAddress::parse("g\u{03BF}\u{03BF}gle@example.com"),
            Err(EmailError::InvalidLocalPart)
        );
        // Single non-Latin scripts and Latin + Han/Kana mixes are fine.
        ok("иван@example.com");
        ok("用户@example.com");
        ok("tanaka.たなか@example.jp");
        ok("ali.veli+tag@example.com");
    }

    #[test]
    fn acc_03_rejects_mixed_script_domains() {
        // Cyrillic "а" inside a Latin label.
        assert_eq!(
            EmailAddress::parse("alice@ex\u{0430}mple.com"),
            Err(EmailError::InvalidDomain)
        );
        // The same attack spelled in punycode.
        let spoof = idna::domain_to_ascii_strict("ex\u{0430}mple.com").unwrap();
        assert_eq!(
            EmailAddress::parse(&format!("alice@{spoof}")),
            Err(EmailError::InvalidDomain)
        );
        let e = ok("info@пример.рф");
        assert!(e.domain().starts_with("xn--"));
        ok("info@例え.jp");
    }

    #[test]
    fn acc_03_rejects_combining_mark_runs() {
        assert_eq!(
            EmailAddress::parse("ab\u{0300}\u{0301}\u{0302}\u{0303}c@example.com"),
            Err(EmailError::InvalidLocalPart)
        );
        // Two marks that NFKC cannot compose stay accepted.
        ok("x\u{0302}\u{0303}y@example.com");
        ok("nguy\u{0065}\u{0302}\u{0303}n@example.vn");
    }

    #[test]
    fn acc_03_rejects_non_deliverable_special_use_tlds() {
        for input in ["a@host.localhost", "a@example.invalid", "a@x.INVALID"] {
            assert_eq!(
                EmailAddress::parse(input),
                Err(EmailError::InvalidDomain),
                "{input}"
            );
        }
    }

    #[test]
    fn acc_03_normalized_form_is_a_fixed_point() {
        for input in ["İLKAY@example.com", "Straße@example.de", "ΣΟΦΙΑ@example.gr"] {
            let first = ok(input);
            let again = ok(first.normalized());
            assert_eq!(again.normalized(), first.normalized(), "{input}");
            assert_eq!(again.as_str(), first.normalized(), "{input}");
        }
    }

    #[test]
    fn acc_03_local_part_that_grows_when_lowercased_is_rejected() {
        // 32 × `İ` = 64 bytes; lowercased (`i` + U+0307) = 96 bytes, which
        // is not a valid local part: the normalized form would not re-parse.
        let input = format!("{}@example.com", "\u{130}".repeat(32));
        assert_eq!(
            EmailAddress::parse(&input),
            Err(EmailError::InvalidLocalPart)
        );
        // Short enough after lowercasing: accepted and a fixed point.
        let e = ok(&format!("{}@example.com", "\u{130}".repeat(21)));
        assert_eq!(ok(e.normalized()).normalized(), e.normalized());
    }

    #[test]
    fn acc_03_enforces_length_limits() {
        let local = "a".repeat(64);
        ok(&format!("{local}@example.com"));
        let local = "a".repeat(65);
        assert_eq!(
            EmailAddress::parse(&format!("{local}@example.com")),
            Err(EmailError::InvalidLocalPart)
        );
        let huge = "a".repeat(MAX_EMAIL_INPUT_BYTES + 1);
        assert_eq!(EmailAddress::parse(&huge), Err(EmailError::TooLong));
        let long_domain = format!("{}.com", vec!["b".repeat(60); 5].join("."));
        assert!(EmailAddress::parse(&format!("a@{long_domain}")).is_err());
    }

    #[test]
    fn acc_03_debug_output_is_masked() {
        let e = ok("alice@example.com");
        assert_eq!(format!("{e:?}"), "EmailAddress(a***@example.com)");
    }

    #[test]
    fn acc_03_serde_validates_on_deserialize() {
        let e: EmailAddress = serde_json::from_str("\"Bob@Example.org\"").unwrap();
        assert_eq!(serde_json::to_string(&e).unwrap(), "\"Bob@example.org\"");
        assert!(serde_json::from_str::<EmailAddress>("\"nope\"").is_err());
    }

    proptest! {
        #[test]
        fn tst_03_normalization_is_idempotent(input in "\\PC{0,80}") {
            if let Ok(first) = EmailAddress::parse(&input) {
                let second = EmailAddress::parse(first.as_str()).unwrap();
                prop_assert_eq!(&first, &second);
                let third = EmailAddress::parse(first.normalized()).unwrap();
                prop_assert_eq!(third.normalized(), first.normalized());
            }
        }

        #[test]
        fn tst_03_ascii_addresses_round_trip(
            local in "[a-zA-Z0-9][a-zA-Z0-9._+-]{0,20}[a-zA-Z0-9]",
            domain in "[a-z][a-z0-9-]{0,10}[a-z0-9]\\.[a-z]{2,6}",
        ) {
            prop_assume!(!local.contains(".."));
            // R-LDH labels ("ab--cd") are reserved for IDNA and rejected.
            prop_assume!(!domain.contains("--"));
            let input = format!("{local}@{domain}");
            let parsed = EmailAddress::parse(&input).unwrap();
            prop_assert_eq!(parsed.as_str(), input.as_str());
            prop_assert_eq!(parsed.normalized(), input.to_lowercase());
        }

        #[test]
        fn tst_04_parse_never_panics(input in "\\PC*") {
            let _ = EmailAddress::parse(&input);
        }
    }
}
