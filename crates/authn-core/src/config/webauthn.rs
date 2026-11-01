//! `[webauthn]` — passkeys and mobile association files (owner:
//! authn-webauthn). PKY-01, PKY-04, PKY-06, PKY-07, PKY-08.
//!
//! Validation is strict on purpose: a wrong relying-party configuration
//! either silently breaks every passkey (users cannot log in) or widens the
//! set of origins allowed to use them (phishing surface). The service in
//! `authn-webauthn` re-checks the semantic rules when it builds the
//! `webauthn-rs` instance and parses the attestation roots (fail-fast).

use std::time::Duration;

use serde::Deserialize;
use uuid::Uuid;

use super::common::{ConfigProblems, days, hours, mins};
use super::password::validate_policy;
use crate::ports::RateLimitPolicy;

/// Prefix of Android app origins (`android:apk-key-hash:<base64url SHA-256>`)
/// accepted in `allowed_origins` (PKY-06).
pub const ANDROID_ORIGIN_PREFIX: &str = "android:apk-key-hash:";

/// Longest list accepted for the list-valued keys (origins, apps, paths,
/// roots); far above any real deployment, low enough to bound the work done
/// per ceremony and the size of the well-known documents.
const MAX_LIST_LEN: usize = 100;

/// An Android app allowed to use the passkeys / app links (PKY-07).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidApp {
    /// Package name, e.g. `com.example.app`.
    pub package_name: String,
    /// SHA-256 signing certificate fingerprints (`AA:BB:…`, 32 upper-case
    /// hex bytes separated by colons).
    pub sha256_cert_fingerprints: Vec<String>,
}

/// A trusted authenticator attestation root (PKY-08). Used only when an
/// organization restricts passkeys to specific authenticator models
/// (AAGUIDs): the model claimed by an authenticator is only trusted when its
/// attestation chains to one of these roots.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRoot {
    /// Human-readable vendor / model family name (1–64 characters), used in
    /// logs only.
    pub name: String,
    /// The vendor's attestation root certificate (PEM,
    /// `-----BEGIN CERTIFICATE-----`). Public data, not a secret.
    pub ca_pem: String,
    /// Authenticator models (AAGUIDs) this root vouches for.
    pub aaguids: Vec<Uuid>,
}

/// `[webauthn]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebauthnConfig {
    /// Relying party id (registrable domain). Default `localhost`. Changing
    /// it later invalidates every registered passkey.
    pub rp_id: String,
    /// Relying party display name. Default `rust-authentication`.
    pub rp_name: String,
    /// Allowed origins: web origins and `android:apk-key-hash:` origins
    /// (PKY-06). Default `["http://localhost:8080"]`. Web origins must be
    /// `rp_id` itself or one of its subdomains, or be listed in
    /// `related_origins`; plain `http` is only accepted for `localhost`.
    pub allowed_origins: Vec<String>,
    /// Ceremony state lifetime (PKY-01). Default `5m`.
    #[serde(with = "super::duration")]
    pub ceremony_ttl: Duration,
    /// Apple app ids (`TEAMID.bundle.id`) for
    /// `/.well-known/apple-app-site-association`. Default none.
    pub apple_app_ids: Vec<String>,
    /// Android apps for `/.well-known/assetlinks.json`. Default none.
    pub android_apps: Vec<AndroidApp>,
    /// Related origins for `/.well-known/webauthn` (optional). Default none.
    pub related_origins: Vec<String>,
    /// URL paths the mobile apps open as universal links / app links
    /// (`/login/*`). Default none: only the passkey association
    /// (`webcredentials`, `get_login_creds`) is published.
    pub app_link_paths: Vec<String>,
    /// Cache lifetime (`Cache-Control: max-age`) of the well-known
    /// documents. Default `1h`.
    #[serde(with = "super::duration")]
    pub well_known_max_age: Duration,
    /// Passkeys per user (bounds the exclude / allow lists). Default 20.
    pub max_credentials_per_user: u32,
    /// Require a recent authentication (step-up, SES-13) even for the
    /// user's first passkey. Default `true`; when `false` only additional
    /// passkeys require step-up.
    pub step_up_for_first_passkey: bool,
    /// Registration ceremonies started per user. Default 10 per hour.
    pub registration_per_user: RateLimitPolicy,
    /// Authentication ceremonies started per client IP (unauthenticated
    /// passkey login, DoS protection). Default 60 per 15 minutes.
    pub authentication_per_ip: RateLimitPolicy,
    /// Trusted attestation roots for organization AAGUID allow-lists
    /// (PKY-08). Default none: attestation `none` only.
    pub attestation_roots: Vec<AttestationRoot>,
}

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_owned(),
            rp_name: "rust-authentication".to_owned(),
            allowed_origins: vec!["http://localhost:8080".to_owned()],
            ceremony_ttl: mins(5),
            apple_app_ids: Vec::new(),
            android_apps: Vec::new(),
            related_origins: Vec::new(),
            app_link_paths: Vec::new(),
            well_known_max_age: hours(1),
            max_credentials_per_user: 20,
            step_up_for_first_passkey: true,
            registration_per_user: RateLimitPolicy::new(10, hours(1)),
            authentication_per_ip: RateLimitPolicy::new(60, mins(15)),
            attestation_roots: Vec::new(),
        }
    }
}

impl WebauthnConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require(
            is_valid_rp_id(&self.rp_id),
            "webauthn.rp_id",
            "must be a lowercase domain without scheme, port or path",
        );
        p.require(
            !self.rp_name.trim().is_empty()
                && self.rp_name.chars().count() <= 64
                && !self.rp_name.chars().any(char::is_control),
            "webauthn.rp_name",
            "must be 1-64 characters without control characters",
        );
        self.validate_origins(p);
        p.require_range(
            self.ceremony_ttl,
            mins(1),
            mins(15),
            "webauthn.ceremony_ttl",
        );
        self.validate_mobile(p);
        p.require_range(
            self.well_known_max_age,
            mins(1),
            days(7),
            "webauthn.well_known_max_age",
        );
        p.require(
            (1..=100).contains(&self.max_credentials_per_user),
            "webauthn.max_credentials_per_user",
            "must be between 1 and 100",
        );
        validate_policy(
            p,
            &self.registration_per_user,
            "webauthn.registration_per_user",
        );
        validate_policy(
            p,
            &self.authentication_per_ip,
            "webauthn.authentication_per_ip",
        );
        self.validate_attestation_roots(p);
    }

    fn validate_origins(&self, p: &mut ConfigProblems) {
        p.require(
            !self.allowed_origins.is_empty(),
            "webauthn.allowed_origins",
            "at least one origin is required",
        );
        p.require(
            self.allowed_origins.len() <= MAX_LIST_LEN,
            "webauthn.allowed_origins",
            "too many origins",
        );
        let mut has_rp_origin = false;
        for (i, origin) in self.allowed_origins.iter().enumerate() {
            let key = format!("webauthn.allowed_origins[{i}]");
            if let Some(hash) = origin.strip_prefix(ANDROID_ORIGIN_PREFIX) {
                p.require(
                    is_base64url_sha256(hash),
                    &key,
                    "android:apk-key-hash: must be followed by the unpadded base64url SHA-256 of the signing certificate",
                );
                continue;
            }
            let Some(host) = web_origin_host(origin) else {
                p.push(
                    &key,
                    "must be a web origin (https://host[:port], http only for localhost) or an android:apk-key-hash: origin",
                );
                continue;
            };
            let same_site = host_matches_rp_id(&host, &self.rp_id);
            has_rp_origin |= same_site;
            p.require(
                same_site || self.related_origins.iter().any(|r| r == origin),
                &key,
                "host must be webauthn.rp_id or a subdomain of it, or the origin must be listed in webauthn.related_origins",
            );
        }
        p.require(
            has_rp_origin,
            "webauthn.allowed_origins",
            "at least one web origin must be webauthn.rp_id or a subdomain of it",
        );
        p.require(
            self.related_origins.len() <= MAX_LIST_LEN,
            "webauthn.related_origins",
            "too many origins",
        );
        for (i, origin) in self.related_origins.iter().enumerate() {
            p.require(
                web_origin_host(origin).is_some(),
                &format!("webauthn.related_origins[{i}]"),
                "must be a web origin (https://host[:port], http only for localhost)",
            );
        }
    }

    fn validate_mobile(&self, p: &mut ConfigProblems) {
        p.require(
            self.apple_app_ids.len() <= MAX_LIST_LEN,
            "webauthn.apple_app_ids",
            "too many app ids",
        );
        for (i, app_id) in self.apple_app_ids.iter().enumerate() {
            p.require(
                is_apple_app_id(app_id),
                &format!("webauthn.apple_app_ids[{i}]"),
                "must be TEAMID.bundle.identifier (10 upper-case alphanumeric team id)",
            );
        }
        p.require(
            self.android_apps.len() <= MAX_LIST_LEN,
            "webauthn.android_apps",
            "too many apps",
        );
        for (i, app) in self.android_apps.iter().enumerate() {
            p.require(
                is_android_package(&app.package_name),
                &format!("webauthn.android_apps[{i}].package_name"),
                "must be a Java package name like com.example.app",
            );
            p.require(
                !app.sha256_cert_fingerprints.is_empty()
                    && app.sha256_cert_fingerprints.len() <= 10
                    && app
                        .sha256_cert_fingerprints
                        .iter()
                        .all(|f| is_sha256_fingerprint(f)),
                &format!("webauthn.android_apps[{i}].sha256_cert_fingerprints"),
                "must list 1-10 SHA-256 fingerprints as 32 upper-case hex bytes separated by ':'",
            );
        }
        p.require(
            self.app_link_paths.len() <= MAX_LIST_LEN,
            "webauthn.app_link_paths",
            "too many paths",
        );
        for (i, path) in self.app_link_paths.iter().enumerate() {
            p.require(
                is_app_link_path(path),
                &format!("webauthn.app_link_paths[{i}]"),
                "must start with '/' and contain only visible ASCII without '?' or '#' (max 256)",
            );
        }
        p.require(
            self.app_link_paths.is_empty()
                || !(self.apple_app_ids.is_empty() && self.android_apps.is_empty()),
            "webauthn.app_link_paths",
            "requires at least one apple_app_ids or android_apps entry",
        );
    }

    fn validate_attestation_roots(&self, p: &mut ConfigProblems) {
        p.require(
            self.attestation_roots.len() <= MAX_LIST_LEN,
            "webauthn.attestation_roots",
            "too many roots",
        );
        for (i, root) in self.attestation_roots.iter().enumerate() {
            let key = format!("webauthn.attestation_roots[{i}]");
            p.require(
                !root.name.trim().is_empty()
                    && root.name.chars().count() <= 64
                    && !root.name.chars().any(char::is_control),
                &format!("{key}.name"),
                "must be 1-64 characters without control characters",
            );
            let pem = root.ca_pem.trim();
            p.require(
                pem.starts_with("-----BEGIN CERTIFICATE-----")
                    && pem.ends_with("-----END CERTIFICATE-----")
                    && pem.len() <= 16 * 1024,
                &format!("{key}.ca_pem"),
                "must be one PEM certificate (-----BEGIN CERTIFICATE-----, at most 16 KiB)",
            );
            p.require(
                !root.aaguids.is_empty()
                    && root.aaguids.len() <= MAX_LIST_LEN
                    && root.aaguids.iter().all(|a| !a.is_nil()),
                &format!("{key}.aaguids"),
                "must list 1-100 non-nil AAGUIDs",
            );
        }
    }
}

/// Whether `rp_id` is a valid relying-party id: `localhost` or a lowercase
/// DNS name (labels of `a-z0-9-`, no leading/trailing hyphen, at most 63
/// bytes each, 253 in total, not an IP address).
#[must_use]
pub fn is_valid_rp_id(rp_id: &str) -> bool {
    if rp_id.is_empty() || rp_id.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = rp_id.split('.').collect();
    let labels_ok = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    // The last label of a DNS name is never all digits (rejects IPv4).
    let tld_ok = labels
        .last()
        .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()));
    labels_ok && tld_ok
}

/// The host of a web origin (`scheme://host[:port]`, no path, query,
/// fragment or credentials). `http` is only accepted for `localhost`
/// (WebAuthn requires a secure context).
#[must_use]
pub fn web_origin_host(origin: &str) -> Option<String> {
    if !super::session::is_origin(origin) {
        return None;
    }
    let url = url::Url::parse(origin).ok()?;
    let host = url.host_str()?.to_owned();
    match url.scheme() {
        "https" => Some(host),
        "http" if host == "localhost" => Some(host),
        _ => None,
    }
}

/// Whether `host` is the relying-party id or one of its subdomains.
#[must_use]
pub fn host_matches_rp_id(host: &str, rp_id: &str) -> bool {
    host == rp_id
        || host
            .strip_suffix(rp_id)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
}

fn is_base64url_sha256(text: &str) -> bool {
    // 32 bytes → 43 unpadded base64url characters; the last character only
    // carries 4 bits (one of `AEIMQUYcgkosw048`).
    text.len() == 43
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && text
            .bytes()
            .last()
            .is_some_and(|b| b"AEIMQUYcgkosw048".contains(&b))
}

fn is_apple_app_id(app_id: &str) -> bool {
    let Some((team, bundle)) = app_id.split_once('.') else {
        return false;
    };
    team.len() == 10
        && team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && !bundle.is_empty()
        && bundle.len() <= 155
        && !bundle.starts_with('.')
        && !bundle.ends_with('.')
        && !bundle.contains("..")
        && bundle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn is_android_package(name: &str) -> bool {
    let segments: Vec<&str> = name.split('.').collect();
    name.len() <= 255
        && segments.len() >= 2
        && segments.iter().all(|s| {
            s.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

fn is_sha256_fingerprint(text: &str) -> bool {
    let parts: Vec<&str> = text.split(':').collect();
    parts.len() == 32
        && parts.iter().all(|part| {
            part.len() == 2
                && part
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        })
}

fn is_app_link_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 256
        && path
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#')
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
    const APK: &str = "android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    fn problems(config: &WebauthnConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    fn production_like() -> WebauthnConfig {
        WebauthnConfig {
            rp_id: "example.com".to_owned(),
            allowed_origins: vec![
                "https://example.com".to_owned(),
                "https://app.example.com".to_owned(),
                APK.to_owned(),
            ],
            apple_app_ids: vec!["ABCDE12345.com.example.app".to_owned()],
            android_apps: vec![AndroidApp {
                package_name: "com.example.app".to_owned(),
                sha256_cert_fingerprints: vec![FP.to_owned()],
            }],
            app_link_paths: vec!["/login/*".to_owned()],
            ..WebauthnConfig::default()
        }
    }

    #[test]
    fn pky_06_defaults_and_production_like_config_are_valid() {
        assert!(problems(&WebauthnConfig::default()).is_empty());
        assert!(problems(&production_like()).is_empty());
        let c = WebauthnConfig::default();
        assert_eq!(c.ceremony_ttl, mins(5));
        assert!(c.step_up_for_first_passkey);
        assert!(c.attestation_roots.is_empty());
    }

    #[test]
    fn pky_06_rp_id_must_be_a_plain_lowercase_domain() {
        for bad in [
            "",
            "Example.com",
            "https://example.com",
            "example.com:443",
            "example.com/",
            "*.example.com",
            ".example.com",
            "example..com",
            "-example.com",
            "192.168.1.1",
            "exa mple.com",
        ] {
            assert!(!is_valid_rp_id(bad), "{bad}");
        }
        for good in [
            "localhost",
            "example.com",
            "auth.example.co.uk",
            "xn--bcher-kva.example",
        ] {
            assert!(is_valid_rp_id(good), "{good}");
        }
    }

    #[test]
    fn pky_06_origins_must_belong_to_the_rp_id_or_be_related() {
        let mut c = production_like();
        c.allowed_origins
            .push("https://evil-example.com".to_owned());
        c.allowed_origins.push("https://notexample.com".to_owned());
        let p = problems(&c);
        assert!(
            p.iter()
                .any(|m| m.starts_with("webauthn.allowed_origins[3]")),
            "{p:?}"
        );
        assert!(
            p.iter()
                .any(|m| m.starts_with("webauthn.allowed_origins[4]")),
            "{p:?}"
        );

        // A related origin is accepted once it is published.
        let mut c = production_like();
        c.allowed_origins.push("https://example.co.uk".to_owned());
        c.related_origins = vec!["https://example.co.uk".to_owned()];
        assert!(problems(&c).is_empty(), "{:?}", problems(&c));
    }

    #[test]
    fn pky_06_rejects_insecure_wildcard_and_malformed_origins() {
        for bad in [
            "http://example.com",
            "https://*.example.com",
            "https://example.com/",
            "https://example.com/login",
            "https://user:pw@example.com",
            "android:apk-key-hash:",
            "android:apk-key-hash:not-base64!",
            "android:apk-key-hash:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=",
            "ftp://example.com",
        ] {
            let mut c = production_like();
            c.allowed_origins = vec!["https://example.com".to_owned(), bad.to_owned()];
            assert!(!problems(&c).is_empty(), "{bad} accepted");
        }
        // At least one origin must be same-site with the RP id.
        let mut c = production_like();
        c.allowed_origins = vec![APK.to_owned()];
        assert!(
            problems(&c)
                .iter()
                .any(|m| m.contains("at least one web origin"))
        );
    }

    #[test]
    fn pky_07_mobile_association_values_are_validated() {
        let mut c = production_like();
        c.apple_app_ids = vec!["abc.com.example".to_owned(), "ABCDE12345.".to_owned()];
        c.android_apps[0].package_name = "example".to_owned();
        c.android_apps[0].sha256_cert_fingerprints = vec!["aa:bb".to_owned()];
        c.app_link_paths = vec!["login".to_owned(), "/a?b".to_owned()];
        let p = problems(&c);
        for key in [
            "webauthn.apple_app_ids[0]",
            "webauthn.apple_app_ids[1]",
            "webauthn.android_apps[0].package_name",
            "webauthn.android_apps[0].sha256_cert_fingerprints",
            "webauthn.app_link_paths[0]",
            "webauthn.app_link_paths[1]",
        ] {
            assert!(p.iter().any(|m| m.starts_with(key)), "{key}: {p:?}");
        }
        let mut c = WebauthnConfig::default();
        c.app_link_paths = vec!["/login/*".to_owned()];
        assert!(!problems(&c).is_empty(), "app links without apps");
    }

    #[test]
    fn pky_08_attestation_roots_are_validated() {
        let mut c = production_like();
        c.attestation_roots = vec![AttestationRoot {
            name: String::new(),
            ca_pem: "not a pem".to_owned(),
            aaguids: vec![Uuid::nil()],
        }];
        let p = problems(&c);
        for key in ["name", "ca_pem", "aaguids"] {
            assert!(
                p.iter()
                    .any(|m| m.starts_with(&format!("webauthn.attestation_roots[0].{key}"))),
                "{key}: {p:?}"
            );
        }
    }

    #[test]
    fn pky_01_limits_are_bounded() {
        let mut c = WebauthnConfig::default();
        c.ceremony_ttl = mins(60);
        c.max_credentials_per_user = 0;
        c.registration_per_user = RateLimitPolicy::new(0, hours(1));
        let p = problems(&c);
        assert!(p.iter().any(|m| m.starts_with("webauthn.ceremony_ttl")));
        assert!(
            p.iter()
                .any(|m| m.starts_with("webauthn.max_credentials_per_user"))
        );
        assert!(
            p.iter()
                .any(|m| m.starts_with("webauthn.registration_per_user"))
        );
    }

    #[test]
    fn pky_06_subdomain_matching_is_label_aligned() {
        assert!(host_matches_rp_id("example.com", "example.com"));
        assert!(host_matches_rp_id("a.example.com", "example.com"));
        assert!(!host_matches_rp_id("badexample.com", "example.com"));
        assert!(!host_matches_rp_id(".example.com", "example.com"));
        assert!(!host_matches_rp_id("example.com.evil", "example.com"));
    }
}
