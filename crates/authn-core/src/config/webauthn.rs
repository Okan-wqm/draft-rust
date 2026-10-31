//! `[webauthn]` — passkeys and mobile association files (owner:
//! authn-webauthn). PKY-01, PKY-06, PKY-07.

use std::time::Duration;

use serde::Deserialize;

use super::common::{ConfigProblems, mins};

/// An Android app allowed to use the passkeys / app links (PKY-07).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidApp {
    /// Package name, e.g. `com.example.app`.
    pub package_name: String,
    /// SHA-256 signing certificate fingerprints (`AA:BB:…`).
    pub sha256_cert_fingerprints: Vec<String>,
}

/// `[webauthn]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebauthnConfig {
    /// Relying party id (registrable domain). Default `localhost`.
    pub rp_id: String,
    /// Relying party display name. Default `rust-authentication`.
    pub rp_name: String,
    /// Allowed origins: web origins and `android:apk-key-hash:` origins
    /// (PKY-06). Default `["http://localhost:8080"]`.
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
        }
    }
}

impl WebauthnConfig {
    /// Validates the section.
    pub fn validate(&self, p: &mut ConfigProblems) {
        p.require(
            !self.rp_id.is_empty()
                && !self.rp_id.contains(['/', ':', '*'])
                && self.rp_id == self.rp_id.to_ascii_lowercase(),
            "webauthn.rp_id",
            "must be a lowercase domain without scheme, port or path",
        );
        p.require(
            !self.rp_name.trim().is_empty(),
            "webauthn.rp_name",
            "must not be empty",
        );
        p.require(
            !self.allowed_origins.is_empty(),
            "webauthn.allowed_origins",
            "at least one origin is required",
        );
        for (i, origin) in self.allowed_origins.iter().enumerate() {
            p.require(
                origin.starts_with("android:apk-key-hash:") || super::session::is_origin(origin),
                &format!("webauthn.allowed_origins[{i}]"),
                "must be a web origin or an android:apk-key-hash: origin",
            );
        }
        p.require_range(
            self.ceremony_ttl,
            mins(1),
            mins(15),
            "webauthn.ceremony_ttl",
        );
    }
}
