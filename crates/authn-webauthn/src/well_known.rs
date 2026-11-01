//! Mobile association and related-origin documents (PKY-07).
//!
//! | Path | Consumer | Content |
//! |------|----------|---------|
//! | `/.well-known/apple-app-site-association` | iOS / macOS (AASA) | `webcredentials.apps` (passkeys) and, when `app_link_paths` is set, `applinks` (universal links) |
//! | `/.well-known/assetlinks.json` | Android (Digital Asset Links) | `delegate_permission/common.get_login_creds` (passkeys / Credential Manager) and, with app links, `common.handle_all_urls` |
//! | `/.well-known/webauthn` | browsers (Related Origin Requests) | `{"origins": [...]}` |
//!
//! The documents are rendered **once** from `[webauthn]` at start-up: they
//! contain configuration only — never user data — and requests cannot
//! influence them (no `Host` header, no query parameters). They are served
//! as `application/json` (Apple requires exactly that, without redirects or
//! a file extension) with a public cache lifetime
//! (`webauthn.well_known_max_age`). An unconfigured document answers `404`
//! with the standard error envelope.

use std::time::Duration;

use authn_core::config::webauthn::WebauthnConfig;
use authn_core::error::{AuthError, codes};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{FromRef, State};
use axum::response::Response;
use axum::routing::get;
use http::{HeaderValue, StatusCode, header};
use serde_json::{Value, json};

/// Path of the Apple app-site-association file.
pub const AASA_PATH: &str = "/.well-known/apple-app-site-association";
/// Path of the Android Digital Asset Links file.
pub const ASSETLINKS_PATH: &str = "/.well-known/assetlinks.json";
/// Path of the WebAuthn related-origins document.
pub const RELATED_ORIGINS_PATH: &str = "/.well-known/webauthn";

/// The pre-rendered well-known documents. Cheap to clone.
#[derive(Clone)]
pub struct WellKnownDocuments {
    aasa: Option<Bytes>,
    assetlinks: Option<Bytes>,
    related_origins: Option<Bytes>,
    cache_control: HeaderValue,
}

impl std::fmt::Debug for WellKnownDocuments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WellKnownDocuments")
            .field("aasa", &self.aasa.is_some())
            .field("assetlinks", &self.assetlinks.is_some())
            .field("related_origins", &self.related_origins.is_some())
            .finish()
    }
}

impl WellKnownDocuments {
    /// Renders the documents from the configuration.
    pub fn from_config(config: &WebauthnConfig) -> Result<Self, AuthError> {
        let aasa = (!config.apple_app_ids.is_empty())
            .then(|| render(&apple_app_site_association(config)))
            .transpose()?;
        let assetlinks = (!config.android_apps.is_empty())
            .then(|| render(&asset_links(config)))
            .transpose()?;
        let related_origins = (!config.related_origins.is_empty())
            .then(|| render(&json!({ "origins": config.related_origins })))
            .transpose()?;
        Ok(Self {
            aasa,
            assetlinks,
            related_origins,
            cache_control: cache_control(config.well_known_max_age)?,
        })
    }

    /// The AASA document, if configured.
    #[must_use]
    pub fn apple_app_site_association(&self) -> Option<&[u8]> {
        self.aasa.as_deref()
    }

    /// The Digital Asset Links document, if configured.
    #[must_use]
    pub fn asset_links(&self) -> Option<&[u8]> {
        self.assetlinks.as_deref()
    }

    /// The related-origins document, if configured.
    #[must_use]
    pub fn related_origins(&self) -> Option<&[u8]> {
        self.related_origins.as_deref()
    }

    fn respond(&self, document: Option<&Bytes>) -> Result<Response, AuthError> {
        let body = document.ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let mut response = Response::new(Body::from(body.clone()));
        *response.status_mut() = StatusCode::OK;
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::CACHE_CONTROL, self.cache_control.clone());
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        Ok(response)
    }
}

fn render(value: &Value) -> Result<Bytes, AuthError> {
    serde_json::to_vec(value)
        .map(Bytes::from)
        .map_err(|_| AuthError::internal("well-known document cannot be serialized"))
}

fn cache_control(max_age: Duration) -> Result<HeaderValue, AuthError> {
    HeaderValue::from_str(&format!("public, max-age={}", max_age.as_secs()))
        .map_err(|_| AuthError::internal("invalid cache-control value"))
}

fn apple_app_site_association(config: &WebauthnConfig) -> Value {
    let mut document = json!({
        "webcredentials": { "apps": config.apple_app_ids },
    });
    if !config.app_link_paths.is_empty() {
        let components: Vec<Value> = config
            .app_link_paths
            .iter()
            .map(|path| json!({ "/": path }))
            .collect();
        document["applinks"] = json!({
            "details": [{
                "appIDs": config.apple_app_ids,
                "components": components,
            }],
        });
    }
    document
}

fn asset_links(config: &WebauthnConfig) -> Value {
    let mut relations = vec!["delegate_permission/common.get_login_creds"];
    if !config.app_link_paths.is_empty() {
        relations.push("delegate_permission/common.handle_all_urls");
    }
    Value::Array(
        config
            .android_apps
            .iter()
            .map(|app| {
                json!({
                    "relation": relations,
                    "target": {
                        "namespace": "android_app",
                        "package_name": app.package_name,
                        "sha256_cert_fingerprints": app.sha256_cert_fingerprints,
                    },
                })
            })
            .collect(),
    )
}

/// Router of the well-known documents. Mount it at the root (outside
/// `/v1`, no authentication, no CSRF). Requires [`WellKnownDocuments`] from
/// the state.
pub fn well_known_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    WellKnownDocuments: FromRef<S>,
{
    Router::new()
        .route(AASA_PATH, get(apple_app_site_association_handler))
        .route(ASSETLINKS_PATH, get(asset_links_handler))
        .route(RELATED_ORIGINS_PATH, get(related_origins_handler))
}

/// Apple app-site-association (passkeys + universal links).
#[utoipa::path(
    get,
    path = "/.well-known/apple-app-site-association",
    tag = "well-known",
    responses(
        (status = 200, description = "AASA document", content_type = "application/json", body = Object),
        (status = 404, description = "No Apple app configured", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn apple_app_site_association_handler(
    State(documents): State<WellKnownDocuments>,
) -> Result<Response, AuthError> {
    documents.respond(documents.aasa.as_ref())
}

/// Android Digital Asset Links (passkeys + app links).
#[utoipa::path(
    get,
    path = "/.well-known/assetlinks.json",
    tag = "well-known",
    responses(
        (status = 200, description = "Digital Asset Links statements", content_type = "application/json", body = Object),
        (status = 404, description = "No Android app configured", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn asset_links_handler(
    State(documents): State<WellKnownDocuments>,
) -> Result<Response, AuthError> {
    documents.respond(documents.assetlinks.as_ref())
}

/// WebAuthn Related Origin Requests document.
#[utoipa::path(
    get,
    path = "/.well-known/webauthn",
    tag = "well-known",
    responses(
        (status = 200, description = "Related origins", content_type = "application/json", body = Object),
        (status = 404, description = "No related origins configured", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn related_origins_handler(
    State(documents): State<WellKnownDocuments>,
) -> Result<Response, AuthError> {
    documents.respond(documents.related_origins.as_ref())
}

#[cfg(test)]
mod tests {
    use authn_core::config::webauthn::AndroidApp;

    use super::*;

    const FP: &str = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";

    fn config(app_links: bool) -> WebauthnConfig {
        WebauthnConfig {
            rp_id: "example.com".to_owned(),
            allowed_origins: vec!["https://example.com".to_owned()],
            apple_app_ids: vec!["ABCDE12345.com.example.app".to_owned()],
            android_apps: vec![AndroidApp {
                package_name: "com.example.app".to_owned(),
                sha256_cert_fingerprints: vec![FP.to_owned()],
            }],
            related_origins: vec!["https://example.co.uk".to_owned()],
            app_link_paths: if app_links {
                vec!["/login/*".to_owned()]
            } else {
                Vec::new()
            },
            ..WebauthnConfig::default()
        }
    }

    fn parse(bytes: Option<&[u8]>) -> Value {
        serde_json::from_slice(bytes.unwrap()).unwrap()
    }

    #[test]
    fn pky_07_documents_follow_the_platform_formats() {
        let docs = WellKnownDocuments::from_config(&config(true)).unwrap();
        let aasa = parse(docs.apple_app_site_association());
        assert_eq!(
            aasa["webcredentials"]["apps"],
            json!(["ABCDE12345.com.example.app"])
        );
        assert_eq!(
            aasa["applinks"]["details"][0]["components"][0]["/"],
            "/login/*"
        );
        let links = parse(docs.asset_links());
        assert_eq!(
            links[0]["relation"],
            json!([
                "delegate_permission/common.get_login_creds",
                "delegate_permission/common.handle_all_urls"
            ])
        );
        assert_eq!(links[0]["target"]["namespace"], "android_app");
        assert_eq!(links[0]["target"]["sha256_cert_fingerprints"][0], FP);
        let related = parse(docs.related_origins());
        assert_eq!(related, json!({ "origins": ["https://example.co.uk"] }));
    }

    #[test]
    fn pky_07_passkey_only_association_has_no_app_links() {
        let docs = WellKnownDocuments::from_config(&config(false)).unwrap();
        let aasa = parse(docs.apple_app_site_association());
        assert!(aasa.get("applinks").is_none());
        let links = parse(docs.asset_links());
        assert_eq!(
            links[0]["relation"],
            json!(["delegate_permission/common.get_login_creds"])
        );
    }

    #[test]
    fn pky_07_unconfigured_documents_are_absent() {
        let docs = WellKnownDocuments::from_config(&WebauthnConfig::default()).unwrap();
        assert!(docs.apple_app_site_association().is_none());
        assert!(docs.asset_links().is_none());
        assert!(docs.related_origins().is_none());
    }
}
