//! Discovery metadata (OpenID Connect Discovery 1.0 §3, RFC 8414 §2;
//! OIDP-09). One document serves both well-known paths: the OAuth
//! metadata is a subset of the OpenID one.

use serde::Serialize;
use utoipa::ToSchema;

use crate::claims::ACR_VALUES;
use crate::settings::{
    AUTHORIZE_PATH, INTROSPECTION_PATH, JWKS_PATH, OidcProviderSettings, REVOCATION_PATH,
    TOKEN_PATH, USERINFO_PATH,
};

/// Provider / authorization server metadata.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizationServerMetadata {
    /// Issuer identifier.
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// UserInfo endpoint.
    pub userinfo_endpoint: String,
    /// JWKS (the server's signing keys, SES-09).
    pub jwks_uri: String,
    /// RFC 7009 endpoint.
    pub revocation_endpoint: String,
    /// RFC 7662 endpoint.
    pub introspection_endpoint: String,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// `code` only.
    pub response_types_supported: Vec<&'static str>,
    /// `query` only.
    pub response_modes_supported: Vec<&'static str>,
    /// `authorization_code`, `refresh_token`.
    pub grant_types_supported: Vec<&'static str>,
    /// `public` subject identifiers.
    pub subject_types_supported: Vec<&'static str>,
    /// `EdDSA` (Ed25519, ADR 0001).
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    /// Client authentication at the token endpoint.
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    /// Client authentication at the revocation endpoint.
    pub revocation_endpoint_auth_methods_supported: Vec<&'static str>,
    /// Client authentication at the introspection endpoint.
    pub introspection_endpoint_auth_methods_supported: Vec<&'static str>,
    /// `S256` only.
    pub code_challenge_methods_supported: Vec<&'static str>,
    /// Claims that may be returned.
    pub claims_supported: Vec<&'static str>,
    /// Supported `acr` values.
    pub acr_values_supported: Vec<&'static str>,
    /// Supported `prompt` values.
    pub prompt_values_supported: Vec<&'static str>,
    /// RFC 9207: `iss` in every authorization response.
    pub authorization_response_iss_parameter_supported: bool,
    /// No request objects.
    pub request_parameter_supported: bool,
    /// No `request_uri`.
    pub request_uri_parameter_supported: bool,
    /// No `claims` parameter.
    pub claims_parameter_supported: bool,
}

/// The metadata of this server.
#[must_use]
pub fn metadata(settings: &OidcProviderSettings) -> AuthorizationServerMetadata {
    let client_auth = vec!["client_secret_basic", "client_secret_post", "none"];
    AuthorizationServerMetadata {
        issuer: settings.issuer.clone(),
        authorization_endpoint: settings.endpoint(AUTHORIZE_PATH),
        token_endpoint: settings.endpoint(TOKEN_PATH),
        userinfo_endpoint: settings.endpoint(USERINFO_PATH),
        jwks_uri: settings.endpoint(JWKS_PATH),
        revocation_endpoint: settings.endpoint(REVOCATION_PATH),
        introspection_endpoint: settings.endpoint(INTROSPECTION_PATH),
        scopes_supported: settings.supported_scopes.clone(),
        response_types_supported: vec!["code"],
        response_modes_supported: vec!["query"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec![authn_crypto::jwt::ALG],
        token_endpoint_auth_methods_supported: client_auth.clone(),
        revocation_endpoint_auth_methods_supported: client_auth,
        introspection_endpoint_auth_methods_supported: vec![
            "client_secret_basic",
            "client_secret_post",
        ],
        code_challenge_methods_supported: vec![crate::pkce::METHOD_S256],
        claims_supported: vec![
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "azp",
            "at_hash",
            "sid",
            "name",
            "locale",
            "zoneinfo",
            "email",
            "email_verified",
        ],
        acr_values_supported: ACR_VALUES.to_vec(),
        prompt_values_supported: vec!["none", "login", "consent", "select_account"],
        authorization_response_iss_parameter_supported: true,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        claims_parameter_supported: false,
    }
}
