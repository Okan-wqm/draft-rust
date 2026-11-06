//! Authorization request parsing and validation (OIDP-02, OIDP-03,
//! OIDP-04). Pure functions, no I/O: fuzzed by `fuzz_targets/oidc_authorize_request.rs`.
//!
//! Two stages, because an error may only be redirected to a redirect URI
//! that was validated against the client registration (RFC 6749 §4.1.2.1,
//! RFC 9700 §4.11):
//!
//! 1. [`parse_query`] splits the query string. Size limits apply, every
//!    parameter except `resource` may appear at most once (RFC 6749 §3.1),
//!    `client_id` and `redirect_uri` must be present exactly once. A
//!    failure here is **never redirected**.
//! 2. [`AuthorizationParams::validate`] checks everything else against the
//!    client's policy; a failure is an [`AuthorizeError`] that is
//!    redirected to the (by then validated) redirect URI with `state` and
//!    `iss` (RFC 9207).

use authn_core::config::oidc_provider::MAX_SCOPE_LEN;

use crate::claims::ACR_VALUES;
use crate::pkce;

/// Longest accepted query string (bytes).
pub const MAX_QUERY_LEN: usize = 16 * 1024;
/// Most parameters per request.
pub const MAX_PARAMS: usize = 64;
/// Longest `state` / `nonce` value.
pub const MAX_STATE_LEN: usize = 1024;
/// Longest single parameter value (other than the above).
pub const MAX_VALUE_LEN: usize = 2048;
/// Most `resource` parameters (RFC 8707).
pub const MAX_RESOURCES: usize = 10;
/// Most scopes per request.
pub const MAX_SCOPES: usize = 32;
/// Largest `max_age` (seconds; ~ 1 year).
pub const MAX_MAX_AGE: i64 = 366 * 86_400;

/// Why stage 1 failed (never redirected; logged as the context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRedirect {
    /// The query string is too long, not decodable or has too many
    /// parameters.
    Malformed,
    /// `client_id` is missing, repeated or too long.
    ClientId,
    /// `redirect_uri` is missing, repeated or too long (OAuth 2.1 requires
    /// it whenever more than one is registered; this server always does).
    RedirectUri,
}

impl NoRedirect {
    /// Stable reason code for logs.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed_query",
            Self::ClientId => "client_id",
            Self::RedirectUri => "redirect_uri",
        }
    }
}

/// OAuth error codes of the authorization endpoint (RFC 6749 §4.1.2.1,
/// OIDC Core §3.1.2.6, RFC 8707 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeErrorCode {
    /// `invalid_request`.
    InvalidRequest,
    /// `unauthorized_client`.
    UnauthorizedClient,
    /// `access_denied`.
    AccessDenied,
    /// `unsupported_response_type`.
    UnsupportedResponseType,
    /// `invalid_scope`.
    InvalidScope,
    /// `server_error`.
    ServerError,
    /// `temporarily_unavailable`.
    TemporarilyUnavailable,
    /// `login_required` (OIDC).
    LoginRequired,
    /// `consent_required` (OIDC).
    ConsentRequired,
    /// `interaction_required` (OIDC).
    InteractionRequired,
    /// `request_not_supported` (OIDC).
    RequestNotSupported,
    /// `request_uri_not_supported` (OIDC).
    RequestUriNotSupported,
    /// `invalid_target` (RFC 8707).
    InvalidTarget,
}

impl AuthorizeErrorCode {
    /// Wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::InteractionRequired => "interaction_required",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::InvalidTarget => "invalid_target",
        }
    }
}

/// A redirectable authorization error: code + fixed English description
/// (never echoes input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizeError {
    /// The OAuth error code.
    pub code: AuthorizeErrorCode,
    /// `error_description` (static, ASCII, no user data).
    pub description: &'static str,
}

impl AuthorizeError {
    /// New error.
    #[must_use]
    pub const fn new(code: AuthorizeErrorCode, description: &'static str) -> Self {
        Self { code, description }
    }
}

fn invalid(description: &'static str) -> AuthorizeError {
    AuthorizeError::new(AuthorizeErrorCode::InvalidRequest, description)
}

/// The raw parameters of an authorization request (stage 1 result).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizationParams {
    /// `client_id` (present exactly once).
    pub client_id: String,
    /// `redirect_uri` (present exactly once; not yet matched).
    pub redirect_uri: String,
    /// `state`, if valid; an invalid `state` is dropped from the error
    /// redirect and reported by stage 2.
    pub state: Option<String>,
    /// Every other parameter, once each (`resource` may repeat).
    rest: Vec<(String, String)>,
    /// Names of repeated parameters.
    duplicates: Vec<String>,
    /// `state` was present but malformed.
    bad_state: bool,
}

/// What the client registration allows (stage 2 input).
#[derive(Debug, Clone, Copy)]
pub struct ClientPolicy<'a> {
    /// Scopes the client may request.
    pub allowed_scopes: &'a [String],
    /// Resources (RFC 8707) the client may request.
    pub allowed_resources: &'a [String],
    /// Whether the client may use the authorization code grant.
    pub code_grant_allowed: bool,
}

/// `prompt` values (OIDC Core §3.1.2.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Prompt {
    /// `none`: no user interaction; fail instead.
    pub none: bool,
    /// `login`: re-authenticate.
    pub login: bool,
    /// `consent`: ask for consent again.
    pub consent: bool,
}

/// A fully validated authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAuthorization {
    /// Requested scopes, deduplicated, in request order.
    pub scopes: Vec<String>,
    /// Requested resources (RFC 8707), deduplicated.
    pub resources: Vec<String>,
    /// `state`.
    pub state: Option<String>,
    /// `nonce`.
    pub nonce: Option<String>,
    /// `S256` code challenge.
    pub code_challenge: String,
    /// `prompt`.
    pub prompt: Prompt,
    /// `max_age` in seconds.
    pub max_age: Option<i64>,
    /// Known `acr_values` (unknown values are ignored, OIDC Core
    /// §3.1.2.1: voluntary claims).
    pub acr_values: Vec<String>,
}

/// Whether `value` is printable ASCII (`VSCHAR`, RFC 6749 Appendix A).
fn is_vschar(value: &str) -> bool {
    value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Whether `token` is a `scope-token` (RFC 6749 §3.3, `NQCHAR`).
fn is_scope_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_SCOPE_LEN
        && token
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

/// Stage 1: splits and size-checks the query string.
pub fn parse_query(query: &str) -> Result<AuthorizationParams, NoRedirect> {
    if query.len() > MAX_QUERY_LEN {
        return Err(NoRedirect::Malformed);
    }
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(query).map_err(|_| NoRedirect::Malformed)?;
    if pairs.len() > MAX_PARAMS {
        return Err(NoRedirect::Malformed);
    }
    let mut client_id: Option<String> = None;
    let mut client_id_count = 0usize;
    let mut redirect_uri: Option<String> = None;
    let mut redirect_count = 0usize;
    let mut out = AuthorizationParams::default();
    for (name, value) in pairs {
        match name.as_str() {
            "client_id" => {
                client_id_count += 1;
                client_id = Some(value);
            }
            "redirect_uri" => {
                redirect_count += 1;
                redirect_uri = Some(value);
            }
            "resource" => out.rest.push((name, value)),
            _ => {
                if out.rest.iter().any(|(n, _)| *n == name)
                    || (name == "state" && out.state.is_some())
                {
                    if !out.duplicates.contains(&name) {
                        out.duplicates.push(name);
                    }
                    continue;
                }
                if name == "state" {
                    if value.is_empty() || value.len() > MAX_STATE_LEN || !is_vschar(&value) {
                        out.bad_state = true;
                        out.rest.push((name, String::new()));
                    } else {
                        out.state = Some(value);
                    }
                } else {
                    out.rest.push((name, value));
                }
            }
        }
    }
    out.client_id = match (client_id, client_id_count) {
        (Some(id), 1) if !id.is_empty() && id.len() <= 64 && is_vschar(&id) => id,
        _ => return Err(NoRedirect::ClientId),
    };
    out.redirect_uri = match (redirect_uri, redirect_count) {
        (Some(uri), 1) if !uri.is_empty() && uri.len() <= MAX_VALUE_LEN => uri,
        _ => return Err(NoRedirect::RedirectUri),
    };
    if out.duplicates.iter().any(|n| n == "state") {
        // A repeated `state` is not echoed: which one would the client
        // expect?
        out.state = None;
    }
    Ok(out)
}

impl AuthorizationParams {
    fn get(&self, name: &str) -> Option<&str> {
        self.rest
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Stage 2: validates the request against the client's policy and the
    /// supported scopes. Order: request objects, `response_type`,
    /// duplicates, sizes, PKCE, scope, resources, OIDC parameters.
    pub fn validate(
        &self,
        policy: &ClientPolicy<'_>,
        supported_scopes: &[String],
    ) -> Result<ValidatedAuthorization, AuthorizeError> {
        use AuthorizeErrorCode as C;
        if self.get("request").is_some() {
            return Err(AuthorizeError::new(
                C::RequestNotSupported,
                "request objects are not supported",
            ));
        }
        if self.get("request_uri").is_some() {
            return Err(AuthorizeError::new(
                C::RequestUriNotSupported,
                "request_uri is not supported",
            ));
        }
        match self.get("response_type") {
            Some("code") => {}
            None => return Err(invalid("response_type is required")),
            Some(_) => {
                return Err(AuthorizeError::new(
                    C::UnsupportedResponseType,
                    "only response_type=code is supported",
                ));
            }
        }
        if !policy.code_grant_allowed {
            return Err(AuthorizeError::new(
                C::UnauthorizedClient,
                "the client may not use the authorization code grant",
            ));
        }
        if !self.duplicates.is_empty() {
            return Err(invalid("a parameter was repeated"));
        }
        if self.bad_state {
            return Err(invalid("state must be 1-1024 printable ASCII characters"));
        }
        if self
            .rest
            .iter()
            .any(|(name, value)| name.len() > 64 || value.len() > MAX_VALUE_LEN)
        {
            return Err(invalid("a parameter is too long"));
        }
        if let Some(mode) = self.get("response_mode")
            && mode != "query"
        {
            return Err(invalid("only response_mode=query is supported"));
        }

        // PKCE S256 is mandatory (OAuth 2.1); `plain` is refused.
        let challenge = self
            .get("code_challenge")
            .ok_or_else(|| invalid("code_challenge is required (PKCE)"))?;
        match self.get("code_challenge_method") {
            Some(pkce::METHOD_S256) => {}
            None => return Err(invalid("code_challenge_method=S256 is required")),
            Some(_) => return Err(invalid("only code_challenge_method=S256 is supported")),
        }
        if !pkce::is_valid_challenge(challenge) {
            return Err(invalid("code_challenge must be a base64url SHA-256 hash"));
        }

        let scopes = self.scopes(policy, supported_scopes)?;
        let resources = self.resources(policy)?;

        let nonce = match self.get("nonce") {
            None => None,
            Some(n) if !n.is_empty() && n.len() <= MAX_STATE_LEN && is_vschar(n) => {
                Some(n.to_owned())
            }
            Some(_) => return Err(invalid("nonce must be 1-1024 printable ASCII characters")),
        };
        let prompt = self.prompt()?;
        let max_age = match self.get("max_age") {
            None => None,
            Some(v) if !v.is_empty() && v.len() <= 10 && v.bytes().all(|b| b.is_ascii_digit()) => {
                let parsed: i64 = v.parse().map_err(|_| invalid("max_age is invalid"))?;
                Some(parsed.min(MAX_MAX_AGE))
            }
            Some(_) => return Err(invalid("max_age must be a non-negative integer")),
        };
        let mut acr_values: Vec<String> = Vec::new();
        if let Some(values) = self.get("acr_values") {
            for value in values.split(' ').filter(|v| !v.is_empty()) {
                if ACR_VALUES.contains(&value) && !acr_values.iter().any(|a| a == value) {
                    acr_values.push(value.to_owned());
                }
            }
        }
        Ok(ValidatedAuthorization {
            scopes,
            resources,
            state: self.state.clone(),
            nonce,
            code_challenge: challenge.to_owned(),
            prompt,
            max_age,
            acr_values,
        })
    }

    fn scopes(
        &self,
        policy: &ClientPolicy<'_>,
        supported: &[String],
    ) -> Result<Vec<String>, AuthorizeError> {
        let invalid_scope =
            |d: &'static str| AuthorizeError::new(AuthorizeErrorCode::InvalidScope, d);
        let raw = self
            .get("scope")
            .ok_or_else(|| invalid_scope("scope is required"))?;
        let mut scopes: Vec<String> = Vec::new();
        for token in raw.split(' ') {
            if !is_scope_token(token) {
                return Err(invalid_scope("scope is malformed"));
            }
            if scopes.iter().any(|s| s == token) {
                continue;
            }
            if !supported.iter().any(|s| s == token)
                || !policy.allowed_scopes.iter().any(|s| s == token)
            {
                return Err(invalid_scope(
                    "a requested scope is not allowed for this client",
                ));
            }
            scopes.push(token.to_owned());
            if scopes.len() > MAX_SCOPES {
                return Err(invalid_scope("too many scopes"));
            }
        }
        Ok(scopes)
    }

    fn resources(&self, policy: &ClientPolicy<'_>) -> Result<Vec<String>, AuthorizeError> {
        let invalid_target =
            |d: &'static str| AuthorizeError::new(AuthorizeErrorCode::InvalidTarget, d);
        let mut resources: Vec<String> = Vec::new();
        for (_, value) in self.rest.iter().filter(|(n, _)| n == "resource") {
            if !policy.allowed_resources.iter().any(|r| r == value) {
                return Err(invalid_target(
                    "a requested resource is not allowed for this client",
                ));
            }
            if !resources.contains(value) {
                resources.push(value.clone());
            }
            if resources.len() > MAX_RESOURCES {
                return Err(invalid_target("too many resources"));
            }
        }
        Ok(resources)
    }

    fn prompt(&self) -> Result<Prompt, AuthorizeError> {
        let mut prompt = Prompt::default();
        let Some(raw) = self.get("prompt") else {
            return Ok(prompt);
        };
        let mut any = false;
        for value in raw.split(' ').filter(|v| !v.is_empty()) {
            any = true;
            match value {
                "none" => prompt.none = true,
                "login" => prompt.login = true,
                "consent" => prompt.consent = true,
                // One account per browser session: nothing to select.
                "select_account" => {}
                _ => return Err(invalid("unsupported prompt value")),
            }
        }
        if !any {
            return Err(invalid("prompt is empty"));
        }
        if prompt.none && (prompt.login || prompt.consent) {
            return Err(invalid("prompt=none cannot be combined with other values"));
        }
        Ok(prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn supported() -> Vec<String> {
        ["openid", "profile", "email"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    fn base() -> String {
        format!(
            "client_id=oc_x&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&response_type=code\
             &scope=openid%20email&state=xyz&nonce=n1&code_challenge={CHALLENGE}\
             &code_challenge_method=S256"
        )
    }

    fn validate(query: &str) -> Result<ValidatedAuthorization, AuthorizeError> {
        let scopes = supported();
        let resources = vec!["https://api.example.com".to_owned()];
        parse_query(query).unwrap().validate(
            &ClientPolicy {
                allowed_scopes: &scopes,
                allowed_resources: &resources,
                code_grant_allowed: true,
            },
            &scopes,
        )
    }

    #[test]
    fn oidp_03_valid_request() {
        let v = validate(&base()).unwrap();
        assert_eq!(v.scopes, ["openid", "email"]);
        assert_eq!(v.state.as_deref(), Some("xyz"));
        assert_eq!(v.nonce.as_deref(), Some("n1"));
        assert_eq!(v.code_challenge, CHALLENGE);
        assert_eq!(v.prompt, Prompt::default());
    }

    #[test]
    fn oidp_03_missing_or_plain_pkce_is_rejected() {
        let no_pkce = base().replace(&format!("&code_challenge={CHALLENGE}"), "");
        assert_eq!(
            validate(&no_pkce).unwrap_err().code,
            AuthorizeErrorCode::InvalidRequest
        );
        let plain = base().replace("S256", "plain");
        assert_eq!(
            validate(&plain).unwrap_err().description,
            "only code_challenge_method=S256 is supported"
        );
        let no_method = base().replace("&code_challenge_method=S256", "");
        assert!(validate(&no_method).is_err());
    }

    #[test]
    fn oidp_03_only_the_code_flow_exists() {
        for rt in ["token", "id_token", "code%20id_token", "none"] {
            let q = base().replace("response_type=code", &format!("response_type={rt}"));
            assert_eq!(
                validate(&q).unwrap_err().code,
                AuthorizeErrorCode::UnsupportedResponseType
            );
        }
        let q = format!("{}&request=eyJ", base());
        assert_eq!(
            validate(&q).unwrap_err().code,
            AuthorizeErrorCode::RequestNotSupported
        );
        let q = format!("{}&response_mode=fragment", base());
        assert!(validate(&q).is_err());
    }

    #[test]
    fn oidp_03_duplicates_are_rejected_and_never_redirected_for_client_or_redirect() {
        let q = format!("{}&client_id=oc_y", base());
        assert_eq!(parse_query(&q).unwrap_err(), NoRedirect::ClientId);
        let q = format!("{}&redirect_uri=https%3A%2F%2Fevil.example%2Fcb", base());
        assert_eq!(parse_query(&q).unwrap_err(), NoRedirect::RedirectUri);
        let q = format!("{}&scope=openid", base());
        assert_eq!(
            validate(&q).unwrap_err().description,
            "a parameter was repeated"
        );
        let q = format!("{}&state=other", base());
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.state, None);
        assert!(validate(&q).is_err());
        assert_eq!(
            parse_query("redirect_uri=x").unwrap_err(),
            NoRedirect::ClientId
        );
        assert_eq!(
            parse_query(&"a=b&".repeat(MAX_PARAMS + 1)).unwrap_err(),
            NoRedirect::Malformed
        );
    }

    #[test]
    fn oidp_03_scope_and_resource_policy() {
        let q = base().replace("openid%20email", "openid%20admin");
        assert_eq!(
            validate(&q).unwrap_err().code,
            AuthorizeErrorCode::InvalidScope
        );
        let q = format!("{}&resource=https%3A%2F%2Fapi.example.com", base());
        assert_eq!(validate(&q).unwrap().resources, ["https://api.example.com"]);
        let q = format!("{}&resource=https%3A%2F%2Fother.example.com", base());
        assert_eq!(
            validate(&q).unwrap_err().code,
            AuthorizeErrorCode::InvalidTarget
        );
    }

    #[test]
    fn oidp_04_prompt_max_age_and_acr_values() {
        let q = format!(
            "{}&prompt=login%20consent&max_age=300&acr_values=urn%3Arust-authentication%3Aacr%3Aaal2%20unknown",
            base()
        );
        let v = validate(&q).unwrap();
        assert!(v.prompt.login && v.prompt.consent && !v.prompt.none);
        assert_eq!(v.max_age, Some(300));
        assert_eq!(v.acr_values, [crate::claims::ACR_AAL2]);
        assert!(validate(&format!("{}&prompt=none%20login", base())).is_err());
        assert!(validate(&format!("{}&prompt=bogus", base())).is_err());
        assert!(validate(&format!("{}&max_age=-1", base())).is_err());
        assert!(validate(&format!("{}&state=%0A", base().replace("&state=xyz", ""))).is_err());
    }
}
