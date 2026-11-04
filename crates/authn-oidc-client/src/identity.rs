//! The external identity a provider asserted, normalized across providers
//! (SOC-01, SOC-05).
//!
//! E-mail verification per provider (only a verified address can create an
//! account or be used for linking, ADR 0002 "non-verifying IdP"):
//!
//! | Provider | Verified when |
//! |----------|---------------|
//! | Google, generic OIDC | `email_verified` is `true` |
//! | Apple | `email_verified` is `true` (also for private relay addresses) |
//! | Microsoft | personal account tenant (`9188040d-…`), or the optional claim `xms_edov` is `true` — the plain `email` claim of work accounts is mutable and unverified ("nOAuth") |
//! | GitHub | the **primary** address of `/user/emails` is `verified` (other verified addresses are ignored) |

use authn_core::error::AuthError;
use authn_core::ports::HttpClient;
use authn_core::secret::SensitiveString;
use serde::Deserialize;
use time::OffsetDateTime;
use url::Url;

use crate::id_token::{IdClaims, invalid};
use crate::outbound;
use crate::provider::{Endpoints, MICROSOFT_CONSUMERS_TENANT, Provider, ProviderKind, is_guid};

/// Longest display name kept (`user_profiles` allows 128 characters).
pub const MAX_DISPLAY_NAME_CHARS: usize = 128;
/// Longest e-mail address kept (`identities_email_check`).
pub const MAX_EMAIL_BYTES: usize = 320;

/// Provider tokens returned by a code exchange (stored only when
/// `oidc_client.store_provider_tokens` is on, envelope encrypted, SOC-08).
#[derive(Debug, Clone)]
pub struct ProviderTokens {
    /// Access token.
    pub access_token: SensitiveString,
    /// Refresh token, if issued.
    pub refresh_token: Option<SensitiveString>,
    /// Access-token expiry, if announced.
    pub expires_at: Option<OffsetDateTime>,
}

/// A verified external identity.
#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    /// `identities.provider`.
    pub provider: String,
    /// Stable subject (`<tid>:<oid>` for Microsoft, the numeric id for
    /// GitHub, `sub` otherwise).
    pub subject: String,
    /// Token issuer (OIDC providers).
    pub issuer: Option<String>,
    /// Asserted address.
    pub email: Option<String>,
    /// Whether the provider verified [`ExternalIdentity::email`].
    pub email_verified: bool,
    /// Display name.
    pub display_name: Option<String>,
    /// The provider asserted MFA (`amr` contains `mfa`); honoured only with
    /// `oidc_client.trust_provider_mfa` (SOC-09).
    pub provider_mfa: bool,
    /// Provider tokens (web flow only).
    pub tokens: Option<ProviderTokens>,
}

impl ExternalIdentity {
    /// The address if — and only if — the provider verified it.
    #[must_use]
    pub fn verified_email(&self) -> Option<&str> {
        self.email.as_deref().filter(|_| self.email_verified)
    }
}

/// Trims, drops control / format characters and bounds a display name.
#[must_use]
pub fn clean_display_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let bounded: String = cleaned.chars().take(MAX_DISPLAY_NAME_CHARS).collect();
    (!bounded.is_empty()).then_some(bounded)
}

fn clean_email(raw: Option<String>) -> Option<String> {
    raw.map(|e| e.trim().to_owned())
        .filter(|e| !e.is_empty() && e.len() <= MAX_EMAIL_BYTES && !e.chars().any(char::is_control))
}

/// Maps verified ID-token claims to an identity.
pub fn from_id_claims(
    provider: &Provider,
    claims: IdClaims,
    first_login_name: Option<String>,
) -> Result<ExternalIdentity, AuthError> {
    let provider_mfa = claims.amr.iter().any(|a| a == "mfa");
    let (subject, email_verified) = match provider.kind {
        ProviderKind::Microsoft => {
            let tid = claims
                .tenant_id
                .as_deref()
                .filter(|t| is_guid(t))
                .ok_or_else(|| invalid("microsoft token without tid"))?
                .to_ascii_lowercase();
            let oid = claims
                .object_id
                .as_deref()
                .filter(|o| is_guid(o))
                .ok_or_else(|| invalid("microsoft token without oid"))?
                .to_ascii_lowercase();
            let verified = tid == MICROSOFT_CONSUMERS_TENANT || claims.email_domain_verified;
            (format!("{tid}:{oid}"), verified)
        }
        _ => (claims.subject.clone(), claims.email_verified),
    };
    let display_name = first_login_name
        .or(claims.name)
        .and_then(|n| clean_display_name(&n));
    let email = clean_email(claims.email);
    Ok(ExternalIdentity {
        provider: provider.storage_id.clone(),
        subject,
        issuer: Some(claims.issuer),
        email_verified: email_verified && email.is_some(),
        email,
        display_name,
        provider_mfa,
        tokens: None,
    })
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    login: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

/// GitHub: `/user` and `/user/emails` with the access token. Only the
/// primary address counts, and only if GitHub verified it.
pub async fn github_identity(
    http: &dyn HttpClient,
    provider: &Provider,
    endpoints: &Endpoints,
    access_token: &str,
) -> Result<ExternalIdentity, AuthError> {
    let api = endpoints
        .api_base
        .as_ref()
        .ok_or_else(|| AuthError::internal("github provider without API base"))?;
    let join = |path: &str| -> Result<Url, AuthError> {
        api.join(path)
            .map_err(|_| AuthError::internal("invalid github API URL"))
    };
    const ACCEPT: &str = "application/vnd.github+json";
    let user: GithubUser = outbound::get(
        http,
        join("user")?,
        endpoints.target,
        Some(access_token),
        Some(ACCEPT),
    )
    .await?
    .json("github user")?;
    let emails: Vec<GithubEmail> = outbound::get(
        http,
        join("user/emails")?,
        endpoints.target,
        Some(access_token),
        Some(ACCEPT),
    )
    .await?
    .json("github emails")?;
    let primary = emails.into_iter().take(100).find(|e| e.primary);
    let (email, verified) = match primary {
        Some(e) => (clean_email(Some(e.email)), e.verified),
        None => (None, false),
    };
    Ok(ExternalIdentity {
        provider: provider.storage_id.clone(),
        subject: user.id.to_string(),
        issuer: None,
        email_verified: verified && email.is_some(),
        email,
        display_name: user
            .name
            .or(user.login)
            .and_then(|n| clean_display_name(&n)),
        provider_mfa: false,
        tokens: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc_07_display_names_are_cleaned_and_bounded() {
        assert_eq!(
            clean_display_name("  Ada \u{202e}\t Lovelace\u{0000} ").as_deref(),
            Some("Ada Lovelace")
        );
        assert_eq!(clean_display_name(" \u{200b} "), None);
        assert_eq!(
            clean_display_name(&"x".repeat(500)).map(|s| s.chars().count()),
            Some(MAX_DISPLAY_NAME_CHARS)
        );
    }
}
