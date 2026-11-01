//! Link construction (NTF-02, PWD-08, contracts §11).
//!
//! Every link in every message is `server.public_base_url` + a configured
//! path (`[notify.links]`) — nothing else. Producers hand over **raw
//! tokens**, never URLs, and nothing derived from a request (`Host`,
//! `X-Forwarded-Host`, `Origin`) is ever involved, so Host-header poisoning
//! cannot redirect a reset or magic link to an attacker.
//!
//! The token travels in the URL **fragment** (`#token=…`): browsers never
//! send fragments to servers, so tokens do not end up in access logs,
//! proxies or `Referer` headers. The front-end reads the fragment and POSTs
//! the token.

use std::fmt;

use authn_core::config::notify::LinkPaths;
use authn_core::secret::SensitiveString;
use url::Url;

use crate::error::{NotifyError, RenderError};

/// Shortest accepted link token (CRY-06 tokens are 43 characters).
pub const MIN_TOKEN_LEN: usize = 16;
/// Longest accepted link token.
pub const MAX_TOKEN_LEN: usize = 256;

/// The configured front-end pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTarget {
    /// `links.email_verification`.
    EmailVerification,
    /// `links.password_reset`.
    PasswordReset,
    /// `links.password_reset_request`.
    PasswordResetRequest,
    /// `links.sign_in`.
    SignIn,
    /// `links.email_change_verification`.
    EmailChangeVerification,
    /// `links.email_change_revert`.
    EmailChangeRevert,
    /// `links.magic_link`.
    MagicLink,
    /// `links.invitation`.
    Invitation,
    /// `links.account_deletion_cancel`.
    AccountDeletionCancel,
    /// `links.not_me`.
    NotMe,
    /// `links.org_ownership_transfer`.
    OrgOwnershipTransfer,
}

/// Whether `token` has the shape of a link token: 16–256 characters of the
/// URL-safe base64 alphabet (`A–Z a–z 0–9 - _`). Anything else (`/`, `?`,
/// `#`, `@`, `%`, whitespace…) could alter the URL and is refused.
#[must_use]
pub fn is_valid_token(token: &str) -> bool {
    (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Builds links from `public_base_url` and the configured paths.
#[derive(Clone)]
pub struct LinkBuilder {
    base: Url,
    base_path: String,
    paths: LinkPaths,
}

impl fmt::Debug for LinkBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkBuilder")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl LinkBuilder {
    /// Validates the base URL (absolute `http(s)`, host, no credentials,
    /// query or fragment) and keeps the paths.
    pub fn new(public_base_url: &Url, paths: &LinkPaths) -> Result<Self, NotifyError> {
        let base = public_base_url;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(NotifyError::config(
                "server.public_base_url must be an absolute http(s) URL without credentials, query or fragment",
            ));
        }
        Ok(Self {
            base_path: base.path().trim_end_matches('/').to_owned(),
            base: base.clone(),
            paths: paths.clone(),
        })
    }

    /// The public base URL.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base
    }

    /// Host of the public base URL (used for origin-bound SMS codes).
    #[must_use]
    pub fn host(&self) -> &str {
        self.base.host_str().unwrap_or_default()
    }

    fn path(&self, target: LinkTarget) -> &str {
        let p = &self.paths;
        match target {
            LinkTarget::EmailVerification => &p.email_verification,
            LinkTarget::PasswordReset => &p.password_reset,
            LinkTarget::PasswordResetRequest => &p.password_reset_request,
            LinkTarget::SignIn => &p.sign_in,
            LinkTarget::EmailChangeVerification => &p.email_change_verification,
            LinkTarget::EmailChangeRevert => &p.email_change_revert,
            LinkTarget::MagicLink => &p.magic_link,
            LinkTarget::Invitation => &p.invitation,
            LinkTarget::AccountDeletionCancel => &p.account_deletion_cancel,
            LinkTarget::NotMe => &p.not_me,
            LinkTarget::OrgOwnershipTransfer => &p.org_ownership_transfer,
        }
    }

    fn url(&self, target: LinkTarget) -> Url {
        let mut url = self.base.clone();
        url.set_path(&format!("{}{}", self.base_path, self.path(target)));
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    /// A page link without token (e.g. "sign in", "forgot password").
    #[must_use]
    pub fn page(&self, target: LinkTarget) -> String {
        self.url(target).into()
    }

    /// A link carrying `token` in the fragment (`…/reset-password#token=…`).
    pub fn with_token(
        &self,
        target: LinkTarget,
        token: &SensitiveString,
    ) -> Result<SensitiveString, RenderError> {
        if !is_valid_token(token.expose()) {
            return Err(RenderError::InvalidToken);
        }
        let mut url = self.url(target);
        url.set_fragment(Some(&format!("token={}", token.expose())));
        Ok(SensitiveString::new(String::from(url)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";

    fn builder(base: &str) -> LinkBuilder {
        LinkBuilder::new(&Url::parse(base).unwrap(), &LinkPaths::default()).unwrap()
    }

    #[test]
    fn ntf_02_links_use_only_the_public_base_url_and_configured_path() {
        let links = builder("https://auth.example.com");
        let link = links
            .with_token(LinkTarget::PasswordReset, &SensitiveString::new(TOKEN))
            .unwrap();
        assert_eq!(
            link.expose(),
            format!("https://auth.example.com/reset-password#token={TOKEN}")
        );
        assert_eq!(
            links.page(LinkTarget::SignIn),
            "https://auth.example.com/login"
        );
        assert_eq!(links.host(), "auth.example.com");
    }

    #[test]
    fn ntf_02_base_path_prefix_is_kept() {
        for base in ["https://example.com/auth", "https://example.com/auth/"] {
            assert_eq!(
                builder(base).page(LinkTarget::MagicLink),
                "https://example.com/auth/magic-link"
            );
        }
        assert_eq!(
            builder("https://example.com:8443/").page(LinkTarget::NotMe),
            "https://example.com:8443/security/not-me"
        );
    }

    #[test]
    fn pwd_08_malicious_tokens_cannot_change_the_link_target() {
        let links = builder("https://auth.example.com");
        for bad in [
            "@evil.example/AAAAAAAAAAAAAAAAAAAA",
            "../../evil?redirect=https://evil.example",
            "AAAAAAAAAAAAAAAAAAAA#x",
            "AAAAAAAAAAAAAAAAAAAA%2F",
            "AAAAAAAAAAAA AAAAAAAAAA",
            "AAAAAAAAAAAA\r\nAAAAAAAA",
            "short",
            &"A".repeat(MAX_TOKEN_LEN + 1),
        ] {
            assert_eq!(
                links
                    .with_token(LinkTarget::MagicLink, &SensitiveString::new(bad))
                    .unwrap_err(),
                RenderError::InvalidToken,
                "{bad}"
            );
        }
    }

    #[test]
    fn ntf_02_unsafe_base_urls_are_refused() {
        for base in [
            "https://user:pw@auth.example.com",
            "https://auth.example.com/?next=x",
            "https://auth.example.com/#frag",
            "ftp://auth.example.com",
        ] {
            assert!(
                LinkBuilder::new(&Url::parse(base).unwrap(), &LinkPaths::default()).is_err(),
                "{base}"
            );
        }
    }
}
