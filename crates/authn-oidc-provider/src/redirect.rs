//! Redirect URI rules (OIDP-02; OAuth 2.1 §2.3.1, §4.1.3, RFC 8252, RFC
//! 9700 §4.1).
//!
//! **Registration** accepts only canonical absolute URIs (the `url`
//! crate's serialization must equal the input byte for byte, so no case,
//! dot-segment or percent-encoding variants can be registered), without
//! fragment, user info or wildcard:
//!
//! | Client | Accepted |
//! |--------|----------|
//! | web | `https://host/…` |
//! | native | `https://host/…` (claimed links), loopback `http://127.0.0.1/…` / `http://[::1]/…` (RFC 8252 §7.3; `localhost` is refused, §8.3), private-use schemes in reverse-domain form with a dot (`com.example.app:/callback`, §7.1) |
//!
//! **Matching** is exact string comparison, with one exception required by
//! RFC 8252 §7.3: for a registered *loopback* URI the port of the request
//! is ignored (native apps bind an ephemeral port). The requested URI must
//! itself be canonical, so `http://127.0.0.1:1234/cb/../x` cannot match
//! `http://127.0.0.1/x`.

use url::{Host, Url};

/// Longest accepted redirect URI.
pub const MAX_REDIRECT_URI_LEN: usize = 2000;

/// The kind of application a client is (OIDC Dynamic Registration
/// `application_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationType {
    /// Server-side or browser application: `https` redirects only.
    Web,
    /// Native / mobile application (RFC 8252).
    Native,
}

impl ApplicationType {
    /// Wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
        }
    }

    /// Parses the wire value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "web" => Some(Self::Web),
            "native" => Some(Self::Native),
            _ => None,
        }
    }
}

/// Schemes that may never be used as a private-use redirect scheme, even
/// if written with a dot (defence in depth; a dotted scheme is required
/// anyway).
const FORBIDDEN_SCHEMES: &[&str] = &[
    "javascript",
    "data",
    "file",
    "vbscript",
    "about",
    "blob",
    "ftp",
    "ws",
    "wss",
    "http",
    "https",
];

fn is_loopback_ip(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        _ => false,
    }
}

/// Parses `uri` and requires its canonical serialization to equal the
/// input.
fn canonical(uri: &str) -> Option<Url> {
    if uri.is_empty()
        || uri.len() > MAX_REDIRECT_URI_LEN
        || !uri.bytes().all(|b| b.is_ascii_graphic())
        || uri.contains('*')
        || uri.contains('#')
    {
        return None;
    }
    let url = Url::parse(uri).ok()?;
    (url.as_str() == uri
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none())
    .then_some(url)
}

fn is_loopback_http(url: &Url) -> bool {
    url.scheme() == "http" && is_loopback_ip(url.host())
}

/// Validates a redirect URI for registration. `Err` carries a short
/// English reason for the admin (no secret data).
pub fn validate_for_registration(uri: &str, app: ApplicationType) -> Result<(), &'static str> {
    let url = canonical(uri).ok_or(
        "must be a canonical absolute URI (no fragment, user info, wildcard or non-normalized form)",
    )?;
    match url.scheme() {
        "https" => {
            if url.host().is_none() {
                return Err("https redirect URIs need a host");
            }
            Ok(())
        }
        "http" => match app {
            ApplicationType::Native if is_loopback_http(&url) => Ok(()),
            ApplicationType::Native => Err(
                "native clients may use http only with the loopback IP literals 127.0.0.1 or [::1]",
            ),
            ApplicationType::Web => Err("web clients must use https redirect URIs"),
        },
        scheme => match app {
            ApplicationType::Web => Err("web clients must use https redirect URIs"),
            ApplicationType::Native => {
                if !scheme.contains('.') || FORBIDDEN_SCHEMES.contains(&scheme) {
                    Err("private-use schemes must be in reverse-domain form, e.g. com.example.app")
                } else {
                    Ok(())
                }
            }
        },
    }
}

/// Whether `requested` matches one of the `registered` URIs (exact match;
/// any port for a registered loopback URI).
#[must_use]
pub fn matches(registered: &[String], requested: &str) -> bool {
    if registered.iter().any(|r| r == requested) {
        return canonical(requested).is_some();
    }
    let Some(mut url) = canonical(requested) else {
        return false;
    };
    if !is_loopback_http(&url) {
        return false;
    }
    if url.set_port(None).is_err() {
        return false;
    }
    let without_port = url.as_str();
    registered.iter().any(|r| {
        canonical(r).is_some_and(|mut reg| {
            is_loopback_http(&reg) && reg.set_port(None).is_ok() && reg.as_str() == without_port
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(uris: &[&str]) -> Vec<String> {
        uris.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn oidp_02_registration_rules() {
        use ApplicationType::{Native, Web};
        assert!(validate_for_registration("https://rp.example.com/cb", Web).is_ok());
        assert!(validate_for_registration("https://rp.example.com/cb?x=1", Web).is_ok());
        for bad in [
            "http://rp.example.com/cb",
            "https://rp.example.com/cb#frag",
            "https://*.example.com/cb",
            "https://user:pw@rp.example.com/cb",
            "HTTPS://rp.example.com/cb",
            "https://RP.example.com/cb",
            "https://rp.example.com/a/../cb",
            "https://rp.example.com",
            "com.example.app:/cb",
            "/relative",
            "",
        ] {
            assert!(validate_for_registration(bad, Web).is_err(), "{bad}");
        }
        assert!(validate_for_registration("http://127.0.0.1/cb", Native).is_ok());
        assert!(validate_for_registration("http://[::1]/cb", Native).is_ok());
        assert!(validate_for_registration("com.example.app:/oauth", Native).is_ok());
        assert!(validate_for_registration("https://app.example.com/cb", Native).is_ok());
        for bad in [
            "http://localhost/cb",
            "http://10.0.0.1/cb",
            "myapp:/cb",
            "javascript:alert(1)",
            "data:text/html,x",
        ] {
            assert!(validate_for_registration(bad, Native).is_err(), "{bad}");
        }
    }

    #[test]
    fn oidp_02_exact_match_rejects_variants() {
        let registered = reg(&["https://rp.example.com/cb"]);
        assert!(matches(&registered, "https://rp.example.com/cb"));
        for variant in [
            "https://rp.example.com/cb/",
            "https://rp.example.com/cb/extra",
            "https://rp.example.com/CB",
            "https://RP.example.com/cb",
            "https://rp.example.com/cb?x=1",
            "https://rp.example.com:443/cb",
            "https://rp.example.com/cb#x",
            "https://rp.example.com.evil.com/cb",
            "https://evil.com/?https://rp.example.com/cb",
            "http://rp.example.com/cb",
            "https://rp.example.com/%63b",
        ] {
            assert!(!matches(&registered, variant), "{variant}");
        }
    }

    #[test]
    fn oidp_02_loopback_ignores_only_the_port() {
        let registered = reg(&["http://127.0.0.1/cb", "http://[::1]/oauth"]);
        assert!(matches(&registered, "http://127.0.0.1:51234/cb"));
        assert!(matches(&registered, "http://127.0.0.1/cb"));
        assert!(matches(&registered, "http://[::1]:8080/oauth"));
        assert!(!matches(&registered, "http://127.0.0.1:51234/other"));
        assert!(!matches(&registered, "http://localhost:51234/cb"));
        assert!(!matches(&registered, "http://127.0.0.1:51234/x/../cb"));
        assert!(!matches(&registered, "https://127.0.0.1:51234/cb"));
        // A non-loopback registration never ignores the port.
        let https = reg(&["https://rp.example.com/cb"]);
        assert!(!matches(&https, "https://rp.example.com:8443/cb"));
    }
}
