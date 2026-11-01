//! Webhook URL validation at registration time (AUD-07, PRT-12).
//!
//! This is the *early* check that gives the endpoint owner a clear error;
//! the authoritative SSRF defence is the `HttpClient` port with
//! `OutboundTarget::UserSupplied`, which resolves the host, refuses
//! non-public addresses and pins the connection to the vetted IP on every
//! delivery (DNS rebinding).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use authn_core::error::{AuthError, codes};
use url::{Host, Url};

/// Longest accepted URL (schema limit).
pub const MAX_URL_LEN: usize = 2048;

/// Host name suffixes that never denote a public destination.
const LOCAL_SUFFIXES: &[&str] = &[
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".home.arpa",
    ".localdomain",
];

fn invalid(context: &'static str) -> AuthError {
    AuthError::new(codes::audit::WEBHOOK_URL_INVALID).with_context(context)
}

/// Validates and normalizes a webhook URL: absolute `https`, no user info,
/// no fragment, a public DNS name or a public IP literal, ≤ 2048 bytes.
pub fn validate_webhook_url(input: &str) -> Result<Url, AuthError> {
    if input.is_empty() || input.len() > MAX_URL_LEN {
        return Err(invalid("webhook url length"));
    }
    if input.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(invalid("webhook url contains control characters"));
    }
    let url = Url::parse(input).map_err(|_| invalid("webhook url unparsable"))?;
    if url.scheme() != "https" {
        return Err(invalid("webhook url must be https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("webhook url must not carry credentials"));
    }
    if url.fragment().is_some() {
        return Err(invalid("webhook url must not have a fragment"));
    }
    if url.port() == Some(0) {
        return Err(invalid("webhook url port 0"));
    }
    match url.host() {
        None => return Err(invalid("webhook url without host")),
        Some(Host::Ipv4(v4)) => {
            if !is_public_ipv4(v4) {
                return Err(invalid("webhook url points at a non-public address"));
            }
        }
        Some(Host::Ipv6(v6)) => {
            if !is_public_ipv6(v6) {
                return Err(invalid("webhook url points at a non-public address"));
            }
        }
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if domain == "localhost"
                || !domain.contains('.')
                || LOCAL_SUFFIXES.iter().any(|suffix| domain.ends_with(suffix))
            {
                return Err(invalid("webhook url host is not public"));
            }
        }
    }
    if url.as_str().len() > MAX_URL_LEN {
        return Err(invalid("webhook url length"));
    }
    Ok(url)
}

/// Cloud metadata / host-service addresses that lie in *public* space
/// (the link-local and CGNAT ones are refused by their ranges anyway).
const PUBLIC_SPACE_METADATA_V4: &[[u8; 4]] = &[
    [168, 63, 129, 16], // Azure WireServer
];

/// Whether an IPv4 address is globally routable (not private, loopback,
/// link-local / cloud metadata, CGNAT, documentation, benchmarking,
/// protocol assignments, 6to4 relay anycast, multicast, reserved or
/// broadcast).
#[must_use]
pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240
        || PUBLIC_SPACE_METADATA_V4.contains(&ip.octets()))
}

/// Whether an IPv6 address is globally routable: inside global unicast
/// `2000::/3` and not in one of its special blocks (IETF protocol
/// assignments `2001::/23` incl. Teredo, documentation `2001:db8::/32` and
/// `3fff::/20`, 6to4 `2002::/16`). Everything outside `2000::/3` — loopback,
/// IPv4-compatible `::/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`,
/// discard `100::/64`, unique local, link-local, site-local, multicast — is
/// refused. IPv4-mapped addresses are judged as IPv4.
#[must_use]
pub fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }
    let segments = ip.segments();
    let first = segments.first().copied().unwrap_or(0);
    let second = segments.get(1).copied().unwrap_or(0);
    let global_unicast = (first & 0xe000) == 0x2000;
    global_unicast
        && !((first == 0x2001 && second < 0x0200)
            || (first == 0x2001 && second == 0x0db8)
            || first == 0x2002
            || (first & 0xfff0) == 0x3ff0)
}

/// Whether an IP address is globally routable.
#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aud_07_public_https_urls_are_accepted_and_normalized() {
        let url = validate_webhook_url("https://Hooks.Example.COM:8443/in/abc?x=1").unwrap();
        assert_eq!(url.as_str(), "https://hooks.example.com:8443/in/abc?x=1");
        assert!(validate_webhook_url("https://93.184.215.14/hook").is_ok());
        assert!(validate_webhook_url("https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/h").is_ok());
        assert!(validate_webhook_url("https://bücher.example/hook").is_ok());
        assert!(validate_webhook_url("https://[2001:4860:4860::8888]/h").is_ok());
        assert!(validate_webhook_url("https://[2a00:1450:4001:80b::200e]/h").is_ok());
    }

    #[test]
    fn prt_12_aud_07_unsafe_urls_are_rejected() {
        for bad in [
            "",
            "http://hooks.example.com/",
            "ftp://hooks.example.com/",
            "https://user:pw@hooks.example.com/",
            "https://user@hooks.example.com/",
            "https://hooks.example.com/#frag",
            "https://localhost/",
            "https://LOCALHOST./",
            "https://api.localhost/",
            "https://printer.local/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://intranet/",
            "https://127.0.0.1/",
            "https://127.1/",
            "https://0x7f000001/",
            "https://2130706433/",
            "https://10.0.0.5/",
            "https://172.16.0.1/",
            "https://192.168.1.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://100.64.0.1/",
            "https://0.0.0.0/",
            "https://[::1]/",
            "https://[::]/",
            "https://[fd00::1]/",
            "https://[fe80::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:169.254.169.254]/",
            "https://[64:ff9b::a00:1]/",
            "https://[64:ff9b:1::a00:1]/",
            "https://[::7f00:1]/",
            "https://[::a9fe:a9fe]/",
            "https://[::a00:5]/",
            "https://[100::1]/",
            "https://[2001::1]/",
            "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/",
            "https://[2001:db8::1]/",
            "https://[2002:7f00:1::1]/",
            "https://[3fff::1]/",
            "https://[fd00:ec2::254]/",
            "https://[fec0::1]/",
            "https://[ff02::1]/",
            "https://168.63.129.16/",
            "https://192.88.99.1/",
            "https://198.18.0.1/",
            "https://hooks.example.com:0/",
            "https://hooks.example.com/ space",
            "https://hooks.example.com/\n",
            "not a url",
            "/relative/path",
        ] {
            let err = validate_webhook_url(bad).unwrap_err();
            assert_eq!(err.code(), codes::audit::WEBHOOK_URL_INVALID, "{bad:?}");
        }
        let long = format!("https://hooks.example.com/{}", "a".repeat(MAX_URL_LEN));
        assert!(validate_webhook_url(&long).is_err());
    }
}
