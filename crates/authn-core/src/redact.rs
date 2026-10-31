//! Personal-data masking for logs and user-facing listings (OPS-03, SES-11).
//!
//! Log lines must never contain full e-mail addresses or full IP addresses.
//! Use these helpers (or the [`Redacted`] wrapper) when a value has to appear
//! in a `tracing` field.

use std::fmt;
use std::net::IpAddr;

/// Masks an e-mail address, keeping the first character of the local part and
/// the domain: `alice@example.com` → `a***@example.com`.
///
/// Input that does not look like an address is fully masked.
#[must_use]
pub fn mask_email(email: &str) -> String {
    match email.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        _ => "***".to_owned(),
    }
}

/// Masks an IP address to its network: IPv4 keeps the /24
/// (`203.0.113.7` → `203.0.113.x`), IPv6 keeps the /48
/// (`2001:db8:1:2::1` → `2001:db8:1::/48`).
#[must_use]
pub fn mask_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.x")
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return mask_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// Wrapper whose `Debug`/`Display` never print the inner value.
///
/// Useful for struct fields that hold personal data or secrets and would
/// otherwise end up in `#[derive(Debug)]` output.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Redacted<T>(pub T);

impl<T> Redacted<T> {
    /// Returns the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(crate::secret::REDACTED)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(crate::secret::REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_03_email_is_partially_masked() {
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
        assert_eq!(mask_email("ş@örnek.com"), "ş***@örnek.com");
        assert_eq!(mask_email("garbage"), "***");
        assert_eq!(mask_email("@example.com"), "***");
    }

    #[test]
    fn ops_03_ip_is_partially_masked() {
        assert_eq!(mask_ip("203.0.113.7".parse().unwrap()), "203.0.113.x");
        assert_eq!(
            mask_ip("2001:db8:1:2::1".parse().unwrap()),
            "2001:db8:1::/48"
        );
        assert_eq!(mask_ip("::ffff:10.1.2.3".parse().unwrap()), "10.1.2.x");
    }

    #[test]
    fn ops_03_redacted_hides_value() {
        let r = Redacted("secret@example.com");
        assert_eq!(format!("{r:?} {r}"), "[REDACTED] [REDACTED]");
    }
}
