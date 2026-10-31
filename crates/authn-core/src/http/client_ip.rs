//! Client IP resolution behind reverse proxies (PRT-06).
//!
//! `X-Forwarded-For` / `Forwarded` are attacker controlled unless they were
//! written by a proxy we trust. The algorithm:
//!
//! 1. If the TCP peer is **not** a trusted proxy, the peer IP is the client
//!    IP and forwarding headers are ignored completely.
//! 2. Otherwise only the configured header ([`ClientIpHeader`]) is read —
//!    never both, because a proxy that sanitizes one header may pass the
//!    other through untouched. Multiple header lines are concatenated in
//!    order.
//! 3. The hop list is walked **from right to left** (nearest hop first),
//!    skipping trusted proxies. The first untrusted address is the client.
//! 4. If a hop is unparsable (`unknown`, obfuscated identifiers, garbage),
//!    the walk stops and the nearest trusted hop seen so far is used — the
//!    garbage cannot be attributed to anyone more precisely.
//! 5. If every hop is trusted, the left-most hop is the client.
//! 6. At most [`MAX_HOPS`] hops are inspected; IPv4-mapped IPv6 addresses
//!    are canonicalized to IPv4.

use std::net::IpAddr;

use http::HeaderMap;
use ipnet::IpNet;

/// Maximum number of forwarding hops inspected.
pub const MAX_HOPS: usize = 32;

text_enum! {
    /// Which forwarding header the trusted proxies maintain.
    #[derive(Default)]
    pub enum ClientIpHeader {
        /// `X-Forwarded-For: client, proxy1, proxy2`.
        #[default]
        XForwardedFor => "x-forwarded-for",
        /// RFC 7239 `Forwarded: for=client, for=proxy1`.
        Forwarded => "forwarded",
    }
}

/// Resolves the client IP for one request (see the module docs).
#[must_use]
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
    header: ClientIpHeader,
) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: &IpAddr| trusted_proxies.iter().any(|net| net.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }

    let hops = collect_hops(headers, header);
    let mut nearest_trusted = peer;
    for hop in hops.iter().rev().take(MAX_HOPS) {
        match hop {
            Some(ip) => {
                let ip = ip.to_canonical();
                if is_trusted(&ip) {
                    nearest_trusted = ip;
                } else {
                    return ip;
                }
            }
            None => return nearest_trusted,
        }
    }
    nearest_trusted
}

/// Parses all hops of the configured header, left to right. `None` marks an
/// unparsable hop.
fn collect_hops(headers: &HeaderMap, header: ClientIpHeader) -> Vec<Option<IpAddr>> {
    let mut hops = Vec::new();
    for value in headers.get_all(header.as_str()) {
        let Ok(value) = value.to_str() else {
            // Non-ASCII header bytes: treat the whole line as one bad hop.
            hops.push(None);
            continue;
        };
        for element in split_outside_quotes(value, ',') {
            let element = element.trim();
            if element.is_empty() {
                continue;
            }
            let hop = match header {
                ClientIpHeader::XForwardedFor => parse_node(element),
                ClientIpHeader::Forwarded => forwarded_for(element).and_then(parse_node),
            };
            hops.push(hop);
        }
    }
    hops
}

/// Extracts the `for=` parameter of one `Forwarded` element.
fn forwarded_for(element: &str) -> Option<&str> {
    split_outside_quotes(element, ';')
        .into_iter()
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("for"))
        .map(|(_, value)| value.trim())
}

/// Parses a node: `1.2.3.4`, `1.2.3.4:80`, `2001:db8::1`, `[2001:db8::1]`,
/// `[2001:db8::1]:443`, optionally double-quoted.
fn parse_node(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    let raw = raw
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(raw);
    if raw.len() > 64 {
        return None;
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        if !(tail.is_empty() || is_port_suffix(tail)) {
            return None;
        }
        return addr.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    // IPv4 with port.
    let (addr, port) = raw.rsplit_once(':')?;
    if !is_port_suffix(&format!(":{port}")) {
        return None;
    }
    addr.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

fn is_port_suffix(tail: &str) -> bool {
    tail.strip_prefix(':')
        .is_some_and(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Splits on `sep`, ignoring separators inside double quotes.
fn split_outside_quotes(input: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in input.char_indices() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == sep && !in_quotes {
            parts.push(input.get(start..i).unwrap_or_default());
            start = i + c.len_utf8();
        }
    }
    parts.push(input.get(start..).unwrap_or_default());
    parts
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn headers(name: &str, values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for v in values {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const XFF: ClientIpHeader = ClientIpHeader::XForwardedFor;

    #[test]
    fn prt_06_untrusted_peer_ignores_forwarding_headers() {
        let h = headers("x-forwarded-for", &["1.1.1.1"]);
        let got = resolve_client_ip(ip("203.0.113.9"), &h, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, ip("203.0.113.9"));
        // No trusted proxies configured at all: same.
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), &h, &[], XFF),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn prt_06_trusted_peer_uses_rightmost_untrusted_hop() {
        // Attacker prepends a spoofed address; the proxy appends the real one.
        let h = headers("x-forwarded-for", &["6.6.6.6, 198.51.100.7"]);
        let got = resolve_client_ip(ip("10.0.0.2"), &h, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn prt_06_skips_chain_of_trusted_proxies() {
        let h = headers("x-forwarded-for", &["198.51.100.7, 10.1.1.1, 10.2.2.2"]);
        let got = resolve_client_ip(ip("10.0.0.2"), &h, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn prt_06_multiple_header_lines_are_concatenated_in_order() {
        let h = headers("x-forwarded-for", &["6.6.6.6", "198.51.100.7, 10.2.2.2"]);
        let got = resolve_client_ip(ip("10.0.0.2"), &h, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn prt_06_all_trusted_hops_yield_leftmost() {
        let h = headers("x-forwarded-for", &["10.9.9.9, 10.1.1.1"]);
        let got = resolve_client_ip(ip("10.0.0.2"), &h, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, ip("10.9.9.9"));
    }

    #[test]
    fn prt_06_missing_header_from_trusted_peer_yields_peer() {
        let got = resolve_client_ip(
            ip("10.0.0.2"),
            &HeaderMap::new(),
            &nets(&["10.0.0.0/8"]),
            XFF,
        );
        assert_eq!(got, ip("10.0.0.2"));
    }

    #[test]
    fn prt_06_garbage_hop_falls_back_to_nearest_trusted_hop() {
        let h = headers("x-forwarded-for", &["198.51.100.7, garbage, 10.1.1.1"]);
        let got = resolve_client_ip(ip("10.0.0.2"), &h, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, ip("10.1.1.1"));
        let h = headers("x-forwarded-for", &["198.51.100.7, unknown"]);
        let got = resolve_client_ip(ip("10.0.0.2"), &h, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, ip("10.0.0.2"));
    }

    #[test]
    fn prt_06_ports_brackets_and_ipv6() {
        let h = headers("x-forwarded-for", &["[2001:db8::7]:443, 198.51.100.1:8080"]);
        let trusted = nets(&["10.0.0.0/8", "198.51.100.1/32"]);
        let got = resolve_client_ip(ip("10.0.0.2"), &h, &trusted, XFF);
        assert_eq!(got, ip("2001:db8::7"));
        let h = headers("x-forwarded-for", &["2001:db8::8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.2"), &h, &trusted, XFF),
            ip("2001:db8::8")
        );
    }

    #[test]
    fn prt_06_ipv4_mapped_addresses_are_canonicalized() {
        let h = headers("x-forwarded-for", &["::ffff:198.51.100.7"]);
        let got = resolve_client_ip(ip("::ffff:10.0.0.2"), &h, &nets(&["10.0.0.0/8"]), XFF);
        assert_eq!(got, ip("198.51.100.7"));
    }

    #[test]
    fn prt_06_only_the_configured_header_is_used() {
        let mut h = headers("x-forwarded-for", &["6.6.6.6"]);
        h.append("forwarded", HeaderValue::from_static("for=198.51.100.7"));
        let trusted = nets(&["10.0.0.0/8"]);
        let fwd = resolve_client_ip(ip("10.0.0.2"), &h, &trusted, ClientIpHeader::Forwarded);
        assert_eq!(fwd, ip("198.51.100.7"));
        let xff = resolve_client_ip(ip("10.0.0.2"), &h, &trusted, XFF);
        assert_eq!(xff, ip("6.6.6.6"));
    }

    #[test]
    fn prt_06_rfc_7239_forwarded_parsing() {
        let h = headers(
            "forwarded",
            &[
                r#"for=6.6.6.6;proto=https, for="[2001:db8:cafe::17]:4711";by=10.0.0.9, For=10.1.1.1"#,
            ],
        );
        let got = resolve_client_ip(
            ip("10.0.0.2"),
            &h,
            &nets(&["10.0.0.0/8"]),
            ClientIpHeader::Forwarded,
        );
        assert_eq!(got, ip("2001:db8:cafe::17"));
        // Obfuscated identifier: stop at the nearest trusted hop.
        let h = headers(
            "forwarded",
            &["for=198.51.100.7, for=_hidden, for=10.1.1.1"],
        );
        let got = resolve_client_ip(
            ip("10.0.0.2"),
            &h,
            &nets(&["10.0.0.0/8"]),
            ClientIpHeader::Forwarded,
        );
        assert_eq!(got, ip("10.1.1.1"));
    }

    #[test]
    fn prt_06_hop_walk_is_bounded() {
        let mut list = vec!["198.51.100.7".to_owned()];
        list.extend((0..100).map(|i| format!("10.0.{}.{}", i / 250, i % 250)));
        let h = headers("x-forwarded-for", &[&list.join(",")]);
        let got = resolve_client_ip(ip("10.0.0.2"), &h, &nets(&["10.0.0.0/8"]), XFF);
        // The real client is beyond MAX_HOPS trusted hops: we stop at a proxy.
        assert!(nets(&["10.0.0.0/8"])[0].contains(&got));
    }

    #[test]
    fn node_parsing_edge_cases() {
        assert_eq!(parse_node("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse_node("\"1.2.3.4:80\""), Some(ip("1.2.3.4")));
        assert_eq!(parse_node("[::1]"), Some(ip("::1")));
        assert_eq!(parse_node("[::1]x"), None);
        assert_eq!(parse_node("1.2.3.4:"), None);
        assert_eq!(parse_node("1.2.3.4:123456"), None);
        assert_eq!(parse_node("example.com"), None);
        assert_eq!(parse_node(""), None);
    }
}
