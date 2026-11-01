//! Network aggregation (RSK-02 "new network") and the optional
//! anonymizing-network list (TOR exits, open proxies, VPN ranges).

use std::net::IpAddr;
use std::path::Path;

use authn_core::error::AuthError;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Largest anonymizing-network file read (32 MiB).
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Most entries accepted from the file.
const MAX_ENTRIES: usize = 2_000_000;

/// The network a login IP is attributed to: `/24` for IPv4 (IPv4-mapped
/// IPv6 included), `/48` for IPv6.
#[must_use]
pub fn network_of(ip: IpAddr) -> IpNet {
    // The prefixes are constants within range, so `new` cannot fail; the
    // host-route fallback only exists to avoid a panicking constructor.
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            let base = std::net::Ipv4Addr::new(a, b, c, 0);
            IpNet::V4(Ipv4Net::new(base, 24).unwrap_or_else(|_| Ipv4Net::from(base)))
        }
        IpAddr::V6(v6) => {
            let [a, b, c, ..] = v6.segments();
            let base = std::net::Ipv6Addr::new(a, b, c, 0, 0, 0, 0, 0);
            IpNet::V6(Ipv6Net::new(base, 48).unwrap_or_else(|_| Ipv6Net::from(base)))
        }
    }
}

/// A set of networks with `O(log n)` membership tests (sorted, aggregated).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnonymizingNetworks {
    v4: Vec<Ipv4Net>,
    v6: Vec<Ipv6Net>,
}

impl AnonymizingNetworks {
    /// Parses one CIDR or bare IP per line; `#` starts a comment, blank
    /// lines are ignored. Errors name the line number, never its content.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut nets = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            if nets.len() >= MAX_ENTRIES {
                return Err(format!("more than {MAX_ENTRIES} entries"));
            }
            let net = line
                .parse::<IpNet>()
                .or_else(|_| line.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| format!("line {}: not an IP address or CIDR", index + 1))?;
            nets.push(net.trunc());
        }
        Ok(Self::from_networks(nets))
    }

    /// Builds the set from networks (aggregated and sorted).
    #[must_use]
    pub fn from_networks(nets: Vec<IpNet>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for net in IpNet::aggregate(&nets) {
            match net {
                IpNet::V4(n) => v4.push(n),
                IpNet::V6(n) => v6.push(n),
            }
        }
        v4.sort_unstable_by_key(Ipv4Net::network);
        v6.sort_unstable_by_key(Ipv6Net::network);
        Self { v4, v6 }
    }

    /// Reads the file configured as `protect.risk.anonymizing_networks_file`
    /// (fail fast at start-up on unreadable or malformed content).
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        let size = std::fs::metadata(path)
            .map_err(|e| {
                AuthError::internal("cannot read anonymizing networks file").with_source(e)
            })?
            .len();
        if size > MAX_FILE_BYTES {
            return Err(AuthError::internal(
                "anonymizing networks file is too large",
            ));
        }
        let text = std::fs::read_to_string(path).map_err(|e| {
            AuthError::internal("cannot read anonymizing networks file").with_source(e)
        })?;
        Self::parse(&text)
            .map_err(|msg| AuthError::internal(format!("invalid anonymizing networks file: {msg}")))
    }

    /// Number of (aggregated) networks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Whether `ip` (IPv4-mapped IPv6 normalised) is inside the set.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let idx = self.v4.partition_point(|n| n.network() <= v4);
                idx.checked_sub(1)
                    .and_then(|i| self.v4.get(i))
                    .is_some_and(|n| n.contains(&v4))
            }
            IpAddr::V6(v6) => {
                let idx = self.v6.partition_point(|n| n.network() <= v6);
                idx.checked_sub(1)
                    .and_then(|i| self.v6.get(i))
                    .is_some_and(|n| n.contains(&v6))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn rsk_02_networks_are_slash_24_and_slash_48() {
        assert_eq!(
            network_of("203.0.113.77".parse().unwrap()).to_string(),
            "203.0.113.0/24"
        );
        assert_eq!(
            network_of("::ffff:203.0.113.77".parse().unwrap()).to_string(),
            "203.0.113.0/24"
        );
        assert_eq!(
            network_of("2001:db8:aa:bb::1".parse().unwrap()).to_string(),
            "2001:db8:aa::/48"
        );
    }

    #[test]
    fn rsk_02_anonymizing_list_parsing_and_lookup() {
        let set = AnonymizingNetworks::parse(
            "# tor exits\n185.220.101.0/24\n  185.220.100.5 # single\n\n2a0b:f4c2::/40\n",
        )
        .unwrap();
        assert_eq!(set.len(), 3);
        for hit in [
            "185.220.101.200",
            "185.220.100.5",
            "::ffff:185.220.101.1",
            "2a0b:f4c2:1::1",
        ] {
            assert!(set.contains(hit.parse().unwrap()), "{hit}");
        }
        for miss in ["185.220.100.6", "185.220.102.1", "8.8.8.8", "2a0b:f4c3::1"] {
            assert!(!set.contains(miss.parse().unwrap()), "{miss}");
        }
        let err = AnonymizingNetworks::parse("1.2.3.0/24\nsecret-value\n").unwrap_err();
        assert_eq!(err, "line 2: not an IP address or CIDR");
        assert!(AnonymizingNetworks::default().is_empty());
    }

    #[test]
    fn rsk_02_anonymizing_file_is_loaded_fail_fast() {
        let dir = std::env::temp_dir().join(format!("authn-protect-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tor.txt");
        std::fs::write(&path, "10.9.8.0/24\n").unwrap();
        assert_eq!(AnonymizingNetworks::load(&path).unwrap().len(), 1);
        std::fs::write(&path, "nope\n").unwrap();
        assert!(AnonymizingNetworks::load(&path).is_err());
        assert!(AnonymizingNetworks::load(&dir.join("missing.txt")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    proptest! {
        #[test]
        fn rsk_02_lookup_matches_linear_scan(
            nets in proptest::collection::vec((any::<u32>(), 8_u8..=32), 0..40),
            probe in any::<u32>(),
        ) {
            let nets: Vec<IpNet> = nets
                .into_iter()
                .map(|(a, p)| IpNet::V4(Ipv4Net::new_assert(a.into(), p).trunc()))
                .collect();
            let set = AnonymizingNetworks::from_networks(nets.clone());
            let ip = IpAddr::V4(probe.into());
            prop_assert_eq!(set.contains(ip), nets.iter().any(|n| n.contains(&ip)));
        }
    }
}
