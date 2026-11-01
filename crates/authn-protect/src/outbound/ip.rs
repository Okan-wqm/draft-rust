//! Classification of destination IP addresses for SSRF protection (PRT-12).
//!
//! Only [`AddressClass::Public`] destinations may be reached with
//! user-supplied URLs. The classifier is deliberately conservative:
//!
//! * IPv4: every IANA special-purpose block that is not globally reachable,
//!   plus cloud metadata endpoints that live in public space (Azure
//!   WireServer `168.63.129.16`).
//! * IPv6: an **allow-list** — only global unicast (`2000::/3`) minus its
//!   special-purpose blocks is public. Forms that embed an IPv4 address
//!   (IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`)
//!   inherit the class of the embedded address, so `::ffff:127.0.0.1`,
//!   `64:ff9b::a9fe:a9fe` or `2002:0a00:0001::` are as forbidden as the
//!   IPv4 they reach. Deprecated IPv4-compatible (`::a.b.c.d`), Teredo
//!   (`2001::/32`) and site-local addresses are always refused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why a destination is (not) allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressClass {
    /// Globally reachable unicast.
    Public,
    /// `0.0.0.0/8`, `::`.
    Unspecified,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918.
    Private,
    /// `100.64.0.0/10` carrier-grade NAT.
    SharedAddressSpace,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// Cloud instance metadata / host services.
    CloudMetadata,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`,
    /// `3fff::/20`.
    Documentation,
    /// `198.18.0.0/15`.
    Benchmarking,
    /// `192.0.0.0/24`, `2001::/23` (IETF protocol assignments).
    ProtocolAssignment,
    /// `240.0.0.0/4`, `192.88.99.0/24` and other reserved space.
    Reserved,
    /// `fc00::/7`.
    UniqueLocal,
    /// `fec0::/10` (deprecated).
    SiteLocal,
    /// `2001::/32` Teredo tunnels (embedded addresses are obfuscated).
    Teredo,
    /// `100::/64` discard-only.
    Discard,
    /// `64:ff9b:1::/48` local-use NAT64.
    LocalNat64,
    /// Deprecated IPv4-compatible IPv6 (`::a.b.c.d`).
    Ipv4Compatible,
    /// IPv6 outside global unicast `2000::/3`.
    NotGlobalUnicast,
}

impl AddressClass {
    /// Whether user-supplied URLs may reach this address.
    #[must_use]
    pub fn is_public(self) -> bool {
        self == Self::Public
    }
}

/// Classifies an address.
#[must_use]
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Whether user-supplied URLs may reach `ip`.
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    classify(ip).is_public()
}

const fn v4_in(ip: u32, net: [u8; 4], prefix: u32) -> bool {
    let net = u32::from_be_bytes(net);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    ip & mask == net & mask
}

/// Cloud metadata / host-service endpoints, checked before the broader
/// blocks (some of them are in public space).
const V4_METADATA: &[[u8; 4]] = &[
    [169, 254, 169, 254], // AWS, GCP, Azure IMDS, OpenStack, Oracle, DigitalOcean…
    [169, 254, 170, 2],   // AWS ECS task metadata
    [169, 254, 170, 23],  // AWS EKS pod identity
    [100, 100, 100, 200], // Alibaba Cloud
    [168, 63, 129, 16],   // Azure WireServer (public space!)
    [192, 0, 0, 192],     // Oracle Cloud
];

const V4_BLOCKS: &[([u8; 4], u32, AddressClass)] = &[
    ([0, 0, 0, 0], 8, AddressClass::Unspecified),
    ([10, 0, 0, 0], 8, AddressClass::Private),
    ([100, 64, 0, 0], 10, AddressClass::SharedAddressSpace),
    ([127, 0, 0, 0], 8, AddressClass::Loopback),
    ([169, 254, 0, 0], 16, AddressClass::LinkLocal),
    ([172, 16, 0, 0], 12, AddressClass::Private),
    ([192, 0, 0, 0], 24, AddressClass::ProtocolAssignment),
    ([192, 0, 2, 0], 24, AddressClass::Documentation),
    ([192, 88, 99, 0], 24, AddressClass::Reserved),
    ([192, 168, 0, 0], 16, AddressClass::Private),
    ([198, 18, 0, 0], 15, AddressClass::Benchmarking),
    ([198, 51, 100, 0], 24, AddressClass::Documentation),
    ([203, 0, 113, 0], 24, AddressClass::Documentation),
    ([224, 0, 0, 0], 4, AddressClass::Multicast),
    ([255, 255, 255, 255], 32, AddressClass::Broadcast),
    ([240, 0, 0, 0], 4, AddressClass::Reserved),
];

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let octets = ip.octets();
    if V4_METADATA.contains(&octets) {
        return AddressClass::CloudMetadata;
    }
    let bits = u32::from(ip);
    V4_BLOCKS
        .iter()
        .find(|(net, prefix, _)| v4_in(bits, *net, *prefix))
        .map_or(AddressClass::Public, |(_, _, class)| *class)
}

const fn v6_in(ip: u128, net: u128, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    ip & mask == net & mask
}

/// AWS IMDS over IPv6 (`fd00:ec2::254`), inside `fc00::/7`.
const V6_METADATA: &[u128] = &[0xfd00_0ec2_0000_0000_0000_0000_0000_0254];

const V6_BLOCKS: &[(u128, u32, AddressClass)] = &[
    (
        0x0100_0000_0000_0000_0000_0000_0000_0000,
        64,
        AddressClass::Discard,
    ),
    (
        0x0064_ff9b_0001_0000_0000_0000_0000_0000,
        48,
        AddressClass::LocalNat64,
    ),
    (
        0x2001_0000_0000_0000_0000_0000_0000_0000,
        32,
        AddressClass::Teredo,
    ),
    (
        0x2001_0db8_0000_0000_0000_0000_0000_0000,
        32,
        AddressClass::Documentation,
    ),
    (
        0x2001_0000_0000_0000_0000_0000_0000_0000,
        23,
        AddressClass::ProtocolAssignment,
    ),
    (
        0x3fff_0000_0000_0000_0000_0000_0000_0000,
        20,
        AddressClass::Documentation,
    ),
    (
        0xfc00_0000_0000_0000_0000_0000_0000_0000,
        7,
        AddressClass::UniqueLocal,
    ),
    (
        0xfe80_0000_0000_0000_0000_0000_0000_0000,
        10,
        AddressClass::LinkLocal,
    ),
    (
        0xfec0_0000_0000_0000_0000_0000_0000_0000,
        10,
        AddressClass::SiteLocal,
    ),
    (
        0xff00_0000_0000_0000_0000_0000_0000_0000,
        8,
        AddressClass::Multicast,
    ),
];

const NAT64_WKP: u128 = 0x0064_ff9b_0000_0000_0000_0000_0000_0000;
const SIX_TO_FOUR: u128 = 0x2002_0000_0000_0000_0000_0000_0000_0000;
const GLOBAL_UNICAST: u128 = 0x2000_0000_0000_0000_0000_0000_0000_0000;

fn low_v4(bits: u128) -> Ipv4Addr {
    // Truncation to the low 32 bits is the point.
    #[allow(clippy::cast_possible_truncation)]
    Ipv4Addr::from(bits as u32)
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    let bits = u128::from(ip);
    if ip.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if ip.is_loopback() {
        return AddressClass::Loopback;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    if V6_METADATA.contains(&bits) {
        return AddressClass::CloudMetadata;
    }
    // Remaining ::/96: deprecated IPv4-compatible addresses.
    if v6_in(bits, 0, 96) {
        return AddressClass::Ipv4Compatible;
    }
    if v6_in(bits, NAT64_WKP, 96) {
        return classify_v4(low_v4(bits));
    }
    if v6_in(bits, SIX_TO_FOUR, 16) {
        #[allow(clippy::cast_possible_truncation)]
        let embedded = Ipv4Addr::from((bits >> 80) as u32);
        return classify_v4(embedded);
    }
    if let Some((_, _, class)) = V6_BLOCKS
        .iter()
        .find(|(net, prefix, _)| v6_in(bits, *net, *prefix))
    {
        return *class;
    }
    if v6_in(bits, GLOBAL_UNICAST, 3) {
        AddressClass::Public
    } else {
        AddressClass::NotGlobalUnicast
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn class(s: &str) -> AddressClass {
        classify(s.parse().unwrap())
    }

    #[test]
    fn prt_12_ipv4_special_ranges_are_refused() {
        let cases = [
            ("0.0.0.0", AddressClass::Unspecified),
            ("0.1.2.3", AddressClass::Unspecified),
            ("10.0.0.1", AddressClass::Private),
            ("10.255.255.255", AddressClass::Private),
            ("100.64.0.1", AddressClass::SharedAddressSpace),
            ("100.127.255.254", AddressClass::SharedAddressSpace),
            ("127.0.0.1", AddressClass::Loopback),
            ("127.255.255.254", AddressClass::Loopback),
            ("169.254.0.1", AddressClass::LinkLocal),
            ("169.254.169.254", AddressClass::CloudMetadata),
            ("169.254.170.2", AddressClass::CloudMetadata),
            ("100.100.100.200", AddressClass::CloudMetadata),
            ("168.63.129.16", AddressClass::CloudMetadata),
            ("192.0.0.192", AddressClass::CloudMetadata),
            ("172.16.0.1", AddressClass::Private),
            ("172.31.255.255", AddressClass::Private),
            ("192.0.0.8", AddressClass::ProtocolAssignment),
            ("192.0.2.1", AddressClass::Documentation),
            ("192.88.99.1", AddressClass::Reserved),
            ("192.168.1.1", AddressClass::Private),
            ("198.18.0.1", AddressClass::Benchmarking),
            ("198.19.255.255", AddressClass::Benchmarking),
            ("198.51.100.1", AddressClass::Documentation),
            ("203.0.113.1", AddressClass::Documentation),
            ("224.0.0.1", AddressClass::Multicast),
            ("239.255.255.250", AddressClass::Multicast),
            ("240.0.0.1", AddressClass::Reserved),
            ("255.255.255.254", AddressClass::Reserved),
            ("255.255.255.255", AddressClass::Broadcast),
        ];
        for (ip, expected) in cases {
            assert_eq!(class(ip), expected, "{ip}");
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn prt_12_ipv4_public_neighbours_are_allowed() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "168.63.129.15",
            "168.63.129.17",
            "192.0.1.0",
            "192.0.3.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            assert_eq!(class(ip), AddressClass::Public, "{ip}");
        }
    }

    #[test]
    fn prt_12_ipv6_special_ranges_are_refused() {
        let cases = [
            ("::", AddressClass::Unspecified),
            ("::1", AddressClass::Loopback),
            ("::ffff:127.0.0.1", AddressClass::Loopback),
            ("::ffff:7f00:1", AddressClass::Loopback),
            ("::ffff:169.254.169.254", AddressClass::CloudMetadata),
            ("::ffff:10.0.0.1", AddressClass::Private),
            ("::127.0.0.1", AddressClass::Ipv4Compatible),
            ("::8.8.8.8", AddressClass::Ipv4Compatible),
            ("::ffff:0:a00:1", AddressClass::NotGlobalUnicast),
            ("64:ff9b::7f00:1", AddressClass::Loopback),
            ("64:ff9b::a9fe:a9fe", AddressClass::CloudMetadata),
            ("64:ff9b::c0a8:1", AddressClass::Private),
            ("64:ff9b:1::1", AddressClass::LocalNat64),
            ("100::1", AddressClass::Discard),
            ("2001::1", AddressClass::Teredo),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", AddressClass::Teredo),
            ("2001:2::1", AddressClass::ProtocolAssignment),
            ("2001:db8::1", AddressClass::Documentation),
            ("2002:7f00:1::", AddressClass::Loopback),
            ("2002:a9fe:a9fe::1", AddressClass::CloudMetadata),
            ("2002:c0a8:101::1", AddressClass::Private),
            ("3fff::1", AddressClass::Documentation),
            ("3fff:fff::1", AddressClass::Documentation),
            ("5f00::1", AddressClass::NotGlobalUnicast),
            ("fc00::1", AddressClass::UniqueLocal),
            ("fd12:3456::1", AddressClass::UniqueLocal),
            ("fd00:ec2::254", AddressClass::CloudMetadata),
            ("fe80::1", AddressClass::LinkLocal),
            ("febf::1", AddressClass::LinkLocal),
            ("fec0::1", AddressClass::SiteLocal),
            ("ff02::1", AddressClass::Multicast),
            ("ff0e::1", AddressClass::Multicast),
            ("4000::1", AddressClass::NotGlobalUnicast),
            ("1::1", AddressClass::NotGlobalUnicast),
        ];
        for (ip, expected) in cases {
            assert_eq!(class(ip), expected, "{ip}");
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn prt_12_ipv6_public_addresses_are_allowed() {
        for ip in [
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2a00:1450:4001::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2001:200::1",
            "3fff:1000::1",
            "3ffe::1",
        ] {
            assert_eq!(class(ip), AddressClass::Public, "{ip}");
        }
    }

    fn v4_in_block() -> impl Strategy<Value = Ipv4Addr> {
        (0..V4_BLOCKS.len(), any::<u32>()).prop_map(|(i, host)| {
            let (net, prefix, _) = V4_BLOCKS[i];
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ipv4Addr::from((u32::from_be_bytes(net) & mask) | (host & !mask))
        })
    }

    proptest! {
        #[test]
        fn prt_12_every_address_of_a_blocked_ipv4_range_is_refused(ip in v4_in_block()) {
            prop_assert!(!is_public(IpAddr::V4(ip)), "{ip}");
        }

        /// IPv4-mapped, NAT64 and 6to4 forms reach the embedded IPv4 and must
        /// be classified exactly like it.
        #[test]
        fn prt_12_embedded_ipv4_forms_inherit_the_ipv4_class(bits in any::<u32>()) {
            let v4 = Ipv4Addr::from(bits);
            let expected = classify_v4(v4);
            let mapped = v4.to_ipv6_mapped();
            let nat64 = Ipv6Addr::from(NAT64_WKP | u128::from(bits));
            let six_to_four = Ipv6Addr::from(SIX_TO_FOUR | (u128::from(bits) << 80) | 1);
            prop_assert_eq!(classify_v6(mapped), expected);
            prop_assert_eq!(classify_v6(nat64), expected);
            prop_assert_eq!(classify_v6(six_to_four), expected);
            // IPv4-compatible is refused whatever it embeds (except :: / ::1).
            if bits > 1 {
                let compat = Ipv6Addr::from(u128::from(bits));
                prop_assert!(!classify_v6(compat).is_public());
            }
        }

        #[test]
        fn prt_12_ipv6_outside_global_unicast_is_refused(bits in any::<u128>()) {
            let ip = Ipv6Addr::from(bits);
            let in_global = v6_in(bits, GLOBAL_UNICAST, 3);
            let embeds_v4 = ip.to_ipv4_mapped().is_some() || v6_in(bits, NAT64_WKP, 96);
            if !in_global && !embeds_v4 {
                prop_assert!(!is_public(IpAddr::V6(ip)), "{ip}");
            }
        }

        #[test]
        fn prt_12_ula_link_local_multicast_teredo_are_refused(host in any::<u128>(), which in 0_usize..5) {
            let (net, prefix) = [
                (0xfc00_u128 << 112, 7),
                (0xfe80_u128 << 112, 10),
                (0xff00_u128 << 112, 8),
                (0x2001_0000_u128 << 96, 32),
                (0x2001_0db8_u128 << 96, 32),
            ][which];
            let mask = u128::MAX << (128 - prefix);
            let ip = Ipv6Addr::from((net & mask) | (host & !mask));
            prop_assert!(!is_public(IpAddr::V6(ip)), "{ip}");
        }
    }
}
