//! A minimal MaxMind DB (`.mmdb`, format 2.0) **writer** for tests
//! (RSK-05, K-98): builds a tiny City-style database deterministically, so
//! no third-party GeoIP data (and no data licence) enters the repository.
//!
//! Supported: an IPv6 search tree (IPv4 networks live under `::/96`, as in
//! MaxMind's own databases), 24-bit records, and the data types a City
//! record needs (map, UTF-8 string, double, uint16/32/64, boolean, array).
//! Format reference: <https://maxmind.github.io/MaxMind-DB/>.

use std::net::IpAddr;

use ipnet::IpNet;

/// A value of the MMDB data section.
#[derive(Debug, Clone, PartialEq)]
pub enum MmdbValue {
    /// Map with UTF-8 keys (written in the given order).
    Map(Vec<(String, MmdbValue)>),
    /// UTF-8 string.
    Str(String),
    /// IEEE-754 double.
    Double(f64),
    /// Unsigned 16-bit.
    U16(u16),
    /// Unsigned 32-bit.
    U32(u32),
    /// Unsigned 64-bit.
    U64(u64),
    /// Boolean.
    Bool(bool),
    /// Array.
    Array(Vec<MmdbValue>),
}

impl MmdbValue {
    /// A map from `(key, value)` pairs.
    #[must_use]
    pub fn map<const N: usize>(pairs: [(&str, MmdbValue); N]) -> Self {
        Self::Map(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    /// A string.
    #[must_use]
    pub fn str(s: &str) -> Self {
        Self::Str(s.to_owned())
    }
}

/// A GeoIP2-City-shaped record. `extra` keys (postal code, subdivision,
/// ...) let tests prove that nothing beyond country/city/coordinates is
/// kept.
#[must_use]
pub fn city_record(
    country: &str,
    city: &str,
    latitude: f64,
    longitude: f64,
    accuracy_km: u16,
) -> MmdbValue {
    MmdbValue::map([
        (
            "city",
            MmdbValue::map([
                ("geoname_id", MmdbValue::U32(1)),
                ("names", MmdbValue::map([("en", MmdbValue::str(city))])),
            ]),
        ),
        (
            "country",
            MmdbValue::map([
                ("iso_code", MmdbValue::str(country)),
                ("names", MmdbValue::map([("en", MmdbValue::str(country))])),
            ]),
        ),
        (
            "location",
            MmdbValue::map([
                ("accuracy_radius", MmdbValue::U16(accuracy_km)),
                ("latitude", MmdbValue::Double(latitude)),
                ("longitude", MmdbValue::Double(longitude)),
                ("time_zone", MmdbValue::str("Etc/UTC")),
            ]),
        ),
        (
            "postal",
            MmdbValue::map([("code", MmdbValue::str("34000"))]),
        ),
        (
            "subdivisions",
            MmdbValue::Array(vec![MmdbValue::map([("iso_code", MmdbValue::str("34"))])]),
        ),
    ])
}

/// A record with a country only (country-level databases).
#[must_use]
pub fn country_record(country: &str) -> MmdbValue {
    MmdbValue::map([(
        "country",
        MmdbValue::map([("iso_code", MmdbValue::str(country))]),
    )])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Record {
    Empty,
    Node(usize),
    Data(usize),
}

/// Builds an `.mmdb` file in memory.
#[derive(Debug, Clone)]
pub struct MmdbBuilder {
    database_type: String,
    build_epoch: u64,
    entries: Vec<(IpNet, MmdbValue)>,
}

impl Default for MmdbBuilder {
    fn default() -> Self {
        Self::new("Test-City")
    }
}

impl MmdbBuilder {
    /// A builder for a database of `database_type`.
    #[must_use]
    pub fn new(database_type: &str) -> Self {
        Self {
            database_type: database_type.to_owned(),
            build_epoch: 1_767_225_600, // 2026-01-01T00:00:00Z
            entries: Vec::new(),
        }
    }

    /// Overrides the build time (seconds since the epoch), e.g. to tell two
    /// versions apart.
    #[must_use]
    pub fn build_epoch(mut self, epoch: u64) -> Self {
        self.build_epoch = epoch;
        self
    }

    /// Maps `network` (e.g. `"81.214.0.0/16"`) to `value`. Later inserts
    /// win inside earlier, shorter networks.
    ///
    /// # Panics
    /// On an unparsable network.
    #[must_use]
    pub fn insert(mut self, network: &str, value: MmdbValue) -> Self {
        let net: IpNet = network.parse().expect("network");
        self.entries.push((net.trunc(), value));
        self
    }

    /// Serialises the database.
    ///
    /// # Panics
    /// When the tree outgrows 24-bit records (never for test data).
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        // Data section: one encoded value per entry.
        let mut data = Vec::new();
        let mut offsets = Vec::with_capacity(self.entries.len());
        for (_, value) in &self.entries {
            offsets.push(data.len());
            encode(value, &mut data);
        }
        // Search tree over 128-bit keys.
        let mut nodes: Vec<[Record; 2]> = vec![[Record::Empty; 2]];
        for ((net, _), offset) in self.entries.iter().zip(offsets) {
            let (bits, prefix) = key_of(net);
            let mut node = 0;
            for depth in 0..prefix {
                let bit = usize::from((bits >> (127 - depth)) & 1 == 1);
                let last = depth + 1 == prefix;
                if last {
                    nodes[node][bit] = Record::Data(offset);
                    break;
                }
                node = match nodes[node][bit] {
                    Record::Node(next) => next,
                    other => {
                        // Split an empty or data record: both halves inherit it.
                        let next = nodes.len();
                        nodes.push([other, other]);
                        nodes[node][bit] = Record::Node(next);
                        next
                    }
                };
            }
        }
        let node_count = nodes.len();
        assert!(node_count + 16 + data.len() < (1 << 24), "tree too large");
        let mut out = Vec::with_capacity(node_count * 6 + 16 + data.len() + 256);
        for node in &nodes {
            for record in node {
                let value = match *record {
                    Record::Empty => node_count,
                    Record::Node(n) => n,
                    Record::Data(offset) => node_count + 16 + offset,
                };
                let value = u32::try_from(value).expect("24-bit record");
                out.extend_from_slice(&value.to_be_bytes()[1..]);
            }
        }
        out.extend_from_slice(&[0_u8; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        let metadata = MmdbValue::map([
            ("binary_format_major_version", MmdbValue::U16(2)),
            ("binary_format_minor_version", MmdbValue::U16(0)),
            ("build_epoch", MmdbValue::U64(self.build_epoch)),
            ("database_type", MmdbValue::Str(self.database_type.clone())),
            (
                "description",
                MmdbValue::map([("en", MmdbValue::str("authn-testkit fixture"))]),
            ),
            ("ip_version", MmdbValue::U16(6)),
            ("languages", MmdbValue::Array(vec![MmdbValue::str("en")])),
            (
                "node_count",
                MmdbValue::U32(u32::try_from(node_count).expect("node count")),
            ),
            ("record_size", MmdbValue::U16(24)),
        ]);
        encode(&metadata, &mut out);
        out
    }
}

/// 128-bit key and prefix length; IPv4 lives under `::/96`.
fn key_of(net: &IpNet) -> (u128, usize) {
    match net.addr() {
        IpAddr::V4(v4) => (
            u128::from(u32::from(v4)),
            96 + usize::from(net.prefix_len()),
        ),
        IpAddr::V6(v6) => (u128::from(v6), usize::from(net.prefix_len())),
    }
}

fn control(type_id: u8, size: usize, out: &mut Vec<u8>) {
    let (size_bits, extra): (u8, Vec<u8>) = if size < 29 {
        (u8::try_from(size).expect("size"), Vec::new())
    } else if size < 285 {
        (29, vec![u8::try_from(size - 29).expect("size")])
    } else if size < 65_821 {
        let s = u16::try_from(size - 285).expect("size");
        (30, s.to_be_bytes().to_vec())
    } else {
        let s = u32::try_from(size - 65_821).expect("size");
        (31, s.to_be_bytes()[1..].to_vec())
    };
    if type_id <= 7 {
        out.push((type_id << 5) | size_bits);
    } else {
        out.push(size_bits);
        out.push(type_id - 7);
    }
    out.extend_from_slice(&extra);
}

fn encode(value: &MmdbValue, out: &mut Vec<u8>) {
    match value {
        MmdbValue::Str(s) => {
            control(2, s.len(), out);
            out.extend_from_slice(s.as_bytes());
        }
        MmdbValue::Double(d) => {
            control(3, 8, out);
            out.extend_from_slice(&d.to_be_bytes());
        }
        MmdbValue::U16(v) => {
            control(5, 2, out);
            out.extend_from_slice(&v.to_be_bytes());
        }
        MmdbValue::U32(v) => {
            control(6, 4, out);
            out.extend_from_slice(&v.to_be_bytes());
        }
        MmdbValue::Map(pairs) => {
            control(7, pairs.len(), out);
            for (k, v) in pairs {
                encode(&MmdbValue::Str(k.clone()), out);
                encode(v, out);
            }
        }
        MmdbValue::U64(v) => {
            control(9, 8, out);
            out.extend_from_slice(&v.to_be_bytes());
        }
        MmdbValue::Array(items) => {
            control(11, items.len(), out);
            for item in items {
                encode(item, out);
            }
        }
        MmdbValue::Bool(b) => control(14, usize::from(*b), out),
    }
}
