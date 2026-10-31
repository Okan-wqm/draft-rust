//! Human-readable durations in configuration: `"500ms"`, `"30s"`, `"15m"`,
//! `"2h"`, `"7d"`, or a bare integer meaning seconds.
//!
//! Use with `#[serde(with = "authn_core::config::duration")]` on
//! `std::time::Duration` fields (and `duration::option` for
//! `Option<Duration>`).

use std::time::Duration;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

/// Parses a duration string. Errors never echo the input.
pub fn parse(input: &str) -> Result<Duration, &'static str> {
    let s = input.trim();
    if s.is_empty() || s.len() > 32 {
        return Err("invalid duration");
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, unit) = s.split_at(split);
    if digits.is_empty() {
        return Err("invalid duration: missing number");
    }
    let value: u64 = digits
        .parse()
        .map_err(|_| "invalid duration: number out of range")?;
    let millis_per_unit: u64 = match unit.trim() {
        "ms" => 1,
        "" | "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err("invalid duration unit (use ms, s, m, h or d)"),
    };
    let millis = value
        .checked_mul(millis_per_unit)
        .ok_or("invalid duration: out of range")?;
    Ok(Duration::from_millis(millis))
}

/// Formats a duration with the largest exact unit.
#[must_use]
pub fn format(d: Duration) -> String {
    let ms = d.as_millis();
    for (unit, size) in [
        ("d", 86_400_000_u128),
        ("h", 3_600_000),
        ("m", 60_000),
        ("s", 1_000),
    ] {
        if ms != 0 && ms.is_multiple_of(size) {
            return format!("{}{unit}", ms / size);
        }
    }
    format!("{ms}ms")
}

/// Serde `serialize` for `Duration`.
pub fn serialize<S: Serializer>(d: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format(*d))
}

/// Serde `deserialize` for `Duration`.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    deserializer.deserialize_any(DurationVisitor)
}

struct DurationVisitor;

impl Visitor<'_> for DurationVisitor {
    type Value = Duration;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a duration such as \"30s\", \"15m\", \"2h\", \"7d\" or seconds")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Duration, E> {
        parse(v).map_err(E::custom)
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Duration, E> {
        Ok(Duration::from_secs(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Duration, E> {
        u64::try_from(v)
            .map(Duration::from_secs)
            .map_err(|_| E::custom("duration must not be negative"))
    }
}

/// `Option<Duration>` support.
pub mod option {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    /// Serde `serialize` for `Option<Duration>`.
    pub fn serialize<S: Serializer>(
        d: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => super::serialize(d, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Serde `deserialize` for `Option<Duration>`.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "super")] Duration);
        Option::<Wrapper>::deserialize(deserializer).map(|w| w.map(|Wrapper(d)| d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_07_duration_parsing() {
        assert_eq!(parse("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse("2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(parse("7d"), Ok(Duration::from_secs(604_800)));
        assert_eq!(parse("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse("42"), Ok(Duration::from_secs(42)));
        assert_eq!(parse(" 5 m "), Ok(Duration::from_secs(300)));
        for bad in [
            "",
            "s",
            "-5s",
            "5x",
            "1.5h",
            "99999999999999999999d",
            "5 days",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn arc_07_duration_formatting_round_trips() {
        for d in [
            Duration::from_secs(30),
            Duration::from_secs(900),
            Duration::from_secs(7200),
            Duration::from_secs(86_400 * 30),
            Duration::from_millis(1500),
            Duration::ZERO,
        ] {
            assert_eq!(parse(&format(d)), Ok(d), "{d:?}");
        }
        assert_eq!(format(Duration::from_secs(7200)), "2h");
    }
}
