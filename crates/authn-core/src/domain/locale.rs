//! Supported user-facing languages (ACC-08, NTF-02, ARC-08).

text_enum! {
    /// A supported locale. Only Turkish and English are supported in Phase 1.
    pub enum Locale {
        /// English.
        En => "en",
        /// Turkish.
        Tr => "tr",
    }
}

impl Default for Locale {
    /// English; the deployment default is configurable
    /// (`server.default_locale`).
    fn default() -> Self {
        Self::En
    }
}

/// Upper bound on `Accept-Language` entries inspected (DoS guard).
const MAX_LANGUAGE_RANGES: usize = 16;

impl Locale {
    /// Maps a BCP 47 language tag (`tr`, `tr-TR`, `en-GB`, case-insensitive)
    /// to a supported locale by its primary subtag.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        let primary = tag.trim().split(['-', '_']).next()?;
        if primary.eq_ignore_ascii_case("tr") {
            Some(Self::Tr)
        } else if primary.eq_ignore_ascii_case("en") {
            Some(Self::En)
        } else {
            None
        }
    }

    /// Picks the best supported locale from an `Accept-Language` header value
    /// (RFC 9110 §12.5.4). Returns `None` when nothing supported is acceptable;
    /// callers then fall back to the configured default locale.
    ///
    /// Only the first 16 language ranges are inspected; malformed entries are
    /// ignored; `q=0` marks a range as not acceptable.
    #[must_use]
    pub fn negotiate(accept_language: &str) -> Option<Self> {
        let mut best: Option<(u16, Self)> = None;
        for entry in accept_language.split(',').take(MAX_LANGUAGE_RANGES) {
            let mut parts = entry.split(';');
            let Some(tag) = parts.next() else { continue };
            let Some(locale) = Self::from_tag(tag) else {
                continue;
            };
            let mut quality = Some(1000_u16);
            for param in parts {
                let param = param.trim();
                if let Some(q) = param
                    .strip_prefix("q=")
                    .or_else(|| param.strip_prefix("Q="))
                {
                    quality = parse_quality(q);
                }
            }
            let Some(quality) = quality else { continue };
            if quality == 0 {
                continue;
            }
            match best {
                Some((q, _)) if q >= quality => {}
                _ => best = Some((quality, locale)),
            }
        }
        best.map(|(_, locale)| locale)
    }
}

/// Parses an RFC 9110 `qvalue` into thousandths (`0.8` → 800).
fn parse_quality(raw: &str) -> Option<u16> {
    let raw = raw.trim();
    let (int, frac) = match raw.split_once('.') {
        Some((i, f)) => (i, f),
        None => (raw, ""),
    };
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut thousandths: u16 = 0;
    for (i, b) in frac.bytes().enumerate() {
        let digit = u16::from(b - b'0');
        thousandths += digit * [100, 10, 1][i];
    }
    match int {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_08_locale_from_tag() {
        assert_eq!(Locale::from_tag("tr"), Some(Locale::Tr));
        assert_eq!(Locale::from_tag("TR-tr"), Some(Locale::Tr));
        assert_eq!(Locale::from_tag("en_GB"), Some(Locale::En));
        assert_eq!(Locale::from_tag("de"), None);
        assert_eq!(Locale::from_tag(""), None);
    }

    #[test]
    fn arc_08_accept_language_negotiation() {
        assert_eq!(
            Locale::negotiate("tr-TR,tr;q=0.9,en;q=0.8"),
            Some(Locale::Tr)
        );
        assert_eq!(Locale::negotiate("en;q=0.5, tr;q=0.7"), Some(Locale::Tr));
        assert_eq!(Locale::negotiate("de, en;q=0.1"), Some(Locale::En));
        assert_eq!(Locale::negotiate("tr;q=0, en;q=0.2"), Some(Locale::En));
        assert_eq!(Locale::negotiate("de, fr"), None);
        assert_eq!(Locale::negotiate("*"), None);
        assert_eq!(Locale::negotiate(""), None);
        // Malformed q-values are ignored rather than trusted.
        assert_eq!(Locale::negotiate("tr;q=2, en;q=0.3"), Some(Locale::En));
        assert_eq!(Locale::negotiate("tr;q=0.1234"), None);
        // Equal quality keeps the first range.
        assert_eq!(Locale::negotiate("en, tr"), Some(Locale::En));
    }

    #[test]
    fn arc_08_negotiation_inspects_bounded_number_of_ranges() {
        let mut header = "de,".repeat(100);
        header.push_str("tr");
        assert_eq!(Locale::negotiate(&header), None);
    }

    #[test]
    fn quality_parsing() {
        assert_eq!(parse_quality("1"), Some(1000));
        assert_eq!(parse_quality("1.000"), Some(1000));
        assert_eq!(parse_quality("0.5"), Some(500));
        assert_eq!(parse_quality("0.05"), Some(50));
        assert_eq!(parse_quality("0"), Some(0));
        assert_eq!(parse_quality("1.5"), None);
        assert_eq!(parse_quality("-1"), None);
        assert_eq!(parse_quality("abc"), None);
    }
}
