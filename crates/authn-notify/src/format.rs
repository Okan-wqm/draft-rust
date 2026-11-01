//! Locale-aware formatting of the values placed into templates.
//!
//! Notifications carry absolute UTC timestamps (the user's time zone is not
//! part of the `Notifier` contract), so dates are rendered explicitly as
//! UTC. Remaining validity ("expires in 30 minutes") is computed at
//! *delivery* time, so a delayed retry never promises more time than is
//! left.

use authn_core::domain::{FactorKind, Locale};
use time::{Month, OffsetDateTime, UtcOffset};

const EN_MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

const TR_MONTHS: [&str; 12] = [
    "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim",
    "Kasım", "Aralık",
];

fn month_name(month: Month, locale: Locale) -> &'static str {
    let names = match locale {
        Locale::En => &EN_MONTHS,
        Locale::Tr => &TR_MONTHS,
    };
    let index = usize::from(u8::from(month)).saturating_sub(1);
    names.get(index).copied().unwrap_or("")
}

/// `1 November 2026, 14:05 UTC` / `1 Kasım 2026 14:05 (UTC)`.
///
/// `to_offset` panics when the UTC value falls outside the supported date
/// range (e.g. `9999-12-31T23:30:00-01:00`); such a timestamp is printed in
/// its own offset instead of crashing the delivery worker.
pub(crate) fn datetime(at: OffsetDateTime, locale: Locale) -> String {
    let at = at.checked_to_offset(UtcOffset::UTC).unwrap_or(at);
    let month = month_name(at.month(), locale);
    match locale {
        Locale::En => format!(
            "{} {month} {}, {:02}:{:02} UTC",
            at.day(),
            at.year(),
            at.hour(),
            at.minute()
        ),
        Locale::Tr => format!(
            "{} {month} {} {:02}:{:02} (UTC)",
            at.day(),
            at.year(),
            at.hour(),
            at.minute()
        ),
    }
}

/// Human validity left between `now` and `until`, rounded up:
/// `30 minutes`, `24 hours`, `7 days` / `30 dakika`, `24 saat`, `7 gün`.
/// Never less than one minute.
pub(crate) fn remaining(now: OffsetDateTime, until: OffsetDateTime, locale: Locale) -> String {
    let seconds = (until - now).whole_seconds().max(0).unsigned_abs();
    let minutes = seconds.div_ceil(60).max(1);
    let (value, unit) = if minutes >= 2 * 1440 {
        (minutes.div_ceil(1440), Unit::Day)
    } else if minutes >= 120 {
        (minutes.div_ceil(60), Unit::Hour)
    } else {
        (minutes, Unit::Minute)
    };
    let label = match (locale, unit) {
        (Locale::Tr, Unit::Minute) => "dakika",
        (Locale::Tr, Unit::Hour) => "saat",
        (Locale::Tr, Unit::Day) => "gün",
        (Locale::En, Unit::Minute) if value == 1 => "minute",
        (Locale::En, Unit::Minute) => "minutes",
        (Locale::En, Unit::Hour) => "hours",
        (Locale::En, Unit::Day) => "days",
    };
    format!("{value} {label}")
}

#[derive(Clone, Copy)]
enum Unit {
    Minute,
    Hour,
    Day,
}

/// Localized name of a second factor.
pub(crate) const fn factor(kind: FactorKind, locale: Locale) -> &'static str {
    match (kind, locale) {
        (FactorKind::Totp, Locale::En) => "Authenticator app",
        (FactorKind::Totp, Locale::Tr) => "Doğrulama uygulaması",
        (FactorKind::Webauthn, Locale::En) => "Passkey / security key",
        (FactorKind::Webauthn, Locale::Tr) => "Passkey / güvenlik anahtarı",
        (FactorKind::RecoveryCode, Locale::En) => "Recovery codes",
        (FactorKind::RecoveryCode, Locale::Tr) => "Kurtarma kodları",
        (FactorKind::Email, Locale::En) => "E-mail code",
        (FactorKind::Email, Locale::Tr) => "E-posta kodu",
        (FactorKind::Sms, Locale::En) => "SMS code",
        (FactorKind::Sms, Locale::Tr) => "SMS kodu",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use time::macros::datetime;

    use super::*;

    #[test]
    fn ntf_02_dates_are_localized_and_explicitly_utc() {
        let at = datetime!(2026-11-01 17:05:09 +03:00);
        assert_eq!(datetime(at, Locale::En), "1 November 2026, 14:05 UTC");
        assert_eq!(datetime(at, Locale::Tr), "1 Kasım 2026 14:05 (UTC)");
    }

    #[test]
    fn ntf_02_out_of_range_timestamps_never_panic() {
        // Converting this instant to UTC overflows the supported year range.
        let edge = datetime!(9999-12-31 23:30:00 -01:00);
        assert!(datetime(edge, Locale::En).starts_with("31 December 9999"));
        assert!(datetime(edge, Locale::Tr).starts_with("31 Aralık 9999"));
        let now = datetime!(2026-01-01 00:00:00 UTC);
        assert_eq!(
            remaining(now, edge, Locale::En).split(' ').nth(1),
            Some("days")
        );
        assert_eq!(remaining(edge, now, Locale::En), "1 minute");
    }

    #[test]
    fn ntf_02_remaining_validity_is_rounded_up() {
        let now = datetime!(2026-01-01 00:00:00 UTC);
        let cases = [
            (Duration::from_secs(0), "1 minute", "1 dakika"),
            (Duration::from_secs(61), "2 minutes", "2 dakika"),
            (Duration::from_secs(30 * 60 - 1), "30 minutes", "30 dakika"),
            (Duration::from_secs(24 * 3600 - 5), "24 hours", "24 saat"),
            (Duration::from_secs(7 * 86_400 - 5), "7 days", "7 gün"),
        ];
        for (left, en, tr) in cases {
            assert_eq!(remaining(now, now + left, Locale::En), en);
            assert_eq!(remaining(now, now + left, Locale::Tr), tr);
        }
        // Already expired: never a negative or zero duration.
        assert_eq!(
            remaining(now, now - Duration::from_secs(60), Locale::En),
            "1 minute"
        );
    }

    #[test]
    fn ntf_01_every_factor_has_both_labels() {
        for kind in FactorKind::ALL {
            assert!(!factor(*kind, Locale::En).is_empty());
            assert!(!factor(*kind, Locale::Tr).is_empty());
        }
    }
}
