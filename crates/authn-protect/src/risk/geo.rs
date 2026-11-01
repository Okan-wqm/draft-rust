//! Great-circle distance and the impossible-travel test (RSK-02). Only used
//! when a `GeoIpLookup` is plugged in; no GeoIP database is embedded.

use time::OffsetDateTime;

const EARTH_RADIUS_KM: f64 = 6371.0;
/// Accuracy assumed for a stored location without an accuracy radius.
pub const DEFAULT_ACCURACY_KM: f64 = 50.0;

/// A located observation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fix {
    /// Latitude in degrees.
    pub latitude: f64,
    /// Longitude in degrees.
    pub longitude: f64,
    /// Accuracy radius in km.
    pub accuracy_km: f64,
    /// When.
    pub at: OffsetDateTime,
}

/// Whether a coordinate pair is a plausible location.
#[must_use]
pub fn valid_coordinates(latitude: f64, longitude: f64) -> bool {
    latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude)
}

/// Haversine distance in km.
#[must_use]
pub fn distance_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = (lat2 - lat1).to_radians();
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * a.sqrt().clamp(0.0, 1.0).asin()
}

/// Whether going from `previous` to `current` needs a speed above
/// `max_speed_kmh`. Accuracy radii are subtracted from the distance and the
/// elapsed time is at least one minute, so imprecise or simultaneous fixes
/// do not trigger false positives.
#[must_use]
pub fn is_impossible_travel(previous: &Fix, current: &Fix, max_speed_kmh: f64) -> bool {
    if !valid_coordinates(previous.latitude, previous.longitude)
        || !valid_coordinates(current.latitude, current.longitude)
    {
        return false;
    }
    let distance = distance_km(
        previous.latitude,
        previous.longitude,
        current.latitude,
        current.longitude,
    ) - previous.accuracy_km.max(0.0)
        - current.accuracy_km.max(0.0);
    if distance <= 0.0 {
        return false;
    }
    let hours = (current.at - previous.at).as_seconds_f64() / 3600.0;
    distance / hours.max(1.0 / 60.0) > max_speed_kmh
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    fn fix(lat: f64, lon: f64, at: OffsetDateTime) -> Fix {
        Fix {
            latitude: lat,
            longitude: lon,
            accuracy_km: 20.0,
            at,
        }
    }

    #[test]
    fn rsk_02_haversine_known_distance() {
        // Istanbul → London ≈ 2500 km.
        let d = distance_km(41.0082, 28.9784, 51.5074, -0.1278);
        assert!((d - 2_500.0).abs() < 30.0, "{d}");
        assert!(distance_km(10.0, 10.0, 10.0, 10.0) < 1e-9);
    }

    #[test]
    fn rsk_02_impossible_travel_detection() {
        let t0 = datetime!(2026-01-01 10:00 UTC);
        let istanbul = fix(41.0082, 28.9784, t0);
        let london_1h = fix(51.5074, -0.1278, datetime!(2026-01-01 11:00 UTC));
        let london_6h = fix(51.5074, -0.1278, datetime!(2026-01-01 16:00 UTC));
        let ankara_1h = fix(39.9334, 32.8597, datetime!(2026-01-01 11:00 UTC));
        assert!(is_impossible_travel(&istanbul, &london_1h, 1000.0));
        assert!(!is_impossible_travel(&istanbul, &london_6h, 1000.0));
        assert!(!is_impossible_travel(&istanbul, &ankara_1h, 1000.0));
        // Same place, same instant: never.
        assert!(!is_impossible_travel(&istanbul, &istanbul, 1000.0));
        // Garbage coordinates are ignored.
        let bogus = fix(f64::NAN, 0.0, t0);
        assert!(!is_impossible_travel(&bogus, &london_1h, 1000.0));
        assert!(!valid_coordinates(91.0, 0.0));
    }
}
