//! `known_devices` / `known_networks` repository (RSK-02, RSK-04).
//!
//! Device ids are stored only as keyed hashes bound to the user
//! ([`KeyHasher::device`]); networks as `/24` / `/48` CIDRs.

use std::net::IpAddr;

use authn_core::error::AuthError;
use authn_core::id::UserId;
use ipnet::IpNet;
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use super::geo::{DEFAULT_ACCURACY_KM, Fix};
use super::networks::network_of;
use crate::keys::KeyHasher;

const KNOWN_DEVICE_SQL: &str =
    "SELECT EXISTS (SELECT 1 FROM known_devices WHERE user_id = $1 AND device_hash = $2)";
const KNOWN_NETWORK_SQL: &str =
    "SELECT EXISTS (SELECT 1 FROM known_networks WHERE user_id = $1 AND network = $2)";
const HISTORY_SQL: &str = "\
SELECT EXISTS (SELECT 1 FROM known_devices WHERE user_id = $1)
    OR EXISTS (SELECT 1 FROM known_networks WHERE user_id = $1)";
const LAST_FIX_SQL: &str = "\
SELECT last_latitude, last_longitude, last_seen_at FROM known_devices
WHERE user_id = $1 AND last_latitude IS NOT NULL AND last_longitude IS NOT NULL
ORDER BY last_seen_at DESC LIMIT 1";
/// The three familiarity facts of [`RiskStore::familiarity`] in one
/// statement (K-128): `$1` user, `$2` device hash (`NULL`: no device id),
/// `$3` network.
const FAMILIARITY_SQL: &str = "\
SELECT EXISTS (SELECT 1 FROM known_devices WHERE user_id = $1)
           OR EXISTS (SELECT 1 FROM known_networks WHERE user_id = $1) AS history,
       $2::bytea IS NOT NULL
           AND EXISTS (SELECT 1 FROM known_devices WHERE user_id = $1 AND device_hash = $2)
           AS known_device,
       EXISTS (SELECT 1 FROM known_networks WHERE user_id = $1 AND network = $3) AS known_network";
/// [`RiskStore::record`] in one statement (K-128): the history read sees
/// the state before the statement (as the separate read before the upserts
/// did), the network and — with a device id (`$4` not `NULL`) — device
/// upserts report whether they inserted. `$1` user, `$2` network, `$3`
/// time, `$4` device hash, `$5` row id, `$6` name, `$7` IP, `$8` country,
/// `$9` / `$10` coordinates.
const RECORD_SQL: &str = "\
WITH history AS (
    SELECT EXISTS (SELECT 1 FROM known_devices WHERE user_id = $1)
        OR EXISTS (SELECT 1 FROM known_networks WHERE user_id = $1) AS seen
), network AS (
    INSERT INTO known_networks AS n (user_id, network, first_seen_at, last_seen_at)
    VALUES ($1, $2, $3, $3)
    ON CONFLICT (user_id, network) DO UPDATE SET
        last_seen_at = GREATEST(n.last_seen_at, EXCLUDED.last_seen_at)
    RETURNING (xmax = 0) AS inserted
), device AS (
    INSERT INTO known_devices AS d
        (id, user_id, device_hash, device_name, first_seen_at, last_seen_at, last_ip,
         last_country, last_latitude, last_longitude)
    SELECT $5, $1, $4::bytea, $6, $3, $3, $7, $8, $9, $10
    WHERE $4::bytea IS NOT NULL
    ON CONFLICT (user_id, device_hash) DO UPDATE SET
        device_name = EXCLUDED.device_name,
        last_seen_at = GREATEST(d.last_seen_at, EXCLUDED.last_seen_at),
        last_ip = EXCLUDED.last_ip,
        last_country = COALESCE(EXCLUDED.last_country, d.last_country),
        last_latitude = COALESCE(EXCLUDED.last_latitude, d.last_latitude),
        last_longitude = COALESCE(EXCLUDED.last_longitude, d.last_longitude)
    RETURNING (xmax = 0) AS inserted
)
SELECT (SELECT seen FROM history) AS history,
       (SELECT inserted FROM network) AS new_network,
       (SELECT inserted FROM device) AS new_device";

/// What [`RiskStore::familiarity`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct Familiarity {
    /// The user has any device or network history.
    pub history: bool,
    /// The device is known (`false` without a device id).
    pub known_device: bool,
    /// The `/24` / `/48` of the IP is known.
    pub known_network: bool,
}

#[derive(sqlx::FromRow)]
struct RecordRow {
    history: Option<bool>,
    new_network: Option<bool>,
    new_device: Option<bool>,
}

/// What is stored about a successful login's device. `Debug` redacts the
/// device id (a bearer-like identifier: knowing it bypasses the soft lock
/// for that user) and masks the IP.
#[derive(Clone, PartialEq)]
pub struct DeviceObservation {
    /// Client device id (validated format), if the client sent one.
    pub device_id: Option<String>,
    /// Human-readable description.
    pub device_name: String,
    /// Client IP.
    pub ip: IpAddr,
    /// ISO country code (validated `^[A-Z]{2}$`).
    pub country: Option<String>,
    /// Location (validated coordinates).
    pub latitude: Option<f64>,
    /// Location.
    pub longitude: Option<f64>,
    /// When.
    pub at: OffsetDateTime,
    /// "City, CC" for notifications (not stored).
    pub approximate_location: Option<String>,
}

impl std::fmt::Debug for DeviceObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceObservation")
            .field(
                "device_id",
                &self
                    .device_id
                    .as_ref()
                    .map(|_| authn_core::secret::REDACTED),
            )
            .field("device_name", &self.device_name)
            .field("ip", &authn_core::redact::mask_ip(self.ip))
            .field("country", &self.country)
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

/// Which records were new.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Novelty {
    /// The device id was not known for the user (or no device id was sent).
    pub new_device: bool,
    /// The network was not known for the user.
    pub new_network: bool,
    /// The user had no device or network history at all before.
    pub first_login: bool,
}

/// Repository of the risk tables.
#[derive(Clone)]
pub struct RiskStore {
    pool: PgPool,
    hasher: KeyHasher,
}

impl std::fmt::Debug for RiskStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RiskStore").finish_non_exhaustive()
    }
}

/// Normalises a GeoIP country code for the `known_devices_country_check`.
#[must_use]
pub fn sanitize_country(code: Option<&str>) -> Option<String> {
    let code = code?.trim().to_ascii_uppercase();
    (code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())).then_some(code)
}

impl RiskStore {
    /// A repository over `pool`.
    #[must_use]
    pub fn new(pool: PgPool, hasher: KeyHasher) -> Self {
        Self { pool, hasher }
    }

    /// The pool (for transactions spanning several calls).
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Whether `device_id` was seen for `user`. Always runs one indexed
    /// query (also for a placeholder user), so callers can use it before
    /// knowing whether the account exists without a timing difference.
    pub async fn is_known_device(&self, user: UserId, device_id: &str) -> Result<bool, AuthError> {
        let hash = self.hasher.device(user, device_id);
        Ok(sqlx::query_scalar(KNOWN_DEVICE_SQL)
            .bind(user)
            .bind(hash.as_slice())
            .fetch_one(&self.pool)
            .await?)
    }

    /// Whether the `/24` / `/48` of `ip` was seen for `user`.
    pub async fn is_known_network(&self, user: UserId, ip: IpAddr) -> Result<bool, AuthError> {
        Ok(sqlx::query_scalar(KNOWN_NETWORK_SQL)
            .bind(user)
            .bind(network_of(ip))
            .fetch_one(&self.pool)
            .await?)
    }

    /// Whether the user has any device or network history.
    pub async fn has_history(&self, user: UserId) -> Result<bool, AuthError> {
        Ok(sqlx::query_scalar(HISTORY_SQL)
            .bind(user)
            .fetch_one(&self.pool)
            .await?)
    }

    /// [`RiskStore::has_history`], [`RiskStore::is_known_device`] (with a
    /// device id) and [`RiskStore::is_known_network`] in one statement
    /// (K-128; the risk score needs all three).
    pub async fn familiarity(
        &self,
        user: UserId,
        device_id: Option<&str>,
        ip: IpAddr,
    ) -> Result<Familiarity, AuthError> {
        let hash = device_id.map(|device| self.hasher.device(user, device).to_vec());
        Ok(sqlx::query_as(FAMILIARITY_SQL)
            .bind(user)
            .bind(hash.as_deref())
            .bind(network_of(ip))
            .fetch_one(&self.pool)
            .await?)
    }

    /// The most recent located login of the user.
    pub async fn last_fix(&self, user: UserId) -> Result<Option<Fix>, AuthError> {
        let row: Option<(Option<f64>, Option<f64>, OffsetDateTime)> = sqlx::query_as(LAST_FIX_SQL)
            .bind(user)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|(lat, lon, at)| {
            Some(Fix {
                latitude: lat?,
                longitude: lon?,
                accuracy_km: DEFAULT_ACCURACY_KM,
                at,
            })
        }))
    }

    /// Records a successful login inside the caller's transaction and
    /// reports what was new. Without a device id the device counts as new
    /// only if the network is new too (API clients without device ids would
    /// otherwise always look new).
    pub async fn record(
        &self,
        conn: &mut PgConnection,
        user: UserId,
        observation: &DeviceObservation,
    ) -> Result<Novelty, AuthError> {
        let network: IpNet = network_of(observation.ip);
        let (lat, lon) = match (observation.latitude, observation.longitude) {
            (Some(lat), Some(lon)) if super::geo::valid_coordinates(lat, lon) => {
                (Some(lat), Some(lon))
            }
            _ => (None, None),
        };
        let name: String = observation
            .device_name
            .chars()
            .take(super::useragent::MAX_DEVICE_NAME_CHARS)
            .collect();
        let device_hash = observation
            .device_id
            .as_deref()
            .map(|device_id| self.hasher.device(user, device_id).to_vec());
        let row: RecordRow = sqlx::query_as(RECORD_SQL)
            .bind(user)
            .bind(network)
            .bind(observation.at)
            .bind(device_hash.as_deref())
            .bind(Uuid::now_v7())
            .bind(name)
            .bind(ipnet::IpNet::from(observation.ip.to_canonical()))
            .bind(sanitize_country(observation.country.as_deref()))
            .bind(lat)
            .bind(lon)
            .fetch_one(&mut *conn)
            .await?;
        let first_login = !row
            .history
            .ok_or_else(|| AuthError::internal("risk history without a result"))?;
        let new_network = row
            .new_network
            .ok_or_else(|| AuthError::internal("network upsert without a result"))?;
        let new_device = match device_hash {
            Some(_) => row
                .new_device
                .ok_or_else(|| AuthError::internal("device upsert without a result"))?,
            None => new_network,
        };
        Ok(Novelty {
            new_device,
            new_network,
            first_login,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (security review): the derived `Debug` printed the raw
    /// device id, which lets its holder bypass the soft lock (known device).
    #[test]
    fn rsk_02_device_observation_debug_redacts_the_device_id() {
        let observation = DeviceObservation {
            device_id: Some("device-id-secret-0123456789".to_owned()),
            device_name: "Firefox on Linux".to_owned(),
            ip: "198.51.100.77".parse().unwrap(),
            country: None,
            latitude: Some(41.0),
            longitude: Some(29.0),
            at: OffsetDateTime::UNIX_EPOCH,
            approximate_location: Some("Istanbul, TR".to_owned()),
        };
        let debug = format!("{observation:?}");
        assert!(!debug.contains("device-id-secret"), "{debug}");
        assert!(!debug.contains("198.51.100.77"), "{debug}");
        assert!(debug.contains("Firefox on Linux"), "{debug}");
    }

    #[test]
    fn rsk_02_country_codes_are_sanitized() {
        assert_eq!(sanitize_country(Some("tr")), Some("TR".to_owned()));
        assert_eq!(sanitize_country(Some(" DE ")), Some("DE".to_owned()));
        for bad in ["TUR", "T1", "", "Ü1", "'; DROP"] {
            assert_eq!(sanitize_country(Some(bad)), None, "{bad}");
        }
    }
}
