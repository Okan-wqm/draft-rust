//! MaxMind DB (`.mmdb`) implementation of the [`GeoIpLookup`] port
//! (RSK-05, K-98).
//!
//! * **No database is shipped.** The operator points
//!   `protect.risk.geoip_database` at a City-level file it licenses itself
//!   (GeoLite2-City, GeoIP2-City, DB-IP City Lite, IPinfo, ...). The data
//!   licences are not this project's (some are CC BY-SA or commercial); see
//!   the crate README.
//! * **Fail fast, then fail safe.** [`MmdbGeoIp::open`] refuses a missing,
//!   oversized or malformed file (startup error). After that a lookup never
//!   blocks a login: an unknown address, a non-public address (private,
//!   loopback, CGNAT, documentation, ... — [`crate::outbound::is_public`])
//!   or a database without coordinates simply yields no location, hence no
//!   impossible-travel signal.
//! * **Data minimisation (KVKK/GDPR).** Only the country code, the English
//!   city name and coordinates **rounded to 0.1°** (≈ 11 km, coarser than
//!   any city database) leave this module; postal code, subdivision,
//!   ISP/ASN and time zone are never decoded into the result. The accuracy
//!   radius is widened by the rounding error so the travel test stays
//!   conservative.
//! * **Reload.** The file is read into memory (no `mmap`: that needs
//!   `unsafe`). [`MmdbGeoIp::reload_if_changed`] swaps in a newer file when
//!   its modification time or size changed; a file that fails to load keeps
//!   the previous database (logged, never fatal). The server calls it every
//!   `protect.risk.geoip_reload_interval`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{GeoIpLookup, GeoLocation};
use maxminddb::Reader;
use maxminddb::geoip2::City;

use crate::outbound::is_public;

/// Largest accepted database file (commercial City databases are well
/// below this; the whole file is held in memory).
pub const MAX_DATABASE_BYTES: u64 = 512 * 1024 * 1024;

/// Coordinate precision kept: one decimal degree (≈ 11 km of latitude).
const COORDINATE_STEP: f64 = 10.0;

/// Kilometres added to the accuracy radius for the rounding (half the
/// diagonal of a 0.1° cell, rounded up).
const ROUNDING_ERROR_KM: u32 = 8;

/// Longest city name kept (characters).
const MAX_CITY_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
}

impl FileStamp {
    fn of(path: &Path) -> Result<Self, AuthError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| AuthError::internal("cannot read the GeoIP database").with_source(e))?;
        Ok(Self {
            modified: meta.modified().ok(),
            len: meta.len(),
        })
    }
}

#[derive(Debug)]
struct Loaded {
    reader: Arc<Reader<Vec<u8>>>,
    stamp: FileStamp,
}

/// MaxMind DB backed [`GeoIpLookup`].
pub struct MmdbGeoIp {
    path: PathBuf,
    loaded: RwLock<Loaded>,
}

impl std::fmt::Debug for MmdbGeoIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmdbGeoIp")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// What a loaded database is (for logs and `check-config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoIpDatabaseInfo {
    /// `database_type` of the metadata (e.g. `GeoLite2-City`).
    pub database_type: String,
    /// Build time, seconds since the Unix epoch.
    pub build_epoch: u64,
    /// 4 or 6.
    pub ip_version: u16,
}

fn load(path: &Path) -> Result<Loaded, AuthError> {
    load_bounded(path, MAX_DATABASE_BYTES)
}

/// [`load`] with an explicit size bound. The bound is enforced on the
/// bytes actually read, not only on the size the file system reports: a
/// file that grows after the `stat` (replaced in place while it is read)
/// or a non-regular file (a device such as `/dev/zero`, a FIFO: size 0)
/// can never make the server read without limit.
fn load_bounded(path: &Path, max_bytes: u64) -> Result<Loaded, AuthError> {
    use std::io::Read as _;

    let stamp = FileStamp::of(path)?;
    if stamp.len > max_bytes {
        return Err(AuthError::internal("the GeoIP database is too large"));
    }
    let file = std::fs::File::open(path)
        .map_err(|e| AuthError::internal("cannot read the GeoIP database").with_source(e))?;
    let is_file = file
        .metadata()
        .map_err(|e| AuthError::internal("cannot read the GeoIP database").with_source(e))?
        .is_file();
    if !is_file {
        return Err(AuthError::internal(
            "the GeoIP database is not a regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(stamp.len).unwrap_or(0));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| AuthError::internal("cannot read the GeoIP database").with_source(e))?;
    if bytes.len() as u64 > max_bytes {
        return Err(AuthError::internal("the GeoIP database is too large"));
    }
    let reader = Reader::from_source(bytes)
        .map_err(|e| AuthError::internal("invalid GeoIP database").with_source(e))?;
    // Walks the whole search tree and data section once, so a truncated or
    // corrupt file is refused here instead of failing lookups later.
    reader
        .verify()
        .map_err(|e| AuthError::internal("invalid GeoIP database").with_source(e))?;
    Ok(Loaded {
        reader: Arc::new(reader),
        stamp,
    })
}

impl MmdbGeoIp {
    /// Loads and verifies `path`. Fails on a missing, oversized
    /// (> [`MAX_DATABASE_BYTES`]) or malformed file.
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        let loaded = load(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            loaded: RwLock::new(loaded),
        })
    }

    fn reader(&self) -> Arc<Reader<Vec<u8>>> {
        // A poisoned lock still holds a fully loaded reader (the swap is a
        // single assignment), so recover it instead of panicking.
        match self.loaded.read() {
            Ok(guard) => guard.reader.clone(),
            Err(poisoned) => poisoned.into_inner().reader.clone(),
        }
    }

    /// Metadata of the database in use.
    #[must_use]
    pub fn info(&self) -> GeoIpDatabaseInfo {
        let reader = self.reader();
        let meta = reader.metadata();
        GeoIpDatabaseInfo {
            database_type: meta.database_type.clone(),
            build_epoch: meta.build_epoch,
            ip_version: meta.ip_version,
        }
    }

    /// Reloads the file when its modification time or size changed.
    /// Returns whether a new database is now in use. On error the previous
    /// database stays in use. Blocking (reads the file): call it from a
    /// blocking task.
    pub fn reload_if_changed(&self) -> Result<bool, AuthError> {
        let current = match self.loaded.read() {
            Ok(guard) => guard.stamp,
            Err(poisoned) => poisoned.into_inner().stamp,
        };
        if FileStamp::of(&self.path)? == current {
            return Ok(false);
        }
        let fresh = load(&self.path)?;
        match self.loaded.write() {
            Ok(mut guard) => *guard = fresh,
            Err(poisoned) => *poisoned.into_inner() = fresh,
        }
        Ok(true)
    }

    /// Synchronous lookup (in-memory; no I/O).
    pub fn lookup_sync(&self, ip: IpAddr) -> Result<Option<GeoLocation>, AuthError> {
        let ip = ip.to_canonical();
        if !is_public(ip) {
            return Ok(None);
        }
        let reader = self.reader();
        if ip.is_ipv6() && reader.metadata().ip_version == 4 {
            return Ok(None);
        }
        let result = reader
            .lookup(ip)
            .map_err(|e| AuthError::internal("GeoIP lookup failed").with_source(e))?;
        let Some(city) = result
            .decode::<City<'_>>()
            .map_err(|e| AuthError::internal("GeoIP record could not be decoded").with_source(e))?
        else {
            return Ok(None);
        };
        Ok(Some(minimise(&city)))
    }
}

/// Keeps only what the risk engine needs, coarsened (see module docs).
fn minimise(city: &City<'_>) -> GeoLocation {
    let country_code = city
        .country
        .iso_code
        .filter(|cc| cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_uppercase()))
        .map(str::to_owned);
    let city_name = city
        .city
        .names
        .english
        .map(|name| {
            name.chars()
                .filter(|c| !c.is_control())
                .take(MAX_CITY_CHARS)
                .collect::<String>()
                .trim()
                .to_owned()
        })
        .filter(|name| !name.is_empty());
    let coordinates = match (city.location.latitude, city.location.longitude) {
        (Some(lat), Some(lon))
            if lat.is_finite()
                && lon.is_finite()
                && (-90.0..=90.0).contains(&lat)
                && (-180.0..=180.0).contains(&lon) =>
        {
            Some((coarsen(lat), coarsen(lon)))
        }
        _ => None,
    };
    let accuracy_km = coordinates.and(
        city.location
            .accuracy_radius
            .map(|r| u32::from(r).saturating_add(ROUNDING_ERROR_KM)),
    );
    GeoLocation {
        country_code,
        city: city_name,
        latitude: coordinates.map(|(lat, _)| lat),
        longitude: coordinates.map(|(_, lon)| lon),
        accuracy_km,
    }
}

fn coarsen(degrees: f64) -> f64 {
    (degrees * COORDINATE_STEP).round() / COORDINATE_STEP
}

#[async_trait]
impl GeoIpLookup for MmdbGeoIp {
    async fn lookup(&self, ip: IpAddr) -> Result<Option<GeoLocation>, AuthError> {
        self.lookup_sync(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsk_05_coordinates_are_coarsened_to_a_tenth_of_a_degree() {
        assert!((coarsen(41.012_345) - 41.0).abs() < 1e-9);
        assert!((coarsen(28.976_01) - 29.0).abs() < 1e-9);
        assert!((coarsen(-0.127_6) - -0.1).abs() < 1e-9);
    }

    /// RSK-05 (audit, wave 11): the size bound holds for what is read,
    /// not only for what `stat` reports. A device reports size 0 and never
    /// ends (`/dev/zero`): before, it was read without limit (memory
    /// exhaustion at start-up or on reload).
    #[cfg(unix)]
    #[test]
    fn rsk_05_non_regular_files_are_refused_without_reading_them() {
        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = load_bounded(Path::new("/dev/zero"), 1024 * 1024);
            let _ = done.send(result.map(|_| ()).map_err(|e| e.to_string()));
        });
        let result = wait
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("loading /dev/zero must end (bounded read)");
        let err = result.unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
    }

    /// RSK-05 (audit, wave 11): bytes beyond the bound are never accepted,
    /// whatever `stat` said before the read.
    #[test]
    fn rsk_05_a_file_larger_than_the_bound_is_refused() {
        let dir = std::env::temp_dir().join(format!("authn-geoip-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.mmdb");
        std::fs::write(&path, vec![0_u8; 4096]).unwrap();
        let err = load_bounded(&path, 1024).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rsk_05_missing_or_garbage_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("authn-geoip-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(MmdbGeoIp::open(&dir.join("missing.mmdb")).is_err());
        let path = dir.join("garbage.mmdb");
        std::fs::write(&path, b"definitely not a maxmind database").unwrap();
        assert!(MmdbGeoIp::open(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
