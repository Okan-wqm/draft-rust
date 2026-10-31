use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{GeoIpLookup, GeoLocation};

use super::lock;

/// GeoIP fake backed by a map.
#[derive(Debug, Default)]
pub struct FakeGeoIp {
    entries: Mutex<HashMap<IpAddr, GeoLocation>>,
}

impl FakeGeoIp {
    /// Registers a location for an IP.
    pub fn insert(&self, ip: IpAddr, location: GeoLocation) {
        lock(&self.entries).insert(ip, location);
    }
}

#[async_trait]
impl GeoIpLookup for FakeGeoIp {
    async fn lookup(&self, ip: IpAddr) -> Result<Option<GeoLocation>, AuthError> {
        Ok(lock(&self.entries).get(&ip).cloned())
    }
}
