//! Optional IP geolocation (RSK-02 impossible travel, RSK-04). Owner of
//! this file: authn-protect. No GeoIP database is embedded; deployments plug
//! in their own provider.

use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

/// Resolves an IP to an approximate location.
#[async_trait]
pub trait GeoIpLookup: Send + Sync {
    /// Looks an address up; `None` when unknown.
    async fn lookup(&self, ip: IpAddr) -> Result<Option<GeoLocation>, AuthError>;
}

/// Approximate location of an IP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    /// ISO 3166-1 alpha-2 country code.
    pub country_code: Option<String>,
    /// City name.
    pub city: Option<String>,
    /// Latitude in degrees.
    pub latitude: Option<f64>,
    /// Longitude in degrees.
    pub longitude: Option<f64>,
    /// Accuracy radius in kilometres.
    pub accuracy_km: Option<u32>,
}
