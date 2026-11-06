//! Risk-based authentication (RSK-01 … RSK-04).
//!
//! * [`DefaultRiskEvaluator`] implements the [`RiskEvaluator`] port:
//!   new device, new network (`/24`, `/48`), recent failures, optional
//!   anonymizing-network list, impossible travel (only with a
//!   [`GeoIpLookup`]; [`MmdbGeoIp`] reads an operator-provided MaxMind DB,
//!   RSK-05).
//! * [`decide`] maps an assessment to the configured reaction (RSK-03).
//! * [`RiskAlerts`] records successful logins and sends the new-device
//!   notification with a "this wasn't me" token (RSK-04), and handles
//!   blocked high-risk logins (RSK-03).
//!
//! Scoring: new device 1, new network 1, recent failures 1, anonymizing
//! network 2, impossible travel 3; `0` → low, `1–2` → medium, `≥ 3` → high.
//! Users without any device/network history (first login after sign-up)
//! get no novelty signals — there is no baseline to compare with. Passkey
//! logins ignore novelty and failure signals (possession + user
//! verification are proven; failures are about guessed passwords).

mod alerts;
pub mod geo;
pub mod geoip;
pub mod networks;
pub mod store;
pub mod useragent;

use std::sync::Arc;

use async_trait::async_trait;
use authn_core::config::protect::{HighRiskAction, MediumRiskAction, RiskConfig};
use authn_core::domain::LoginMethod;
use authn_core::error::AuthError;
use authn_core::ports::{
    GeoIpLookup, RateLimitKey, RateLimitPolicy, RateLimiter, RiskAssessment, RiskEvaluator,
    RiskInput, RiskLevel, RiskReason,
};
use sqlx::PgPool;

pub use alerts::{DeviceLoginOutcome, NotMeTokenIssuer, RiskAlerts};
pub use geoip::{GeoIpDatabaseInfo, MmdbGeoIp};
pub use networks::{AnonymizingNetworks, network_of};
pub use store::{DeviceObservation, Novelty, RiskStore};

use crate::keys::KeyHasher;

/// Rate-limit action of the login-failure velocity counters (fed by
/// [`crate::login::LoginProtection::record_failure`]).
pub const FAILURE_ACTION: &str = "login_failure";

/// The reaction to a login risk (RSK-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskResponse {
    /// Continue normally.
    Allow,
    /// Ask for the second factor (MFA is enrolled).
    RequireMfa,
    /// Ask for an e-mail confirmation (no MFA enrolled).
    RequireEmailConfirmation,
    /// Refuse the login and notify the user ([`RiskAlerts::on_blocked_login`]).
    Block,
}

/// Maps an assessment to the configured reaction (RSK-03): `medium` →
/// MFA if enrolled, otherwise e-mail confirmation; `high` → block (or treat
/// as medium when `high_action = "step_up"`).
#[must_use]
pub fn decide(
    config: &RiskConfig,
    assessment: &RiskAssessment,
    mfa_enrolled: bool,
) -> RiskResponse {
    let step_up = if mfa_enrolled {
        RiskResponse::RequireMfa
    } else {
        RiskResponse::RequireEmailConfirmation
    };
    match assessment.level {
        RiskLevel::Low => RiskResponse::Allow,
        RiskLevel::Medium => match config.medium_action {
            MediumRiskAction::StepUp => step_up,
            MediumRiskAction::Allow => RiskResponse::Allow,
        },
        RiskLevel::High => match config.high_action {
            HighRiskAction::Block => RiskResponse::Block,
            HighRiskAction::StepUp => step_up,
        },
    }
}

fn weight(reason: RiskReason) -> u32 {
    match reason {
        RiskReason::NewDevice | RiskReason::NewNetwork | RiskReason::RecentFailures => 1,
        RiskReason::AnonymizingNetwork => 2,
        RiskReason::ImpossibleTravel => 3,
    }
}

/// Level of a set of reasons.
#[must_use]
pub fn level_of(reasons: &[RiskReason]) -> RiskLevel {
    match reasons.iter().map(|r| weight(*r)).sum::<u32>() {
        0 => RiskLevel::Low,
        1 | 2 => RiskLevel::Medium,
        _ => RiskLevel::High,
    }
}

/// The default [`RiskEvaluator`] (RSK-02).
#[derive(Clone)]
pub struct DefaultRiskEvaluator {
    store: RiskStore,
    limiter: Arc<dyn RateLimiter>,
    config: RiskConfig,
    anonymizers: Arc<AnonymizingNetworks>,
    geoip: Option<Arc<dyn GeoIpLookup>>,
}

impl std::fmt::Debug for DefaultRiskEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultRiskEvaluator")
            .field("enabled", &self.config.enabled)
            .field("anonymizing_networks", &self.anonymizers.len())
            .field("geoip", &self.geoip.is_some())
            .finish_non_exhaustive()
    }
}

impl DefaultRiskEvaluator {
    /// Builds the evaluator; loads `risk.anonymizing_networks_file` when
    /// configured (fails fast on an unreadable or malformed file).
    pub fn new(
        pool: PgPool,
        hasher: KeyHasher,
        limiter: Arc<dyn RateLimiter>,
        config: &RiskConfig,
        geoip: Option<Arc<dyn GeoIpLookup>>,
    ) -> Result<Self, AuthError> {
        let anonymizers = match &config.anonymizing_networks_file {
            Some(path) => AnonymizingNetworks::load(path)?,
            None => AnonymizingNetworks::default(),
        };
        Ok(Self {
            store: RiskStore::new(pool, hasher),
            limiter,
            config: config.clone(),
            anonymizers: Arc::new(anonymizers),
            geoip,
        })
    }

    /// Replaces the anonymizing-network list (e.g. after a refresh).
    #[must_use]
    pub fn with_anonymizing_networks(mut self, networks: AnonymizingNetworks) -> Self {
        self.anonymizers = Arc::new(networks);
        self
    }

    /// The underlying repository (shared with [`RiskAlerts`]).
    #[must_use]
    pub fn store(&self) -> &RiskStore {
        &self.store
    }

    /// The failure-velocity policy (`failure_threshold` per
    /// `failure_window`).
    #[must_use]
    pub fn failure_policy(&self) -> RateLimitPolicy {
        RateLimitPolicy::new(self.config.failure_threshold, self.config.failure_window)
    }

    async fn recent_failures(&self, input: &RiskInput) -> Result<bool, AuthError> {
        let policy = self.failure_policy();
        let ip_key = RateLimitKey::ip(FAILURE_ACTION, input.ip);
        let user_key = input.user_id.map(|u| RateLimitKey::user(FAILURE_ACTION, u));
        let mut keys = vec![(&ip_key, policy)];
        if let Some(key) = &user_key {
            keys.push((key, policy));
        }
        // One round trip for both counters (K-128).
        Ok(self
            .limiter
            .peek_many(&keys)
            .await?
            .iter()
            .any(|d| !d.allowed))
    }

    async fn impossible_travel(&self, input: &RiskInput) -> bool {
        let (Some(geoip), Some(user)) = (&self.geoip, input.user_id) else {
            return false;
        };
        let current = match geoip.lookup(input.ip).await {
            Ok(Some(location)) => location,
            Ok(None) => return false,
            Err(err) => {
                tracing::warn!(error = %err, "geoip lookup failed; impossible-travel check skipped");
                return false;
            }
        };
        let (Some(latitude), Some(longitude)) = (current.latitude, current.longitude) else {
            return false;
        };
        let previous = match self.store.last_fix(user).await {
            Ok(Some(fix)) => fix,
            Ok(None) => return false,
            Err(err) => {
                tracing::warn!(error = %err, "loading last location failed");
                return false;
            }
        };
        let current = geo::Fix {
            latitude,
            longitude,
            accuracy_km: current
                .accuracy_km
                .map_or(geo::DEFAULT_ACCURACY_KM, f64::from),
            at: input.at,
        };
        geo::is_impossible_travel(
            &previous,
            &current,
            f64::from(self.config.impossible_travel_speed_kmh),
        )
    }

    /// Everything [`RiskEvaluator::record_successful_login`] stores, with
    /// GeoIP enrichment when available.
    pub async fn observation(&self, input: &RiskInput) -> DeviceObservation {
        let location = match &self.geoip {
            Some(geoip) => geoip.lookup(input.ip).await.unwrap_or_else(|err| {
                tracing::warn!(error = %err, "geoip lookup failed");
                None
            }),
            None => None,
        };
        let country =
            store::sanitize_country(location.as_ref().and_then(|l| l.country_code.as_deref()));
        let city = location
            .as_ref()
            .and_then(|l| l.city.as_deref())
            .map(|c| {
                c.chars()
                    .filter(|ch| !ch.is_control())
                    .take(64)
                    .collect::<String>()
            })
            .filter(|c| !c.trim().is_empty());
        let approximate_location = match (city, country.as_deref()) {
            (Some(city), Some(cc)) => Some(format!("{}, {cc}", city.trim())),
            (Some(city), None) => Some(city.trim().to_owned()),
            (None, Some(cc)) => Some(cc.to_owned()),
            (None, None) => None,
        };
        DeviceObservation {
            device_id: input.device_id.clone(),
            device_name: useragent::describe(input.user_agent.as_deref()),
            ip: input.ip,
            country,
            latitude: location.as_ref().and_then(|l| l.latitude),
            longitude: location.as_ref().and_then(|l| l.longitude),
            at: input.at,
            approximate_location,
        }
    }
}

#[async_trait]
impl RiskEvaluator for DefaultRiskEvaluator {
    async fn evaluate(&self, input: &RiskInput) -> Result<RiskAssessment, AuthError> {
        if !self.config.enabled {
            return Ok(RiskAssessment::low());
        }
        let passkey = input.method == LoginMethod::Passkey;
        let mut reasons = Vec::new();
        if let Some(user) = input.user_id
            && !passkey
        {
            let seen = self
                .store
                .familiarity(user, input.device_id.as_deref(), input.ip)
                .await?;
            if seen.history {
                if !seen.known_device {
                    reasons.push(RiskReason::NewDevice);
                }
                if !seen.known_network {
                    reasons.push(RiskReason::NewNetwork);
                }
            }
        }
        if !passkey && self.recent_failures(input).await? {
            reasons.push(RiskReason::RecentFailures);
        }
        if self.anonymizers.contains(input.ip) {
            reasons.push(RiskReason::AnonymizingNetwork);
        }
        if self.impossible_travel(input).await {
            reasons.push(RiskReason::ImpossibleTravel);
        }
        Ok(RiskAssessment {
            level: level_of(&reasons),
            reasons,
        })
    }

    async fn record_successful_login(&self, input: &RiskInput) -> Result<(), AuthError> {
        let Some(user) = input.user_id else {
            return Ok(());
        };
        let observation = self.observation(input).await;
        let mut tx = self.store.pool().begin().await?;
        self.store.record(&mut tx, user, &observation).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsk_01_levels_follow_the_documented_scoring() {
        use RiskReason::{
            AnonymizingNetwork, ImpossibleTravel, NewDevice, NewNetwork, RecentFailures,
        };
        assert_eq!(level_of(&[]), RiskLevel::Low);
        assert_eq!(level_of(&[NewDevice]), RiskLevel::Medium);
        assert_eq!(level_of(&[NewDevice, NewNetwork]), RiskLevel::Medium);
        assert_eq!(level_of(&[AnonymizingNetwork]), RiskLevel::Medium);
        assert_eq!(
            level_of(&[NewDevice, NewNetwork, RecentFailures]),
            RiskLevel::High
        );
        assert_eq!(level_of(&[AnonymizingNetwork, NewDevice]), RiskLevel::High);
        assert_eq!(level_of(&[ImpossibleTravel]), RiskLevel::High);
    }

    #[test]
    fn rsk_03_policy_mapping_is_configurable() {
        let medium = RiskAssessment {
            level: RiskLevel::Medium,
            reasons: vec![RiskReason::NewDevice],
        };
        let high = RiskAssessment {
            level: RiskLevel::High,
            reasons: vec![RiskReason::ImpossibleTravel],
        };
        let mut config = RiskConfig::default();
        assert_eq!(
            decide(&config, &RiskAssessment::low(), true),
            RiskResponse::Allow
        );
        assert_eq!(decide(&config, &medium, true), RiskResponse::RequireMfa);
        assert_eq!(
            decide(&config, &medium, false),
            RiskResponse::RequireEmailConfirmation
        );
        assert_eq!(decide(&config, &high, true), RiskResponse::Block);
        config.high_action = HighRiskAction::StepUp;
        assert_eq!(
            decide(&config, &high, false),
            RiskResponse::RequireEmailConfirmation
        );
        config.medium_action = MediumRiskAction::Allow;
        assert_eq!(decide(&config, &medium, true), RiskResponse::Allow);
    }
}
