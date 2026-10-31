//! Risk-based authentication (RSK-01 … RSK-03). Owner of this file:
//! authn-protect.
//!
//! The default evaluator considers a new device, a new network (/24 or /48),
//! recent failures, optional anonymizing-network lists and impossible travel
//! (only when a [`super::GeoIpLookup`] is plugged in).

use std::net::IpAddr;

use async_trait::async_trait;
use serde::Serialize;
use time::OffsetDateTime;

use crate::domain::LoginMethod;
use crate::error::AuthError;
use crate::http::RequestContext;
use crate::id::UserId;

/// Evaluates login risk.
#[async_trait]
pub trait RiskEvaluator: Send + Sync {
    /// Assesses one login attempt.
    async fn evaluate(&self, input: &RiskInput) -> Result<RiskAssessment, AuthError>;

    /// Learns from a successful login (marks device / network as known).
    async fn record_successful_login(&self, input: &RiskInput) -> Result<(), AuthError>;
}

text_enum! {
    /// Risk level (RSK-01).
    pub enum RiskLevel {
        /// Nothing unusual.
        Low => "low",
        /// Step up: MFA or e-mail confirmation (RSK-03).
        Medium => "medium",
        /// Block and notify the user (RSK-03).
        High => "high",
    }
}

text_enum! {
    /// Why a login was considered risky.
    pub enum RiskReason {
        /// Device id never seen for this user.
        NewDevice => "new_device",
        /// IP network (/24, /48) never seen for this user.
        NewNetwork => "new_network",
        /// Many recent failures for this account or IP.
        RecentFailures => "recent_failures",
        /// IP on a TOR / proxy list.
        AnonymizingNetwork => "anonymizing_network",
        /// Physically impossible travel since the last login.
        ImpossibleTravel => "impossible_travel",
    }
}

/// Input of a risk evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskInput {
    /// The user, when known (after identification).
    pub user_id: Option<UserId>,
    /// Client IP.
    pub ip: IpAddr,
    /// User agent.
    pub user_agent: Option<String>,
    /// Client-provided device id (untrusted, validated format).
    pub device_id: Option<String>,
    /// Evaluation time.
    pub at: OffsetDateTime,
    /// Login method.
    pub method: LoginMethod,
}

impl RiskInput {
    /// Builds the input from the request context.
    #[must_use]
    pub fn from_context(
        ctx: &RequestContext,
        user_id: Option<UserId>,
        method: LoginMethod,
        at: OffsetDateTime,
    ) -> Self {
        Self {
            user_id,
            ip: ctx.client_ip,
            user_agent: ctx.user_agent.clone(),
            device_id: ctx.device_id.clone(),
            at,
            method,
        }
    }
}

/// Output of a risk evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskAssessment {
    /// Overall level.
    pub level: RiskLevel,
    /// Contributing reasons.
    pub reasons: Vec<RiskReason>,
}

impl RiskAssessment {
    /// A low-risk assessment without reasons.
    #[must_use]
    pub fn low() -> Self {
        Self {
            level: RiskLevel::Low,
            reasons: Vec::new(),
        }
    }
}
