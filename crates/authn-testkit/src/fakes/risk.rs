use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{RiskAssessment, RiskEvaluator, RiskInput};

use super::lock;

/// Returns a configurable assessment (default: low risk) and records inputs.
#[derive(Debug)]
pub struct FakeRiskEvaluator {
    assessment: Mutex<RiskAssessment>,
    evaluated: Mutex<Vec<RiskInput>>,
    successes: Mutex<Vec<RiskInput>>,
}

impl Default for FakeRiskEvaluator {
    fn default() -> Self {
        Self {
            assessment: Mutex::new(RiskAssessment::low()),
            evaluated: Mutex::new(Vec::new()),
            successes: Mutex::new(Vec::new()),
        }
    }
}

impl FakeRiskEvaluator {
    /// Sets the assessment returned from now on.
    pub fn set(&self, assessment: RiskAssessment) {
        *lock(&self.assessment) = assessment;
    }

    /// Inputs passed to `evaluate`.
    #[must_use]
    pub fn evaluated(&self) -> Vec<RiskInput> {
        lock(&self.evaluated).clone()
    }

    /// Inputs passed to `record_successful_login`.
    #[must_use]
    pub fn successes(&self) -> Vec<RiskInput> {
        lock(&self.successes).clone()
    }
}

#[async_trait]
impl RiskEvaluator for FakeRiskEvaluator {
    async fn evaluate(&self, input: &RiskInput) -> Result<RiskAssessment, AuthError> {
        lock(&self.evaluated).push(input.clone());
        Ok(lock(&self.assessment).clone())
    }

    async fn record_successful_login(&self, input: &RiskInput) -> Result<(), AuthError> {
        lock(&self.successes).push(input.clone());
        Ok(())
    }
}
