use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{
    BreachStatus, BreachedPasswordChecker, PasswordCheck, PasswordContext, PasswordValidator,
    PasswordViolation,
};
use authn_core::secret::{ExposeSecret, SecretString};

use super::lock;

/// Breach checker with an in-memory list; can simulate an outage.
#[derive(Debug, Default)]
pub struct FakeBreachedPasswordChecker {
    breached: Mutex<HashSet<String>>,
    unavailable: Mutex<bool>,
}

impl FakeBreachedPasswordChecker {
    /// Marks a password as breached.
    pub fn add_breached(&self, password: &str) {
        lock(&self.breached).insert(password.to_owned());
    }

    /// Simulates HIBP being unreachable (`BreachStatus::Unknown`).
    pub fn set_unavailable(&self, unavailable: bool) {
        *lock(&self.unavailable) = unavailable;
    }
}

#[async_trait]
impl BreachedPasswordChecker for FakeBreachedPasswordChecker {
    async fn check(&self, password: &SecretString) -> Result<BreachStatus, AuthError> {
        if *lock(&self.unavailable) {
            return Ok(BreachStatus::Unknown);
        }
        Ok(if lock(&self.breached).contains(password.expose_secret()) {
            BreachStatus::Breached { occurrences: 1 }
        } else {
            BreachStatus::NotFound
        })
    }
}

/// Length-only validator (min 12, max 128 characters by default) plus an
/// optional deny list. Real policy lives in authn-password.
#[derive(Debug)]
pub struct FakePasswordValidator {
    /// Minimum length in characters.
    pub min_length: u32,
    /// Maximum length in characters.
    pub max_length: u32,
    weak: Mutex<HashSet<String>>,
}

impl Default for FakePasswordValidator {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            weak: Mutex::new(HashSet::new()),
        }
    }
}

impl FakePasswordValidator {
    /// Marks a password as too weak.
    pub fn add_weak(&self, password: &str) {
        lock(&self.weak).insert(password.to_owned());
    }
}

#[async_trait]
impl PasswordValidator for FakePasswordValidator {
    async fn validate(
        &self,
        password: &SecretString,
        _ctx: &PasswordContext,
    ) -> Result<PasswordCheck, AuthError> {
        let value = password.expose_secret();
        let len = u32::try_from(value.chars().count()).unwrap_or(u32::MAX);
        let mut violations = Vec::new();
        if len < self.min_length {
            violations.push(PasswordViolation::TooShort {
                min: self.min_length,
            });
        }
        if len > self.max_length {
            violations.push(PasswordViolation::TooLong {
                max: self.max_length,
            });
        }
        let weak = lock(&self.weak).contains(value);
        if weak {
            violations.push(PasswordViolation::TooWeak {
                score: 0,
                min_score: 3,
            });
        }
        Ok(PasswordCheck {
            score: if weak { 0 } else { 4 },
            violations,
            feedback: Vec::new(),
            breach_check_skipped: false,
        })
    }
}
