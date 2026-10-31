//! Password policy validation (ACC-01, PWD-01 … PWD-04). Owner of this file:
//! authn-password.
//!
//! Policy: 12 ≤ length ≤ 128 characters after NFKC (configurable), no
//! composition rules, breach check, zxcvbn score ≥ 3 with user-specific
//! inputs. Feedback is localized (TR/EN). Passwords are never logged.

use async_trait::async_trait;
use serde::Serialize;

use crate::domain::{EmailAddress, Locale};
use crate::error::AuthError;
use crate::secret::SecretString;

/// Validates candidate passwords against the policy.
#[async_trait]
pub trait PasswordValidator: Send + Sync {
    /// Checks a candidate password.
    async fn validate(
        &self,
        password: &SecretString,
        ctx: &PasswordContext,
    ) -> Result<PasswordCheck, AuthError>;
}

/// User-specific inputs for strength estimation and feedback language.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswordContext {
    /// The account e-mail, if known.
    pub email: Option<EmailAddress>,
    /// The display name, if known.
    pub display_name: Option<String>,
    /// Language of the feedback.
    pub locale: Locale,
}

/// A policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum PasswordViolation {
    /// Shorter than the minimum.
    TooShort {
        /// Minimum length in characters.
        min: u32,
    },
    /// Longer than the maximum.
    TooLong {
        /// Maximum length in characters.
        max: u32,
    },
    /// Found in breach corpora.
    Breached,
    /// Estimated strength too low.
    TooWeak {
        /// zxcvbn score (0–4).
        score: u8,
        /// Required score.
        min_score: u8,
    },
}

/// Result of a validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasswordCheck {
    /// zxcvbn score 0–4.
    pub score: u8,
    /// Violations; empty means acceptable.
    pub violations: Vec<PasswordViolation>,
    /// Localized suggestions.
    pub feedback: Vec<String>,
    /// `true` when the breach check could not run (fail-open, PWD-03).
    pub breach_check_skipped: bool,
}

impl PasswordCheck {
    /// Whether the password satisfies the policy.
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        self.violations.is_empty()
    }
}
