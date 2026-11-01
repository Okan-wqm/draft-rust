//! Password policy (PWD-01, PWD-02, PWD-04) and the [`PasswordValidator`]
//! port implementation used by registration (ACC-01), password change,
//! reset and the live check endpoint (PWD-05).
//!
//! Rules (NIST SP 800-63B rev. 4, OWASP ASVS V2.1):
//!
//! 1. The candidate is normalized with the single canonical normalizer of
//!    `authn-crypto` (Unicode NFKC, PWD-02) — exactly what is later hashed.
//! 2. Length is counted in Unicode scalar values *after* normalization:
//!    `min_length ≤ n ≤ max_length` (defaults 12 and 128). Every character,
//!    including spaces and emoji, is allowed; there are **no composition
//!    rules** (PWD-01). Inputs above the hashing layer's 4096-byte DoS bound
//!    are rejected as too long without further work.
//! 3. Strength is estimated with zxcvbn (PWD-04) with user-specific inputs:
//!    the e-mail address (and its local-part pieces), the display name (and
//!    its words) and the service name. The score must reach
//!    `min_strength_score` (default 3).
//! 4. Only a candidate that passed 2 and 3 is looked up in breach corpora
//!    (PWD-03) — this keeps the live check endpoint from sending a k-anonymity
//!    query per keystroke. When the lookup is impossible the configured fail
//!    mode applies: fail-open (default) accepts the password with a warning
//!    log, a metric and `breach_check_skipped = true`; fail-closed answers
//!    `503 password_breach_check_unavailable`.
//! 5. Feedback is localized (TR/EN, [`feedback`]).
//!
//! The password never appears in logs, errors or metrics.

pub mod feedback;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::config::password::PasswordConfig;
use authn_core::domain::Locale;
use authn_core::error::{AuthError, codes};
use authn_core::ports::{
    BreachStatus, BreachedPasswordChecker, PasswordCheck, PasswordContext, PasswordValidator,
    PasswordViolation,
};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_crypto::password::canonicalize_password;
use zeroize::Zeroizing;
use zxcvbn::feedback::{Suggestion, Warning};
use zxcvbn::matching::patterns::MatchPattern;

use crate::metrics;

/// At most this many user inputs are given to zxcvbn (bounds its work).
const MAX_USER_INPUTS: usize = 32;
/// User inputs shorter than this (in characters) are ignored: a one-letter
/// "input" would only add noise.
const MIN_USER_INPUT_CHARS: usize = 3;
/// User inputs are truncated to this many characters.
const MAX_USER_INPUT_CHARS: usize = 64;
/// `Retry-After` of the fail-closed answer.
const BREACH_RETRY_AFTER: Duration = Duration::from_secs(30);

/// The policy parameters (from `[password]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySettings {
    /// Minimum length in characters after NFKC (PWD-01).
    pub min_length: u32,
    /// Maximum length in characters after NFKC (PWD-01).
    pub max_length: u32,
    /// Minimum zxcvbn score 0–4 (PWD-04).
    pub min_score: u8,
    /// Service name given to zxcvbn as a user-specific input (PWD-04).
    pub service_name: String,
    /// Accept passwords when the breach lookup is impossible (PWD-03).
    pub fail_open: bool,
}

impl From<&PasswordConfig> for PolicySettings {
    fn from(config: &PasswordConfig) -> Self {
        Self {
            min_length: config.min_length,
            max_length: config.max_length,
            min_score: config.min_strength_score,
            service_name: config.service_name.clone(),
            fail_open: config.breach_check.fail_open,
        }
    }
}

/// The password policy. Cheap to clone.
#[derive(Clone)]
pub struct PasswordPolicy {
    settings: Arc<PolicySettings>,
    breach: Arc<dyn BreachedPasswordChecker>,
}

impl std::fmt::Debug for PasswordPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordPolicy")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl PasswordPolicy {
    /// A policy with explicit settings.
    #[must_use]
    pub fn new(settings: PolicySettings, breach: Arc<dyn BreachedPasswordChecker>) -> Self {
        Self {
            settings: Arc::new(settings),
            breach,
        }
    }

    /// A policy from `[password]`.
    #[must_use]
    pub fn from_config(config: &PasswordConfig, breach: Arc<dyn BreachedPasswordChecker>) -> Self {
        Self::new(PolicySettings::from(config), breach)
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &PolicySettings {
        &self.settings
    }

    /// Evaluates a candidate. `Ok` carries the verdict (possibly with
    /// violations); `Err` only for fail-closed breach checks and internal
    /// failures.
    pub async fn evaluate(
        &self,
        password: &SecretString,
        ctx: &PasswordContext,
    ) -> Result<PasswordCheck, AuthError> {
        let settings = &self.settings;
        let locale = ctx.locale;
        let Ok(canonical) = canonicalize_password(password.expose_secret()) else {
            // Above the 4096-byte hashing bound: reject without more work.
            let violation = PasswordViolation::TooLong {
                max: settings.max_length,
            };
            return Ok(PasswordCheck {
                score: 0,
                violations: vec![violation],
                feedback: vec![feedback::violation_message(violation, locale)],
                breach_check_skipped: false,
            });
        };
        let length = u32::try_from(canonical.chars().count()).unwrap_or(u32::MAX);
        if length > settings.max_length {
            // DoS guard: no strength estimation or breach lookup.
            let violation = PasswordViolation::TooLong {
                max: settings.max_length,
            };
            return Ok(PasswordCheck {
                score: 0,
                violations: vec![violation],
                feedback: vec![feedback::violation_message(violation, locale)],
                breach_check_skipped: false,
            });
        }

        let mut violations = Vec::new();
        if length < settings.min_length {
            violations.push(PasswordViolation::TooShort {
                min: settings.min_length,
            });
        }

        let inputs = user_inputs(ctx, &settings.service_name);
        let strength = estimate_strength(canonical.clone(), inputs).await?;
        if strength.score < settings.min_score {
            violations.push(PasswordViolation::TooWeak {
                score: strength.score,
                min_score: settings.min_score,
            });
        }

        let mut breach_check_skipped = false;
        if violations.is_empty() {
            let candidate = SecretString::from(canonical.as_str());
            let status = match self.breach.check(&candidate).await {
                Ok(status) => status,
                Err(err) => {
                    tracing::warn!(error = %err, "breached-password checker failed");
                    BreachStatus::Unknown
                }
            };
            match status {
                BreachStatus::Breached { .. } => violations.push(PasswordViolation::Breached),
                BreachStatus::NotFound => {}
                BreachStatus::Unknown if settings.fail_open => {
                    metrics::breach_check_unavailable(true);
                    tracing::warn!(
                        "breached-password check unavailable; password accepted (fail-open, PWD-03)"
                    );
                    breach_check_skipped = true;
                }
                BreachStatus::Unknown => {
                    metrics::breach_check_unavailable(false);
                    tracing::warn!(
                        "breached-password check unavailable; password refused (fail-closed, PWD-03)"
                    );
                    return Err(
                        AuthError::new(codes::password::PASSWORD_BREACH_CHECK_UNAVAILABLE)
                            .with_retry_after(BREACH_RETRY_AFTER),
                    );
                }
            }
        }

        let feedback = build_feedback(&violations, &strength, locale);
        Ok(PasswordCheck {
            score: strength.score,
            violations,
            feedback,
            breach_check_skipped,
        })
    }

    /// Evaluates a candidate and fails with `password_policy_violation`
    /// (details: violations + localized feedback) unless it is acceptable.
    pub async fn enforce(
        &self,
        password: &SecretString,
        ctx: &PasswordContext,
    ) -> Result<PasswordCheck, AuthError> {
        let check = self.evaluate(password, ctx).await?;
        if check.is_acceptable() {
            Ok(check)
        } else {
            Err(policy_violation_error(&check))
        }
    }
}

/// The `password_policy_violation` error for a failed check. The details
/// only describe the submitted password.
#[must_use]
pub fn policy_violation_error(check: &PasswordCheck) -> AuthError {
    AuthError::new(codes::password::PASSWORD_POLICY_VIOLATION).with_details(serde_json::json!({
        "score": check.score,
        "violations": check.violations,
        "feedback": check.feedback,
    }))
}

#[async_trait]
impl PasswordValidator for PasswordPolicy {
    async fn validate(
        &self,
        password: &SecretString,
        ctx: &PasswordContext,
    ) -> Result<PasswordCheck, AuthError> {
        self.evaluate(password, ctx).await
    }
}

/// zxcvbn result reduced to what the policy needs.
#[derive(Debug, Clone, PartialEq)]
struct Strength {
    score: u8,
    warning: Option<Warning>,
    suggestions: Vec<Suggestion>,
    matched_user_input: bool,
}

/// Runs zxcvbn on the blocking pool (it is CPU bound; zxcvbn itself only
/// looks at the first 100 characters).
async fn estimate_strength(
    canonical: Zeroizing<String>,
    inputs: Vec<String>,
) -> Result<Strength, AuthError> {
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
        let entropy = zxcvbn::zxcvbn(canonical.as_str(), &refs);
        let matched_user_input = entropy.sequence().iter().any(|m| match &m.pattern {
            MatchPattern::Dictionary(d) => inputs.contains(&d.matched_word),
            _ => false,
        });
        let (warning, suggestions) = entropy
            .feedback()
            .map(|f| (f.warning(), f.suggestions().to_vec()))
            .unwrap_or_default();
        Strength {
            score: u8::from(entropy.score()),
            warning,
            suggestions,
            matched_user_input,
        }
    })
    .await
    .map_err(|err| AuthError::internal("strength estimation task failed").with_source(err))
}

fn build_feedback(
    violations: &[PasswordViolation],
    strength: &Strength,
    locale: Locale,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |message: String| {
        if !out.contains(&message) {
            out.push(message);
        }
    };
    for violation in violations {
        push(feedback::violation_message(*violation, locale));
    }
    if strength.matched_user_input && !violations.is_empty() {
        push(feedback::user_input_message(locale).to_owned());
    }
    if let Some(warning) = strength.warning {
        push(feedback::warning_message(warning, locale).to_owned());
    }
    for suggestion in &strength.suggestions {
        push(feedback::suggestion_message(*suggestion, locale).to_owned());
    }
    out
}

/// User-specific zxcvbn inputs (PWD-04): display name and its words, the
/// e-mail address and its pieces, the service name and its words —
/// lowercased, deduplicated and bounded in number and size. Earlier inputs
/// get a lower zxcvbn rank (more likely guesses), so the most personal ones
/// come first.
fn user_inputs(ctx: &PasswordContext, service_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(name) = &ctx.display_name {
        push_input(&mut out, name);
        for word in words(name) {
            push_input(&mut out, word);
        }
    }
    if let Some(email) = &ctx.email {
        let local = email.local_part();
        push_input(&mut out, local);
        push_input(&mut out, email.normalized());
        for piece in local.split(['.', '_', '-', '+']) {
            push_input(&mut out, piece);
        }
        if let Some(label) = email.domain().split('.').next() {
            push_input(&mut out, label);
        }
    }
    push_input(&mut out, service_name);
    for word in words(service_name) {
        push_input(&mut out, word);
    }
    out
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
}

fn push_input(out: &mut Vec<String>, raw: &str) {
    if out.len() >= MAX_USER_INPUTS {
        return;
    }
    let value: String = raw
        .trim()
        .chars()
        .take(MAX_USER_INPUT_CHARS)
        .collect::<String>()
        .to_lowercase();
    if value.chars().count() >= MIN_USER_INPUT_CHARS && !out.contains(&value) {
        out.push(value);
    }
}

#[cfg(test)]
mod tests {
    use authn_core::domain::EmailAddress;

    use super::*;

    #[test]
    fn pwd_04_user_inputs_cover_email_name_and_service() {
        let ctx = PasswordContext {
            email: Some(EmailAddress::parse("Ayse.Yilmaz+shop@Example.com").unwrap()),
            display_name: Some("Ayşe Yılmaz".to_owned()),
            locale: Locale::Tr,
        };
        let inputs = user_inputs(&ctx, "Acme Cloud");
        for expected in [
            "acme cloud",
            "acme",
            "cloud",
            "ayse.yilmaz+shop@example.com",
            "ayse.yilmaz+shop",
            "ayse",
            "yilmaz",
            "shop",
            "example",
            "ayşe yılmaz",
            "ayşe",
            "yılmaz",
        ] {
            assert!(
                inputs.iter().any(|i| i == expected),
                "{expected} missing: {inputs:?}"
            );
        }
        assert!(
            inputs
                .iter()
                .all(|i| i.chars().count() >= MIN_USER_INPUT_CHARS)
        );
    }

    #[test]
    fn pwd_04_user_inputs_are_bounded() {
        let long_name = (0..200)
            .map(|i| format!("word{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ctx = PasswordContext {
            email: None,
            display_name: Some(long_name),
            locale: Locale::En,
        };
        let inputs = user_inputs(&ctx, "svc");
        assert!(inputs.len() <= MAX_USER_INPUTS);
        assert!(
            inputs
                .iter()
                .all(|i| i.chars().count() <= MAX_USER_INPUT_CHARS)
        );
    }
}
