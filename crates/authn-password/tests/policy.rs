#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! Password policy: PWD-01 (length, no composition rules), PWD-02 (NFKC),
//! PWD-03 (breach verdict and fail modes), PWD-04 (zxcvbn, user inputs,
//! TR/EN feedback).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use authn_core::domain::{EmailAddress, Locale};
use authn_core::error::{AuthError, codes};
use authn_core::ports::{
    BreachStatus, BreachedPasswordChecker, PasswordContext, PasswordValidator, PasswordViolation,
};
use authn_core::secret::{ExposeSecret, SecretString};
use authn_password::{PasswordPolicy, PolicySettings};
use authn_testkit::fakes::FakeBreachedPasswordChecker;

/// Records what reaches the breach checker.
#[derive(Default)]
struct RecordingChecker {
    seen: Mutex<Vec<String>>,
    status: Mutex<Option<BreachStatus>>,
}

#[async_trait]
impl BreachedPasswordChecker for RecordingChecker {
    async fn check(&self, password: &SecretString) -> Result<BreachStatus, AuthError> {
        self.seen
            .lock()
            .unwrap()
            .push(password.expose_secret().to_owned());
        Ok(self
            .status
            .lock()
            .unwrap()
            .unwrap_or(BreachStatus::NotFound))
    }
}

fn settings() -> PolicySettings {
    PolicySettings {
        min_length: 12,
        max_length: 128,
        min_score: 3,
        service_name: "Acme Cloud Service".to_owned(),
        fail_open: true,
    }
}

fn policy_with(checker: Arc<dyn BreachedPasswordChecker>) -> PasswordPolicy {
    PasswordPolicy::new(settings(), checker)
}

fn ctx(locale: Locale) -> PasswordContext {
    PasswordContext {
        email: None,
        display_name: None,
        locale,
    }
}

fn pw(value: &str) -> SecretString {
    SecretString::from(value)
}

#[tokio::test]
async fn pwd_01_no_composition_rules_lowercase_passphrase_with_spaces_is_accepted() {
    let policy = policy_with(Arc::new(RecordingChecker::default()));
    for candidate in [
        "tramway galaxy orchid lantern 47",
        "çay bahçesi üzüm dağı yeşil ırmak",
        "日本語のパスワードはとても長いです安全",
        "🦀 rustacean ferris crab shell 🦀",
    ] {
        let check = policy
            .evaluate(&pw(candidate), &ctx(Locale::En))
            .await
            .unwrap();
        assert!(check.is_acceptable(), "{candidate}: {check:?}");
        assert!(check.feedback.is_empty() || check.score >= 3);
    }
}

#[tokio::test]
async fn pwd_01_length_limits_are_enforced_in_characters() {
    let checker = Arc::new(RecordingChecker::default());
    let policy = policy_with(checker.clone());
    let short = policy
        .evaluate(&pw("ab cd ef gh"), &ctx(Locale::En))
        .await
        .unwrap();
    assert!(
        short
            .violations
            .contains(&PasswordViolation::TooShort { min: 12 })
    );
    // 12 multi-byte characters are 12 characters, not 24+ bytes.
    let twelve = "ğüşiöçĞÜŞİÖÇ";
    assert_eq!(twelve.chars().count(), 12);
    let check = policy
        .evaluate(&pw(twelve), &ctx(Locale::En))
        .await
        .unwrap();
    assert!(
        !check
            .violations
            .iter()
            .any(|v| matches!(v, PasswordViolation::TooShort { .. }))
    );

    let calls_before = checker.seen.lock().unwrap().len();
    let too_long = "a".repeat(129);
    let check = policy
        .evaluate(&pw(&too_long), &ctx(Locale::En))
        .await
        .unwrap();
    assert_eq!(
        check.violations,
        vec![PasswordViolation::TooLong { max: 128 }]
    );
    assert_eq!(
        check.feedback,
        vec!["Use at most 128 characters.".to_owned()]
    );
    // DoS guard: oversized input never reaches zxcvbn or the breach lookup.
    let huge = "x".repeat(100_000);
    let check = policy.evaluate(&pw(&huge), &ctx(Locale::Tr)).await.unwrap();
    assert_eq!(
        check.violations,
        vec![PasswordViolation::TooLong { max: 128 }]
    );
    assert_eq!(
        check.feedback,
        vec!["En fazla 128 karakter kullanın.".to_owned()]
    );
    assert_eq!(checker.seen.lock().unwrap().len(), calls_before);
}

#[tokio::test]
async fn pwd_02_length_and_verdict_use_the_nfkc_form() {
    let checker = Arc::new(RecordingChecker::default());
    let policy = policy_with(checker.clone());
    // Six "ﬁ" ligatures are 6 characters raw but 12 after NFKC.
    let ligatures = "\u{fb01}".repeat(6);
    let check = policy
        .evaluate(&pw(&ligatures), &ctx(Locale::En))
        .await
        .unwrap();
    assert!(
        !check
            .violations
            .iter()
            .any(|v| matches!(v, PasswordViolation::TooShort { .. }))
    );
    // Eleven "é" typed decomposed (e + U+0301) are 22 scalars raw, 11 after NFKC.
    let decomposed = "e\u{301}".repeat(11);
    let check = policy
        .evaluate(&pw(&decomposed), &ctx(Locale::En))
        .await
        .unwrap();
    assert!(
        check
            .violations
            .contains(&PasswordViolation::TooShort { min: 12 })
    );
    // NFC and NFD spellings of the same password get the same verdict and the
    // breach lookup sees the normalized form.
    let nfc = "kahvé makinesi çok güzel dün";
    let nfd = "kahve\u{301} makinesi c\u{327}ok gu\u{308}zel du\u{308}n";
    let a = policy.evaluate(&pw(nfc), &ctx(Locale::En)).await.unwrap();
    let b = policy.evaluate(&pw(nfd), &ctx(Locale::En)).await.unwrap();
    assert_eq!(a, b);
    let seen = checker.seen.lock().unwrap().clone();
    assert!(seen.len() >= 2);
    assert!(seen.iter().rev().take(2).all(|s| s == nfc), "{seen:?}");
    // Fullwidth compatibility characters fold to ASCII before the lookup.
    let fullwidth = "ｔｒａｍｗａｙ ｇａｌａｘｙ ｏｒｃｈｉｄ ４７";
    policy
        .evaluate(&pw(fullwidth), &ctx(Locale::En))
        .await
        .unwrap();
    assert_eq!(
        checker.seen.lock().unwrap().last().unwrap(),
        "tramway galaxy orchid 47"
    );
}

#[tokio::test]
async fn pwd_03_breached_password_is_rejected_with_feedback() {
    let fake = Arc::new(FakeBreachedPasswordChecker::default());
    fake.add_breached("tramway galaxy orchid lantern 47");
    let policy = policy_with(fake);
    let check = policy
        .evaluate(&pw("tramway galaxy orchid lantern 47"), &ctx(Locale::Tr))
        .await
        .unwrap();
    assert_eq!(check.violations, vec![PasswordViolation::Breached]);
    assert!(
        check.feedback[0].contains("veri ihlalinde"),
        "{:?}",
        check.feedback
    );
    let err = policy
        .enforce(&pw("tramway galaxy orchid lantern 47"), &ctx(Locale::En))
        .await
        .unwrap_err();
    assert_eq!(err.code(), codes::password::PASSWORD_POLICY_VIOLATION);
    let details = err.details().unwrap();
    assert_eq!(details["violations"][0]["code"], "breached");
}

#[tokio::test]
async fn pwd_03_breach_lookup_is_skipped_for_rejected_candidates() {
    let checker = Arc::new(RecordingChecker::default());
    let policy = policy_with(checker.clone());
    policy
        .evaluate(&pw("password1234"), &ctx(Locale::En))
        .await
        .unwrap();
    policy
        .evaluate(&pw("short"), &ctx(Locale::En))
        .await
        .unwrap();
    assert!(checker.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pwd_03_outage_fails_open_by_default_and_flags_the_result() {
    let fake = Arc::new(FakeBreachedPasswordChecker::default());
    fake.set_unavailable(true);
    let policy = policy_with(fake);
    let check = policy
        .evaluate(&pw("tramway galaxy orchid lantern 47"), &ctx(Locale::En))
        .await
        .unwrap();
    assert!(check.is_acceptable());
    assert!(check.breach_check_skipped);
}

#[tokio::test]
async fn pwd_03_outage_fails_closed_when_configured() {
    let fake = Arc::new(FakeBreachedPasswordChecker::default());
    fake.set_unavailable(true);
    let mut settings = settings();
    settings.fail_open = false;
    let policy = PasswordPolicy::new(settings, fake.clone());
    let err = policy
        .evaluate(&pw("tramway galaxy orchid lantern 47"), &ctx(Locale::En))
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        codes::password::PASSWORD_BREACH_CHECK_UNAVAILABLE
    );
    assert_eq!(err.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(err.retry_after().is_some());
    fake.set_unavailable(false);
    assert!(
        policy
            .evaluate(&pw("tramway galaxy orchid lantern 47"), &ctx(Locale::En))
            .await
            .unwrap()
            .is_acceptable()
    );
}

#[tokio::test]
async fn pwd_04_weak_passwords_fail_the_minimum_score_with_localized_feedback() {
    let policy = policy_with(Arc::new(RecordingChecker::default()));
    let en = policy
        .evaluate(&pw("password1234"), &ctx(Locale::En))
        .await
        .unwrap();
    assert!(en.score < 3);
    assert!(
        en.violations
            .iter()
            .any(|v| matches!(v, PasswordViolation::TooWeak { min_score: 3, .. }))
    );
    assert!(
        en.feedback
            .contains(&"This password is too easy to guess.".to_owned())
    );
    assert!(
        en.feedback.len() >= 2,
        "zxcvbn hints included: {:?}",
        en.feedback
    );
    let tr = policy
        .evaluate(&pw("password1234"), &ctx(Locale::Tr))
        .await
        .unwrap();
    assert!(
        tr.feedback
            .contains(&"Bu şifre çok kolay tahmin edilebilir.".to_owned())
    );
    assert_eq!(en.feedback.len(), tr.feedback.len());
    assert!(tr.feedback.iter().all(|f| !en.feedback.contains(f)));
}

#[tokio::test]
async fn pwd_04_email_display_name_and_service_name_are_user_inputs() {
    let policy = policy_with(Arc::new(RecordingChecker::default()));
    let with_ctx = PasswordContext {
        email: Some(EmailAddress::parse("zeynepkaraca@example.com").unwrap()),
        display_name: Some("Zeynep Karaca".to_owned()),
        locale: Locale::En,
    };
    for candidate in ["zeynepkaraca1989", "Zeynep Karaca 1989"] {
        let plain = policy
            .evaluate(&pw(candidate), &ctx(Locale::En))
            .await
            .unwrap();
        let personal = policy.evaluate(&pw(candidate), &with_ctx).await.unwrap();
        assert!(plain.is_acceptable(), "{candidate} alone is strong");
        assert!(
            personal.score < plain.score,
            "{candidate}: {} vs {}",
            personal.score,
            plain.score
        );
        assert!(!personal.is_acceptable(), "{candidate}");
    }
    let personal = policy
        .evaluate(&pw("zeynepkaraca1989"), &with_ctx)
        .await
        .unwrap();
    assert!(
        personal.feedback.contains(
            &"Avoid your e-mail address, your name and the name of this service.".to_owned()
        ),
        "{:?}",
        personal.feedback
    );

    // The configured service name is always an input.
    let mut other = settings();
    other.service_name = "Unrelated Product".to_owned();
    let unrelated = PasswordPolicy::new(other, Arc::new(RecordingChecker::default()));
    let candidate = pw("acme cloud service 42");
    let elsewhere = unrelated
        .evaluate(&candidate, &ctx(Locale::En))
        .await
        .unwrap();
    let here = policy.evaluate(&candidate, &ctx(Locale::En)).await.unwrap();
    assert!(elsewhere.is_acceptable());
    assert!(here.score < elsewhere.score && !here.is_acceptable());
}

#[tokio::test]
async fn pwd_04_minimum_score_is_configurable() {
    let mut settings = settings();
    settings.min_score = 0;
    let lenient = PasswordPolicy::new(settings, Arc::new(RecordingChecker::default()));
    assert!(
        lenient
            .evaluate(&pw("password1234"), &ctx(Locale::En))
            .await
            .unwrap()
            .is_acceptable()
    );
}

#[tokio::test]
async fn pwd_04_policy_implements_the_password_validator_port() {
    let validator: Arc<dyn PasswordValidator> =
        Arc::new(policy_with(Arc::new(RecordingChecker::default())));
    let check = validator
        .validate(&pw("tramway galaxy orchid lantern 47"), &ctx(Locale::En))
        .await
        .unwrap();
    assert!(check.is_acceptable());
    assert!(check.score >= 3);
}
