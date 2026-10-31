use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use authn_testkit::timing::compare_timings;

use super::*;
use crate::secret::SecretBytes;

const CHEAP: Argon2Settings = Argon2Settings {
    memory_kib: 7_168,
    iterations: 1,
    parallelism: 1,
};

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn peppers(current: u32, versions: &[u32]) -> Peppers {
    Peppers::new(
        current,
        versions
            .iter()
            .map(|v| (*v, SecretBytes::new(vec![u8::try_from(*v).unwrap(); 32]))),
    )
    .unwrap()
}

async fn hasher(settings: Argon2Settings, current: u32, versions: &[u32]) -> PasswordHasher {
    PasswordHasher::new(settings, peppers(current, versions), 4)
        .await
        .unwrap()
}

#[tokio::test]
async fn cry_01_hash_is_argon2id_phc_with_configured_parameters() {
    let h = hasher(CHEAP, 1, &[1]).await;
    let record = h
        .hash(&secret("correct horse battery staple"))
        .await
        .unwrap();
    assert_eq!(record.algorithm, HashAlgorithm::Argon2id);
    assert_eq!(record.pepper_version, Some(1));
    assert!(
        record
            .hash
            .expose()
            .starts_with("$argon2id$v=19$m=7168,t=1,p=1$")
    );
    let stored = StoredPasswordHash::from(&record);
    assert_eq!(
        h.verify(&secret("correct horse battery staple"), Some(&stored))
            .await
            .unwrap(),
        VerifyOutcome::Valid { rehash: None }
    );
    assert_eq!(
        h.verify(&secret("correct horse battery stapl"), Some(&stored))
            .await
            .unwrap(),
        VerifyOutcome::Invalid
    );
    assert_eq!(h.needs_rehash(&stored), None);
}

#[tokio::test]
async fn cry_01_production_defaults_from_config() {
    let config = authn_testkit::config::TestConfigBuilder::new()
        .production_argon2()
        .build();
    let h = PasswordHasher::from_config(&config.crypto).await.unwrap();
    assert_eq!(h.settings(), Argon2Settings::DEFAULT);
    let record = h.hash(&secret("pw")).await.unwrap();
    assert!(
        record
            .hash
            .expose()
            .starts_with("$argon2id$v=19$m=19456,t=2,p=1$")
    );
}

#[tokio::test]
async fn cry_02_the_pepper_is_part_of_the_hash() {
    let h1 = hasher(CHEAP, 1, &[1]).await;
    let record = h1.hash(&secret("pw")).await.unwrap();
    let stored = StoredPasswordHash::from(&record);
    // Same hash, same pepper version number, different pepper key: no match.
    let other = PasswordHasher::new(
        CHEAP,
        Peppers::new(1, [(1, SecretBytes::new(vec![0xEE; 32]))]).unwrap(),
        1,
    )
    .await
    .unwrap();
    assert_eq!(
        other.verify(&secret("pw"), Some(&stored)).await.unwrap(),
        VerifyOutcome::Invalid
    );
    // A plain (unpeppered) Argon2 of the password does not match either.
    let unpeppered = argon::hash(CHEAP, b"pw").unwrap();
    let parsed = Argon2Phc::parse(record.hash.expose()).unwrap();
    assert!(!parsed.verify(b"pw").unwrap());
    assert!(
        Argon2Phc::parse(&unpeppered)
            .unwrap()
            .verify(b"pw")
            .unwrap()
    );
}

#[tokio::test]
async fn cry_02_cry_03_pepper_rotation_upgrades_on_login() {
    let old = hasher(CHEAP, 1, &[1]).await;
    let stored = StoredPasswordHash::from(&old.hash(&secret("pw")).await.unwrap());

    let rotated = hasher(CHEAP, 2, &[1, 2]).await;
    assert_eq!(rotated.current_pepper_version(), 2);
    assert_eq!(
        rotated.needs_rehash(&stored),
        Some(RehashReason::OutdatedPepper)
    );
    assert_eq!(
        rotated.verify(&secret("pw"), Some(&stored)).await.unwrap(),
        VerifyOutcome::Valid {
            rehash: Some(RehashReason::OutdatedPepper)
        }
    );
    let upgraded = rotated.hash(&secret("pw")).await.unwrap();
    assert_eq!(upgraded.pepper_version, Some(2));
    assert_eq!(
        rotated
            .verify(&secret("pw"), Some(&StoredPasswordHash::from(&upgraded)))
            .await
            .unwrap(),
        VerifyOutcome::Valid { rehash: None }
    );

    // Once version 1 is removed from the configuration, its hashes fail
    // closed (Invalid, not an error that would reveal the account).
    let removed = hasher(CHEAP, 2, &[2]).await;
    assert_eq!(
        removed.verify(&secret("pw"), Some(&stored)).await.unwrap(),
        VerifyOutcome::Invalid
    );
}

#[tokio::test]
async fn cry_03_outdated_parameters_trigger_rehash() {
    let weak = hasher(CHEAP, 1, &[1]).await;
    let stored = StoredPasswordHash::from(&weak.hash(&secret("pw")).await.unwrap());
    let stronger = hasher(
        Argon2Settings {
            iterations: 2,
            ..CHEAP
        },
        1,
        &[1],
    )
    .await;
    assert_eq!(
        stronger.needs_rehash(&stored),
        Some(RehashReason::OutdatedParameters)
    );
    assert_eq!(
        stronger.verify(&secret("pw"), Some(&stored)).await.unwrap(),
        VerifyOutcome::Valid {
            rehash: Some(RehashReason::OutdatedParameters)
        }
    );
    assert_eq!(
        stronger.verify(&secret("pW"), Some(&stored)).await.unwrap(),
        VerifyOutcome::Invalid
    );
}

#[tokio::test]
async fn pwd_02_verification_uses_the_canonical_form() {
    let h = hasher(CHEAP, 1, &[1]).await;
    let stored = StoredPasswordHash::from(&h.hash(&secret("caf\u{e9} \u{ff21}")).await.unwrap());
    assert!(
        h.verify(&secret("cafe\u{301} A"), Some(&stored))
            .await
            .unwrap()
            .is_valid()
    );
}

#[tokio::test]
async fn cry_04_bcrypt_verifies_and_must_be_upgraded() {
    let h = hasher(CHEAP, 1, &[1]).await;
    let legacy = bcrypt::hash_with_salt(b"Tr0ub4dor&3", 4, [1; 16])
        .unwrap()
        .format_for_version(bcrypt::Version::TwoY);
    let stored = StoredPasswordHash::new(&SensitiveString::new(legacy), "bcrypt", None);
    assert_eq!(h.needs_rehash(&stored), Some(RehashReason::LegacyAlgorithm));
    assert_eq!(
        h.verify(&secret("Tr0ub4dor&3"), Some(&stored))
            .await
            .unwrap(),
        VerifyOutcome::Valid {
            rehash: Some(RehashReason::LegacyAlgorithm)
        }
    );
    assert_eq!(
        h.verify(&secret("Tr0ub4dor&4"), Some(&stored))
            .await
            .unwrap(),
        VerifyOutcome::Invalid
    );
}

#[tokio::test]
async fn cry_04_pbkdf2_verifies_and_must_be_upgraded() {
    let h = hasher(CHEAP, 1, &[1]).await;
    let mut dk = [0_u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"hunter2", b"pepperless", 1_000, &mut dk);
    let django = format!(
        "pbkdf2_sha256$1000$pepperless${}",
        crate::encoding::b64_encode(&dk)
    );
    let stored = StoredPasswordHash::new(&SensitiveString::new(django), "pbkdf2_sha256", None);
    assert_eq!(
        h.verify(&secret("hunter2"), Some(&stored)).await.unwrap(),
        VerifyOutcome::Valid {
            rehash: Some(RehashReason::LegacyAlgorithm)
        }
    );
    assert_eq!(
        h.verify(&secret("hunter3"), Some(&stored)).await.unwrap(),
        VerifyOutcome::Invalid
    );
}

#[tokio::test]
async fn cry_04_wrapped_md5_and_sha1_hashes() {
    let h = hasher(CHEAP, 1, &[1]).await;
    for (digest, legacy_hex) in [
        (LegacyDigest::Md5, "5F4DCC3B5AA765D61D8327DEB882CF99"),
        (
            LegacyDigest::Sha1,
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        ),
    ] {
        let wrapped = h.wrap_legacy_digest(digest, legacy_hex).await.unwrap();
        assert!(wrapped.algorithm.is_legacy());
        assert_eq!(wrapped.pepper_version, Some(1));
        assert!(wrapped.hash.expose().starts_with("$argon2id$"));
        // The database never contains the fast digest.
        assert!(!wrapped.hash.expose().to_lowercase().contains("5f4dcc"));
        let stored = StoredPasswordHash::from(&wrapped);
        assert_eq!(
            h.verify(&secret("password"), Some(&stored)).await.unwrap(),
            VerifyOutcome::Valid {
                rehash: Some(RehashReason::LegacyAlgorithm)
            },
            "{digest:?}"
        );
        assert_eq!(
            h.verify(&secret("Password"), Some(&stored)).await.unwrap(),
            VerifyOutcome::Invalid
        );
    }
    assert!(
        h.wrap_legacy_digest(LegacyDigest::Md5, "not-hex")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cry_05_unknown_account_does_equal_work_and_fails() {
    let h = hasher(CHEAP, 1, &[1]).await;
    assert_eq!(
        h.verify(&secret("anything"), None).await.unwrap(),
        VerifyOutcome::Invalid
    );
    assert_eq!(
        h.verify_dummy(&secret("anything")).await.unwrap(),
        VerifyOutcome::Invalid
    );
    let stored = StoredPasswordHash::from(&h.hash(&secret("real")).await.unwrap());
    let real = h.clone();
    let dummy = h.clone();
    let stored = Arc::new(stored);
    let report = compare_timings(
        30,
        || {
            let h = real.clone();
            let stored = Arc::clone(&stored);
            async move {
                let _ = h.verify(&secret("wrong"), Some(&stored)).await.unwrap();
            }
        },
        || {
            let h = dummy.clone();
            async move {
                let _ = h.verify(&secret("wrong"), None).await.unwrap();
            }
        },
    )
    .await;
    report.assert_indistinguishable(0.35);
}

#[tokio::test]
async fn cry_05_unusable_stored_hashes_fail_closed() {
    let h = hasher(CHEAP, 1, &[1]).await;
    let good = h.hash(&secret("pw")).await.unwrap();
    let cases = [
        StoredPasswordHash::new(
            &SensitiveString::new("garbage-garbage-garbage"),
            "argon2id",
            Some(1),
        ),
        StoredPasswordHash::new(&good.hash, "argon2id", None),
        StoredPasswordHash::new(&good.hash, "argon2id", Some(9)),
        StoredPasswordHash::new(&good.hash, "scrypt", Some(1)),
        StoredPasswordHash::new(&good.hash, "bcrypt", None),
        StoredPasswordHash::new(
            &SensitiveString::new("$2b$31$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "bcrypt",
            None,
        ),
    ];
    for case in &cases {
        assert_eq!(
            h.verify(&secret("pw"), Some(case)).await.unwrap(),
            VerifyOutcome::Invalid,
            "{case:?}"
        );
    }
    // Oversized input: refused for new hashes, plain Invalid on verification.
    let huge = secret(&"a".repeat(MAX_PASSWORD_BYTES + 1));
    assert_eq!(h.hash(&huge).await.unwrap_err(), CryptoError::TooLarge);
    assert_eq!(
        h.verify(&huge, Some(&StoredPasswordHash::from(&good)))
            .await
            .unwrap(),
        VerifyOutcome::Invalid
    );
}

#[tokio::test]
async fn arc_12_hashing_concurrency_is_bounded_by_the_semaphore() {
    let permits = Arc::new(Semaphore::new(2));
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let permits = Arc::clone(&permits);
        let running = Arc::clone(&running);
        let peak = Arc::clone(&peak);
        tasks.push(tokio::spawn(async move {
            run_blocking(&permits, move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(30));
                running.fetch_sub(1, Ordering::SeqCst);
            })
            .await
            .unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(permits.available_permits(), 2);
}

#[tokio::test]
async fn arc_12_closed_semaphore_is_reported() {
    let permits = Arc::new(Semaphore::new(1));
    permits.close();
    assert_eq!(
        run_blocking(&permits, || ()).await.unwrap_err(),
        CryptoError::WorkerUnavailable
    );
}

#[tokio::test]
async fn cry_13_debug_output_contains_no_secrets() {
    let h = hasher(CHEAP, 1, &[1]).await;
    let record = h.hash(&secret("pw")).await.unwrap();
    let debug = format!("{h:?} {record:?}");
    assert!(!debug.contains("$argon2id$"), "{debug}");
    assert!(debug.contains("REDACTED"));
}

#[test]
fn cry_04_algorithm_identifiers_round_trip() {
    for algorithm in HashAlgorithm::ALL {
        assert_eq!(algorithm.as_str().parse::<HashAlgorithm>(), Ok(*algorithm));
        assert_eq!(algorithm.to_string(), algorithm.as_str());
        assert_eq!(
            algorithm.uses_pepper(),
            algorithm.as_str().starts_with("argon2id")
        );
    }
    assert!("md5".parse::<HashAlgorithm>().is_err());
}
