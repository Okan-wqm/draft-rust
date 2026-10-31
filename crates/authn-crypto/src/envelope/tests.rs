use proptest::prelude::*;

use super::*;
use crate::secret::SecretKey;

fn provider(current: &str) -> EnvKeyProvider {
    EnvKeyProvider::new(
        current,
        [
            (KekId::new("kek-1").unwrap(), SecretKey::from_bytes([1; 32])),
            (KekId::new("kek-2").unwrap(), SecretKey::from_bytes([2; 32])),
        ],
    )
    .unwrap()
}

fn cipher(current: &str) -> EnvelopeCipher {
    EnvelopeCipher::new(Arc::new(provider(current)))
}

fn ctx(table: &'static str, column: &'static str, row: &str) -> EnvelopeContext {
    EnvelopeContext::new(table, column, row).unwrap()
}

#[tokio::test]
async fn cry_08_seal_open_round_trip() {
    let c = cipher("kek-1");
    let context = ctx("mfa_factors", "secret_ciphertext", "0190-row");
    let sealed = c.seal(b"JBSWY3DPEHPK3PXP", &context).await.unwrap();
    let parsed = Envelope::parse(&sealed).unwrap();
    assert_eq!(parsed.kek_id(), "kek-1");
    assert_eq!(parsed.plaintext_len(), 16);
    assert_eq!(parsed.encode().unwrap(), sealed);
    assert_eq!(sealed.first(), Some(&ENVELOPE_VERSION));
    assert_eq!(
        sealed.len(),
        4 + "kek-1".len() + ENV_BLOB_LEN + NONCE_LEN + 16 + TAG_LEN
    );
    let opened = c.open(&sealed, &context).await.unwrap();
    assert_eq!(opened.expose(), b"JBSWY3DPEHPK3PXP");
    // Each seal uses a fresh DEK and nonce.
    assert_ne!(c.seal(b"JBSWY3DPEHPK3PXP", &context).await.unwrap(), sealed);
    // Empty plaintext is fine.
    let empty = c.seal(b"", &context).await.unwrap();
    assert!(c.open(&empty, &context).await.unwrap().is_empty());
}

#[tokio::test]
async fn cry_08_aad_binds_table_column_and_row() {
    let c = cipher("kek-1");
    let context = ctx("mfa_factors", "secret_ciphertext", "row-1");
    let sealed = c.seal(b"secret", &context).await.unwrap();
    for other in [
        ctx("mfa_factors", "secret_ciphertext", "row-2"),
        ctx("mfa_factors", "other_ciphertext", "row-1"),
        ctx("identities", "secret_ciphertext", "row-1"),
        // Field framing: "ab"+"c" must differ from "a"+"bc".
        ctx("mfa_factors", "secret_ciphertex", "trow-1"),
    ] {
        assert_eq!(
            c.open(&sealed, &other).await.unwrap_err(),
            CryptoError::Unauthentic,
            "{other:?}"
        );
    }
}

#[tokio::test]
async fn cry_08_every_byte_is_authenticated() {
    let c = cipher("kek-1");
    let context = ctx("t", "c", "r");
    let sealed = c.seal(b"0123456789", &context).await.unwrap();
    for index in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[index] ^= 0x01;
        assert!(c.open(&tampered, &context).await.is_err(), "byte {index}");
    }
    // Truncation and extension fail too.
    assert!(c.open(&sealed[..sealed.len() - 1], &context).await.is_err());
    let mut extended = sealed.clone();
    extended.push(0);
    assert!(c.open(&extended, &context).await.is_err());
}

#[tokio::test]
async fn cry_08_kek_rotation_rewraps_without_touching_data() {
    let old = cipher("kek-1");
    let context = ctx("signing_keys", "private_key_ciphertext", "id");
    let sealed = old.seal(b"private key", &context).await.unwrap();

    let rotated = cipher("kek-2");
    assert!(rotated.needs_rewrap(&sealed).unwrap());
    assert!(!old.needs_rewrap(&sealed).unwrap());
    // Old envelopes still open while kek-1 is configured.
    assert_eq!(
        rotated.open(&sealed, &context).await.unwrap().expose(),
        b"private key"
    );

    let rewrapped = rotated.rewrap(&sealed, &context).await.unwrap().unwrap();
    let before = Envelope::parse(&sealed).unwrap();
    let after = Envelope::parse(&rewrapped).unwrap();
    assert_eq!(after.kek_id(), "kek-2");
    assert_eq!(after.ciphertext, before.ciphertext);
    assert_eq!(after.nonce, before.nonce);
    assert!(!rotated.needs_rewrap(&rewrapped).unwrap());
    assert!(
        rotated
            .rewrap(&rewrapped, &context)
            .await
            .unwrap()
            .is_none()
    );

    // After kek-1 is removed the rewrapped envelope still opens…
    let only_new = EnvelopeCipher::new(Arc::new(
        EnvKeyProvider::new(
            "kek-2",
            [(KekId::new("kek-2").unwrap(), SecretKey::from_bytes([2; 32]))],
        )
        .unwrap(),
    ));
    assert_eq!(
        only_new.open(&rewrapped, &context).await.unwrap().expose(),
        b"private key"
    );
    // …and the old one fails closed.
    assert_eq!(
        only_new.open(&sealed, &context).await.unwrap_err(),
        CryptoError::UnknownKey
    );
    // Rewrap refuses an envelope for another row (no laundering).
    assert!(
        rotated
            .rewrap(
                &sealed,
                &ctx("signing_keys", "private_key_ciphertext", "other")
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cry_08_limits() {
    let c = cipher("kek-1");
    let context = ctx("t", "c", "r");
    assert_eq!(
        c.seal(&vec![0; MAX_PLAINTEXT_LEN + 1], &context)
            .await
            .unwrap_err(),
        CryptoError::TooLarge
    );
    assert!(EnvelopeContext::new("Bad", "c", "r").is_err());
    assert!(EnvelopeContext::new("t", "c;", "r").is_err());
    assert!(EnvelopeContext::new("t", "c", "").is_err());
    assert!(EnvelopeContext::new("t", "c", "x".repeat(257)).is_err());
    assert!(EnvelopeContext::new("t", "c", "x".repeat(256)).is_ok());
}

#[test]
fn cry_08_parser_rejects_malformed_envelopes() {
    let mut good = vec![ENVELOPE_VERSION, 1, b'k', 0, 1, 0xAA];
    good.extend_from_slice(&[0; NONCE_LEN]);
    good.extend_from_slice(&[0; TAG_LEN]);
    assert!(Envelope::parse(&good).is_ok());

    let mut cases: Vec<Vec<u8>> = vec![Vec::new(), vec![ENVELOPE_VERSION]];
    let mut v2 = good.clone();
    v2[0] = 2;
    cases.push(v2);
    let mut no_kek = good.clone();
    no_kek[1] = 0;
    cases.push(no_kek);
    let mut bad_kek = good.clone();
    bad_kek[2] = b' ';
    cases.push(bad_kek);
    let mut long_kek = good.clone();
    long_kek[1] = 200;
    cases.push(long_kek);
    let mut zero_wrap = good.clone();
    zero_wrap[4] = 0;
    cases.push(zero_wrap);
    let mut huge_wrap = good.clone();
    huge_wrap[3] = 0xFF;
    cases.push(huge_wrap);
    cases.push(good[..good.len() - 1].to_vec());
    for case in &cases {
        assert!(Envelope::parse(case).is_err(), "{case:?}");
    }
    assert_eq!(
        Envelope::parse(&vec![1; MAX_ENVELOPE_LEN + 1]).unwrap_err(),
        CryptoError::TooLarge
    );
    assert!(format!("{:?}", Envelope::parse(&good).unwrap()).contains("kek_id"));
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// TST-03: any plaintext round-trips for any valid context, and the
    /// envelope parses and re-encodes byte for byte.
    #[test]
    fn cry_08_prop_round_trip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        row in "[a-zA-Z0-9-]{1,64}",
    ) {
        let rt = runtime();
        let c = cipher("kek-2");
        let context = EnvelopeContext::new("tbl", "col", &row).unwrap();
        let sealed = rt.block_on(c.seal(&plaintext, &context)).unwrap();
        prop_assert_eq!(Envelope::parse(&sealed).unwrap().encode().unwrap(), sealed.clone());
        let opened = rt.block_on(c.open(&sealed, &context)).unwrap();
        prop_assert_eq!(opened.expose(), plaintext.as_slice());
    }

    /// The parser never panics and only accepts what it can re-encode
    /// identically.
    #[test]
    fn cry_08_prop_parser_total(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(parsed) = Envelope::parse(&bytes) {
            prop_assert_eq!(parsed.encode().unwrap(), bytes);
        }
    }
}
