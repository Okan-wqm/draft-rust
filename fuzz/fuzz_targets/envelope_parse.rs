//! Owner: authn-crypto (CRY-08). TST-04: encrypted envelope
//! (version || kek_id || wrapped DEK || nonce || ciphertext) parsing and
//! authenticated opening.
//!
//! Invariants: the parser never panics; whatever it accepts re-encodes to
//! the identical bytes; opening attacker-supplied bytes never succeeds.
#![no_main]

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};

use authn_crypto::envelope::{EnvKeyProvider, Envelope, EnvelopeCipher, EnvelopeContext, KekId};
use authn_crypto::secret::SecretKey;
use libfuzzer_sys::fuzz_target;

fn cipher() -> &'static EnvelopeCipher {
    static CIPHER: OnceLock<EnvelopeCipher> = OnceLock::new();
    CIPHER.get_or_init(|| {
        let provider = EnvKeyProvider::new(
            "k",
            [(KekId::new("k").expect("kek id"), SecretKey::from_bytes([3; 32]))],
        )
        .expect("provider");
        EnvelopeCipher::new(Arc::new(provider))
    })
}

/// The environment provider never suspends, so one poll completes.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("EnvKeyProvider futures complete immediately"),
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = Envelope::parse(data) {
        assert_eq!(parsed.encode().expect("re-encode"), data);
        assert!(parsed.plaintext_len() <= authn_crypto::envelope::MAX_PLAINTEXT_LEN);
    }
    let context = EnvelopeContext::new("fuzz", "data", "row").expect("context");
    assert!(ready(cipher().open(data, &context)).is_err());
    let _ = cipher().needs_rewrap(data);
});
