//! Owner: authn-core (baseline) / authn-account (ACC-03). TST-04.
//! E-mail parsing must never panic and must be idempotent.
#![no_main]

use authn_core::domain::EmailAddress;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else { return };
    if let Ok(first) = EmailAddress::parse(input) {
        let second = EmailAddress::parse(first.as_str()).expect("canonical form re-parses");
        assert_eq!(first, second);
        assert!(first.normalized().len() <= 254);
    }
});
