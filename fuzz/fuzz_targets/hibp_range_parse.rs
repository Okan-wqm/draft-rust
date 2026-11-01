//! Owner: authn-password (PWD-03). TST-04: parsing of HIBP Pwned Passwords
//! range responses and of the offline breach list.
//!
//! Registration in `fuzz/Cargo.toml` (`[[bin]] hibp_range_parse` and the
//! `authn-password` path dependency) is requested in
//! `docs/architecture/contract-change-requests.md` (authn-password).
//!
//! Invariants checked for every input:
//! * neither parser panics, whatever the bytes;
//! * a reported hit always has a count above zero (padding entries with
//!   count `0` are never hits);
//! * a suffix that is not 35 hex characters never matches.
#![no_main]

use authn_password::OfflineBreachList;
use authn_password::breach::{SUFFIX_LEN, lookup_in_range_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First line of the input is the suffix to look for, the rest is the body.
    let split = data.iter().position(|b| *b == b'\n').unwrap_or(data.len());
    let (suffix, body) = data.split_at(split);
    let suffix = String::from_utf8_lossy(suffix);
    if let Ok(Some(count)) = lookup_in_range_response(body, &suffix) {
        assert!(count > 0, "padding entry reported as a hit");
        assert_eq!(suffix.len(), SUFFIX_LEN);
        assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(list) = OfflineBreachList::parse(text)
    {
        assert!(list.len() <= text.lines().count());
    }
});
