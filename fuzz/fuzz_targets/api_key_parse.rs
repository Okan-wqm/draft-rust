//! Owner: authn-org (ORG-08). TST-04: API key format and CRC32 checksum parsing.
//!
//! Placeholder created by the architect so the harness builds from day one.
//! The owning agent replaces the body with a call into its parser, e.g.
//! `let _ = authn_org::...::parse(data);`, plus invariants.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data;
});
