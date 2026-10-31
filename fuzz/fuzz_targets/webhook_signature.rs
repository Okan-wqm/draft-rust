//! Owner: authn-audit (AUD-07). TST-04: Standard Webhooks signature header parsing and verification.
//!
//! Placeholder created by the architect so the harness builds from day one.
//! The owning agent replaces the body with a call into its parser, e.g.
//! `let _ = authn_audit::...::parse(data);`, plus invariants.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data;
});
