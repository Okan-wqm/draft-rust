//! Owner: authn-protect (PRT-10). TST-04: return_to / redirect_uri validation.
//!
//! Placeholder created by the architect so the harness builds from day one.
//! The owning agent replaces the body with a call into its parser, e.g.
//! `let _ = authn_protect::...::parse(data);`, plus invariants.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data;
});
