//! Production `Set-Cookie` storage and `Cookie` request-field construction.
//!
//! The harness, its structural seed, and its deterministic regressions live in
//! `phantom_fuzz::cookie_jar`, which documents the production functions this
//! target drives and the invariants it asserts.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    phantom_fuzz::cookie_jar::exercise(input);
});
