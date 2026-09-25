//! HTTPS DNS record extraction and RDATA parsing.
//!
//! The harness, its structural seed, and its deterministic regressions live in
//! `phantom_fuzz::https_record`, which documents the production functions this
//! target drives and the invariants it asserts.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    phantom_fuzz::https_record::exercise(input);
});
