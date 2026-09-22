//! Revalidation of caller-persisted Alt-Svc alternatives.
//!
//! The harness, its structural seed, and its deterministic regressions live in
//! `phantom_fuzz::alt_svc_snapshot`, which documents the production function
//! this target drives and the invariant it asserts.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    phantom_fuzz::alt_svc_snapshot::exercise(input);
});
