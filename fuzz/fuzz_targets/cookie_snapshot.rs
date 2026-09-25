//! Revalidation of caller-persisted cookie snapshots.
//!
//! The harness, its structural seed, and its deterministic regressions live in
//! `phantom_fuzz::cookie_snapshot`, which documents the production function
//! this target drives and the invariants it asserts.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    phantom_fuzz::cookie_snapshot::exercise(input);
});
