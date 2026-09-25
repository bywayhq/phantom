//! `ECHConfigList` parsing.
//!
//! The harness, its structural seed, and its deterministic regressions live in
//! `phantom_fuzz::ech_config_list`, which documents the production function
//! this target drives and the invariants it asserts.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    phantom_fuzz::ech_config_list::exercise(input);
});
