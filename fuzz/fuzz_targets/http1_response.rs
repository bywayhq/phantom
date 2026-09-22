//! Production HTTP/1.1 response heads and bodies.
//!
//! The harness, its structural seeds, and its deterministic regressions live
//! in `phantom_fuzz::http1_response`, which documents the production functions
//! this target drives.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    phantom_fuzz::http1_response::exercise(input);
});
