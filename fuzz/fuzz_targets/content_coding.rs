//! Production content-coding fields, chained decoding and decoded-byte limits.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    phantom_fuzz::content_coding::exercise(input);
});
