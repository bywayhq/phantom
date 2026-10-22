//! Incremental SSE decoding, chunk boundaries, and encoded-byte limits.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    phantom_fuzz::sse::exercise(input);
});
