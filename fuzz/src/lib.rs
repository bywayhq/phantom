//! Harnesses for Phantom's production parser fuzz targets.
//!
//! Each module owns one target's harness, its structural seeds, and the
//! deterministic regressions that pin the seeds down. The binaries under
//! `fuzz_targets/` are thin wrappers, so `cargo test` covers exactly the code
//! libFuzzer drives, and a seed that stops parsing fails a test instead of
//! silently weakening every fuzz iteration.

pub mod alt_svc_snapshot;
pub mod cookie_jar;
pub mod http1_response;
pub mod seed;
