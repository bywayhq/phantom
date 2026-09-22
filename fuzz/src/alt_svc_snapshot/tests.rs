//! Deterministic regressions for the Alt-Svc snapshot harness.

use std::time::SystemTime;

use super::{VALID_ENTRIES, drive, entries};

/// The embedded seed must keep importing. A seed that stopped validating would
/// leave the fuzz target perturbing entries that the store rejects before it
/// ever reaches the expiry, duplicate-origin, and capacity rules.
#[test]
fn structural_seeds_import() {
    assert!(drive(VALID_ENTRIES), "the structural seed was rejected");
}

/// The seed's record grammar must keep producing the entries it describes; a
/// separator change would silently collapse every record into one.
#[test]
fn structural_seeds_decode_to_distinct_origins() {
    let decoded = entries(VALID_ENTRIES, SystemTime::now());
    assert_eq!(decoded.len(), 2, "the seed must describe two entries");
    assert_eq!(decoded[0].origin(), "https://example.com");
    assert_eq!(decoded[0].alternative_host(), "alt.example.com");
    assert_eq!(decoded[0].alternative_port(), 443);
    assert_eq!(decoded[1].origin(), "https://other.example:8443");
}
