//! Deterministic regressions for the cookie-jar harness.

use super::{VALID_SET_COOKIES, drive, fields};

/// The embedded seed must keep reaching the jar. A seed that stopped storing
/// would leave the fuzz target asserting its origin invariants over an empty
/// jar, where they hold trivially.
#[test]
fn structural_seeds_store_cookies() {
    assert!(
        drive(&fields(VALID_SET_COOKIES)),
        "no structural seed field was stored"
    );
}

/// The seed covers the attribute shapes the origin rules turn on, so a change
/// that dropped one from the seed would quietly narrow the fuzzed surface.
/// `Partitioned` is the one whose stored state is schemeful.
#[test]
fn structural_seeds_cover_the_guarded_attributes() {
    let seed = fields(VALID_SET_COOKIES);
    for attribute in [
        "Path=/",
        "Domain=",
        "Max-Age=",
        "__Host-",
        "__Secure-",
        "Partitioned",
    ] {
        assert!(
            seed.iter().any(|field| field.contains(attribute)),
            "no structural seed field carries {attribute}"
        );
    }
}
