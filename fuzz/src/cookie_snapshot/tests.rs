//! Deterministic regressions for the cookie snapshot harness.

use std::time::SystemTime;

use phantom::CookieSourceScheme;

use super::{VALID_ENTRIES, drive, entries};

/// The embedded seed must keep importing. A seed that stopped validating
/// would leave the fuzz target perturbing entries that import rejects
/// before the expiry, partition-key, and prefix rules are reached.
#[test]
fn structural_seeds_import() {
    assert!(drive(VALID_ENTRIES), "the structural seed was rejected");
}

/// The seed's record grammar must keep producing the entries it describes;
/// a separator or flag change would silently turn every entry into another.
#[test]
fn structural_seeds_decode_to_the_described_entries() {
    let decoded = entries(VALID_ENTRIES, SystemTime::now());
    assert_eq!(decoded.len(), 4, "the seed must describe four entries");
    assert_eq!(decoded[0].name(), "id");
    assert!(decoded[0].host_only());
    assert_eq!(decoded[1].path(), "/app");
    assert!(!decoded[1].host_only() && decoded[1].expires_at().is_some());
    assert_eq!(decoded[2].partition_key(), Some("https://shop.example"));
    assert!(decoded[2].secure() && decoded[2].http_only());
    assert_eq!(decoded[3].source_scheme(), CookieSourceScheme::Http);
    assert!(decoded[3].secure());
}

/// A `Secure` cookie from a plain `http://` named host is refused, so the
/// harness's rejection branch is reachable.
#[test]
fn secure_cookie_from_an_untrustworthy_http_origin_is_rejected() {
    assert!(!drive(b"\x06\tsid\tv\texample.com\t/\t\t\x00"));
}
