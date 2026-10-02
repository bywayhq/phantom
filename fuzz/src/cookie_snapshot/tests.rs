//! Deterministic regressions for the cookie snapshot harness.

use std::time::{Duration, SystemTime};

use phantom::CookieSourceScheme;

use super::{VALID_ENTRIES, drive, entries};
use crate::seed;

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

/// A CI input that merges the seed's third and fourth records into a
/// `Partitioned` entry whose lifetime byte is 1, with the rest of the fourth
/// record left in fields the decoder ignores.
const ONE_UNIT_LIFETIME: &[u8] =
    b"\x63\x01\x00\x00\x00\x00\x00\x00\x00\x0b..\x00\x00\x00\x00\x00\x00\x00";

/// The perturbed seed imports and round-trips. With lifetimes in seconds its
/// `Partitioned` entry could expire between the export and the second
/// import, which drops it, and the run then failed invariant 3.
#[test]
fn entry_with_the_shortest_lifetime_round_trips() {
    assert!(drive(&seed::perturb(VALID_ENTRIES, ONE_UNIT_LIFETIME)));
}

/// No decoded entry may expire within a run: invariant 3 compares two
/// imports made at different instants, and import drops an expired entry.
#[test]
fn shortest_decoded_lifetime_outlasts_any_run() {
    let now = SystemTime::now();
    let decoded = entries(&seed::perturb(VALID_ENTRIES, ONE_UNIT_LIFETIME), now);
    let shortest = decoded
        .iter()
        .filter_map(|entry| entry.expires_at()?.duration_since(now).ok())
        .min();
    assert_eq!(shortest, Some(Duration::from_secs(60 * 60)));
}
