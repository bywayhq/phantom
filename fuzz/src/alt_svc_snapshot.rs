//! Revalidation of caller-persisted Alt-Svc alternatives.
//!
//! The harness drives `phantom::Client::import_alt_svc`, which is
//! `AltSvcStore::import` in `crates/phantom/src/session/alt_svc/snapshot.rs`.
//! That is the production entry point a caller feeds with snapshot state it
//! persisted itself, so the origin, host, port, and expiry of every entry
//! reach the real `parse_origin` and `parse_alternative` revalidation, the
//! expiry clamp, the duplicate-origin rule, and the capacity-bounded store.
//!
//! When an import is accepted, the exported snapshot is imported again. Only
//! the origin half of that round trip is a real cross-check, between
//! `OriginKey::serialize` and the `canonical_origin` form `parse_origin`
//! accepts. The alternative half cannot fail by construction: export re-emits
//! the stored host verbatim and `parse_alternative` already required that host
//! to equal its own canonical form. The round trip is safe from expiry races
//! because `import` skips an expired entry rather than rejecting the snapshot.
//!
//! Alt-Svc is a facade policy; the Alt-Svc *field* parser that reads a peer's
//! `Alt-Svc` response field has no public entry point and is not covered here.

#[cfg(test)]
mod tests;

use std::{
    num::NonZeroUsize,
    sync::OnceLock,
    time::{Duration, SystemTime},
};

use phantom::{
    AltSvcSnapshot, AltSvcSnapshotEntry, Client,
    profile::{ClientProfile, Http3ClientSettings, chromium},
};

use crate::seed;

/// Tab-separated `origin`, alternative host, and a port-and-lifetime seed, one
/// record per line. The seed's first two bytes are the port and its third byte
/// is the lifetime in seconds.
pub const VALID_ENTRIES: &[u8] =
    b"https://example.com\talt.example.com\t\x01\xbb\x3c\nhttps://other.example:8443\t2001:db8::1\t\x10\x01\x78";

/// Largest number of snapshot entries one input builds.
const MAX_ENTRIES: usize = 64;

/// Store capacity; small enough that the capacity and eviction rules are hit.
const ORIGIN_CAPACITY: usize = 8;

/// A client with Alt-Svc enabled, built once.
///
/// Building one needs negotiated HTTP/1.1+HTTP/2 and HTTP/3 profiles and real
/// TLS contexts, so it is far more expensive than one import. The store is
/// cleared before every import, so each input still sees an empty store.
///
/// Every failure here panics rather than returning: a harness that skipped its
/// work would report a green run while testing nothing.
fn client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let http3 = Http3ClientSettings::new(
            chromium::v152_http3_tls(),
            chromium::v152_quic(),
            chromium::v152_http3(),
            chromium::v152_http3_request(),
        );
        let profile = ClientProfile::new(chromium::v152_tls())
            .with_http2(chromium::v152_http2())
            .with_http3(http3);
        let capacity = NonZeroUsize::new(ORIGIN_CAPACITY).expect("a non-zero store capacity");
        Client::builder(profile)
            .alt_svc(capacity)
            .build()
            .expect("an Alt-Svc client must build")
    })
}

fn text(field: &[u8]) -> String {
    String::from_utf8_lossy(field).into_owned()
}

/// Builds snapshot entries from tab-separated records, one per line.
#[must_use]
pub fn entries(input: &[u8], now: SystemTime) -> Vec<AltSvcSnapshotEntry> {
    input
        .split(|&byte| byte == b'\n')
        .take(MAX_ENTRIES)
        .map(|record| {
            let mut fields = record.split(|&byte| byte == b'\t');
            let origin = text(fields.next().unwrap_or_default());
            let host = text(fields.next().unwrap_or_default());
            let seed = fields.next().unwrap_or_default();
            let port = u16::from_be_bytes([
                seed.first().copied().unwrap_or(0x01),
                seed.get(1).copied().unwrap_or(0xbb),
            ]);
            let lifetime = Duration::from_secs(u64::from(seed.get(2).copied().unwrap_or(60)));
            AltSvcSnapshotEntry::new(origin, host, port, now + lifetime)
        })
        .collect()
}

/// Imports one snapshot into a freshly cleared store and reports acceptance.
pub fn drive(encoded: &[u8]) -> bool {
    let client = client();
    client.clear_alt_svc();
    let snapshot = AltSvcSnapshot::new(entries(encoded, SystemTime::now()));
    if std::hint::black_box(client.import_alt_svc(&snapshot)).is_err() {
        return false;
    }
    let exported = client
        .export_alt_svc()
        .expect("Alt-Svc is enabled on this client");
    client
        .import_alt_svc(&exported)
        .expect("an exported snapshot must pass import revalidation");
    true
}

/// Drives the raw input and the perturbed structural seed.
pub fn exercise(input: &[u8]) {
    let _ = drive(input);
    let _ = drive(&seed::perturb(VALID_ENTRIES, input));
}
