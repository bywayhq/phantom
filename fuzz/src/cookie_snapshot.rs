//! Revalidation of caller-persisted cookie snapshots.
//!
//! The harness drives `phantom::Client::import_cookies`, which is
//! `CookieJar::import` in `crates/phantom/src/session/cookies.rs` with the
//! entry revalidation in `crates/phantom/src/session/cookies/snapshot.rs`.
//! That is the production entry point a caller feeds with cookie state it
//! persisted itself, so every name, value, domain, path, attribute, partition
//! key, and expiry reaches the same `Set-Cookie` rules a response cookie
//! meets.
//!
//! Three invariants are asserted:
//!
//! 1. A rejected snapshot leaves the jar unchanged; the jar is cleared
//!    before each import, so it must stay empty.
//! 2. No stored cookie is `Secure` with an `http` source scheme unless its
//!    host is potentially trustworthy (loopback or `localhost`), because a
//!    response from any other `http://` origin cannot store one.
//! 3. A snapshot the client exported passes the client's own import again
//!    and yields the same number of cookies.

#[cfg(test)]
mod tests;

use std::{
    net::Ipv4Addr,
    sync::OnceLock,
    time::{Duration, SystemTime},
};

use phantom::{
    Client, CookieSameSite, CookieSnapshot, CookieSnapshotEntry, CookieSourceScheme,
    profile::{ClientProfile, chromium},
};

use crate::seed;

/// Tab-separated flags, name, value, domain, path, partition key, and
/// lifetime, one entry per line. See [`entries`] for the flag bits.
pub const VALID_ENTRIES: &[u8] = b"\x03\tid\t1\texample.com\t/\t\t\x00\n\
\x05\tsid\tabc\texample.com\t/app\t\t\x3c\n\
\x4f\tpart\tv\tshop.example\t/\thttps://shop.example\t\x00\n\
\x06\tlocal\tv\tapp.localhost\t/\t\t\x00";

/// Largest number of snapshot entries one input builds.
const MAX_ENTRIES: usize = 32;

/// A client with a default cookie jar, built once. The jar is cleared before
/// every import, so each input still sees an empty jar.
///
/// A failure here panics rather than returning: a harness that skipped its
/// work would report a green run while testing nothing.
fn client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        Client::builder(ClientProfile::new(chromium::v154_tls()))
            .cookies()
            .build()
            .expect("a cookie client must build")
    })
}

fn text(field: &[u8]) -> String {
    String::from_utf8_lossy(field).into_owned()
}

/// Builds snapshot entries from tab-separated records, one per line.
///
/// The flags byte's bits are: 0 `https` source scheme, 1 host-only, 2
/// `Secure`, 3 `HttpOnly`, 4 and 5 `SameSite` (none, `Strict`, `Lax`,
/// `None`), and 6 a partition key taken from the sixth field. A lifetime of
/// zero seconds makes a session cookie.
#[must_use]
pub fn entries(input: &[u8], now: SystemTime) -> Vec<CookieSnapshotEntry> {
    input
        .split(|&byte| byte == b'\n')
        .take(MAX_ENTRIES)
        .map(|record| {
            let mut fields = record.split(|&byte| byte == b'\t');
            let flags = fields
                .next()
                .and_then(|flags| flags.first().copied())
                .unwrap_or(0x03);
            let scheme = if flags & 0x01 == 0 {
                CookieSourceScheme::Http
            } else {
                CookieSourceScheme::Https
            };
            let name = text(fields.next().unwrap_or_default());
            let value = text(fields.next().unwrap_or_default());
            let domain = text(fields.next().unwrap_or_default());
            let path = text(fields.next().unwrap_or_default());
            let partition = text(fields.next().unwrap_or_default());
            let lifetime = fields
                .next()
                .and_then(|lifetime| lifetime.first().copied())
                .unwrap_or(0);
            let mut entry = CookieSnapshotEntry::new(scheme, name, value, domain, path)
                .with_host_only(flags & 0x02 != 0)
                .with_secure(flags & 0x04 != 0)
                .with_http_only(flags & 0x08 != 0);
            entry = match (flags >> 4) & 0x03 {
                1 => entry.with_same_site(CookieSameSite::Strict),
                2 => entry.with_same_site(CookieSameSite::Lax),
                3 => entry.with_same_site(CookieSameSite::None),
                _ => entry,
            };
            if flags & 0x40 != 0 {
                entry = entry.with_partition_key(partition);
            }
            if lifetime != 0 {
                entry = entry.with_expires_at(now + Duration::from_secs(u64::from(lifetime)));
            }
            entry
        })
        .collect()
}

/// Returns whether `domain` names a host that is potentially trustworthy
/// under either scheme: a loopback address or a `localhost` name.
fn trustworthy(domain: &str) -> bool {
    domain == "localhost"
        || domain.ends_with(".localhost")
        || domain == "[::1]"
        || domain
            .parse::<Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Exports the jar and checks invariant 2 on every stored cookie.
fn export_checked(client: &Client) -> CookieSnapshot {
    let exported = client
        .export_cookies()
        .expect("cookies are enabled on this client");
    for entry in exported.entries() {
        assert!(
            !entry.secure()
                || entry.source_scheme() == CookieSourceScheme::Https
                || trustworthy(entry.domain()),
            "an http:// origin that is not trustworthy stored a Secure cookie"
        );
    }
    exported
}

/// Imports one snapshot into a freshly cleared jar and reports acceptance.
pub fn drive(encoded: &[u8]) -> bool {
    let client = client();
    let jar = client
        .cookie_jar()
        .expect("cookies are enabled on this client");
    jar.clear();
    let snapshot = CookieSnapshot::new(entries(encoded, SystemTime::now()));
    if std::hint::black_box(client.import_cookies(&snapshot)).is_err() {
        assert!(jar.is_empty(), "a rejected snapshot changed the jar");
        return false;
    }
    let exported = export_checked(client);
    jar.clear();
    client
        .import_cookies(&exported)
        .expect("an exported snapshot must pass import revalidation");
    assert_eq!(
        export_checked(client).len(),
        exported.len(),
        "re-importing an export changed the cookie count"
    );
    true
}

/// Drives the raw input and the perturbed structural seed.
pub fn exercise(input: &[u8]) {
    let _ = drive(input);
    let _ = drive(&seed::perturb(VALID_ENTRIES, input));
}
