//! Production cookie storage and request-field construction.
//!
//! The harness drives `phantom::CookieJar::set_cookie` and
//! `phantom::CookieJar::request_value` in
//! `crates/phantom/src/session/cookies.rs`. That is the jar a `Client` uses for
//! every response `Set-Cookie` field and every request `Cookie` field, so the
//! fuzzed bytes take the same storage and matching path a response cookie
//! takes. The one step above it is not covered: a real response reaches
//! `CookieJar::store_response_headers`, which converts `HeaderMap` bytes to
//! `&str`, and that conversion is why this harness must supply text.
//!
//! Three invariants are asserted, each of which a real confusion in attribute
//! parsing, origin gating, or domain matching would break:
//!
//! 1. Every field stored into `secure_jar` ends in `; Secure`, and `Secure`
//!    has no "off" spelling, so every cookie it holds is secure-only. No
//!    request to an origin that is not potentially trustworthy may therefore
//!    receive a `Cookie` field from it.
//! 2. The jar rejects a `Secure` cookie set by an origin that is not
//!    potentially trustworthy, so a jar that only ever received `; Secure`
//!    fields from such an origin must stay empty.
//! 3. A loopback or `localhost` authority is potentially trustworthy under
//!    either scheme, so the scheme must be invisible there in both
//!    directions: the same fields stored from `http://` and from `https://`
//!    leave the same number of cookies and produce the same `Cookie` field.
//!    See [`TRUSTWORTHY_URL_PAIRS`].
//!
//! Invariants 1 and 2 are asserted over named hosts, which no rule makes
//! trustworthy over `http://`. Invariant 3 guards the trustworthy-origin rule
//! in both directions, and fails whichever of the jar's two gates a change
//! inverts: a storage gate that refuses `http://` empties one jar, and a
//! matching gate that refuses it empties one `Cookie` field.

#[cfg(test)]
mod tests;

use phantom::CookieJar;

use crate::seed;

/// Secure origins used to store cookies and to read them back.
const SECURE_URLS: [&str; 2] = ["https://sub.example.com/a/b", "https://example.com/"];

/// Insecure origins for the same hosts and paths. A named host is never
/// potentially trustworthy over `http://`.
const INSECURE_URLS: [&str; 2] = ["http://sub.example.com/a/b", "http://example.com/"];

/// Authorities that are potentially trustworthy under either scheme, each as
/// an `[https, http]` pair that differs only in scheme and port. No cookie
/// rule reads the port.
///
/// Both pairs are needed, because the two gates fail on different hosts.
/// `cookie_store`'s own `utils::is_secure` accepts a loopback IP literal, so
/// the matching gate agrees there whatever the jar does, and the loopback pair
/// constrains only the storage gate. It accepts the exact host `localhost` and
/// nothing beneath it, so for a `.localhost` subdomain the `http://` request
/// sees a `Secure` cookie only through the jar's own trustworthy test, and the
/// `.localhost` pair constrains both gates.
const TRUSTWORTHY_URL_PAIRS: [[&str; 2]; 2] = [
    ["https://127.0.0.1:8443/a", "http://127.0.0.1:8080/a"],
    ["https://app.localhost/a", "http://app.localhost/a"],
];

/// `Set-Cookie` fields whose storage and retrieval must keep working.
///
/// `Partitioned` earns its place: its partition key is schemeful, so it is the
/// one attribute whose stored state differs between the two origins of a pair,
/// and invariant 3 holds only because each jar is read back over the scheme it
/// was filled from.
pub const VALID_SET_COOKIES: &[u8] =
    b"id=1; Path=/\nsession=abc; Domain=example.com; Max-Age=600\n__Host-h=v; Path=/; Secure\n__Secure-s=v; Secure; SameSite=None\npart=v; Path=/; Partitioned\nempty=";

/// Largest number of `Set-Cookie` fields one input applies to one jar.
const MAX_FIELDS: usize = 24;

/// Splits the input into newline-separated `Set-Cookie` field values.
///
/// A newline cannot occur inside a field value, so it separates fields
/// cleanly; non-UTF-8 bytes are replaced because the public API takes `&str`.
#[must_use]
pub fn fields(input: &[u8]) -> Vec<String> {
    input
        .split(|&byte| byte == b'\n')
        .take(MAX_FIELDS)
        .map(|field| String::from_utf8_lossy(field).into_owned())
        .collect()
}

/// Every origin the harness touches, including the trustworthy pairs.
fn every_url() -> impl Iterator<Item = &'static &'static str> {
    SECURE_URLS
        .iter()
        .chain(INSECURE_URLS.iter())
        .chain(TRUSTWORTHY_URL_PAIRS.iter().flatten())
}

/// Stores every field, marked `Secure`, from each URL in `origins`.
fn store_secure(jar: &CookieJar, origins: &[&str], fields: &[String]) {
    for origin in origins {
        for field in fields {
            let secure = format!("{field}; Secure");
            let _ = std::hint::black_box(jar.set_cookie(origin, &secure));
        }
    }
}

/// Applies one field set to fresh jars and checks all three origin invariants.
///
/// Returns whether any field was stored at all, which the regressions use to
/// prove the structural seeds still reach the jar.
pub fn drive(fields: &[String]) -> bool {
    let secure_jar = CookieJar::default();
    store_secure(&secure_jar, &SECURE_URLS, fields);
    for origin in INSECURE_URLS {
        let value = secure_jar
            .request_value(origin)
            .expect("a fixed origin URL must stay valid");
        assert!(
            value.is_none(),
            "a Secure cookie was offered to the untrustworthy origin {origin}"
        );
    }

    let rejected_jar = CookieJar::default();
    store_secure(&rejected_jar, &INSECURE_URLS, fields);
    assert!(
        rejected_jar.is_empty(),
        "an untrustworthy origin stored a Secure cookie"
    );

    // A trustworthy authority is trustworthy under either scheme, so the
    // scheme must change neither what is stored nor what is sent back. Each
    // jar is read over the scheme it was filled from, because a `Partitioned`
    // cookie's key is schemeful.
    for [over_https, over_http] in TRUSTWORTHY_URL_PAIRS {
        let https_jar = CookieJar::default();
        store_secure(&https_jar, &[over_https], fields);
        let http_jar = CookieJar::default();
        store_secure(&http_jar, &[over_http], fields);
        assert_eq!(
            http_jar.len(),
            https_jar.len(),
            "{over_http} and {over_https} stored different cookie counts"
        );
        assert_eq!(
            http_jar
                .request_value(over_http)
                .expect("a fixed origin URL must stay valid"),
            https_jar
                .request_value(over_https)
                .expect("a fixed origin URL must stay valid"),
            "the Cookie field for {over_http} depended on its scheme"
        );
    }

    // Unmarked fields exercise the ordinary storage, matching, eviction, and
    // request-field paths without constraining the outcome.
    let jar = CookieJar::default();
    let mut stored = false;
    for origin in every_url() {
        for field in fields {
            stored |= jar.set_cookie(origin, field).is_ok();
        }
    }
    for origin in every_url() {
        let _ = std::hint::black_box(jar.request_value(origin));
    }
    let _ = std::hint::black_box(jar.len());
    jar.clear();
    stored
}

/// Drives the raw input and the perturbed structural seed.
pub fn exercise(input: &[u8]) {
    let _ = drive(&fields(input));
    let _ = drive(&fields(&seed::perturb(VALID_SET_COOKIES, input)));
}
