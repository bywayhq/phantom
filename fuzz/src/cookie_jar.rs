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
//! Two invariants are asserted, both of which a real confusion in attribute
//! parsing, scheme gating, or domain matching would break:
//!
//! 1. Every field stored into `secure_jar` ends in `; Secure`, and `Secure`
//!    has no "off" spelling, so every cookie it holds is secure-only. No
//!    `http://` request may therefore receive a `Cookie` field from it.
//! 2. The jar documents that it rejects a `Secure` cookie set by an `http://`
//!    URL, so a jar that only ever received `; Secure` fields over `http://`
//!    must stay empty.
//!
//! Both invariants exclude loopback authorities, where the jar's two scheme
//! rules already disagree; see [`LOOPBACK_URLS`].

#[cfg(test)]
mod tests;

use phantom::CookieJar;

use crate::seed;

/// Secure origins used to store cookies and to read them back.
const SECURE_URLS: [&str; 2] = ["https://sub.example.com/a/b", "https://example.com/"];

/// Insecure origins for the same hosts and paths.
const INSECURE_URLS: [&str; 2] = ["http://sub.example.com/a/b", "http://example.com/"];

/// Loopback origins, which the asserted invariants deliberately exclude.
///
/// The jar's store treats a loopback authority as a trustworthy origin and
/// sends `Secure` cookies to `http://127.0.0.1`, while the jar's own storage
/// gate requires the `https` scheme literally. The two rules disagree, so
/// loopback URLs only add coverage here and constrain nothing.
const LOOPBACK_URLS: [&str; 2] = ["https://127.0.0.1:8443/a", "http://127.0.0.1:8080/a"];

/// `Set-Cookie` fields whose storage and retrieval must keep working.
pub const VALID_SET_COOKIES: &[u8] =
    b"id=1; Path=/\nsession=abc; Domain=example.com; Max-Age=600\n__Host-h=v; Path=/; Secure\n__Secure-s=v; Secure; SameSite=None\nempty=";

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

/// Every origin the harness touches, including the loopback ones.
fn every_url() -> impl Iterator<Item = &'static &'static str> {
    SECURE_URLS
        .iter()
        .chain(INSECURE_URLS.iter())
        .chain(LOOPBACK_URLS.iter())
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

/// Applies one field set to fresh jars and checks both scheme invariants.
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
            "a Secure cookie was offered to an http:// request for {origin}"
        );
    }

    let rejected_jar = CookieJar::default();
    store_secure(&rejected_jar, &INSECURE_URLS, fields);
    assert!(
        rejected_jar.is_empty(),
        "an http:// URL stored a Secure cookie"
    );

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
