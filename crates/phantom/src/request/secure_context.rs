//! The W3C Secure Contexts test browsers apply to a request URL.

use url::{Host, Url};

/// Returns whether `url` is a potentially trustworthy origin.
///
/// This is W3C Secure Contexts' "Is origin potentially trustworthy?" for the
/// `http` and `https` URLs a request can have: an `https` scheme, a loopback
/// IP literal (`127.0.0.0/8` or exactly `::1`), or the host `localhost` or a
/// `.localhost` name, ignoring one trailing dot and ASCII case.
///
/// Chromium 154 answers the same for these URLs in
/// `net::IsOriginPotentiallyTrustworthy`
/// (`net/base/is_potentially_trustworthy.cc` lines 294-346 at tag
/// `154.0.8037.58`), whose loopback and `localhost` step is `net::IsLocalhost`
/// (`net/base/url_util.cc` lines 468-477 and 582-589); its remaining steps
/// cover `file`, other authenticated schemes, and a command-line allowlist
/// that a request URL cannot reach. Firefox 156 answers the same in
/// `nsMixedContentBlocker::IsPotentiallyTrustworthyOrigin`
/// (`dom/security/nsMixedContentBlocker.cpp` lines 221-248 and 294-362 at
/// `FIREFOX_156_0_RELEASE`), apart from its off-by-default `.onion` and
/// host allowlist preferences.
///
/// Chromium sends client hints and `Sec-Fetch-*` fields, and both browsers
/// offer `br` and `zstd`, only to such an origin. The cookie jar uses the
/// same test for `Secure` cookies.
pub(crate) fn is_potentially_trustworthy(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(host)) => is_localhost_name(host),
        None => false,
    }
}

fn is_localhost_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .len()
            .checked_sub(".localhost".len())
            .and_then(|start| host.get(start..))
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".localhost"))
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::is_potentially_trustworthy;

    #[test]
    fn follows_the_secure_contexts_host_rules() -> Result<(), url::ParseError> {
        for (url, trustworthy) in [
            ("https://example.test/", true),
            ("http://127.0.0.1/", true),
            ("http://127.255.0.9:8080/", true),
            ("http://[::1]/", true),
            ("http://localhost/", true),
            ("http://LOCALHOST./", true),
            ("http://app.localhost/", true),
            ("http://app.localhost./", true),
            ("http://origin.phantom.test/", false),
            ("http://128.0.0.1/", false),
            ("http://[::ffff:127.0.0.1]/", false),
            ("http://localhost.example/", false),
            ("http://notlocalhost/", false),
            ("http://192.168.1.1/", false),
        ] {
            assert_eq!(
                is_potentially_trustworthy(&Url::parse(url)?),
                trustworthy,
                "{url}"
            );
        }
        Ok(())
    }
}
