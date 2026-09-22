use std::num::NonZeroUsize;

use url::Url;

use super::{CookieError, CookieErrorKind, CookieJar, CookieLimits};

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
}

/// Returns the `Cookie` value a request to `url` sends, recording the use.
fn send(jar: &CookieJar, url: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    Ok(jar.request_value_for_url(&Url::parse(url)?))
}

/// Fills `https://one.test` with one `Secure` and five other cookies, an
/// unrelated `other.test` cookie, and returns the names of the one.test
/// cookies left after a seventh is stored under a per-domain limit of six.
fn domain_eviction_survivors(
    jar: &CookieJar,
    between: impl FnOnce(&CookieJar) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    let base = "https://one.test";
    jar.set_cookie(base, "secure=1; Secure; Path=/secure")?;
    for name in ["a", "b", "c", "d", "e"] {
        jar.set_cookie(base, &format!("{name}=1; Path=/{name}"))?;
    }
    jar.set_cookie("https://other.test/", "other=1")?;
    between(jar)?;

    // The seventh one.test cookie exceeds 6; one sixth is purged to leave 5.
    jar.set_cookie(base, "f=1; Path=/f")?;

    Ok(["secure", "a", "b", "c", "d", "e", "f"]
        .into_iter()
        .filter(|name| {
            jar.request_value(&format!("{base}/{name}"))
                .ok()
                .flatten()
                .is_some()
        })
        .collect())
}

#[test]
fn orders_longer_paths_before_creation_order() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    let url = "https://example.test/account/settings";
    jar.set_cookie(url, "first=1; Path=/")?;
    jar.set_cookie(url, "second=2; Path=/")?;
    jar.set_cookie(url, "deep=3; Path=/account")?;

    assert_eq!(
        jar.request_value(url)?.as_deref(),
        Some("deep=3; first=1; second=2")
    );
    Ok(())
}

#[test]
fn updating_cookie_retains_creation_position() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    let url = "https://example.test/";
    jar.set_cookie(url, "first=1; Path=/")?;
    jar.set_cookie(url, "second=2; Path=/")?;
    jar.set_cookie(url, "first=updated; Path=/")?;

    assert_eq!(
        jar.request_value(url)?.as_deref(),
        Some("first=updated; second=2")
    );
    Ok(())
}

#[test]
fn host_only_and_domain_cookies_have_distinct_storage_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    let url = "https://example.test/";
    jar.set_cookie(url, "sid=host; Path=/")?;
    jar.set_cookie(url, "sid=domain; Domain=example.test; Path=/")?;

    assert_eq!(
        jar.request_value(url)?.as_deref(),
        Some("sid=host; sid=domain")
    );
    assert_eq!(
        jar.request_value("https://sub.example.test/")?.as_deref(),
        Some("sid=domain")
    );
    Ok(())
}

#[test]
fn enforces_secure_prefix_same_site_none_and_partition_requirements() {
    let jar = CookieJar::default();

    for (url, value, kind) in [
        (
            "http://example.test/",
            "__Secure-id=1; Secure",
            CookieErrorKind::InvalidPrefix,
        ),
        (
            "https://example.test/",
            "__SeCuRe-id=1",
            CookieErrorKind::InvalidPrefix,
        ),
        (
            "https://example.test/",
            "__Host-id=1; Secure; Path=/; Domain=example.test",
            CookieErrorKind::InvalidPrefix,
        ),
        (
            "https://example.test/",
            "__hOsT-id=1; Secure; Path=/account",
            CookieErrorKind::InvalidPrefix,
        ),
        (
            "https://example.test/",
            "id=1; Partitioned",
            CookieErrorKind::UnsupportedPolicy,
        ),
        (
            "https://example.test/",
            "id=1; SameSite=None",
            CookieErrorKind::UnsupportedPolicy,
        ),
        (
            "http://example.test/",
            "id=1; SameSite=None; Secure",
            CookieErrorKind::UnsupportedPolicy,
        ),
    ] {
        let error = rejected(
            jar.set_cookie(url, value),
            "unsupported cookie was accepted",
        );
        assert_eq!(error.kind(), kind);
    }
}

#[test]
fn same_site_cookies_are_sent_as_top_level_navigation() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    let url = "https://example.test/";
    jar.set_cookie(url, "strict=1; SameSite=Strict")?;
    jar.set_cookie(url, "lax=2; SameSite=Lax")?;
    jar.set_cookie(url, "none=3; SameSite=None; Secure")?;
    jar.set_cookie("http://plain.test/", "plain_lax=4; SameSite=Lax")?;

    assert_eq!(
        jar.request_value(url)?.as_deref(),
        Some("strict=1; lax=2; none=3")
    );
    assert_eq!(
        jar.request_value("http://plain.test/")?.as_deref(),
        Some("plain_lax=4")
    );
    Ok(())
}

#[test]
fn partitioned_cookie_is_kept_apart_from_unpartitioned_cookie()
-> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    let url = "https://www.example.test/";
    jar.set_cookie(url, "id=plain; Secure; Domain=example.test")?;
    jar.set_cookie(url, "id=chips; Secure; Domain=example.test; Partitioned")?;

    assert_eq!(jar.len(), 2);
    assert_eq!(
        jar.request_value("https://api.example.test/")?.as_deref(),
        Some("id=plain; id=chips")
    );

    jar.set_cookie(
        url,
        "id=gone; Secure; Domain=example.test; Partitioned; Max-Age=0",
    )?;
    assert_eq!(jar.request_value(url)?.as_deref(), Some("id=plain"));
    Ok(())
}

#[test]
fn insecure_cookie_cannot_overlay_secure_cookie() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    jar.set_cookie(
        "https://login.example.test/account",
        "sid=good; Secure; Domain=example.test; Path=/account",
    )?;

    for (url, value) in [
        ("http://example.test/account", "sid=evil; Path=/account"),
        (
            "http://sub.example.test/account/details",
            "sid=evil; Path=/account/details",
        ),
    ] {
        let error = rejected(
            jar.set_cookie(url, value),
            "insecure cookie overlaid a secure cookie",
        );
        assert_eq!(error.kind(), CookieErrorKind::SecureOverlay);
    }

    jar.set_cookie("http://login.example.test/", "sid=root; Path=/")?;
    assert_eq!(
        jar.request_value("https://login.example.test/account")?
            .as_deref(),
        Some("sid=good; sid=root")
    );
    Ok(())
}

#[test]
fn rejects_public_suffix_but_accepts_identical_host_as_host_only()
-> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    let error = rejected(
        jar.set_cookie("https://example.com/", "id=1; Domain=com"),
        "public-suffix cookie was accepted",
    );
    assert_eq!(error.kind(), CookieErrorKind::PublicSuffix);

    jar.set_cookie("https://com/", "id=2; Domain=com")?;
    assert_eq!(jar.request_value("https://com/")?.as_deref(), Some("id=2"));
    assert_eq!(jar.request_value("https://example.com/")?.as_deref(), None);
    Ok(())
}

#[test]
fn unlisted_and_private_suffixes_cannot_receive_domain_cookies()
-> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    for (url, value) in [
        ("https://a.corp/", "id=1; Domain=corp"),
        ("https://a.corp/", "id=1; Domain=.corp"),
        ("https://intranet.lan/", "id=1; Domain=lan"),
        ("https://user.github.io/", "id=1; Domain=github.io"),
    ] {
        let error = rejected(
            jar.set_cookie(url, value),
            "suffix Domain cookie was accepted",
        );
        assert_eq!(error.kind(), CookieErrorKind::PublicSuffix);
    }

    jar.set_cookie("https://corp/", "exact=1; Domain=corp")?;
    jar.set_cookie("https://a.b.corp/", "site=2; Domain=b.corp")?;
    assert_eq!(
        jar.request_value("https://corp/")?.as_deref(),
        Some("exact=1")
    );
    assert_eq!(jar.request_value("https://a.corp/")?.as_deref(), None);
    assert_eq!(
        jar.request_value("https://c.b.corp/")?.as_deref(),
        Some("site=2")
    );
    Ok(())
}

#[test]
fn canonicalizes_cookie_domains_before_public_suffix_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    let error = rejected(
        jar.set_cookie("https://example.com/", "mixed=1; Domain=CoM"),
        "mixed-case public-suffix cookie was accepted",
    );
    assert_eq!(error.kind(), CookieErrorKind::PublicSuffix);

    jar.set_cookie("https://CoM/", "exact=1; Domain=CoM")?;
    assert_eq!(
        jar.request_value("https://com/")?.as_deref(),
        Some("exact=1")
    );
    assert_eq!(jar.request_value("https://example.com/")?.as_deref(), None);

    jar.set_cookie("https://bücher.example/", "idna=1; Domain=BÜCHER.EXAMPLE")?;
    assert_eq!(
        jar.request_value("https://xn--bcher-kva.example/")?
            .as_deref(),
        Some("idna=1")
    );
    assert_eq!(
        jar.request_value("https://sub.bücher.example/")?.as_deref(),
        Some("idna=1")
    );
    Ok(())
}

#[test]
fn trailing_dot_does_not_bypass_public_suffix_policy() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();

    for (url, value) in [
        ("https://example.com/", "plain=1; Domain=com."),
        ("https://example.com./", "dotted=1; Domain=com"),
    ] {
        let error = rejected(
            jar.set_cookie(url, value),
            "mismatched trailing-dot cookie was accepted",
        );
        assert_eq!(error.kind(), CookieErrorKind::InvalidSetCookie);
    }

    let error = rejected(
        jar.set_cookie("https://example.com./", "suffix=1; Domain=com."),
        "dot-terminated public-suffix cookie was accepted",
    );
    assert_eq!(error.kind(), CookieErrorKind::PublicSuffix);

    jar.set_cookie("https://com./", "exact=1; Domain=com.")?;
    assert_eq!(
        jar.request_value("https://com./")?.as_deref(),
        Some("exact=1")
    );
    assert_eq!(jar.request_value("https://example.com./")?.as_deref(), None);
    Ok(())
}

#[test]
fn secure_and_path_matching_follow_request_url() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    jar.set_cookie("https://example.test/private", "secure=1; Secure; Path=/")?;
    jar.set_cookie("https://example.test/private", "private=2; Path=/private")?;

    assert_eq!(
        jar.request_value("https://example.test/private/page")?
            .as_deref(),
        Some("private=2; secure=1")
    );
    assert_eq!(jar.request_value("http://example.test/")?.as_deref(), None);
    Ok(())
}

#[test]
fn domain_limit_evicts_least_recent_insecure_cookies_first()
-> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(64), nonzero(6), nonzero(100)));
    let retained = domain_eviction_survivors(&jar, |jar| {
        assert_eq!(send(jar, "https://one.test/a")?.as_deref(), Some("a=1"));
        Ok(())
    })?;

    assert_eq!(retained, ["secure", "a", "d", "e", "f"]);
    assert_eq!(
        jar.request_value("https://other.test/")?.as_deref(),
        Some("other=1")
    );
    Ok(())
}

#[test]
fn inspecting_the_jar_does_not_change_eviction_order() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(64), nonzero(6), nonzero(100)));
    let retained = domain_eviction_survivors(&jar, |jar| {
        assert_eq!(
            jar.request_value("https://one.test/a")?.as_deref(),
            Some("a=1")
        );
        Ok(())
    })?;

    assert_eq!(retained, ["secure", "c", "d", "e", "f"]);
    Ok(())
}

#[test]
fn total_limit_evicts_least_recent_cookies_across_domains() -> Result<(), Box<dyn std::error::Error>>
{
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(64), nonzero(100), nonzero(11)));
    for index in 0..11 {
        jar.set_cookie(&format!("https://site{index}.test/"), "flood=1")?;
    }
    assert_eq!(jar.len(), 11);

    jar.set_cookie("https://login.test/", "session=1")?;

    assert_eq!(jar.len(), 10);
    assert_eq!(jar.request_value("https://site0.test/")?, None);
    assert_eq!(jar.request_value("https://site1.test/")?, None);
    assert_eq!(
        jar.request_value("https://site2.test/")?.as_deref(),
        Some("flood=1")
    );
    assert_eq!(
        jar.request_value("https://login.test/")?.as_deref(),
        Some("session=1")
    );
    Ok(())
}

#[test]
fn each_ip_address_host_has_its_own_domain_limit() -> Result<(), Box<dyn std::error::Error>> {
    // Chromium's CookieMonster::GetKey falls back to the host when
    // GetDomainAndRegistry finds no registrable domain, which it never does
    // for an IP address. 10.0.0.1 and 10.1.0.1 share their last two labels.
    let hosts = ["10.0.0.1", "10.0.0.2", "10.1.0.1"];
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(64), nonzero(2), nonzero(100)));
    for host in hosts {
        jar.set_cookie(&format!("https://{host}/"), "a=1; Path=/a")?;
        jar.set_cookie(&format!("https://{host}/"), "b=1; Path=/b")?;
    }

    // A third 10.0.0.1 cookie exceeds that host's limit of 2 only.
    jar.set_cookie("https://10.0.0.1/", "c=1; Path=/c")?;

    assert_eq!(jar.len(), 6);
    let retained = hosts
        .into_iter()
        .flat_map(|host| ["a", "b", "c"].map(|name| format!("https://{host}/{name}")))
        .filter(|url| jar.request_value(url).ok().flatten().is_some())
        .collect::<Vec<_>>();
    assert_eq!(
        retained,
        [
            "https://10.0.0.1/b",
            "https://10.0.0.1/c",
            "https://10.0.0.2/a",
            "https://10.0.0.2/b",
            "https://10.1.0.1/a",
            "https://10.1.0.1/b",
        ]
    );
    Ok(())
}

#[test]
fn single_cookie_limit_keeps_the_newest_cookie() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(64), nonzero(1), nonzero(1)));
    jar.set_cookie("https://one.test/", "a=1")?;
    jar.set_cookie("https://one.test/", "b=2")?;
    jar.set_cookie("https://two.test/", "c=3")?;

    assert_eq!(jar.len(), 1);
    assert_eq!(jar.request_value("https://one.test/")?, None);
    assert_eq!(
        jar.request_value("https://two.test/")?.as_deref(),
        Some("c=3")
    );
    Ok(())
}

#[test]
fn oversized_cookie_is_rejected() {
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(32), nonzero(1), nonzero(2)));
    let error = rejected(
        jar.set_cookie("https://one.test/", &format!("a={}", "x".repeat(40))),
        "oversized cookie was accepted",
    );
    assert_eq!(error.kind(), CookieErrorKind::CookieTooLarge);
    assert!(jar.is_empty());
}

#[test]
fn expiry_is_a_successful_deletion_or_no_op() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    let url = "https://example.test/";

    jar.set_cookie(url, "absent=gone; Max-Age=0")?;
    assert!(jar.is_empty());

    jar.set_cookie(url, "present=value")?;
    jar.set_cookie(url, "present=gone; Max-Age=0")?;
    assert!(jar.is_empty());
    assert_eq!(jar.request_value(url)?, None);
    Ok(())
}

#[test]
fn secure_cookie_set_over_loopback_http_is_stored_and_sent_back()
-> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    jar.set_cookie("http://127.0.0.1:8080/", "sid=1; Secure")?;

    assert_eq!(
        jar.request_value("http://127.0.0.1:8080/")?.as_deref(),
        Some("sid=1")
    );
    // The port is not part of a cookie's identity, and a loopback origin is
    // trustworthy whatever the scheme.
    assert_eq!(
        jar.request_value("https://127.0.0.1:8443/")?.as_deref(),
        Some("sid=1")
    );
    Ok(())
}

#[test]
fn secure_cookie_set_over_public_http_is_still_rejected() {
    let jar = CookieJar::default();
    let error = rejected(
        jar.set_cookie("http://example.test/", "sid=1; Secure"),
        "Secure cookie from a public http origin was accepted",
    );
    assert_eq!(error.kind(), CookieErrorKind::UnsupportedPolicy);
    assert!(jar.is_empty());
}

#[test]
fn trustworthy_origins_are_loopback_addresses_and_localhost_names()
-> Result<(), Box<dyn std::error::Error>> {
    for url in [
        "http://localhost/",
        "http://localhost./",
        "http://LoCaLhOsT/",
        "http://app.localhost/",
        "http://deep.app.localhost./",
        "http://127.0.0.1/",
        "http://127.13.2.9/",
        "http://[::1]/",
    ] {
        let jar = CookieJar::default();
        jar.set_cookie(url, "sid=1; Secure")?;
        assert_eq!(
            jar.request_value(url)?.as_deref(),
            Some("sid=1"),
            "{url} should store and send a Secure cookie"
        );
    }

    for url in [
        "http://localhost.test/",
        "http://notlocalhost/",
        "http://xlocalhost/",
        "http://128.0.0.1/",
        // Only `::1` is loopback; an IPv4-mapped loopback address is not.
        "http://[::ffff:127.0.0.1]/",
    ] {
        let jar = CookieJar::default();
        let error = rejected(
            jar.set_cookie(url, "sid=1; Secure"),
            "Secure cookie from an untrustworthy origin was accepted",
        );
        assert_eq!(
            error.kind(),
            CookieErrorKind::UnsupportedPolicy,
            "{url} should not be trustworthy"
        );
    }
    Ok(())
}

#[test]
fn prefixed_cookies_accept_a_trustworthy_http_origin() -> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    jar.set_cookie("http://localhost/", "__Secure-id=1; Secure")?;
    jar.set_cookie("http://localhost/", "__Host-id=2; Secure; Path=/")?;

    assert_eq!(
        jar.request_value("http://localhost/")?.as_deref(),
        Some("__Secure-id=1; __Host-id=2")
    );

    for value in ["__Secure-id=1; Secure", "__Host-id=2; Secure; Path=/"] {
        let error = rejected(
            jar.set_cookie("http://example.test/", value),
            "prefixed cookie from a public http origin was accepted",
        );
        assert_eq!(error.kind(), CookieErrorKind::InvalidPrefix);
    }
    Ok(())
}

#[test]
fn same_site_none_and_partitioned_require_secure_not_https()
-> Result<(), Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    jar.set_cookie("http://127.0.0.1/", "none=1; SameSite=None; Secure")?;
    jar.set_cookie("http://127.0.0.1/", "chips=2; Secure; Partitioned")?;

    assert_eq!(
        jar.request_value("http://127.0.0.1/")?.as_deref(),
        Some("none=1; chips=2")
    );

    // The `Secure` attribute, not the scheme, is what these two demand, so a
    // trustworthy origin does not excuse its absence.
    for value in ["none=1; SameSite=None", "chips=2; Partitioned"] {
        let error = rejected(
            jar.set_cookie("http://127.0.0.1/", value),
            "insecure SameSite=None or Partitioned cookie was accepted",
        );
        assert_eq!(error.kind(), CookieErrorKind::UnsupportedPolicy);
    }
    Ok(())
}

#[test]
fn trustworthy_origin_may_overlay_its_own_secure_cookie() -> Result<(), Box<dyn std::error::Error>>
{
    let jar = CookieJar::default();
    jar.set_cookie("https://localhost/account", "sid=good; Secure; Path=/")?;
    jar.set_cookie("http://localhost/account", "sid=plain; Path=/")?;

    assert_eq!(
        jar.request_value("http://localhost/account")?.as_deref(),
        Some("sid=plain")
    );
    Ok(())
}

fn rejected(result: Result<(), CookieError>, message: &'static str) -> CookieError {
    match result {
        Ok(()) => panic!("{message}"),
        Err(error) => error,
    }
}
