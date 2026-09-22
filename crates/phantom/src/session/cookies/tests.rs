use std::num::NonZeroUsize;

use super::{CookieError, CookieErrorKind, CookieJar, CookieLimits};

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
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
fn enforces_secure_prefix_and_partition_boundaries() {
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
            "id=1; Secure; Partitioned",
            CookieErrorKind::UnsupportedPolicy,
        ),
        (
            "https://example.test/",
            "id=1; SameSite=None",
            CookieErrorKind::UnsupportedPolicy,
        ),
        (
            "https://example.test/",
            "id=1; SameSite=Strict",
            CookieErrorKind::UnsupportedPolicy,
        ),
        (
            "https://example.test/",
            "id=1; SameSite=Lax",
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
fn count_and_byte_limits_are_applied_without_evicting() -> Result<(), Box<dyn std::error::Error>> {
    let limits = CookieLimits::new(nonzero(32), nonzero(1), nonzero(2));
    let jar = CookieJar::with_limits(limits);
    jar.set_cookie("https://one.test/", "a=1")?;

    let domain_error = rejected(
        jar.set_cookie("https://one.test/", "b=2"),
        "per-domain capacity was exceeded",
    );
    assert_eq!(domain_error.kind(), CookieErrorKind::Capacity);

    jar.set_cookie("https://two.test/", "b=2")?;
    let total_error = rejected(
        jar.set_cookie("https://three.test/", "c=3"),
        "total capacity was exceeded",
    );
    assert_eq!(total_error.kind(), CookieErrorKind::Capacity);

    let size_error = rejected(
        jar.set_cookie("https://one.test/", &format!("a={}", "x".repeat(40))),
        "oversized cookie was accepted",
    );
    assert_eq!(size_error.kind(), CookieErrorKind::CookieTooLarge);
    assert_eq!(jar.len(), 2);
    Ok(())
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

fn rejected(result: Result<(), CookieError>, message: &'static str) -> CookieError {
    match result {
        Ok(()) => panic!("{message}"),
        Err(error) => error,
    }
}
