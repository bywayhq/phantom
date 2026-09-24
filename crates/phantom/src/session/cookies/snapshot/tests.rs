use std::{
    num::NonZeroUsize,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{
    CookieJar, CookieLimits, CookieSameSite, CookieSnapshot, CookieSnapshotEntry,
    CookieSnapshotErrorKind, CookieSourceScheme,
};
use crate::{
    Client,
    profile::{ClientProfile, chromium},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HOUR: Duration = Duration::from_secs(60 * 60);

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
}

fn https(name: &str, domain: &str) -> CookieSnapshotEntry {
    CookieSnapshotEntry::new(CookieSourceScheme::Https, name, "1", domain, "/")
}

fn rejection(
    jar: &CookieJar,
    entries: Vec<CookieSnapshotEntry>,
) -> Option<(CookieSnapshotErrorKind, Option<usize>)> {
    jar.import(&CookieSnapshot::new(entries))
        .err()
        .map(|error| (error.kind(), error.entry_index()))
}

fn names(snapshot: &CookieSnapshot) -> Vec<&str> {
    snapshot
        .entries()
        .iter()
        .map(CookieSnapshotEntry::name)
        .collect()
}

/// Fills a jar with cookies that exercise every exported attribute.
fn populated_jar() -> Result<CookieJar, Box<dyn std::error::Error>> {
    let jar = CookieJar::default();
    jar.set_cookie(
        "https://www.example.com/account",
        "sid=abc; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Path=/account",
    )?;
    jar.set_cookie(
        "https://www.example.com/",
        "pref=dark; Domain=example.com; SameSite=Lax; Expires=Wed, 01 Jan 2200 00:00:00 GMT",
    )?;
    jar.set_cookie(
        "https://shop.example.org/",
        "__Host-cart=7; Secure; Path=/; SameSite=None; Partitioned",
    )?;
    jar.set_cookie("http://plain.test/docs/page", "visit=1")?;
    jar.set_cookie("http://localhost:8080/", "__Secure-dev=1; Secure; Path=/")?;
    jar.set_cookie(
        "http://app.localhost/",
        "local=1; Secure; SameSite=None; Partitioned; Path=/",
    )?;
    Ok(jar)
}

#[test]
fn round_trip_preserves_every_attribute_and_partition_key() -> TestResult {
    let original = populated_jar()?;
    let snapshot = original.export();
    assert_eq!(
        names(&snapshot),
        [
            "sid",
            "pref",
            "__Host-cart",
            "visit",
            "__Secure-dev",
            "local"
        ]
    );

    let [sid, pref, cart, visit, dev, local] = snapshot.entries() else {
        return Err("expected six exported cookies".into());
    };
    assert_eq!(
        (sid.domain(), sid.host_only(), sid.path()),
        ("www.example.com", true, "/account")
    );
    assert!(sid.secure() && sid.http_only());
    assert_eq!(sid.same_site(), Some(CookieSameSite::Strict));
    assert_eq!(sid.source_scheme(), CookieSourceScheme::Https);
    assert!(
        sid.expires_at()
            .is_some_and(|expiry| expiry > SystemTime::now())
    );
    assert_eq!((pref.domain(), pref.host_only()), ("example.com", false));
    assert_eq!(pref.same_site(), Some(CookieSameSite::Lax));
    assert_eq!(
        pref.expires_at(),
        Some(UNIX_EPOCH + Duration::from_secs(7_258_118_400))
    );
    assert_eq!(cart.partition_key(), Some("https://example.org"));
    assert_eq!(cart.same_site(), Some(CookieSameSite::None));
    assert_eq!((visit.path(), visit.expires_at()), ("/docs", None));
    assert_eq!(visit.source_scheme(), CookieSourceScheme::Http);
    assert_eq!(dev.source_scheme(), CookieSourceScheme::Http);
    assert_eq!(local.partition_key(), Some("http://app.localhost"));

    let restored = CookieJar::default();
    restored.import(&snapshot)?;
    assert_eq!(restored.export(), snapshot);
    for url in [
        "https://www.example.com/account",
        "https://api.example.com/",
        "https://shop.example.org/",
        "https://example.org/",
        "http://plain.test/docs",
        "http://localhost/",
        "http://app.localhost/",
    ] {
        assert_eq!(
            restored.request_value(url)?,
            original.request_value(url)?,
            "{url}"
        );
    }
    Ok(())
}

#[test]
fn partitioned_cookie_is_sent_only_to_its_restored_partition() -> TestResult {
    let jar = CookieJar::default();
    jar.import(&CookieSnapshot::new(vec![
        https("chip", "example.org")
            .with_secure(true)
            .with_partition_key("https://example.org"),
    ]))?;
    assert_eq!(
        jar.request_value("https://example.org/")?.as_deref(),
        Some("chip=1")
    );
    assert_eq!(jar.request_value("http://example.org/")?, None);
    Ok(())
}

#[test]
fn import_keeps_the_exported_cookie_order() -> TestResult {
    let original = CookieJar::default();
    let url = "https://example.test/a/b";
    original.set_cookie(url, "second=2; Path=/")?;
    original.set_cookie(url, "first=1; Path=/")?;
    original.set_cookie(url, "deep=3; Path=/a")?;
    original.set_cookie(url, "second=updated; Path=/")?;

    let restored = CookieJar::default();
    restored.import(&original.export())?;
    assert_eq!(
        restored.request_value(url)?.as_deref(),
        Some("deep=3; second=updated; first=1")
    );
    Ok(())
}

#[test]
fn import_rejects_secure_cookie_from_untrustworthy_origin() -> TestResult {
    let jar = CookieJar::default();
    let entry = CookieSnapshotEntry::new(CookieSourceScheme::Http, "sid", "1", "example.test", "/")
        .with_secure(true);
    assert_eq!(
        rejection(&jar, vec![https("ok", "example.test"), entry]),
        Some((CookieSnapshotErrorKind::UnsupportedPolicy, Some(1)))
    );
    assert!(jar.is_empty());
    Ok(())
}

#[test]
fn import_rejects_invalid_cookie_prefixes() {
    let jar = CookieJar::default();
    for entry in [
        https("__Secure-id", "example.test"),
        https("__Host-id", "example.test")
            .with_secure(true)
            .with_host_only(false),
        CookieSnapshotEntry::new(
            CookieSourceScheme::Https,
            "__Host-id",
            "1",
            "example.test",
            "/x",
        )
        .with_secure(true),
        CookieSnapshotEntry::new(
            CookieSourceScheme::Http,
            "__Host-id",
            "1",
            "example.test",
            "/",
        )
        .with_secure(true),
    ] {
        assert_eq!(
            rejection(&jar, vec![entry]),
            Some((CookieSnapshotErrorKind::InvalidPrefix, Some(0)))
        );
    }
    assert!(jar.is_empty());
}

#[test]
fn import_rejects_same_site_none_without_secure() {
    let jar = CookieJar::default();
    assert_eq!(
        rejection(
            &jar,
            vec![https("id", "example.test").with_same_site(CookieSameSite::None)]
        ),
        Some((CookieSnapshotErrorKind::UnsupportedPolicy, Some(0)))
    );
}

#[test]
fn import_rejects_partitioned_cookie_without_secure() {
    let jar = CookieJar::default();
    assert_eq!(
        rejection(
            &jar,
            vec![https("id", "example.test").with_partition_key("https://example.test")]
        ),
        Some((CookieSnapshotErrorKind::UnsupportedPolicy, Some(0)))
    );
}

#[test]
fn import_rejects_domain_cookie_on_public_suffix() -> TestResult {
    let jar = CookieJar::default();
    for domain in ["com", "github.io", "corp"] {
        assert_eq!(
            rejection(&jar, vec![https("id", domain).with_host_only(false)]),
            Some((CookieSnapshotErrorKind::PublicSuffix, Some(0))),
            "{domain}"
        );
    }
    // A response from the suffix host itself may set a host-only cookie.
    jar.import(&CookieSnapshot::new(vec![https("id", "github.io")]))?;
    assert_eq!(jar.len(), 1);
    Ok(())
}

#[test]
fn import_rejects_a_partition_key_storage_would_not_assign() {
    let jar = CookieJar::default();
    let secure = || https("id", "www.example.test").with_secure(true);
    for key in [
        "https://www.example.test",
        "https://other.test",
        "http://example.test",
        "https://example.test/",
    ] {
        assert_eq!(
            rejection(&jar, vec![secure().with_partition_key(key)]),
            Some((CookieSnapshotErrorKind::InvalidPartitionKey, Some(0))),
            "{key}"
        );
    }
}

#[test]
fn import_rejects_noncanonical_or_injected_fields() {
    let jar = CookieJar::default();
    for entry in [
        https("id", "Example.test"),
        https("id", "example.test:443"),
        https("id", "user@example.test"),
        https("id", "example.test/path"),
        https("id", ""),
        CookieSnapshotEntry::new(CookieSourceScheme::Https, "id", "1", "example.test", "path"),
        CookieSnapshotEntry::new(
            CookieSourceScheme::Https,
            "id",
            "1; Domain=other.test",
            "example.test",
            "/",
        ),
        CookieSnapshotEntry::new(
            CookieSourceScheme::Https,
            "id",
            "1",
            "example.test",
            "/; Secure",
        ),
        CookieSnapshotEntry::new(CookieSourceScheme::Https, "id", " 1", "example.test", "/"),
        CookieSnapshotEntry::new(CookieSourceScheme::Https, "a=b", "1", "example.test", "/"),
    ] {
        assert_eq!(
            rejection(&jar, vec![entry.clone()]),
            Some((CookieSnapshotErrorKind::InvalidCookie, Some(0))),
            "{entry:?} {} {} {}",
            entry.name(),
            entry.value(),
            entry.domain()
        );
    }
    assert!(jar.is_empty());
}

#[test]
fn import_applies_the_jar_byte_limit() {
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(32), nonzero(10), nonzero(10)));
    let entry = CookieSnapshotEntry::new(
        CookieSourceScheme::Https,
        "id",
        "x".repeat(32),
        "example.test",
        "/",
    );
    assert_eq!(
        rejection(&jar, vec![entry]),
        Some((CookieSnapshotErrorKind::CookieTooLarge, Some(0)))
    );
}

#[test]
fn one_invalid_entry_leaves_the_jar_unchanged() -> TestResult {
    let jar = CookieJar::default();
    jar.set_cookie("https://example.test/", "held=1")?;
    let before = jar.export();
    assert!(
        rejection(
            &jar,
            vec![
                https("new", "example.test"),
                https("bad", "example.test")
                    .with_secure(true)
                    .with_same_site(CookieSameSite::None)
                    .with_host_only(false)
                    .with_partition_key("https://nope.test")
            ]
        )
        .is_some()
    );
    assert_eq!(jar.export(), before);
    Ok(())
}

#[test]
fn expired_entries_are_skipped_and_session_entries_kept() -> TestResult {
    let jar = CookieJar::default();
    let now = SystemTime::now();
    jar.import(&CookieSnapshot::new(vec![
        https("past", "example.test").with_expires_at(now - HOUR),
        https("epoch", "example.test").with_expires_at(UNIX_EPOCH),
        https("future", "example.test").with_expires_at(now + HOUR),
        https("session", "example.test"),
    ]))?;
    assert_eq!(names(&jar.export()), ["future", "session"]);
    Ok(())
}

#[test]
fn imported_expiry_is_rounded_down_and_never_extended() -> TestResult {
    let jar = CookieJar::default();
    let expires_at = SystemTime::now() + HOUR + Duration::from_millis(900);
    jar.import(&CookieSnapshot::new(vec![
        https("id", "example.test").with_expires_at(expires_at),
    ]))?;
    let exported = jar.export();
    let [entry] = exported.entries() else {
        return Err("expected one cookie".into());
    };
    let restored = entry.expires_at().ok_or("expected an expiry")?;
    assert!(restored <= expires_at);
    assert!(expires_at.duration_since(restored)? < Duration::from_secs(1));

    let far = UNIX_EPOCH + Duration::from_secs(400_000_000_000);
    jar.import(&CookieSnapshot::new(vec![
        https("far", "example.test").with_expires_at(far),
    ]))?;
    let far_expiry = jar
        .export()
        .entries()
        .iter()
        .find(|entry| entry.name() == "far")
        .and_then(CookieSnapshotEntry::expires_at);
    assert_eq!(
        far_expiry,
        Some(UNIX_EPOCH + Duration::from_secs(253_402_300_799))
    );
    Ok(())
}

#[test]
fn held_cookies_win_and_a_later_duplicate_wins_within_a_snapshot() -> TestResult {
    let jar = CookieJar::default();
    jar.set_cookie("https://example.test/", "held=live")?;
    jar.import(&CookieSnapshot::new(vec![
        CookieSnapshotEntry::new(
            CookieSourceScheme::Https,
            "held",
            "stale",
            "example.test",
            "/",
        ),
        CookieSnapshotEntry::new(CookieSourceScheme::Https, "dup", "old", "example.test", "/"),
        CookieSnapshotEntry::new(CookieSourceScheme::Https, "dup", "new", "example.test", "/"),
    ]))?;
    assert_eq!(
        jar.request_value("https://example.test/")?.as_deref(),
        Some("dup=new; held=live")
    );
    Ok(())
}

#[test]
fn import_cannot_overlay_a_held_secure_cookie_from_an_untrustworthy_origin() -> TestResult {
    let jar = CookieJar::default();
    jar.set_cookie("https://example.test/", "sid=secure; Secure; Path=/")?;
    jar.import(&CookieSnapshot::new(vec![CookieSnapshotEntry::new(
        CookieSourceScheme::Http,
        "sid",
        "plain",
        "example.test",
        "/app",
    )]))?;
    assert_eq!(names(&jar.export()), ["sid"]);
    assert_eq!(
        jar.request_value("https://example.test/app")?.as_deref(),
        Some("sid=secure")
    );
    Ok(())
}

#[test]
fn capacity_keeps_held_cookies_then_the_newest_entries() -> TestResult {
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(4096), nonzero(3), nonzero(5)));
    jar.set_cookie("https://one.test/", "held=1")?;
    jar.import(&CookieSnapshot::new(vec![
        https("a", "one.test"),
        https("b", "one.test"),
        https("c", "one.test"),
        https("d", "one.test"),
        https("x", "two.test"),
        https("y", "two.test"),
    ]))?;
    // Newest first: both two.test cookies fit, one.test admits two beside
    // the held cookie, and the total of five is then full. Nothing held is
    // evicted, and the imports keep their snapshot order before it.
    assert_eq!(names(&jar.export()), ["c", "d", "x", "y", "held"]);
    Ok(())
}

#[test]
fn imported_cookies_are_evicted_before_held_ones() -> TestResult {
    let jar = CookieJar::with_limits(CookieLimits::new(nonzero(4096), nonzero(6), nonzero(100)));
    jar.set_cookie("https://one.test/", "held=1; Path=/held")?;
    jar.import(&CookieSnapshot::new(
        ["a", "b", "c", "d", "e"]
            .into_iter()
            .map(|name| {
                CookieSnapshotEntry::new(
                    CookieSourceScheme::Https,
                    name,
                    "1",
                    "one.test",
                    format!("/{name}"),
                )
            })
            .collect(),
    ))?;
    // A seventh one.test cookie purges down to five: the two oldest imports go.
    jar.set_cookie("https://one.test/", "new=1; Path=/new")?;
    assert_eq!(names(&jar.export()), ["c", "d", "e", "held", "new"]);
    Ok(())
}

#[test]
fn client_round_trips_cookies_and_reports_a_missing_jar() -> TestResult {
    let profile = || ClientProfile::new(chromium::v154_tls());
    let without = Client::builder(profile()).build()?;
    assert!(without.export_cookies().is_none());
    let error = without
        .import_cookies(&CookieSnapshot::default())
        .err()
        .ok_or("import succeeded without a cookie jar")?;
    assert_eq!(
        (error.kind(), error.entry_index()),
        (CookieSnapshotErrorKind::Disabled, None)
    );

    let source = Client::builder(profile())
        .cookie_jar(populated_jar()?)
        .build()?;
    let snapshot = source.export_cookies().ok_or("cookies are enabled")?;
    let restored = Client::builder(profile()).cookies().build()?;
    restored.import_cookies(&snapshot)?;
    assert_eq!(restored.export_cookies(), Some(snapshot));
    Ok(())
}

#[test]
fn debug_output_omits_cookie_contents() -> TestResult {
    let snapshot = populated_jar()?.export();
    let formatted = format!("{snapshot:?}");
    for secret in ["abc", "sid", "example.com", "/account", "example.org"] {
        assert!(!formatted.contains(secret), "{secret} in {formatted}");
    }
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn serialized_snapshot_round_trips_and_is_revalidated() -> TestResult {
    let snapshot = populated_jar()?.export();
    let json = serde_json::to_string(&snapshot)?;
    let decoded: CookieSnapshot = serde_json::from_str(&json)?;
    assert_eq!(decoded, snapshot);

    let restored = CookieJar::default();
    restored.import(&decoded)?;
    assert_eq!(restored.export(), snapshot);

    let widened = json.replacen(
        "\"source_scheme\":\"https\"",
        "\"source_scheme\":\"http\"",
        1,
    );
    let widened: CookieSnapshot = serde_json::from_str(&widened)?;
    assert_eq!(
        rejection(&CookieJar::default(), widened.entries().to_vec()),
        Some((CookieSnapshotErrorKind::UnsupportedPolicy, Some(0)))
    );
    Ok(())
}
