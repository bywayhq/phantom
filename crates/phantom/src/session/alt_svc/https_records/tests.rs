use std::{num::NonZeroUsize, time::Duration};

use http::uri::Authority;
use phantom_net::dns::{HttpsRecord, HttpsRecordResolver};
use phantom_testkit::dns::{DnsAnswer, DnsQuery, DnsReply, DnsServer};

use super::{Discovery, HttpsRecordDiscovery, advertises_h3, summarize};
use crate::authority::Endpoint;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const HOST: &str = "origin.test";
const OWNER: &str = "_8443._https.origin.test";

fn rdata(priority: u16, target: &[&str], params: &[(u16, &[u8])]) -> Vec<u8> {
    let mut bytes = priority.to_be_bytes().to_vec();
    for label in target {
        bytes.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    for (key, value) in params {
        bytes.extend_from_slice(&key.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}

fn record(bytes: &[u8]) -> TestResult<HttpsRecord> {
    Ok(HttpsRecord::from_rdata(bytes)?)
}

fn advertises(records: &[Vec<u8>]) -> TestResult<bool> {
    let parsed = records
        .iter()
        .map(|bytes| record(bytes))
        .collect::<TestResult<Vec<_>>>()?;
    let answers = parsed
        .iter()
        .map(|record| (OWNER, record))
        .collect::<Vec<_>>();
    Ok(advertises_h3(&answers, HOST, 8443))
}

const H3: (u16, &[u8]) = (1, b"\x02h3");

#[test]
fn service_record_listing_h3_for_the_origin_advertises_it() -> TestResult<()> {
    assert!(advertises(&[rdata(1, &[], &[H3])])?);
    assert!(advertises(&[rdata(1, &["Origin", "Test"], &[H3])])?);
    assert!(advertises(&[rdata(
        1,
        &["_8443", "_https", "origin", "test"],
        &[H3]
    )])?);
    assert!(advertises(&[rdata(
        1,
        &[],
        &[H3, (3, &8443_u16.to_be_bytes())]
    )])?);
    // Any kept record may carry h3, whatever its priority.
    assert!(advertises(&[
        rdata(1, &[], &[(1, b"\x02h2")]),
        rdata(2, &[], &[H3]),
    ])?);
    Ok(())
}

#[test]
fn records_chromium_ignores_do_not_advertise_h3() -> TestResult<()> {
    let cases = [
        ("no h3", vec![rdata(1, &[], &[(1, b"\x02h2")])]),
        ("no records", vec![]),
        (
            "an alias record hides every record",
            vec![rdata(0, &["cdn", "test"], &[]), rdata(1, &[], &[H3])],
        ),
        ("another target", vec![rdata(1, &["cdn", "test"], &[H3])]),
        (
            "another port",
            vec![rdata(1, &[], &[H3, (3, &443_u16.to_be_bytes())])],
        ),
        (
            "an unsupported mandatory key",
            vec![rdata(1, &[], &[(0, &[0, 7]), H3, (7, b"x")])],
        ),
        (
            "every record sets no-default-alpn",
            vec![rdata(1, &[], &[H3, (2, b"")])],
        ),
    ];
    for (name, records) in cases {
        assert!(!advertises(&records)?, "{name}");
    }
    // One record without no-default-alpn keeps the others.
    assert!(advertises(&[
        rdata(1, &[], &[H3, (2, b"")]),
        rdata(2, &[], &[(1, b"\x02h2")]),
    ])?);
    // A supported mandatory key keeps the record.
    assert!(advertises(&[rdata(1, &[], &[(0, &[0, 1]), H3])])?);
    Ok(())
}

fn endpoint(authority: &'static str) -> TestResult<Endpoint> {
    Ok(Endpoint::new(Authority::from_static(authority), 443).map_err(|error| error.message())?)
}

async fn server(ttl: u32, delay: Duration) -> TestResult<DnsServer> {
    Ok(DnsServer::spawn(move |_: &DnsQuery| {
        DnsReply::new(DnsAnswer::Records {
            ttl,
            rdata: vec![rdata(1, &[], &[H3])],
        })
        .delayed(delay)
    })
    .await?)
}

fn discovery(server: &DnsServer, capacity: usize) -> TestResult<HttpsRecordDiscovery> {
    Ok(HttpsRecordDiscovery::new(
        HttpsRecordResolver::with_nameservers([server.address()])?,
        NonZeroUsize::new(capacity).ok_or("zero capacity")?,
    ))
}

async fn settle(discovery: &HttpsRecordDiscovery, origin: &Endpoint) -> TestResult<bool> {
    match discovery.discover(origin) {
        Discovery::Pending(lookup) => Ok(lookup.advertises_h3().await),
        Discovery::Advertised => Ok(true),
        Discovery::NotAdvertised => Ok(false),
    }
}

#[tokio::test]
async fn concurrent_requests_share_one_lookup_and_reuse_its_result() -> TestResult<()> {
    let server = server(300, Duration::from_millis(100)).await?;
    let discovery = discovery(&server, 4)?;
    let origin = endpoint("origin.test:8443")?;

    let first = discovery.discover(&origin);
    let second = discovery.discover(&origin);
    let (Discovery::Pending(first), Discovery::Pending(second)) = (first, second) else {
        return Err("an uncached origin did not start a lookup".into());
    };
    assert!(first.advertises_h3().await);
    assert!(second.advertises_h3().await);
    assert!(matches!(discovery.discover(&origin), Discovery::Advertised));
    assert_eq!(server.queries().len(), 1);
    assert_eq!(server.queries()[0].name(), OWNER);
    Ok(())
}

#[tokio::test]
async fn expired_results_are_looked_up_again() -> TestResult<()> {
    let server = server(0, Duration::ZERO).await?;
    let discovery = discovery(&server, 4)?;
    let origin = endpoint("origin.test:8443")?;
    assert!(settle(&discovery, &origin).await?);
    assert!(matches!(discovery.discover(&origin), Discovery::Pending(_)));
    Ok(())
}

#[tokio::test]
async fn cache_holds_at_most_its_capacity() -> TestResult<()> {
    let server = server(300, Duration::ZERO).await?;
    let discovery = discovery(&server, 1)?;
    let first = endpoint("origin.test:8443")?;
    let second = endpoint("other.test")?;
    assert!(settle(&discovery, &first).await?);
    assert!(settle(&discovery, &second).await?);
    assert_eq!(discovery.cache.lock_entries().len(), 1);
    // The first origin was evicted, so it is queried again.
    let Discovery::Pending(lookup) = discovery.discover(&first) else {
        return Err("an evicted origin was still cached".into());
    };
    assert!(lookup.advertises_h3().await);
    assert_eq!(server.queries().len(), 3);
    Ok(())
}

#[tokio::test]
async fn failed_lookup_is_remembered_as_no_advertisement() -> TestResult<()> {
    let server = DnsServer::spawn(|_| DnsReply::new(DnsAnswer::ServerFailure)).await?;
    let discovery = discovery(&server, 4)?;
    let origin = endpoint("origin.test:8443")?;
    assert!(!settle(&discovery, &origin).await?);
    let queries = server.queries().len();
    assert!(matches!(
        discovery.discover(&origin),
        Discovery::NotAdvertised
    ));
    assert_eq!(server.queries().len(), queries);
    Ok(())
}

#[tokio::test]
async fn ip_literal_origins_are_never_queried() -> TestResult<()> {
    let server = server(300, Duration::ZERO).await?;
    let discovery = discovery(&server, 4)?;
    for authority in ["127.0.0.1:8443", "[::1]:8443"] {
        assert!(matches!(
            discovery.discover(&endpoint(authority)?),
            Discovery::NotAdvertised
        ));
    }
    tokio::task::yield_now().await;
    assert!(server.queries().is_empty());
    Ok(())
}

fn tcp_ech(records: &[Vec<u8>]) -> TestResult<Option<Vec<u8>>> {
    let parsed = records
        .iter()
        .map(|bytes| record(bytes))
        .collect::<TestResult<Vec<_>>>()?;
    let answers = parsed
        .iter()
        .map(|record| (OWNER, record))
        .collect::<Vec<_>>();
    let alpn = [Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])];
    Ok(summarize(&answers, HOST, 8443)
        .tcp_ech(&alpn)
        .map(|list| list.as_bytes().to_vec()))
}

const ECH_A: (u16, &[u8]) = (5, b"\x00\x01\xaa");
const ECH_B: (u16, &[u8]) = (5, b"\x00\x01\xbb");
const H2: (u16, &[u8]) = (1, b"\x02h2");
const NO_DEFAULT_ALPN: (u16, &[u8]) = (2, b"");

#[test]
fn tcp_uses_the_ech_of_the_first_record_by_priority() -> TestResult<()> {
    let records = [rdata(2, &[], &[H2, ECH_B]), rdata(1, &[], &[H2, ECH_A])];
    assert_eq!(tcp_ech(&records)?.as_deref(), Some(&b"\x00\x01\xaa"[..]));
    Ok(())
}

#[test]
fn a_first_record_without_ech_means_no_ech() -> TestResult<()> {
    let records = [rdata(1, &[], &[H2]), rdata(2, &[], &[H2, ECH_A])];
    assert_eq!(tcp_ech(&records)?, None);
    Ok(())
}

#[test]
fn records_tcp_cannot_use_are_skipped() -> TestResult<()> {
    // HTTP/3 only: no `h2`, and `no-default-alpn` drops `http/1.1`.
    let quic_only = rdata(1, &[], &[H3, NO_DEFAULT_ALPN, ECH_B]);
    let records = [quic_only, rdata(2, &[], &[H2, ECH_A])];
    assert_eq!(tcp_ech(&records)?.as_deref(), Some(&b"\x00\x01\xaa"[..]));
    Ok(())
}

#[test]
fn records_chromium_ignores_carry_no_ech() -> TestResult<()> {
    let alias = rdata(0, &["elsewhere", "test"], &[]);
    assert_eq!(tcp_ech(&[alias, rdata(1, &[], &[H2, ECH_A])])?, None);
    let other_port = rdata(1, &[], &[H2, (3, b"\x00\x01"), ECH_A]);
    assert_eq!(tcp_ech(&[other_port])?, None);
    let other_target = rdata(1, &["cdn", "test"], &[H2, ECH_A]);
    assert_eq!(tcp_ech(&[other_target])?, None);
    Ok(())
}
