use std::{io, net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use phantom_profile::browser::chrome;

use phantom_net::dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup};
use tokio::time::Instant;

use super::{apply_deadline, limit_expiry, origin_query};
use crate::doh::{DnsOverHttps, DohAddressFamilies, DohConfiguration, DohMethod};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn held_cname_deadline_does_not_restart_https_answer_freshness() -> TestResult {
    let expired_hop = std::time::Instant::now()
        .checked_sub(Duration::from_secs(1))
        .ok_or("clock cannot represent expired hop")?;
    let earlier = Instant::from_std(expired_hop);
    let current = Instant::now() + Duration::from_secs(120);
    let held_deadline = limit_expiry(Some(earlier), current);
    assert_eq!(held_deadline.into_std(), expired_hop);
    // Construct the usable final answer after the held hop's deadline.
    let record = HttpsRecord::from_rdata(&[0, 1, 0, 0, 1, 0, 3, 2, b'h', b'3'])?;
    let answer = HttpsRecordAnswer::new("terminal.test", 120, record);
    let lookup = apply_deadline(
        HttpsRecordLookup::new(vec![answer.clone()], None),
        held_deadline,
    );
    assert_eq!(lookup.answers(), &[answer]);
    assert_eq!(lookup.cache_deadline(Duration::from_secs(120)), None);
    Ok(())
}

fn endpoint() -> Result<DnsOverHttps, Box<dyn std::error::Error>> {
    Ok(DnsOverHttps::builder(
        chrome::v154_windows(),
        DohConfiguration::new(
            "https://resolver.test/dns-query",
            [Ipv4Addr::LOCALHOST.into()],
            DohMethod::Post,
            DohAddressFamilies::Ipv4Only,
            Duration::from_secs(3),
            NonZeroUsize::MIN,
        ),
    )?
    .build()?)
}

#[test]
fn https_query_names_preserve_origin_port_and_explicit_wire_configuration() -> TestResult {
    let owner = endpoint()?;
    assert_eq!(
        origin_query(&owner.endpoint, "EXAMPLE.test.", 443)?.name(),
        "example.test."
    );
    let query = origin_query(&owner.endpoint, "example.test", 8443)?;
    assert_eq!(query.name(), "_8443._https.example.test.");
    assert_eq!(&query.as_bytes()[..2], &[0, 0]);
    assert!(query.as_bytes().ends_with(&[0, 65, 0, 1]));
    Ok(())
}

#[tokio::test]
async fn invalid_https_origins_fail_before_endpoint_admission_or_network() -> TestResult {
    let owner = endpoint()?;
    let _permit = owner.endpoint.admission.try_acquire()?;
    for (host, port) in [
        ("", 443),
        (".", 443),
        ("example.test..", 443),
        ("two..labels", 443),
        ("127.0.0.1", 443),
        ("127.0.0.1.", 443),
        ("127.1", 443),
        ("0x7f000001", 443),
        ("::1", 443),
        ("[::1]", 443),
        ("bücher.test", 443),
        ("space name.test", 443),
        ("escaped\\032name.test", 443),
        ("example.test", 0),
    ] {
        let failure = owner.https_record_resolver().lookup(host, port).await;
        let error = failure.err().ok_or("invalid origin was accepted")?;
        let source = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .ok_or("missing input error source")?;
        assert_eq!(source.kind(), io::ErrorKind::InvalidInput, "{host}:{port}");
    }
    Ok(())
}

#[tokio::test]
async fn https_and_address_lookups_share_the_endpoint_admission_bound() -> TestResult {
    let owner = endpoint()?;
    let resolver = owner.clone().https_record_resolver();
    let _permit = owner.endpoint.admission.try_acquire()?;
    let error = resolver
        .lookup("example.test", 443)
        .await
        .err()
        .ok_or("admission exceeded")?;
    let source = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<io::Error>())
        .ok_or("missing admission error source")?;
    assert_eq!(source.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        crate::doh::address::lookup(&owner.endpoint, "example.test")
            .await
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock),
    );
    Ok(())
}
