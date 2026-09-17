//! Browser ClientHello fixture integrity and semantic assertions.

#[path = "browser_client_hello_fixtures/chrome.rs"]
mod chrome;
#[path = "browser_client_hello_fixtures/chrome_quic.rs"]
mod chrome_quic;
#[path = "browser_client_hello_fixtures/firefox.rs"]
mod firefox;
#[path = "browser_client_hello_fixtures/fixture.rs"]
mod fixture;
#[path = "browser_client_hello_fixtures/safari.rs"]
mod safari;

use std::{error::Error, io, time::Duration};

use fixture::{Fixture, hex, u8_list, u16_list};
use phantom_testkit::tls::{CaptureLimits, ClientHelloSummary, capture_client_hello};
use tokio::io::{AsyncWriteExt, duplex};

type TestResult<T> = Result<T, Box<dyn Error>>;

async fn redecode(fixture: &Fixture<'_>) -> TestResult<ClientHelloSummary> {
    let wire = fixture.records().concat();
    let (mut writer, mut reader) = duplex(wire.len());
    writer.write_all(&wire).await?;
    drop(writer);

    let capture = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        CaptureLimits::new(4_096, 4_096, 2),
    )
    .await?;
    assert_eq!(capture.records().len(), fixture.records().len());
    for (record, expected) in capture.records().iter().zip(fixture.records()) {
        assert_eq!(record.wire_bytes(), expected);
    }

    let summary = capture.summary()?;
    assert_summary_fields(fixture, &summary)?;
    let server_name = summary
        .server_name()
        .ok_or_else(|| fixture::invalid_fixture("captured ClientHello has no SNI host name"))?;
    assert_eq!(server_name, fixture.value("hostname")?.as_bytes());
    Ok(summary)
}

fn assert_summary_fields(
    fixture: &Fixture<'_>,
    summary: &ClientHelloSummary,
) -> Result<(), io::Error> {
    assert_eq!(
        fixture.value("legacy_version")?,
        format!("{:#06x}", summary.legacy_version())
    );
    assert_eq!(
        fixture.value("cipher_suites")?,
        u16_list(summary.cipher_suites())
    );
    assert_eq!(
        fixture.value("extension_types")?,
        u16_list(summary.extension_types())
    );
    assert_eq!(
        fixture.value("supported_groups")?,
        u16_list(summary.supported_groups())
    );
    assert_eq!(
        fixture.value("ec_point_formats")?,
        u8_list(summary.ec_point_formats())
    );
    assert_eq!(
        fixture.value("signature_algorithms")?,
        u16_list(summary.signature_algorithms())
    );
    assert_eq!(
        fixture.value("alpn_protocols_hex")?,
        summary
            .alpn_protocols()
            .iter()
            .map(|protocol| hex(protocol))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        fixture.value("supported_versions")?,
        u16_list(summary.supported_versions())
    );
    assert_eq!(
        fixture.value("key_share_groups")?,
        u16_list(summary.key_share_groups())
    );
    assert_eq!(
        fixture.value("server_name_hex")?,
        summary.server_name().map(hex).unwrap_or_default()
    );
    Ok(())
}
