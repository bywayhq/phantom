//! Browser ClientHello fixture integrity and semantic assertions.

#[path = "browser_client_hello_fixtures/fixture.rs"]
mod fixture;

use std::{error::Error, io, time::Duration};

use fixture::{Fixture, hex, invalid_fixture, u8_list, u16_list};
use phantom_testkit::tls::{CaptureLimits, ClientHelloSummary, capture_client_hello, is_grease};
use tokio::io::{AsyncWriteExt, duplex};

const FIXTURE_TEXT: &str =
    include_str!("../../../fixtures/tls/chrome/152.0.7977.83/macos-15.5/client-hello.txt");
const GREASE_SENTINEL: u16 = 0x0a0a;
const EXPECTED_LAUNCH_ARGUMENTS: &str = concat!(
    "--headless=new --user-data-dir=<temporary-directory> --no-first-run ",
    "--no-default-browser-check --disable-background-networking ",
    "--disable-component-update --disable-default-apps --disable-quic ",
    "--no-proxy-server --host-resolver-rules=MAP server.phantom.test 127.0.0.1, ",
    "EXCLUDE localhost --ignore-certificate-errors --dump-dom",
);

#[tokio::test]
async fn chrome_152_fixture_matches_raw_client_hello() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    assert_eq!(fixture.value("format")?, "phantom-client-hello-v2");
    assert_eq!(fixture.value("browser")?, "Google Chrome");
    assert_eq!(fixture.value("browser_version")?, "152.0.7977.83");
    assert_eq!(fixture.value("operating_system")?, "macOS 15.5 (24F74)");
    assert_eq!(fixture.value("launch_mode")?, "command-line");
    assert_eq!(
        fixture.value("launch_arguments")?,
        EXPECTED_LAUNCH_ARGUMENTS
    );

    let wire = fixture.records().concat();
    assert_eq!(wire.len(), 2_043);
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
    assert_summary_fields(&fixture, &summary)?;
    assert_browser_relevant_fields(&summary);

    let server_name = summary
        .server_name()
        .ok_or_else(|| invalid_fixture("captured ClientHello has no SNI host name"))?;
    assert_eq!(server_name, fixture.value("hostname")?.as_bytes());
    Ok(())
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

fn assert_browser_relevant_fields(summary: &ClientHelloSummary) {
    assert_eq!(summary.legacy_version(), 0x0303);
    assert_eq!(
        normalize_grease(summary.cipher_suites()),
        [
            GREASE_SENTINEL,
            0x1301,
            0x1302,
            0x1303,
            0xc02b,
            0xc02f,
            0xc02c,
            0xc030,
            0xcca9,
            0xcca8,
            0xc013,
            0xc014,
            0x009c,
            0x009d,
            0x002f,
            0x0035,
        ]
    );
    assert_eq!(
        normalize_grease(summary.supported_versions()),
        [GREASE_SENTINEL, 0x0304, 0x0303]
    );
    assert_eq!(
        normalize_grease(summary.supported_groups()),
        [GREASE_SENTINEL, 0x11ec, 0x001d, 0x0017, 0x0018]
    );
    assert_eq!(summary.ec_point_formats(), [0]);
    assert_eq!(
        normalize_grease(summary.signature_algorithms()),
        [
            GREASE_SENTINEL,
            0x0904,
            0x0905,
            0x0906,
            0x0403,
            0x0804,
            0x0401,
            0x0503,
            0x0805,
            0x0501,
            0x0806,
            0x0601,
        ]
    );
    assert_eq!(
        summary.alpn_protocols(),
        [b"h2".as_slice(), b"http/1.1".as_slice()]
    );
    assert_eq!(
        normalize_grease(summary.key_share_groups()),
        [GREASE_SENTINEL, 0x11ec, 0x001d]
    );
    assert_eq!(
        summary.requested_trust_anchor_ids().map(<[_]>::len),
        Some(32)
    );

    for required_extension in [0, 10, 11, 13, 16, 43, 45, 51, 0xfe0d] {
        assert!(summary.extension_types().contains(&required_extension));
    }
    assert_eq!(summary.extension_types().len(), 19);
    assert_eq!(
        summary
            .extension_types()
            .iter()
            .filter(|&&value| is_grease(value))
            .count(),
        2
    );
}

fn normalize_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .map(|&value| {
            if is_grease(value) {
                GREASE_SENTINEL
            } else {
                value
            }
        })
        .collect()
}
