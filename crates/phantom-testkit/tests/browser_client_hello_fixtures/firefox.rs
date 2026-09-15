use phantom_testkit::tls::is_grease;

use super::{TestResult, fixture::Fixture, redecode};

const FIXTURE_TEXT: &str = include_str!(concat!(
    "../../../../fixtures/tls/firefox/154.0/",
    "macos-15.5/client-hello.txt"
));

#[tokio::test]
async fn firefox_154_fixture_retains_exact_metadata_and_client_hello() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    assert_eq!(fixture.value("format")?, "phantom-client-hello-v2");
    assert_eq!(fixture.value("captured_at_unix")?, "1789497815");
    assert_eq!(fixture.value("browser")?, "Mozilla Firefox");
    assert_eq!(fixture.value("browser_version")?, "154.0");
    assert_eq!(fixture.value("operating_system")?, "macOS 15.5 (24F74)");
    assert_eq!(fixture.value("hostname")?, "localhost");
    assert_eq!(fixture.value("listen_address")?, "127.0.0.1:9446");
    assert_eq!(fixture.value("launch_mode")?, "command-line");
    assert_eq!(
        fixture.value("launch_arguments")?,
        "--headless --no-remote --profile <temporary-profile>"
    );
    assert_eq!(fixture.records().concat().len(), 1_890);

    let summary = redecode(&fixture).await?;
    assert_eq!(summary.legacy_version(), 0x0303);
    assert_eq!(
        summary.cipher_suites(),
        [
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ]
    );
    assert_eq!(
        summary.supported_groups(),
        [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
    );
    assert_eq!(summary.ec_point_formats(), [0]);
    assert_eq!(
        summary.signature_algorithms(),
        [
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ]
    );
    assert_eq!(
        summary.alpn_protocols(),
        [b"h2".as_slice(), b"http/1.1".as_slice()]
    );
    assert_eq!(summary.supported_versions(), [0x0304, 0x0303]);
    assert_eq!(summary.key_share_groups(), [0x11ec, 0x001d, 0x0017]);
    assert_eq!(summary.requested_trust_anchor_ids(), None);
    assert!(
        summary
            .cipher_suites()
            .iter()
            .chain(summary.supported_groups())
            .chain(summary.signature_algorithms())
            .chain(summary.supported_versions())
            .chain(summary.key_share_groups())
            .chain(summary.extension_types())
            .all(|&value| !is_grease(value))
    );
    assert_eq!(
        summary.extension_layout().collect::<Vec<_>>(),
        [
            (0x0000, 14),
            (0x0017, 0),
            (0xff01, 1),
            (0x000a, 16),
            (0x000b, 2),
            (0x0023, 0),
            (0x0010, 14),
            (0x0005, 5),
            (0x0022, 10),
            (0x0012, 0),
            (0x0033, 1_327),
            (0x002b, 5),
            (0x000d, 24),
            (0x002d, 2),
            (0x001c, 2),
            (0x001b, 7),
            (0xfe0d, 281),
        ]
    );
    Ok(())
}
