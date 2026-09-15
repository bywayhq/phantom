use phantom_testkit::tls::is_grease;

use super::{TestResult, fixture::Fixture, redecode};

const FIXTURE_TEXT: &str = include_str!(concat!(
    "../../../../fixtures/tls/safari/18.5/",
    "macos-15.5/client-hello.txt"
));
const GREASE_SENTINEL: u16 = 0x0a0a;

#[tokio::test]
async fn safari_18_5_fixture_retains_exact_metadata_and_client_hello() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    assert_eq!(fixture.value("format")?, "phantom-client-hello-v2");
    assert_eq!(fixture.value("captured_at_unix")?, "1789497889");
    assert_eq!(fixture.value("browser")?, "Safari");
    assert_eq!(fixture.value("browser_version")?, "18.5");
    assert_eq!(fixture.value("operating_system")?, "macOS 15.5 (24F74)");
    assert_eq!(fixture.value("hostname")?, "localhost");
    assert_eq!(fixture.value("listen_address")?, "127.0.0.1:9445");
    assert_eq!(fixture.value("launch_mode")?, "application");
    assert_eq!(fixture.value("launch_arguments")?, "");
    assert_eq!(fixture.records().concat().len(), 517);

    let summary = redecode(&fixture).await?;
    assert_eq!(summary.legacy_version(), 0x0303);
    assert_eq!(
        normalize_grease(summary.cipher_suites()),
        [
            GREASE_SENTINEL,
            0x1301,
            0x1302,
            0x1303,
            0xc02c,
            0xc02b,
            0xcca9,
            0xc030,
            0xc02f,
            0xcca8,
            0xc00a,
            0xc009,
            0xc014,
            0xc013,
            0x009d,
            0x009c,
            0x0035,
            0x002f,
            0xc008,
            0xc012,
            0x000a,
        ]
    );
    assert_eq!(
        normalize_grease(summary.supported_groups()),
        [GREASE_SENTINEL, 0x001d, 0x0017, 0x0018, 0x0019]
    );
    assert_eq!(summary.ec_point_formats(), [0]);
    assert_eq!(
        summary.signature_algorithms(),
        [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
        ]
    );
    assert_eq!(
        summary.alpn_protocols(),
        [b"h2".as_slice(), b"http/1.1".as_slice()]
    );
    assert_eq!(
        normalize_grease(summary.supported_versions()),
        [GREASE_SENTINEL, 0x0304, 0x0303, 0x0302, 0x0301]
    );
    assert_eq!(
        normalize_grease(summary.key_share_groups()),
        [GREASE_SENTINEL, 0x001d]
    );
    assert_eq!(summary.requested_trust_anchor_ids(), None);
    assert_eq!(
        summary.extension_layout().collect::<Vec<_>>(),
        [
            (0x9a9a, 0),
            (0x0000, 14),
            (0x0017, 0),
            (0xff01, 1),
            (0x000a, 12),
            (0x000b, 2),
            (0x0010, 14),
            (0x0005, 5),
            (0x000d, 22),
            (0x0012, 0),
            (0x0033, 43),
            (0x002d, 2),
            (0x002b, 11),
            (0x001b, 3),
            (0xcaca, 1),
            (0x0015, 199),
        ]
    );
    Ok(())
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
