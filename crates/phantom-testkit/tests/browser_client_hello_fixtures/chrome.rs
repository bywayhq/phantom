use phantom_testkit::tls::{ClientHelloSummary, is_grease};

use super::{TestResult, fixture::Fixture, redecode};

pub(super) const FIXTURE_TEXT: &str = include_str!(concat!(
    "../../../../fixtures/tls/chrome/154.0.8037.58/",
    "windows-11-26200/client-hello.txt"
));
const GREASE_SENTINEL: u16 = 0x0a0a;
const EXPECTED_LAUNCH_ARGUMENTS: &str = concat!(
    "--headless=new --user-data-dir=<temporary-directory> --no-first-run ",
    "--no-default-browser-check --disable-background-networking ",
    "--disable-component-update --disable-default-apps --disable-quic ",
    "--no-proxy-server --host-resolver-rules=MAP server.phantom.test 127.0.0.1, ",
    "EXCLUDE localhost --ignore-certificate-errors --dump-dom",
);

#[tokio::test]
async fn chrome_154_fixture_retains_exact_metadata_and_client_hello() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    assert_eq!(fixture.value("format")?, "phantom-client-hello-v2");
    assert_eq!(fixture.value("captured_at_unix")?, "1790242735");
    assert_eq!(fixture.value("browser")?, "Google Chrome");
    assert_eq!(fixture.value("browser_version")?, "154.0.8037.58");
    assert_eq!(
        fixture.value("operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(fixture.value("hostname")?, "server.phantom.test");
    assert_eq!(fixture.value("listen_address")?, "127.0.0.1:49688");
    assert_eq!(fixture.value("launch_mode")?, "command-line");
    assert_eq!(
        fixture.value("launch_arguments")?,
        EXPECTED_LAUNCH_ARGUMENTS
    );
    assert_eq!(fixture.records().concat().len(), 1_959);

    let summary = redecode(&fixture).await?;
    assert_browser_fields(&summary);
    assert_eq!(
        summary.extension_layout().collect::<Vec<_>>(),
        [
            (0xbaba, 0),
            (0x001b, 3),
            (0x002d, 2),
            (0x000b, 2),
            (0x000a, 12),
            (0x0005, 5),
            (0xca34, 186),
            (0x000d, 26),
            (0x0000, 24),
            (0x44cd, 5),
            (0x0012, 0),
            (0x0023, 0),
            (0xfe0d, 218),
            (0x0010, 14),
            (0x0033, 1_263),
            (0x0017, 0),
            (0x002b, 7),
            (0xff01, 1),
            (0x4a4a, 1),
        ]
    );
    Ok(())
}

fn assert_browser_fields(summary: &ClientHelloSummary) {
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
        Some(28)
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
