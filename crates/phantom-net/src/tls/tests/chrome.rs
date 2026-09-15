//! Chrome-specific TLS differential tests.

use std::io;

use phantom_profile::TlsSettings;
use phantom_testkit::tls::{
    CaptureLimits, ClientHelloCapture, ClientHelloSummary, capture_client_hello, is_grease,
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::Instant};

use super::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestResult, TlsConnector, chromium_152_macos_reference,
};

const CHROME_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/152.0.7977.83/",
    "macos-15.5/client-hello.txt"
));
const GREASE_SENTINEL: u16 = 0x0a0a;
const TRUST_ANCHORS_EXTENSION: u16 = 0xca34;

#[tokio::test]
async fn chromium_152_macos_matches_retained_client_hello() -> TestResult<()> {
    let expected = fixture_summary().await?;
    let actual = capture_summary(&chromium_152_macos_reference()).await?;

    assert_eq!(actual.legacy_version(), expected.legacy_version());
    assert_eq!(
        normalize_grease(actual.cipher_suites()),
        normalize_grease(expected.cipher_suites())
    );
    assert_eq!(
        normalize_grease(actual.supported_groups()),
        normalize_grease(expected.supported_groups())
    );
    assert_eq!(actual.ec_point_formats(), expected.ec_point_formats());
    assert_eq!(
        normalize_grease(actual.signature_algorithms()),
        normalize_grease(expected.signature_algorithms())
    );
    assert_eq!(actual.alpn_protocols(), expected.alpn_protocols());
    assert_eq!(
        normalize_grease(actual.supported_versions()),
        normalize_grease(expected.supported_versions())
    );
    assert_eq!(
        normalize_grease(actual.key_share_groups()),
        normalize_grease(expected.key_share_groups())
    );
    assert_eq!(actual.server_name(), expected.server_name());
    assert_eq!(actual.server_name(), Some(TEST_SERVER_NAME.as_bytes()));

    // Chrome permutes eligible extensions on each connection. Sorting only this
    // vector compares exact membership and count without inventing a stable order.
    assert_eq!(
        actual.extension_types().len(),
        expected.extension_types().len()
    );
    assert_eq!(
        grease_count(actual.extension_types()),
        grease_count(expected.extension_types())
    );
    assert_eq!(
        normalized_extensions(actual.extension_types()),
        normalized_extensions(expected.extension_types())
    );
    assert!(actual.extension_types().contains(&TRUST_ANCHORS_EXTENSION));
    Ok(())
}

#[tokio::test]
async fn omitted_trust_anchor_ids_omit_the_extension() -> TestResult<()> {
    let mut settings = chromium_152_macos_reference();
    settings.requested_trust_anchor_ids = None;

    let summary = capture_summary(&settings).await?;
    assert!(!summary.extension_types().contains(&TRUST_ANCHORS_EXTENSION));
    Ok(())
}

async fn capture_summary(settings: &TlsSettings) -> TestResult<ClientHelloSummary> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let capture_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        capture_client_hello(
            &mut stream,
            Instant::now() + TEST_TIMEOUT,
            CaptureLimits::new(32 * 1024, 40 * 1024, 4),
        )
        .await
        .map_err(io::Error::other)
    });

    let connector = TlsConnector::new(settings)?;
    let tcp = tokio::time::timeout(TEST_TIMEOUT, tokio::net::TcpStream::connect(address)).await??;
    let handshake = tokio::time::timeout(TEST_TIMEOUT, connector.connect(TEST_SERVER_NAME, tcp));
    if handshake.await?.is_ok() {
        return Err("capture peer unexpectedly completed TLS".into());
    }

    let capture = tokio::time::timeout(TEST_TIMEOUT, capture_task).await???;
    Ok(capture.summary()?)
}

async fn fixture_summary() -> TestResult<ClientHelloSummary> {
    let record_count = fixture_value("record_count")?.parse::<usize>()?;
    let records = (0..record_count)
        .map(|index| decode_hex(fixture_value(&format!("record_{index}_hex"))?))
        .collect::<Result<Vec<_>, _>>()?;
    let wire = records.concat();
    let (mut writer, mut reader) = tokio::io::duplex(wire.len());
    writer.write_all(&wire).await?;
    drop(writer);

    let capture: ClientHelloCapture = capture_client_hello(
        &mut reader,
        Instant::now() + TEST_TIMEOUT,
        CaptureLimits::new(32 * 1024, 40 * 1024, 4),
    )
    .await?;
    Ok(capture.summary()?)
}

fn fixture_value(field: &str) -> Result<&'static str, io::Error> {
    let prefix = format!("{field}=");
    CHROME_FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {field}")))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, io::Error> {
    if value.len() % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture contains odd-length hex",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture contains non-lowercase hex",
        )),
    }
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

fn normalized_extensions(values: &[u16]) -> Vec<u16> {
    let mut extensions = normalize_grease(values);
    extensions.sort_unstable();
    extensions
}

fn grease_count(values: &[u16]) -> usize {
    values.iter().filter(|&&value| is_grease(value)).count()
}
