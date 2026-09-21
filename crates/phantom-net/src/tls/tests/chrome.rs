//! Chrome-specific TLS differential tests.

use phantom_profile::chromium::v152_tls;
use phantom_testkit::tls::{ClientHelloCapture, ClientHelloSummary, is_grease};

use super::{capture_client_hello_from, client_hello_fixture};
use crate::tls::test_support::{TEST_SERVER_NAME, TestResult};

const CHROME_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/152.0.7977.83/",
    "macos-15.5/client-hello.txt"
));
const WINDOWS_CHROME_FOR_TESTING_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/152.0.7977.83/",
    "windows-11-26200/client-hello.txt"
));
const GREASE_SENTINEL: u16 = 0x0a0a;
const TRUST_ANCHORS_EXTENSION: u16 = 0xca34;

#[tokio::test]
async fn chromium_152_macos_matches_retained_client_hello() -> TestResult<()> {
    assert_recipe_matches_fixture(CHROME_FIXTURE).await?;
    let expected = client_hello_fixture::capture(CHROME_FIXTURE)
        .await?
        .summary()?;
    let actual = capture_client_hello_from(&v152_tls()).await?.summary()?;
    assert_eq!(
        actual.requested_trust_anchor_ids(),
        expected.requested_trust_anchor_ids()
    );
    Ok(())
}

#[tokio::test]
async fn chrome_152_tls_recipe_matches_windows_chrome_for_testing_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(WINDOWS_CHROME_FOR_TESTING_FIXTURE).await
}

async fn assert_recipe_matches_fixture(fixture: &str) -> TestResult<()> {
    let expected_capture = client_hello_fixture::capture(fixture).await?;
    let actual_capture = capture_client_hello_from(&v152_tls()).await?;

    assert_eq!(
        actual_capture.records().len(),
        expected_capture.records().len()
    );

    let expected = expected_capture.summary()?;
    let actual = actual_capture.summary()?;
    assert_eq!(actual_capture.records().len(), 1);
    assert_eq!(
        record_length_without_ech(&actual_capture, &actual)?,
        record_length_without_ech(&expected_capture, &expected)?
    );

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
    // Chrome keeps one trust-anchor order for every connection in a browser
    // process, but different processes can use different orders. Cross-capture
    // comparison is therefore membership; the macOS test also pins order.
    assert_eq!(
        sorted_trust_anchor_ids(&actual),
        sorted_trust_anchor_ids(&expected)
    );
    assert_eq!(
        actual.requested_trust_anchor_ids().map(<[_]>::len),
        Some(32)
    );
    // Every retained Chrome sample uses HKDF-SHA256 with AES-128-GCM.
    assert_eq!(
        client_hello_fixture::ech_cipher_suite(actual_capture.handshake_bytes())?,
        client_hello_fixture::ech_cipher_suite(expected_capture.handshake_bytes())?
    );

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
    assert_eq!(
        stable_extension_layout(&actual),
        stable_extension_layout(&expected)
    );
    assert!(actual.extension_types().contains(&TRUST_ANCHORS_EXTENSION));
    Ok(())
}

#[tokio::test]
async fn omitted_trust_anchor_ids_omit_the_extension() -> TestResult<()> {
    let mut settings = v152_tls();
    settings.requested_trust_anchor_ids = None;

    let summary = capture_client_hello_from(&settings).await?.summary()?;
    assert!(!summary.extension_types().contains(&TRUST_ANCHORS_EXTENSION));
    Ok(())
}

fn sorted_trust_anchor_ids(summary: &ClientHelloSummary) -> Option<Vec<Vec<u8>>> {
    summary.requested_trust_anchor_ids().map(|ids| {
        let mut ids = ids.to_vec();
        ids.sort_unstable();
        ids
    })
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

fn stable_extension_layout(summary: &ClientHelloSummary) -> Vec<(u16, usize)> {
    let mut layout = summary
        .extension_layout()
        .filter(|(extension_type, _)| *extension_type != 0xfe0d)
        .map(|(extension_type, payload_length)| {
            (
                if is_grease(extension_type) {
                    GREASE_SENTINEL
                } else {
                    extension_type
                },
                payload_length,
            )
        })
        .collect::<Vec<_>>();
    layout.sort_unstable();
    layout
}

fn record_length_without_ech(
    capture: &ClientHelloCapture,
    summary: &ClientHelloSummary,
) -> TestResult<usize> {
    let ech_payload_length = summary
        .extension_layout()
        .find_map(|(extension_type, payload_length)| {
            (extension_type == 0xfe0d).then_some(payload_length)
        })
        .ok_or("ClientHello has no ECH GREASE extension")?;
    let record = capture
        .records()
        .first()
        .ok_or("ClientHello capture has no TLS record")?;

    // Pinned BoringSSL deliberately chooses the ECH GREASE payload estimate at
    // random in 32-byte increments. Only that payload length is normalized;
    // every other extension payload length is compared exactly above.
    record
        .fragment()
        .len()
        .checked_sub(ech_payload_length)
        .ok_or_else(|| "ECH payload is larger than its TLS record".into())
}
