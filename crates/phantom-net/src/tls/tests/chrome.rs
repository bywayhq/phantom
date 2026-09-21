//! Chromium-family (Chrome and Edge) TLS differential tests.

use phantom_profile::{
    TlsSettings,
    chromium::{v152_tls, v153_tls},
    edge,
};
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
const CHROME_153_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/153.0.8010.48/",
    "windows-11-26200/client-hello.txt"
));
const CHROME_153_TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/153.0.8010.48/",
    "windows-11-26200/trust-anchor-orders.txt"
));
const EDGE_153_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/edge/153.0.4234.48/",
    "windows-11-26200/client-hello.txt"
));
const GREASE_SENTINEL: u16 = 0x0a0a;
const TRUST_ANCHORS_EXTENSION: u16 = 0xca34;

#[tokio::test]
async fn chromium_152_macos_matches_retained_client_hello() -> TestResult<()> {
    assert_recipe_matches_fixture(CHROME_FIXTURE, &v152_tls(), Some(32)).await?;
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
    assert_recipe_matches_fixture(WINDOWS_CHROME_FOR_TESTING_FIXTURE, &v152_tls(), Some(32)).await
}

#[tokio::test]
async fn chrome_153_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(CHROME_153_FIXTURE, &v153_tls(), Some(28)).await
}

/// Each Chrome process fixes one trust-anchor order; the recipe emits the
/// order observed in the most fresh processes (`order_0`).
#[tokio::test]
async fn chrome_153_tls_recipe_emits_the_most_frequent_trust_anchor_order() -> TestResult<()> {
    let encoded = CHROME_153_TRUST_ANCHOR_ORDERS
        .lines()
        .find_map(|line| line.strip_prefix("order_0="))
        .and_then(|order| order.split_once(",ids:"))
        .map(|(_, ids)| ids)
        .ok_or("trust-anchor order fixture omitted order_0")?;
    let expected = encoded
        .split(',')
        .map(|id| {
            (0..id.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&id[index..index + 2], 16))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let actual = capture_client_hello_from(&v153_tls()).await?.summary()?;
    let actual = actual
        .requested_trust_anchor_ids()
        .ok_or("Chrome 153 recipe omitted trust-anchor IDs")?
        .to_vec();
    assert_eq!(actual, expected);
    Ok(())
}

/// Edge 153 sends the Chrome 153 ClientHello without trust-anchor IDs.
#[tokio::test]
async fn edge_153_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(EDGE_153_FIXTURE, &edge::v153_tls(), None).await
}

async fn assert_recipe_matches_fixture(
    fixture: &str,
    settings: &TlsSettings,
    trust_anchor_id_count: Option<usize>,
) -> TestResult<()> {
    let expected_capture = client_hello_fixture::capture(fixture).await?;
    let actual_capture = capture_client_hello_from(settings).await?;

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
        trust_anchor_id_count
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
    assert_eq!(
        actual.extension_types().contains(&TRUST_ANCHORS_EXTENSION),
        trust_anchor_id_count.is_some()
    );
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
