//! Chromium-family (Chrome, Edge, Brave, and Opera) TLS differential tests.

use phantom_profile::{TlsSettings, brave, chrome_android, chromium::v154_tls, edge, opera};
use phantom_testkit::tls::{ClientHelloCapture, ClientHelloSummary, is_grease};

use super::{capture_client_hello_from, capture_client_hellos_from, client_hello_fixture};
use crate::tls::test_support::{TEST_SERVER_NAME, TestResult};

const CHROME_154_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/154.0.8037.58/",
    "windows-11-26200/client-hello.txt"
));
const CHROME_154_TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome/154.0.8037.58/",
    "windows-11-26200/trust-anchor-orders.txt"
));
const EDGE_153_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/edge/153.0.4234.48/",
    "windows-11-26200/client-hello.txt"
));
const BRAVE_154_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/brave/154.1.96.59/",
    "windows-11-26200/client-hello.txt"
));
const OPERA_135_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/opera/135.0.5973.92/",
    "windows-11-26200/client-hello.txt"
));
const CHROME_ANDROID_153_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome-android/153.0.8010.52/",
    "android-35-emulator/client-hello.txt"
));
const CHROME_ANDROID_153_TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    "../../../../../fixtures/tls/chrome-android/153.0.8010.52/",
    "android-35-emulator/trust-anchor-orders.txt"
));
const GREASE_SENTINEL: u16 = 0x0a0a;
const TRUST_ANCHORS_EXTENSION: u16 = 0xca34;

#[tokio::test]
async fn chrome_154_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(CHROME_154_FIXTURE, &v154_tls(), Some(28)).await
}

/// Chrome 154 sorts its trust-anchor list before encoding it, so every
/// browser process emits the one order the recipe carries.
#[tokio::test]
async fn chrome_154_tls_recipe_emits_the_sorted_trust_anchor_order() -> TestResult<()> {
    let fields = |key: &str| {
        CHROME_154_TRUST_ANCHOR_ORDERS
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::to_owned)
    };
    assert_eq!(fields("distinct_order_count=").as_deref(), Some("1"));
    assert_eq!(fields("process_count=").as_deref(), Some("60"));
    let encoded = fields("order_0=")
        .and_then(|order| order.split_once(",ids:").map(|(_, ids)| ids.to_owned()))
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
    let mut sorted = expected.clone();
    sorted.sort_unstable();
    assert_eq!(expected, sorted, "the captured order is not ascending");

    let actual = capture_client_hello_from(&v154_tls()).await?.summary()?;
    let actual = actual
        .requested_trust_anchor_ids()
        .ok_or("Chrome 154 recipe omitted trust-anchor IDs")?
        .to_vec();
    assert_eq!(actual, expected);
    Ok(())
}

#[tokio::test]
async fn chrome_android_153_tls_recipe_matches_android_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(
        CHROME_ANDROID_153_FIXTURE,
        &chrome_android::v153_tls(),
        Some(28),
    )
    .await
}

/// Chrome 153 does not sort its trust-anchor list. Every process of the
/// Android capture sent one unsorted order, which the recipe carries.
#[tokio::test]
async fn chrome_android_153_tls_recipe_emits_the_captured_trust_anchor_order() -> TestResult<()> {
    let field = |key: &str| {
        CHROME_ANDROID_153_TRUST_ANCHOR_ORDERS
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::to_owned)
    };
    assert_eq!(field("browser_version=").as_deref(), Some("153.0.8010.52"));
    assert_eq!(field("distinct_order_count=").as_deref(), Some("1"));
    let encoded = field("order_0=")
        .and_then(|order| order.split_once(",ids:").map(|(_, ids)| ids.to_owned()))
        .ok_or("trust-anchor order fixture omitted order_0")?;
    let expected = decode_ids(&encoded)?;
    let mut sorted = expected.clone();
    sorted.sort_unstable();
    assert_ne!(
        expected, sorted,
        "the Chrome 153 order is not the sorted one"
    );

    let actual = capture_client_hello_from(&chrome_android::v153_tls())
        .await?
        .summary()?;
    let actual = actual
        .requested_trust_anchor_ids()
        .ok_or("Chrome 153 recipe omitted trust-anchor IDs")?
        .to_vec();
    assert_eq!(actual, expected);
    Ok(())
}

fn decode_ids(encoded: &str) -> Result<Vec<Vec<u8>>, std::num::ParseIntError> {
    encoded
        .split(',')
        .map(|id| {
            (0..id.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&id[index..index + 2], 16))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

/// Edge 153 sends the Chromium ClientHello without trust-anchor IDs.
#[tokio::test]
async fn edge_153_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(EDGE_153_FIXTURE, &edge::v153_tls(), None).await
}

/// Brave 154 sends the Chrome 154 ClientHello without trust-anchor IDs.
#[tokio::test]
async fn brave_154_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(BRAVE_154_FIXTURE, &brave::v154_tls(), None).await
}

/// Opera 135 sends the Chrome 154 ClientHello without trust-anchor IDs and
/// without a GREASE signature algorithm; the replay compares the signature
/// algorithm list with its GREASE entries in place.
#[tokio::test]
async fn opera_135_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(OPERA_135_FIXTURE, &opera::v135_tls(), None).await
}

/// Chromium-family browsers advertise HKDF-SHA256 with AES-128-GCM on every
/// connection; their recipes keep the backend default AEAD policy.
#[tokio::test]
async fn chromium_recipes_emit_aes_128_gcm_ech_grease_on_every_connection() -> TestResult<()> {
    const AES_128_GCM: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x01];
    for settings in [
        v154_tls(),
        edge::v153_tls(),
        brave::v154_tls(),
        opera::v135_tls(),
        chrome_android::v153_tls(),
    ] {
        assert!(settings.ech_grease_aeads.is_empty());
        for capture in capture_client_hellos_from(&settings, TEST_SERVER_NAME, 64).await? {
            assert_eq!(
                client_hello_fixture::ech_cipher_suite(capture.handshake_bytes())?,
                AES_128_GCM
            );
        }
    }
    Ok(())
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
    // Cross-capture comparison is membership only; the Chrome 154 order test
    // pins the exact order the connector emits.
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
    let mut settings = v154_tls();
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
