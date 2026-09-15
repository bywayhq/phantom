//! Safari-specific TLS differential tests.

use phantom_profile::safari::v18_5_macos_tls;
use phantom_testkit::tls::{ClientHelloSummary, is_grease};

use super::{capture_client_hello_from_server_name, client_hello_fixture};
use crate::tls::test_support::TestResult;

const SAFARI_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/safari/18.5/",
    "macos-15.5/client-hello.txt"
));
const SAFARI_SERVER_NAME: &str = "localhost";
const GREASE_SENTINEL: u16 = 0x0a0a;
const PADDING_EXTENSION: u16 = 0x0015;
const CERTIFICATE_COMPRESSION_EXTENSION: u16 = 0x001b;
const SESSION_TICKET_EXTENSION: u16 = 0x0023;
const APPLICATION_SETTINGS_EXTENSIONS: [u16; 2] = [0x4469, 0x44cd];
const ENCRYPTED_CLIENT_HELLO_EXTENSION: u16 = 0xfe0d;
const TRUST_ANCHORS_EXTENSION: u16 = 0xca34;

#[tokio::test]
async fn safari_18_5_macos_matches_retained_client_hello() -> TestResult<()> {
    let expected_capture = client_hello_fixture::capture(SAFARI_FIXTURE).await?;
    let actual_capture =
        capture_client_hello_from_server_name(&v18_5_macos_tls(), SAFARI_SERVER_NAME).await?;

    assert_eq!(
        actual_capture.records().len(),
        expected_capture.records().len()
    );
    assert_eq!(actual_capture.records().len(), 1);
    for (actual, expected) in actual_capture
        .records()
        .iter()
        .zip(expected_capture.records())
    {
        assert_eq!(actual.content_type(), expected.content_type());
        assert_eq!(actual.legacy_version(), expected.legacy_version());
        assert_eq!(actual.wire_bytes().len(), expected.wire_bytes().len());
        assert_eq!(actual.fragment().len(), expected.fragment().len());
    }

    // Semantic decoding excludes only the client random, session ID, and key
    // exchange bytes that carry per-connection cryptographic entropy. Record
    // and extension lengths remain exact comparisons above and below.
    let expected = expected_capture.summary()?;
    let actual = actual_capture.summary()?;
    assert_stable_vectors(&actual, &expected);
    assert_eq!(actual.server_name(), expected.server_name());
    assert_eq!(actual.server_name(), Some(SAFARI_SERVER_NAME.as_bytes()));
    assert_eq!(actual.alpn_protocols(), expected.alpn_protocols());
    assert_eq!(
        actual.alpn_protocols(),
        [b"h2".as_slice(), b"http/1.1".as_slice()]
    );

    assert_eq!(
        normalized_extension_layout(&actual),
        normalized_extension_layout(&expected)
    );
    assert_eq!(actual.extension_types().len(), 16);
    assert_eq!(grease_count(actual.extension_types()), 2);
    assert_absent_extensions(&actual);
    assert_eq!(actual.requested_trust_anchor_ids(), None);

    let expected_padding = [0_u8; 199];
    for capture in [&expected_capture, &actual_capture] {
        assert_eq!(
            client_hello_fixture::extension_payload(capture.handshake_bytes(), PADDING_EXTENSION)?,
            expected_padding.as_slice()
        );
        assert_eq!(
            client_hello_fixture::extension_payload(
                capture.handshake_bytes(),
                CERTIFICATE_COMPRESSION_EXTENSION
            )?,
            &[0x02, 0x00, 0x01]
        );
    }
    Ok(())
}

fn assert_stable_vectors(actual: &ClientHelloSummary, expected: &ClientHelloSummary) {
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
    assert_eq!(
        normalize_grease(actual.supported_versions()),
        normalize_grease(expected.supported_versions())
    );
    assert_eq!(
        normalize_grease(actual.key_share_groups()),
        normalize_grease(expected.key_share_groups())
    );
}

fn normalized_extension_layout(summary: &ClientHelloSummary) -> Vec<(u16, usize)> {
    summary
        .extension_layout()
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
        .collect()
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

fn grease_count(values: &[u16]) -> usize {
    values.iter().filter(|&&value| is_grease(value)).count()
}

fn assert_absent_extensions(summary: &ClientHelloSummary) {
    let extensions = summary.extension_types();
    assert!(!extensions.contains(&SESSION_TICKET_EXTENSION));
    for extension in APPLICATION_SETTINGS_EXTENSIONS {
        assert!(!extensions.contains(&extension));
    }
    assert!(!extensions.contains(&ENCRYPTED_CLIENT_HELLO_EXTENSION));
    assert!(!extensions.contains(&TRUST_ANCHORS_EXTENSION));
}
