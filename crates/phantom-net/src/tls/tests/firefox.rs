//! Firefox-specific TLS differential tests.

use phantom_profile::firefox::v154_tls;
use phantom_testkit::tls::ClientHelloSummary;

use super::{capture_client_hello_from_server_name, client_hello_fixture};
use crate::tls::test_support::TestResult;

const FIREFOX_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/firefox/154.0/",
    "macos-15.5/client-hello.txt"
));
const WINDOWS_FIREFOX_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/firefox/154.0/",
    "windows-11-26200/client-hello.txt"
));
const FIREFOX_SERVER_NAME: &str = "localhost";
const DELEGATED_CREDENTIAL_EXTENSION: u16 = 0x0022;
const RECORD_SIZE_LIMIT_EXTENSION: u16 = 0x001c;
const CERTIFICATE_COMPRESSION_EXTENSION: u16 = 0x001b;
const ENCRYPTED_CLIENT_HELLO_EXTENSION: u16 = 0xfe0d;

#[tokio::test]
async fn firefox_154_macos_matches_retained_client_hello() -> TestResult<()> {
    assert_recipe_matches_fixture(FIREFOX_FIXTURE).await
}

#[tokio::test]
async fn firefox_154_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(WINDOWS_FIREFOX_FIXTURE).await
}

/// Firefox picks AES-128-GCM or ChaCha20-Poly1305 for each ECH GREASE
/// extension. The backend exposes no per-connection AEAD choice, so the recipe
/// reproduces only the AES-128-GCM branch.
#[tokio::test]
async fn firefox_154_recipe_emits_the_aes_128_gcm_ech_grease_choice() -> TestResult<()> {
    // ECHClientHello type outer (0), HKDF-SHA256 (0x0001), then the AEAD.
    const AES_128_GCM: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x01];
    const CHACHA20_POLY1305: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x03];
    let mut captured = Vec::new();
    for fixture in [FIREFOX_FIXTURE, WINDOWS_FIREFOX_FIXTURE] {
        let capture = client_hello_fixture::capture(fixture).await?;
        captured.push(client_hello_fixture::ech_cipher_suite(
            capture.handshake_bytes(),
        )?);
    }
    assert_eq!(captured, [AES_128_GCM, CHACHA20_POLY1305]);

    let actual = capture_client_hello_from_server_name(&v154_tls(), FIREFOX_SERVER_NAME).await?;
    assert_eq!(
        client_hello_fixture::ech_cipher_suite(actual.handshake_bytes())?,
        AES_128_GCM
    );
    Ok(())
}

async fn assert_recipe_matches_fixture(fixture: &str) -> TestResult<()> {
    let expected_capture = client_hello_fixture::capture(fixture).await?;
    let actual_capture =
        capture_client_hello_from_server_name(&v154_tls(), FIREFOX_SERVER_NAME).await?;

    assert_eq!(actual_capture.records().len(), 1);
    assert_eq!(
        actual_capture.records().len(),
        expected_capture.records().len()
    );
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

    // Client random, session ID, key-share bytes, and ECH payload are fresh
    // cryptographic entropy. Every ordered semantic vector, extension payload
    // length, and record boundary remains an exact comparison.
    let expected = expected_capture.summary()?;
    let actual = actual_capture.summary()?;
    assert_stable_vectors(&actual, &expected);
    assert_eq!(actual.server_name(), expected.server_name());
    assert_eq!(actual.server_name(), Some(FIREFOX_SERVER_NAME.as_bytes()));
    assert_eq!(actual.alpn_protocols(), expected.alpn_protocols());
    assert_eq!(
        actual.alpn_protocols(),
        [b"h2".as_slice(), b"http/1.1".as_slice()]
    );
    assert_eq!(actual.extension_types(), expected.extension_types());
    assert_eq!(
        actual.extension_layout().collect::<Vec<_>>(),
        expected.extension_layout().collect::<Vec<_>>()
    );
    assert_eq!(actual.requested_trust_anchor_ids(), None);

    const DELEGATED_CREDENTIAL_BODY: &[u8] =
        &[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03];
    const RECORD_SIZE_LIMIT_BODY: &[u8] = &[0x40, 0x01];
    const CERTIFICATE_COMPRESSION_BODY: &[u8] = &[0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
    for capture in [&expected_capture, &actual_capture] {
        assert_eq!(
            client_hello_fixture::extension_payload(
                capture.handshake_bytes(),
                DELEGATED_CREDENTIAL_EXTENSION,
            )?,
            DELEGATED_CREDENTIAL_BODY
        );
        assert_eq!(
            client_hello_fixture::extension_payload(
                capture.handshake_bytes(),
                RECORD_SIZE_LIMIT_EXTENSION,
            )?,
            RECORD_SIZE_LIMIT_BODY
        );
        assert_eq!(
            client_hello_fixture::extension_payload(
                capture.handshake_bytes(),
                CERTIFICATE_COMPRESSION_EXTENSION,
            )?,
            CERTIFICATE_COMPRESSION_BODY
        );
        assert_eq!(
            client_hello_fixture::extension_payload(
                capture.handshake_bytes(),
                ENCRYPTED_CLIENT_HELLO_EXTENSION,
            )?
            .len(),
            281
        );
    }

    Ok(())
}

fn assert_stable_vectors(actual: &ClientHelloSummary, expected: &ClientHelloSummary) {
    assert_eq!(actual.legacy_version(), expected.legacy_version());
    assert_eq!(actual.cipher_suites(), expected.cipher_suites());
    assert_eq!(actual.supported_groups(), expected.supported_groups());
    assert_eq!(actual.ec_point_formats(), expected.ec_point_formats());
    assert_eq!(
        actual.signature_algorithms(),
        expected.signature_algorithms()
    );
    assert_eq!(actual.supported_versions(), expected.supported_versions());
    assert_eq!(actual.key_share_groups(), expected.key_share_groups());
}
