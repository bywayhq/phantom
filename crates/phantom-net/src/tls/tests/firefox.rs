//! Firefox-specific TLS differential tests.

use phantom_profile::{TlsSettings, firefox::v156_tls};
use phantom_testkit::tls::ClientHelloSummary;

use super::{
    capture_client_hello_from_server_name, capture_client_hellos_from, client_hello_fixture,
};
use crate::tls::test_support::TestResult;

const WINDOWS_FIREFOX_156_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/firefox/156.0/",
    "windows-11-26200/client-hello.txt"
));
const WINDOWS_FIREFOX_156_CHACHA20_ECH_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/firefox/156.0/",
    "windows-11-26200/client-hello-chacha20-ech.txt"
));
const FIREFOX_SERVER_NAME: &str = "localhost";
// ECHClientHello type outer (0), HKDF-SHA256 (0x0001), then the AEAD.
const AES_128_GCM: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x01];
const CHACHA20_POLY1305: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x03];
const DELEGATED_CREDENTIAL_EXTENSION: u16 = 0x0022;
const RECORD_SIZE_LIMIT_EXTENSION: u16 = 0x001c;
const CERTIFICATE_COMPRESSION_EXTENSION: u16 = 0x001b;
const ENCRYPTED_CLIENT_HELLO_EXTENSION: u16 = 0xfe0d;

#[tokio::test]
async fn firefox_156_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(WINDOWS_FIREFOX_156_FIXTURE, &v156_tls(), 282).await
}

#[tokio::test]
async fn firefox_156_tls_recipe_matches_windows_capture_with_chacha20_ech_grease() -> TestResult<()>
{
    assert_recipe_matches_fixture(WINDOWS_FIREFOX_156_CHACHA20_ECH_FIXTURE, &v156_tls(), 282).await
}

/// Firefox 156 still picks the ECH GREASE AEAD per connection (7 AES-128-GCM
/// and 5 ChaCha20-Poly1305 of 12 Windows samples); one of each is retained.
#[tokio::test]
async fn firefox_156_recipe_draws_either_ech_grease_aead_per_connection() -> TestResult<()> {
    assert_recipe_draws_either_ech_grease_aead(
        [
            WINDOWS_FIREFOX_156_FIXTURE,
            WINDOWS_FIREFOX_156_CHACHA20_ECH_FIXTURE,
        ],
        &v156_tls(),
    )
    .await
}

/// Replays both retained AEAD branches, then requires one connector's
/// ClientHellos to draw only those two AEADs in fair proportion.
async fn assert_recipe_draws_either_ech_grease_aead(
    fixtures: [&str; 2],
    settings: &TlsSettings,
) -> TestResult<()> {
    const CONNECTIONS: usize = 200;
    let mut captured = Vec::new();
    for fixture in fixtures {
        let capture = client_hello_fixture::capture(fixture).await?;
        captured.push(client_hello_fixture::ech_cipher_suite(
            capture.handshake_bytes(),
        )?);
    }
    assert_eq!(captured, [AES_128_GCM, CHACHA20_POLY1305]);

    let (mut aes_128_gcm, mut chacha20_poly1305) = (0_usize, 0_usize);
    for capture in capture_client_hellos_from(settings, FIREFOX_SERVER_NAME, CONNECTIONS).await? {
        match client_hello_fixture::ech_cipher_suite(capture.handshake_bytes())? {
            AES_128_GCM => aes_128_gcm += 1,
            CHACHA20_POLY1305 => chacha20_poly1305 += 1,
            other => return Err(format!("unexpected ECH GREASE cipher suite {other:02x?}").into()),
        }
    }
    // A fair draw leaves each count within 100 +/- 40 (5.6 standard
    // deviations) except with probability below 1e-7.
    assert_eq!(aes_128_gcm + chacha20_poly1305, CONNECTIONS);
    assert!(
        (60..=140).contains(&aes_128_gcm),
        "AES-128-GCM chosen {aes_128_gcm} of {CONNECTIONS} times"
    );
    Ok(())
}

async fn assert_recipe_matches_fixture(
    fixture: &str,
    settings: &TlsSettings,
    ech_extension_length: usize,
) -> TestResult<()> {
    let expected_capture = client_hello_fixture::capture(fixture).await?;
    let actual_capture =
        capture_client_hello_from_server_name(settings, FIREFOX_SERVER_NAME).await?;

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
            ech_extension_length
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
