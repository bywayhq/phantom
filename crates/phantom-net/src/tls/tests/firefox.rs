//! Firefox-specific TLS differential tests.

use phantom_profile::{TlsSettings, firefox::v157_tls};
use phantom_testkit::tls::ClientHelloSummary;

use super::{
    capture_client_hello_from_server_name, capture_client_hellos_from, client_hello_fixture,
};
use crate::tls::test_support::{TestResult, nss_ech_grease};

const WINDOWS_FIREFOX_157_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/firefox/157.0/",
    "windows-11-26200/client-hello.txt"
));
const WINDOWS_FIREFOX_157_CHACHA20_ECH_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/firefox/157.0/",
    "windows-11-26200/client-hello-chacha20-ech.txt"
));
const ANDROID_FIREFOX_156_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/firefox-android/156.0.1/",
    "android-35-emulator/client-hello.txt"
));
const ANDROID_FIREFOX_156_CHACHA20_ECH_FIXTURE: &str = include_str!(concat!(
    "../../../../../fixtures/tls/firefox-android/156.0.1/",
    "android-35-emulator/client-hello-chacha20-ech.txt"
));
macro_rules! ip_literal_fixture {
    ($name:literal) => {
        include_str!(concat!(
            "../../../../../fixtures/tls/firefox/157.0/windows-11-26200/ip-literal/",
            $name,
            ".txt"
        ))
    };
}

/// Firefox 157's TCP ClientHellos to `https://127.0.0.1:<port>/` and
/// `https://[::1]:<port>/`, with the `security.tls.ech.grease_size` each
/// run used: 100 by default, and on either side of the size at which one
/// more byte of padding adds a 32-byte block for that host.
const IP_LITERAL_CAPTURES: [(&str, &str, usize); 6] = [
    (ip_literal_fixture!("tcp-ipv4"), "127.0.0.1", 100),
    (
        ip_literal_fixture!("tcp-ipv4-grease-size-93"),
        "127.0.0.1",
        93,
    ),
    (
        ip_literal_fixture!("tcp-ipv4-grease-size-94"),
        "127.0.0.1",
        94,
    ),
    (ip_literal_fixture!("tcp-ipv6"), "::1", 100),
    (ip_literal_fixture!("tcp-ipv6-grease-size-87"), "::1", 87),
    (ip_literal_fixture!("tcp-ipv6-grease-size-88"), "::1", 88),
];
const FIREFOX_SERVER_NAME: &str = "localhost";
// ECHClientHello type outer (0), HKDF-SHA256 (0x0001), then the AEAD.
const AES_128_GCM: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x01];
const CHACHA20_POLY1305: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x03];
const DELEGATED_CREDENTIAL_EXTENSION: u16 = 0x0022;
const RECORD_SIZE_LIMIT_EXTENSION: u16 = 0x001c;
const CERTIFICATE_COMPRESSION_EXTENSION: u16 = 0x001b;
const ENCRYPTED_CLIENT_HELLO_EXTENSION: u16 = 0xfe0d;

#[tokio::test]
async fn firefox_157_tls_recipe_matches_windows_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(WINDOWS_FIREFOX_157_FIXTURE, &v157_tls(), 282).await
}

#[tokio::test]
async fn firefox_157_tls_recipe_matches_windows_capture_with_chacha20_ech_grease() -> TestResult<()>
{
    assert_recipe_matches_fixture(WINDOWS_FIREFOX_157_CHACHA20_ECH_FIXTURE, &v157_tls(), 282).await
}

/// Firefox 156.0.1 for Android sends the desktop Firefox 156 ClientHello:
/// the same fixed extension order and a per-connection ECH GREASE AEAD.
#[tokio::test]
async fn firefox_android_156_tls_recipe_matches_android_captures() -> TestResult<()> {
    let recipe = phantom_profile::firefox_android::v156_tls();
    assert_eq!(recipe, v157_tls());
    assert_recipe_matches_fixture(ANDROID_FIREFOX_156_FIXTURE, &recipe, 282).await?;
    assert_recipe_matches_fixture(ANDROID_FIREFOX_156_CHACHA20_ECH_FIXTURE, &recipe, 282).await
}

/// Firefox 157 still picks the ECH GREASE AEAD per connection: 36 of 69
/// Windows TCP ClientHellos used AES-128-GCM and 33 ChaCha20-Poly1305 (the
/// five snapshots and the first run of each TLS resumption scenario). One
/// standalone sample of each is retained.
#[tokio::test]
async fn firefox_157_recipe_draws_either_ech_grease_aead_per_connection() -> TestResult<()> {
    assert_recipe_draws_either_ech_grease_aead(
        [
            WINDOWS_FIREFOX_157_FIXTURE,
            WINDOWS_FIREFOX_157_CHACHA20_ECH_FIXTURE,
        ],
        &v157_tls(),
    )
    .await
}

macro_rules! firefox_157_fixtures {
    ($directory:literal: $($name:literal),+ $(,)?) => {
        [$(include_str!(concat!(
            "../../../../../fixtures/",
            $directory,
            "/firefox/157.0/windows-11-26200/",
            $name,
            ".txt"
        ))),+]
    };
}

/// Every ClientHello record in the Firefox 157.0 TCP and QUIC fixtures to a
/// host name, fresh or resumed, carries the ECH GREASE payload NSS's rule
/// gives it with a `maximum_name_length` of 100. The files split from a
/// snapshot repeat some records.
#[test]
fn firefox_157_captured_ech_grease_payloads_follow_the_nss_rule() -> TestResult<()> {
    let tcp = firefox_157_fixtures!("tls":
        "client-hello",
        "client-hello-chacha20-ech",
        "resumption-issue-once",
        "resumption-methods",
        "resumption-methods-http1",
        "resumption-no-early-data",
        "resumption-origins",
        "resumption-parallel",
        "resumption-partition",
        "resumption-sequential",
        "resumption-sequential-http1",
    );
    let quic = firefox_157_fixtures!("http3":
        "quic-client-hello-1",
        "quic-client-hello-2",
        "quic-client-hello-3",
        "resumption-accept",
        "resumption-accept-delayed",
        "resumption-reject",
        "snapshot-1",
        "snapshot-2",
        "snapshot-3",
        "snapshot-4",
        "snapshot-5",
    );
    let mut lengths = Vec::new();
    for fixture in tcp.into_iter().chain(quic) {
        for (key, value) in fixture.lines().filter_map(|line| line.split_once('=')) {
            if !(key.ends_with("client_hello_hex") || key.ends_with("handshake_hex")) {
                continue;
            }
            let hello = client_hello_fixture::decode_hex(value)?;
            if hello.first() != Some(&1) {
                continue;
            }
            let sent = nss_ech_grease::sent_payload_length(&hello)?;
            assert_eq!(
                sent,
                nss_ech_grease::payload_length(&hello, 100, None)?,
                "{key}"
            );
            lengths.push(sent);
        }
    }
    let fresh = lengths.iter().filter(|&&length| length == 240).count();
    let resumed = lengths.iter().filter(|&&length| length == 368).count();
    assert_eq!((fresh, resumed, lengths.len()), (41, 46, 87));
    Ok(())
}

/// Firefox sends no `server_name` to an IP literal but pads its ECH GREASE
/// payload by the address text, an IPv6 address without brackets. Each pair
/// of runs straddles the `grease_size` at which one more byte of padding
/// adds a 32-byte block, which pins the padded length: padding by no host
/// would already add that block in the run below the boundary.
#[test]
fn firefox_157_ip_literal_captures_pad_ech_grease_by_the_host_text() -> TestResult<()> {
    for (fixture, host, grease_size) in IP_LITERAL_CAPTURES {
        let hellos = fixture_client_hellos(fixture)?;
        // Firefox retries a connection the listener closed, and the later
        // ClientHellos drop `compress_certificate`; the rule covers them too.
        for hello in &hellos {
            let summary = ClientHelloSummary::from_handshake_bytes(hello)?;
            assert_eq!(summary.server_name(), None);
            assert_eq!(
                nss_ech_grease::sent_payload_length(hello)?,
                nss_ech_grease::payload_length(hello, grease_size, Some(host.len()))?,
                "{host} at grease_size {grease_size}"
            );
        }
        let first = hellos.first().ok_or("the capture holds no ClientHello")?;
        let below_boundary = grease_size == 93 || grease_size == 87;
        let sent = nss_ech_grease::sent_payload_length(first)?;
        assert_eq!(sent, if below_boundary { 208 } else { 240 });
        if below_boundary {
            assert_ne!(
                nss_ech_grease::payload_length(first, grease_size, Some(0))?,
                sent
            );
        }
    }
    Ok(())
}

/// To an IP literal the recipe sends Firefox's first ClientHello shape: no
/// `server_name`, the same extensions and lengths, and the same 240-byte ECH
/// GREASE payload, padded by the address text.
#[tokio::test]
async fn firefox_157_recipe_matches_the_ip_literal_captures() -> TestResult<()> {
    for (fixture, host) in [
        (ip_literal_fixture!("tcp-ipv4"), "127.0.0.1"),
        (ip_literal_fixture!("tcp-ipv6"), "::1"),
    ] {
        let expected_hello = fixture_client_hellos(fixture)?
            .into_iter()
            .next()
            .ok_or("the capture holds no ClientHello")?;
        let expected = ClientHelloSummary::from_handshake_bytes(&expected_hello)?;
        let actual_capture = capture_client_hello_from_server_name(&v157_tls(), host).await?;
        let actual_hello = actual_capture.handshake_bytes();
        let actual = actual_capture.summary()?;
        assert_stable_vectors(&actual, &expected);
        assert_eq!(actual.server_name(), None);
        assert_eq!(
            actual.extension_layout().collect::<Vec<_>>(),
            expected.extension_layout().collect::<Vec<_>>()
        );
        assert_eq!(nss_ech_grease::sent_payload_length(actual_hello)?, 240);
        assert_eq!(
            nss_ech_grease::sent_payload_length(actual_hello)?,
            nss_ech_grease::payload_length(actual_hello, 100, Some(host.len()))?
        );
    }
    Ok(())
}

/// Returns every ClientHello a capture script's `client_hello_<n>_hex` lines
/// hold.
fn fixture_client_hellos(fixture: &str) -> TestResult<Vec<Vec<u8>>> {
    fixture
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| key.starts_with("client_hello_") && key.ends_with("_hex"))
        .map(|(_, value)| Ok(client_hello_fixture::decode_hex(value)?))
        .collect()
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
    // Each capture names the host it reached; both map the test name with
    // `network.dns.localDomains`.
    let server_name = fixture
        .lines()
        .find_map(|line| line.strip_prefix("hostname="))
        .unwrap_or(FIREFOX_SERVER_NAME);
    let expected_capture = client_hello_fixture::capture(fixture).await?;
    let actual_capture = capture_client_hello_from_server_name(settings, server_name).await?;

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
    assert_eq!(actual.server_name(), Some(server_name.as_bytes()));
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
