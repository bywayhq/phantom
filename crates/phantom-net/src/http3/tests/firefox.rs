//! The Firefox 156 HTTP/3 recipe against the retained Firefox 156.0.1 captures.

use std::{net::SocketAddr, sync::Arc};

use btls::ssl::{AlpnError, select_next_proto};
use phantom_profile::firefox;
use phantom_quic_btls::{QuicServerConfig, ServerHandshakeData};
use phantom_testkit::tls::ClientHelloSummary;
use tokio::{net::UdpSocket, time::timeout};

use super::super::Http3Connector;
use super::connector::{client_hello_extension, fixture_hex};
use super::{TEST_TIMEOUT, TestResult};
use crate::tls::test_support::{TEST_SERVER_NAME, TestIdentity};

const SNAPSHOTS: [&str; 3] = [
    include_str!("../../../../../fixtures/http3/firefox/156.0.1/windows-11-26200/snapshot-1.txt"),
    include_str!("../../../../../fixtures/http3/firefox/156.0.1/windows-11-26200/snapshot-2.txt"),
    include_str!("../../../../../fixtures/http3/firefox/156.0.1/windows-11-26200/snapshot-3.txt"),
];
const CLIENT_HELLOS: [&str; 3] = [
    include_str!(
        "../../../../../fixtures/http3/firefox/156.0.1/windows-11-26200/quic-client-hello-1.txt"
    ),
    include_str!(
        "../../../../../fixtures/http3/firefox/156.0.1/windows-11-26200/quic-client-hello-2.txt"
    ),
    include_str!(
        "../../../../../fixtures/http3/firefox/156.0.1/windows-11-26200/quic-client-hello-3.txt"
    ),
];
const H3_ALPN_WIRE: &[u8] = b"\x02h3";
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;
/// `record_size_limit`, `extended_master_secret`, and `renegotiation_info`.
const OMITTED_BY_BORINGSSL: [u16; 3] = [0x1c, 0x17, 0xff01];
const QUIC_V1: u32 = 1;
const QUIC_V2: u32 = 0x6b33_43cf;

fn connector(identity: &TestIdentity) -> TestResult<Http3Connector> {
    Ok(Http3Connector::new_with_additional_roots(
        &firefox::v156_http3_tls(),
        &firefox::v156_quic(),
        &firefox::v156_http3(),
        &firefox::v156_http3_request(),
        [identity.root_der()],
    )?)
}

/// A loopback BoringSSL QUIC server that records the ClientHello.
fn server(identity: &TestIdentity) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let mut builder = identity.acceptor_builder()?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(H3_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    let crypto = QuicServerConfig::new(builder.build().into_context());
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// One transport parameter: identifier, identifier width, length width, value.
type Parameter = (u64, usize, usize, Vec<u8>);

fn transport_parameters(encoded: &[u8]) -> TestResult<Vec<Parameter>> {
    let mut offset = 0;
    let mut parameters = Vec::new();
    while offset < encoded.len() {
        let (id, id_width) = varint(encoded, &mut offset)?;
        let (length, length_width) = varint(encoded, &mut offset)?;
        let end = offset + usize::try_from(length)?;
        let value = encoded.get(offset..end).ok_or("truncated parameter")?;
        parameters.push((id, id_width, length_width, value.to_vec()));
        offset = end;
    }
    Ok(parameters)
}

fn varint(bytes: &[u8], offset: &mut usize) -> TestResult<(u64, usize)> {
    let first = *bytes.get(*offset).ok_or("truncated varint")?;
    let width = 1 << (first >> 6);
    let slice = bytes
        .get(*offset..*offset + width)
        .ok_or("truncated varint")?;
    let mut value = u64::from(first & 0x3f);
    for byte in &slice[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *offset += width;
    Ok((value, width))
}

fn words(value: &[u8]) -> Vec<u32> {
    value
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_be_bytes(*word))
        .collect()
}

/// Compares a Phantom transport-parameter list with a captured one: the same
/// parameters in the same order and encoding, with the connection ID bytes
/// and the reserved version free to differ.
fn assert_parameters_match(actual: &[Parameter], captured: &[Parameter]) {
    assert_eq!(actual.len(), captured.len());
    for (actual, captured) in actual.iter().zip(captured) {
        assert_eq!(
            (actual.0, actual.1, actual.2),
            (captured.0, captured.1, captured.2),
            "parameter {:#x}",
            captured.0
        );
        match captured.0 {
            0x0f => assert_eq!(actual.3.len(), captured.3.len()),
            0x11 => {
                let (actual, captured) = (words(&actual.3), words(&captured.3));
                assert_eq!(actual.len(), captured.len());
                assert_eq!(actual[0], QUIC_V1);
                assert_eq!(actual[1] & 0x0f0f_0f0f, 0x0a0a_0a0a);
                assert_eq!(captured[1] & 0x0f0f_0f0f, 0x0a0a_0a0a);
                assert_eq!(actual[2..], captured[2..]);
                assert_eq!(actual[2..], [QUIC_V2, QUIC_V1]);
            }
            _ => assert_eq!(actual.3, captured.3, "parameter {:#x}", captured.0),
        }
    }
}

fn extension_set(summary: &ClientHelloSummary) -> Vec<u16> {
    let mut extensions = summary.extension_types().to_vec();
    extensions.sort_unstable();
    extensions
}

#[tokio::test(flavor = "current_thread")]
async fn firefox_156_quic_offer_and_streams_match_windows_capture() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = connector(&identity)?;
    let (address, endpoint) = server(&identity)?;
    let host = address.ip().to_string();
    let client = async {
        connector
            .connect_direct(&host, address.port(), TEST_SERVER_NAME)
            .await
            .map_err(Into::into)
    };
    let observed = async {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let mut connecting = incoming.accept()?;
        let data = connecting
            .handshake_data()
            .await?
            .downcast::<ServerHandshakeData>()
            .map_err(|_| "unexpected server handshake data")?;
        let connection = connecting.await?;
        TestResult::Ok((data.client_hello().to_vec(), connection))
    };
    let (_client, (client_hello, connection)) =
        timeout(TEST_TIMEOUT, async { tokio::try_join!(client, observed) }).await??;

    let actual = ClientHelloSummary::from_handshake_bytes(&client_hello)?;
    let actual_parameters = transport_parameters(
        client_hello_extension(&client_hello, QUIC_TRANSPORT_PARAMETERS)
            .ok_or("Phantom sent no transport parameters")?,
    )?;
    for (snapshot, client_hello_fixture) in SNAPSHOTS.iter().zip(CLIENT_HELLOS) {
        let expected_hello = fixture_hex(client_hello_fixture, "handshake_hex")?;
        let expected = ClientHelloSummary::from_handshake_bytes(&expected_hello)?;
        assert_eq!(actual.cipher_suites(), expected.cipher_suites());
        assert_eq!(actual.supported_versions(), expected.supported_versions());
        assert_eq!(actual.supported_groups(), expected.supported_groups());
        assert_eq!(actual.key_share_groups(), expected.key_share_groups());
        assert_eq!(
            actual.signature_algorithms(),
            expected.signature_algorithms()
        );
        assert_eq!(actual.alpn_protocols(), expected.alpn_protocols());
        assert_eq!(actual.server_name(), expected.server_name());
        // BoringSSL refuses record_size_limit on QUIC connections and omits the
        // TLS 1.2 extensions from a TLS 1.3-only offer.
        let mut captured_extensions = extension_set(&expected);
        captured_extensions.retain(|extension| !OMITTED_BY_BORINGSSL.contains(extension));
        assert_eq!(extension_set(&actual), captured_extensions);
        // delegated_credentials, status_request, compress_certificate, and
        // psk_key_exchange_modes bodies.
        for extension in [0x22, 0x05, 0x1b, 0x2d] {
            assert_eq!(
                client_hello_extension(&client_hello, extension),
                client_hello_extension(&expected_hello, extension),
                "extension {extension:#06x}"
            );
        }
        assert_eq!(
            client_hello_extension(&client_hello, 0xfe0d).map(<[u8]>::len),
            client_hello_extension(&expected_hello, 0xfe0d).map(<[u8]>::len),
        );
        let captured =
            transport_parameters(&fixture_hex(snapshot, "h3.transport_parameters_hex")?)?;
        assert_parameters_match(&actual_parameters, &captured);
    }

    // Client streams 2, 6, and 10: control, QPACK encoder, QPACK decoder.
    let expected_settings = fixture_hex(SNAPSHOTS[0], "h3.settings_frame_hex")?;
    let mut types = Vec::new();
    for _ in 0..3 {
        let mut stream = timeout(TEST_TIMEOUT, connection.accept_uni()).await??;
        let id = stream.id().index() * 4 + 2;
        let mut bytes = Vec::new();
        while let Some(chunk) = timeout(TEST_TIMEOUT, stream.read_chunk(256, true)).await?? {
            bytes.extend_from_slice(&chunk.bytes);
            if bytes.first() != Some(&0x00) || bytes.len() > expected_settings.len() + 16 {
                break;
            }
            if control_prefix_complete(&bytes, expected_settings.len())? {
                break;
            }
        }
        let stream_type = *bytes.first().ok_or("empty unidirectional stream")?;
        types.push((id, stream_type));
        if stream_type == 0x00 {
            assert_eq!(&bytes[1..=expected_settings.len()], expected_settings);
            let mut offset = 1 + expected_settings.len();
            let (frame_type, _) = varint(&bytes, &mut offset)?;
            let (length, _) = varint(&bytes, &mut offset)?;
            assert!(frame_type >= 0x21 && (frame_type - 0x21) % 0x1f == 0);
            assert!(length <= 7);
        }
    }
    types.sort_unstable();
    assert_eq!(types, [(2, 0x00), (6, 0x02), (10, 0x03)]);
    Ok(())
}

/// Whether `bytes` holds the stream type, SETTINGS, and one whole frame after it.
fn control_prefix_complete(bytes: &[u8], settings_len: usize) -> TestResult<bool> {
    let mut offset = 1 + settings_len;
    if bytes.len() <= offset {
        return Ok(false);
    }
    let Ok((_, _)) = varint(bytes, &mut offset) else {
        return Ok(false);
    };
    let Ok((length, _)) = varint(bytes, &mut offset) else {
        return Ok(false);
    };
    Ok(bytes.len() >= offset + usize::try_from(length)?)
}

#[tokio::test(flavor = "current_thread")]
async fn firefox_156_initial_datagrams_match_windows_capture() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = connector(&identity)?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let host = address.ip().to_string();
    let attempt = tokio::spawn(async move {
        let _ = connector
            .connect_direct(&host, address.port(), TEST_SERVER_NAME)
            .await;
    });

    // The X25519MLKEM768 key share puts the ClientHello in two Initial packets.
    let mut buffer = [0_u8; 2048];
    for _ in 0..2 {
        let (length, _) = timeout(TEST_TIMEOUT, socket.recv_from(&mut buffer)).await??;
        let datagram = &buffer[..length];
        assert_eq!(length, 1_252);
        assert_eq!(datagram[0] & 0xb0, 0x80, "a version 1 Initial");
        assert_eq!(datagram[1..5], QUIC_V1.to_be_bytes());
        let destination_length = usize::from(datagram[5]);
        assert!((8..=20).contains(&destination_length));
        assert_eq!(datagram[6 + destination_length], 3);
    }
    attempt.abort();
    Ok(())
}
