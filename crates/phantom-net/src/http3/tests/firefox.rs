//! The Firefox 157 HTTP/3 recipe against the retained Firefox 157.0 captures.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use btls::ssl::{AlpnError, select_next_proto};
use bytes::{Bytes, BytesMut};
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::firefox;
use phantom_quic_btls::{QuicServerConfig, ServerHandshakeData};
use phantom_testkit::tls::ClientHelloSummary;
use quinn::crypto::ServerConfig as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{net::UdpSocket, time::timeout};

use super::super::Http3Connector;
use super::connector::{client_hello_extension, fixture_hex};
use super::{TEST_TIMEOUT, TestResult, accept_request, server_endpoint};
use crate::request::{OriginForm, RequestHeader};
use crate::tls::test_support::{TEST_SERVER_NAME, TestIdentity, nss_ech_grease};

const SNAPSHOTS: [&str; 3] = [
    include_str!("../../../../../fixtures/http3/firefox/157.0/windows-11-26200/snapshot-1.txt"),
    include_str!("../../../../../fixtures/http3/firefox/157.0/windows-11-26200/snapshot-2.txt"),
    include_str!("../../../../../fixtures/http3/firefox/157.0/windows-11-26200/snapshot-3.txt"),
];
const CLIENT_HELLOS: [&str; 3] = [
    include_str!(
        "../../../../../fixtures/http3/firefox/157.0/windows-11-26200/quic-client-hello-1.txt"
    ),
    include_str!(
        "../../../../../fixtures/http3/firefox/157.0/windows-11-26200/quic-client-hello-2.txt"
    ),
    include_str!(
        "../../../../../fixtures/http3/firefox/157.0/windows-11-26200/quic-client-hello-3.txt"
    ),
];
const RESUMPTIONS: [&str; 3] = [
    include_str!(
        "../../../../../fixtures/http3/firefox/157.0/windows-11-26200/resumption-accept.txt"
    ),
    include_str!(
        "../../../../../fixtures/http3/firefox/157.0/windows-11-26200/resumption-accept-delayed.txt"
    ),
    include_str!(
        "../../../../../fixtures/http3/firefox/157.0/windows-11-26200/resumption-reject.txt"
    ),
];
/// Firefox 157's QUIC ClientHellos to `https://127.0.0.1:<port>/`, by the
/// `security.tls.ech.grease_size` each run set, which QUIC does not read.
const IP_LITERAL_CLIENT_HELLOS: [&str; 4] = [
    include_str!(
        "../../../../../fixtures/tls/firefox/157.0/windows-11-26200/ip-literal/quic-ipv4.txt"
    ),
    include_str!(
        "../../../../../fixtures/tls/firefox/157.0/windows-11-26200/ip-literal/quic-ipv4-grease-size-77.txt"
    ),
    include_str!(
        "../../../../../fixtures/tls/firefox/157.0/windows-11-26200/ip-literal/quic-ipv4-grease-size-85.txt"
    ),
    include_str!(
        "../../../../../fixtures/tls/firefox/157.0/windows-11-26200/ip-literal/quic-ipv4-grease-size-86.txt"
    ),
];
const H3_ALPN_WIRE: &[u8] = b"\x02h3";
const EXTENDED_MASTER_SECRET: u16 = 0x17;
const RECORD_SIZE_LIMIT: u16 = 0x1c;
const EARLY_DATA: u16 = 0x2a;
const PRE_SHARED_KEY: u16 = 0x29;
const PSK_KEY_EXCHANGE_MODES: u16 = 0x2d;
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;
const RENEGOTIATION_INFO: u16 = 0xff01;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// neqo writes these two after its shuffled extensions, and before only
/// `pre_shared_key`.
const QUIC_TAIL: [u16; 2] = [QUIC_TRANSPORT_PARAMETERS, ENCRYPTED_CLIENT_HELLO];
/// NSS's default ECH GREASE `maximum_name_length`, which QUIC uses.
const ECH_MAXIMUM_NAME_LENGTH: usize = 100;
const QUIC_V1: u32 = 1;
const QUIC_V2: u32 = 0x6b33_43cf;

fn connector(identity: &TestIdentity) -> TestResult<Http3Connector> {
    Ok(Http3Connector::new_with_additional_roots(
        &firefox::v157_http3_tls(),
        &firefox::v157_quic(),
        &firefox::v157_http3(),
        &firefox::v157_http3_request(),
        [identity.root_der()],
    )?)
}

/// A loopback BoringSSL QUIC server that records the ClientHello.
fn server(identity: &TestIdentity) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    server_at(identity, (Ipv4Addr::LOCALHOST, 0).into())
}

fn server_at(
    identity: &TestIdentity,
    bind: SocketAddr,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let mut builder = identity.acceptor_builder()?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(H3_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    let crypto = QuicServerConfig::new(builder.build().into_context());
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = super::quic_server(config, bind)?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// Returns the ClientHello of `connector`'s next connection to `server_name`
/// at a recording server bound to `bind`. The handshake itself may fail.
async fn recorded_client_hello(
    identity: &TestIdentity,
    connector: &Http3Connector,
    bind: SocketAddr,
    server_name: &str,
) -> TestResult<Vec<u8>> {
    let (address, endpoint) = server_at(identity, bind)?;
    let host = address.ip().to_string();
    // A resumed connection that offers 0-RTT returns before the server
    // answers, so the attempt holds it until the server has the ClientHello.
    let attempt = async {
        let _connection = connector
            .connect(
                crate::route::DatagramRoute::Direct(crate::route::Endpoint {
                    host: &host,
                    port: address.port(),
                }),
                server_name,
            )
            .await;
        std::future::pending::<()>().await;
    };
    let observed = async {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let mut connecting = incoming.accept()?;
        let data = connecting
            .handshake_data()
            .await?
            .downcast::<ServerHandshakeData>()
            .map_err(|_| "unexpected server handshake data")?;
        TestResult::Ok(data.client_hello().to_vec())
    };
    let client_hello = timeout(TEST_TIMEOUT, async {
        tokio::select! {
            () = attempt => Err("the client stopped before the server saw it".into()),
            client_hello = observed => client_hello,
        }
    })
    .await??;
    Ok(client_hello)
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
async fn firefox_157_quic_offer_and_streams_match_windows_capture() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = connector(&identity)?;
    let (address, endpoint) = server(&identity)?;
    let host = address.ip().to_string();
    let client = async {
        connector
            .connect(
                crate::route::DatagramRoute::Direct(crate::route::Endpoint {
                    host: &host,
                    port: address.port(),
                }),
                TEST_SERVER_NAME,
            )
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
        // The same extensions; the order of all but the last two is drawn
        // per connection.
        assert_eq!(extension_set(&actual), extension_set(&expected));
        assert!(actual.extension_types().ends_with(&QUIC_TAIL));
        assert!(expected.extension_types().ends_with(&QUIC_TAIL));
        // delegated_credentials, status_request, compress_certificate,
        // psk_key_exchange_modes, and the TLS 1.2 extensions of a TLS
        // 1.3-only offer.
        for extension in [
            0x22,
            0x05,
            0x1b,
            PSK_KEY_EXCHANGE_MODES,
            EXTENDED_MASTER_SECRET,
            RENEGOTIATION_INFO,
            RECORD_SIZE_LIMIT,
        ] {
            assert_eq!(
                client_hello_extension(&client_hello, extension),
                client_hello_extension(&expected_hello, extension),
                "extension {extension:#06x}"
            );
        }
        assert_tls12_extensions_and_record_size_limit(&client_hello);
        assert_eq!(
            client_hello_extension(&client_hello, ENCRYPTED_CLIENT_HELLO).map(<[u8]>::len),
            client_hello_extension(&expected_hello, ENCRYPTED_CLIENT_HELLO).map(<[u8]>::len),
        );
        assert_eq!(nss_ech_grease::sent_payload_length(&expected_hello)?, 240);
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

/// An empty `extended_master_secret`, a `renegotiation_info` with an empty
/// renegotiated connection, and a `record_size_limit` of 16385.
fn assert_tls12_extensions_and_record_size_limit(client_hello: &[u8]) {
    assert_eq!(
        client_hello_extension(client_hello, EXTENDED_MASTER_SECRET),
        Some(&b""[..])
    );
    assert_eq!(
        client_hello_extension(client_hello, RENEGOTIATION_INFO),
        Some(&[0][..])
    );
    assert_eq!(
        client_hello_extension(client_hello, RECORD_SIZE_LIMIT),
        Some(&[0x40, 0x01][..])
    );
}

/// A resumed ClientHello adds `early_data` and, after the fixed tail,
/// `pre_shared_key`, as every resumed Firefox 157 QUIC ClientHello in the
/// resumption captures does. Their ECH GREASE payload is 368 bytes, sized
/// by NSS from a ClientHello whose `pre_shared_key` carries the capture
/// server's 64-byte ticket and a 48-byte SHA-384 binder. The loopback
/// server's ticket and binder have other lengths, so the payload is compared
/// through NSS's rule: Phantom's payload follows the rule for its own
/// ClientHello, and the rule gives 368 for that ClientHello with the
/// captured `pre_shared_key` length.
#[tokio::test(flavor = "current_thread")]
async fn firefox_157_resumed_quic_client_hello_matches_the_resumption_captures() -> TestResult<()> {
    use super::early_data::{Served, learn_ticket};
    use super::resumption::resumed_captured_client_hellos;

    let identity = TestIdentity::generate()?;
    let connector = connector(&identity)?.with_isolated_session_cache();
    let (_address, _endpoint, server) =
        learn_ticket(&identity, &connector, &Served::default()).await?;
    // The ticket is kept by server name, so the next connection presents it
    // to the recording server too.
    let resumed = recorded_client_hello(
        &identity,
        &connector,
        (Ipv4Addr::LOCALHOST, 0).into(),
        TEST_SERVER_NAME,
    )
    .await?;
    server.abort();

    let actual = ClientHelloSummary::from_handshake_bytes(&resumed)?;
    let mut tail = QUIC_TAIL.to_vec();
    tail.push(PRE_SHARED_KEY);
    assert!(actual.extension_types().ends_with(&tail));
    assert!(actual.extension_types().contains(&EARLY_DATA));
    assert_tls12_extensions_and_record_size_limit(&resumed);
    assert_eq!(
        nss_ech_grease::sent_payload_length(&resumed)?,
        nss_ech_grease::payload_length(&resumed, ECH_MAXIMUM_NAME_LENGTH, None)?
    );

    let mut compared = 0;
    for capture in RESUMPTIONS {
        for captured in resumed_captured_client_hellos(capture)? {
            let expected = ClientHelloSummary::from_handshake_bytes(&captured)?;
            assert!(expected.extension_types().ends_with(&tail));
            assert_eq!(extension_set(&actual), extension_set(&expected));
            for extension in [
                EARLY_DATA,
                PSK_KEY_EXCHANGE_MODES,
                EXTENDED_MASTER_SECRET,
                RENEGOTIATION_INFO,
                RECORD_SIZE_LIMIT,
            ] {
                assert_eq!(
                    client_hello_extension(&resumed, extension),
                    client_hello_extension(&captured, extension),
                    "extension {extension:#06x}"
                );
            }
            let pre_shared_key = nss_ech_grease::pre_shared_key_length(&captured)?;
            assert_eq!(nss_ech_grease::sent_payload_length(&captured)?, 368);
            assert_eq!(
                nss_ech_grease::payload_length(&captured, ECH_MAXIMUM_NAME_LENGTH, None)?,
                368
            );
            assert_eq!(
                nss_ech_grease::payload_length_with_pre_shared_key(
                    &resumed,
                    ECH_MAXIMUM_NAME_LENGTH,
                    None,
                    pre_shared_key
                )?,
                368
            );
            compared += 1;
        }
    }
    assert!(compared >= 3, "too few resumed captures were compared");
    Ok(())
}

/// Firefox's QUIC ClientHello to `127.0.0.1` sends no `server_name` and pads
/// its ECH GREASE payload by the address text, to 208 bytes whatever
/// `security.tls.ech.grease_size` says. The recipe sends the same extensions
/// and the same length there. No QUIC capture to `[::1]` exists; there the
/// recipe follows NSS's rule for the three-byte host `::1`.
#[tokio::test(flavor = "current_thread")]
async fn firefox_157_quic_client_hello_pads_ech_grease_by_an_ip_literal_host() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = connector(&identity)?;
    let ipv4 = recorded_client_hello(
        &identity,
        &connector,
        (Ipv4Addr::LOCALHOST, 0).into(),
        "127.0.0.1",
    )
    .await?;
    let actual = ClientHelloSummary::from_handshake_bytes(&ipv4)?;
    assert_eq!(actual.server_name(), None);
    assert!(actual.extension_types().ends_with(&QUIC_TAIL));
    assert_eq!(nss_ech_grease::sent_payload_length(&ipv4)?, 208);
    for capture in IP_LITERAL_CLIENT_HELLOS {
        let captured = fixture_hex(capture, "client_hello_0_hex")?;
        let expected = ClientHelloSummary::from_handshake_bytes(&captured)?;
        assert_eq!(expected.server_name(), None);
        assert!(expected.extension_types().ends_with(&QUIC_TAIL));
        assert_eq!(extension_set(&actual), extension_set(&expected));
        assert_eq!(nss_ech_grease::sent_payload_length(&captured)?, 208);
        assert_eq!(
            nss_ech_grease::payload_length(
                &captured,
                ECH_MAXIMUM_NAME_LENGTH,
                Some("127.0.0.1".len())
            )?,
            208
        );
    }

    let ipv6 = recorded_client_hello(
        &identity,
        &connector,
        (Ipv6Addr::LOCALHOST, 0).into(),
        "::1",
    )
    .await?;
    assert_eq!(
        ClientHelloSummary::from_handshake_bytes(&ipv6)?.server_name(),
        None
    );
    assert_eq!(
        nss_ech_grease::sent_payload_length(&ipv6)?,
        nss_ech_grease::payload_length(&ipv6, ECH_MAXIMUM_NAME_LENGTH, Some("::1".len()))?
    );
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

/// One client Initial datagram: size, version, and the lengths of its
/// Destination and Source Connection IDs.
type InitialDatagram = (usize, u32, usize, usize);

fn captured_initial_datagram(snapshot: &str, index: usize) -> TestResult<InitialDatagram> {
    let key = format!("quic_connection_0_initial_datagram_{index}=");
    let line = snapshot
        .lines()
        .find_map(|line| line.strip_prefix(key.as_str()))
        .ok_or("snapshot has no such Initial datagram")?;
    let mut fields = line.split(',').map(|field| field.split_once(':'));
    let mut next = |name: &str| -> TestResult<String> {
        match fields.next().flatten() {
            Some((key, value)) if key == name => Ok(value.to_owned()),
            _ => Err(format!("snapshot Initial datagram has no {name}").into()),
        }
    };
    Ok((
        next("size")?.parse()?,
        u32::from_str_radix(next("version")?.trim_start_matches("0x"), 16)?,
        next("destination_cid_length")?.parse()?,
        next("source_cid_length")?.parse()?,
    ))
}

/// Sends the first flight to a silent loopback socket bound to `bind` and
/// returns its first two datagrams.
async fn first_flight(bind: SocketAddr) -> TestResult<Vec<InitialDatagram>> {
    first_flight_of(connector(&TestIdentity::generate()?)?, bind).await
}

/// Sends `connector`'s first flight as [`first_flight`] does.
async fn first_flight_of(
    connector: Http3Connector,
    bind: SocketAddr,
) -> TestResult<Vec<InitialDatagram>> {
    let socket = phantom_testkit::udp::bind_tokio(bind)?;
    let address = socket.local_addr()?;
    let host = address.ip().to_string();
    let attempt = tokio::spawn(async move {
        let _ = connector
            .connect(
                crate::route::DatagramRoute::Direct(crate::route::Endpoint {
                    host: &host,
                    port: address.port(),
                }),
                TEST_SERVER_NAME,
            )
            .await;
    });

    // The X25519MLKEM768 key share puts the ClientHello in two Initial packets.
    let mut buffer = [0_u8; 2048];
    let mut datagrams = Vec::new();
    for _ in 0..2 {
        let (length, _) = timeout(TEST_TIMEOUT, socket.recv_from(&mut buffer)).await??;
        let datagram = &buffer[..length];
        assert_eq!(datagram[0] & 0xb0, 0x80, "a version 1 Initial");
        let destination_length = usize::from(datagram[5]);
        datagrams.push((
            length,
            u32::from_be_bytes(datagram[1..5].try_into()?),
            destination_length,
            usize::from(datagram[6 + destination_length]),
        ));
    }
    attempt.abort();
    Ok(datagrams)
}

/// The snapshots record Firefox's Initial datagrams over IPv4 loopback. neqo
/// draws a Destination Connection ID of 8 to 20 bytes
/// (`ConnectionId::generate_initial`, `neqo-transport/src/cid.rs` lines 54 to
/// 59 in neqo 0.31.1), so only that range is compared.
#[tokio::test(flavor = "current_thread")]
async fn firefox_157_initial_datagrams_match_the_capture() -> TestResult<()> {
    let actual = first_flight((Ipv4Addr::LOCALHOST, 0).into()).await?;
    assert_eq!(actual[0].2, actual[1].2);
    for snapshot in SNAPSHOTS {
        for (index, actual) in actual.iter().enumerate() {
            let captured = captured_initial_datagram(snapshot, index)?;
            assert_eq!(
                (actual.0, actual.1, actual.3),
                (captured.0, captured.1, captured.3)
            );
            assert!((8..=20).contains(&actual.2));
            assert!((8..=20).contains(&captured.2));
        }
    }
    assert_eq!((actual[0].0, actual[0].1), (1_252, QUIC_V1));
    Ok(())
}

/// neqo starts a path at a 1280-byte IP MTU less the IPv6 and UDP headers
/// (`neqo-transport/src/pmtud.rs` lines 76 to 81 in neqo 0.31.1). No capture
/// covers IPv6.
#[tokio::test(flavor = "current_thread")]
async fn firefox_157_initial_datagrams_leave_room_for_ipv6_headers() -> TestResult<()> {
    let actual = first_flight((Ipv6Addr::LOCALHOST, 0).into()).await?;
    assert!(
        actual.iter().all(|datagram| datagram.0 == 1_232),
        "{actual:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn firefox_157_recipe_completes_a_request() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = connector(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    // The server keeps its connection until the client has read the body.
    let server = async {
        let (request, mut stream, connection) = accept_request(&endpoint).await?;
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), "/firefox");
        let probe = request
            .headers()
            .get("x-probe")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream.send_data(Bytes::from_static(b"served")).await?;
        stream.finish().await?;
        TestResult::Ok((probe, connection))
    };
    let request = super::super::prepare_traced_request(
        &firefox::v157_http3_request(),
        http::Method::GET,
        TEST_SERVER_NAME,
        OriginForm::parse("/firefox")?,
        vec![RequestHeader::new("x-probe", "firefox")],
        None,
    )?;
    let client = async {
        let response = connector
            .send_prepared_to_addresses(vec![address], TEST_SERVER_NAME, request)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        TestResult::Ok(response.into_body().collect().await?.to_bytes())
    };
    let (body, (probe, _connection)) =
        timeout(TEST_TIMEOUT, async { tokio::try_join!(client, server) }).await??;
    assert_eq!(body, "served");
    assert_eq!(probe.as_deref(), Some("firefox"));
    Ok(())
}

/// A rustls QUIC server for `h3` that speaks only version 2 and names it in
/// its `version_information`.
fn v2_server(
    identity: &TestIdentity,
) -> TestResult<(
    SocketAddr,
    quinn::Endpoint,
    Arc<quinn::crypto::rustls::QuicServerConfig>,
)> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls)?);
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .supported_versions(vec![QUIC_V2])
        .compatible_versions(vec![QUIC_V2]);
    let socket = phantom_testkit::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?;
    let endpoint = quinn::Endpoint::new(
        endpoint_config,
        Some(quinn::ServerConfig::with_crypto(crypto.clone())),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    Ok((endpoint.local_addr()?, endpoint, crypto))
}

/// Protects a client's version 1 Initial again as a version 2 Initial (RFC
/// 9369), keeping its packet number, connection IDs, and payload.
fn initial_v1_as_v2(
    keys: &quinn::crypto::rustls::QuicServerConfig,
    datagram: &[u8],
) -> TestResult<Vec<u8>> {
    let mut packet = datagram.to_vec();
    assert_eq!(packet[0] & 0xb0, 0x80, "a version 1 Initial");
    let destination_length = usize::from(packet[5]);
    let destination = quinn::ConnectionId::new(&packet[6..6 + destination_length]);
    let mut offset = 6 + destination_length;
    offset += 1 + usize::from(packet[offset]);
    let (token_length, _) = varint(&packet, &mut offset)?;
    offset += usize::try_from(token_length)?;
    let (length, _) = varint(&packet, &mut offset)?;
    let pn_offset = offset;
    assert_eq!(
        pn_offset + usize::try_from(length)?,
        packet.len(),
        "one Initial per datagram"
    );

    let v1 = keys
        .initial_keys(QUIC_V1, &destination)
        .map_err(|_| "no version 1 Initial keys")?;
    v1.header.remote.decrypt(pn_offset, &mut packet);
    let header_length = pn_offset + usize::from(packet[0] & 0x03) + 1;
    let number = packet[pn_offset..header_length]
        .iter()
        .fold(0_u64, |number, byte| (number << 8) | u64::from(*byte));
    let mut payload = BytesMut::from(&packet[header_length..]);
    v1.packet
        .remote
        .decrypt(number, &packet[..header_length], &mut payload)
        .map_err(|_| "the version 1 Initial did not authenticate")?;

    let v2 = keys
        .initial_keys(QUIC_V2, &destination)
        .map_err(|_| "no version 2 Initial keys")?;
    packet[0] = (packet[0] & !0x30) | 0x10;
    packet[1..5].copy_from_slice(&QUIC_V2.to_be_bytes());
    packet.truncate(header_length);
    packet.extend_from_slice(&payload);
    packet.resize(packet.len() + v2.packet.remote.tag_len(), 0);
    v2.packet.remote.encrypt(number, &mut packet, header_length);
    v2.header.remote.encrypt(pn_offset, &mut packet);
    Ok(packet)
}

/// Forwards datagrams between one client and `server`, re-protecting the
/// client's version 1 Initials as version 2, and counts the client's
/// version 2 long-header packets.
async fn v2_relay(
    socket: UdpSocket,
    server: SocketAddr,
    keys: Arc<quinn::crypto::rustls::QuicServerConfig>,
    client_v2_packets: Arc<AtomicUsize>,
) -> TestResult<()> {
    let mut client = None;
    let mut buffer = [0_u8; 2048];
    loop {
        let (length, from) = socket.recv_from(&mut buffer).await?;
        let datagram = &buffer[..length];
        if from == server {
            if let Some(client) = client {
                socket.send_to(datagram, client).await?;
            }
            continue;
        }
        client = Some(from);
        let long_version = (datagram[0] & 0x80 != 0).then(|| &datagram[1..5]);
        let forwarded = match long_version {
            Some(version) if version == QUIC_V1.to_be_bytes() => initial_v1_as_v2(&keys, datagram)?,
            Some(version) => {
                assert_eq!(version, QUIC_V2.to_be_bytes());
                client_v2_packets.fetch_add(1, Ordering::Relaxed);
                datagram.to_vec()
            }
            None => datagram.to_vec(),
        };
        socket.send_to(&forwarded, server).await?;
    }
}

/// The BoringSSL session switches from version 1 to version 2 when a
/// version 2-only server answers its first flight in version 2 (RFC 9368
/// section 2.3), and the request completes in version 2.
#[tokio::test(flavor = "current_thread")]
async fn firefox_157_client_follows_a_server_to_version_2() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    follow_a_server_to_version_2(&identity, connector(&identity)?).await
}

/// A connector bound to a source address and holding a client certificate
/// keeps the recipe's QUIC v2 offer and Initial datagram size.
#[tokio::test(flavor = "current_thread")]
async fn firefox_157_bound_certificate_connector_keeps_initials_and_version_2() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let bound = |connector: Http3Connector| -> TestResult<Http3Connector> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let certificate = rcgen::CertificateParams::new(Vec::<String>::new())?.self_signed(&key)?;
        Ok(connector
            .with_source_binding(
                crate::SourceBinding::new().with_address(Ipv4Addr::LOCALHOST.into()),
            )
            .with_client_certificate(&crate::tls::ClientCertificate::from_der(
                [certificate.der().as_ref()],
                &key.serialize_der(),
            )?))
    };

    let datagrams = first_flight_of(
        bound(connector(&identity)?)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .await?;
    assert!(
        datagrams
            .iter()
            .all(|datagram| (datagram.0, datagram.1) == (1_252, QUIC_V1)),
        "{datagrams:?}"
    );
    follow_a_server_to_version_2(&identity, bound(connector(&identity)?)?).await
}

/// Sends one request through a relay that answers `connector`'s first flight
/// in version 2, and checks that the client finishes the handshake in it.
async fn follow_a_server_to_version_2(
    identity: &TestIdentity,
    connector: Http3Connector,
) -> TestResult<()> {
    let (server_address, endpoint, keys) = v2_server(identity)?;
    let relay_socket = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
    let relay_address = relay_socket.local_addr()?;
    let client_v2_packets = Arc::new(AtomicUsize::new(0));
    let relay = tokio::spawn(v2_relay(
        relay_socket,
        server_address,
        keys,
        client_v2_packets.clone(),
    ));
    let server = async {
        let (_request, mut stream, connection) = accept_request(&endpoint).await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        TestResult::Ok(connection)
    };
    let request = super::super::prepare_traced_request(
        &firefox::v157_http3_request(),
        http::Method::GET,
        TEST_SERVER_NAME,
        OriginForm::parse("/")?,
        Vec::new(),
        None,
    )?;
    let client = async {
        let response = connector
            .send_prepared_to_addresses(vec![relay_address], TEST_SERVER_NAME, request)
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        TestResult::Ok(())
    };
    let ((), _connection) =
        timeout(TEST_TIMEOUT, async { tokio::try_join!(client, server) }).await??;
    relay.abort();
    // The Handshake packets that finish the handshake can only be version 2.
    assert!(client_v2_packets.load(Ordering::Relaxed) > 0);
    Ok(())
}
