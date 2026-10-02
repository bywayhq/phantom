//! The Firefox 156 HTTP/3 recipe against the retained Firefox 156.0.1 captures.

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
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        phantom_testkit::udp::bind("127.0.0.1:0".parse()?)?,
        Arc::new(quinn::TokioRuntime),
    )?;
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
            .connect_direct(&host, address.port(), TEST_SERVER_NAME)
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
/// 59 in neqo 0.30.1), so only that range is compared.
#[tokio::test(flavor = "current_thread")]
async fn firefox_156_initial_datagrams_match_the_capture() -> TestResult<()> {
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
/// (`neqo-transport/src/pmtud.rs` lines 76 to 81 in neqo 0.30.1). No capture
/// covers IPv6.
#[tokio::test(flavor = "current_thread")]
async fn firefox_156_initial_datagrams_leave_room_for_ipv6_headers() -> TestResult<()> {
    let actual = first_flight((Ipv6Addr::LOCALHOST, 0).into()).await?;
    assert!(
        actual.iter().all(|datagram| datagram.0 == 1_232),
        "{actual:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn firefox_156_recipe_completes_a_request() -> TestResult<()> {
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
        &firefox::v156_http3_request(),
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
async fn firefox_156_client_follows_a_server_to_version_2() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    follow_a_server_to_version_2(&identity, connector(&identity)?).await
}

/// A connector bound to a source address and holding a client certificate
/// keeps the recipe's QUIC v2 offer and Initial datagram size.
#[tokio::test(flavor = "current_thread")]
async fn firefox_156_bound_certificate_connector_keeps_initials_and_version_2() -> TestResult<()> {
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
        &firefox::v156_http3_request(),
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
