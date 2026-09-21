use std::{
    collections::BTreeSet,
    future::poll_fn,
    io::IoSliceMut,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Response, StatusCode};
use phantom_profile::{Http3PseudoHeader, Http3RequestSettings, chromium};
use quinn::{AsyncUdpSocket, udp};
use tokio::{sync::oneshot, time::timeout};

use super::{TestResult, join_server, server_endpoint_with_transport};
use crate::{
    http3::{
        ConnectUdpErrorKind, Http3Connector, OriginForm, capsule,
        connect_udp::{self, OUTER_PATH_MTU},
    },
    tls::test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity},
};

type ServerConnection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[tokio::test]
async fn socket_presents_one_logical_peer_for_datagrams_and_capsules() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = proxy_endpoint(&identity, None)?;
    let (client_sent, sent_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (connection, mut stream) = accept_connect_udp(&endpoint, true).await?;
        let stream_id = stream.id();
        let mut sender = connection.get_datagram_sender(stream_id);
        sender.send_datagram(Bytes::from_static(b"\x02unknown-context"))?;
        sender.send_datagram(Bytes::from_static(b"\x00from-datagram"))?;
        stream
            .send_data(Bytes::from(capsule::encode(0x2a, b"ignored")))
            .await?;
        stream
            .send_data(Bytes::from(capsule::encode(
                capsule::DATAGRAM,
                b"\x00from-capsule",
            )))
            .await?;
        let mut reader = connection.get_datagram_reader();
        let datagram = timeout(TEST_TIMEOUT, reader.read_datagram())
            .await
            .map_err(|_| "client datagram timed out")??;
        assert_eq!(datagram.stream_id(), stream_id);
        assert_eq!(datagram.payload().as_ref(), b"\x00to-target");
        let _ = sent_received.await;
        Ok(())
    });

    let (socket, peer) = open_tunnel(address, &identity).await?;
    assert_eq!(peer, SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)));

    let mut received = BTreeSet::new();
    while received.len() < 2 {
        let (payload, from) = timeout(TEST_TIMEOUT, recv(socket.as_ref()))
            .await
            .map_err(|_| "tunnel payload timed out")??;
        assert_eq!(from, peer);
        received.insert(payload);
    }
    assert_eq!(
        received,
        BTreeSet::from([b"from-capsule".to_vec(), b"from-datagram".to_vec()])
    );

    socket.try_send(&transmit(peer, b"to-target"))?;
    let other = SocketAddr::from((Ipv4Addr::LOCALHOST, peer.port()));
    let error = socket
        .try_send(&transmit(other, b"elsewhere"))
        .err()
        .ok_or("socket sent to a second peer")?;
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let oversized = vec![0; 1300];
    socket.try_send(&transmit(peer, &oversized))?;

    let _ = client_sent.send(());
    join_server(server).await
}

#[tokio::test]
async fn small_peer_datagram_limit_is_a_typed_capacity_failure() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = proxy_endpoint(&identity, Some(1_000))?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_connection, _stream) = accept_connect_udp(&endpoint, true).await?;
        let _ = done_received.await;
        Ok(())
    });

    let error = open_tunnel(address, &identity)
        .await
        .err()
        .ok_or("tunnel opened with an unusable datagram limit")?;
    let error = error
        .downcast_ref::<connect_udp::ConnectUdpError>()
        .ok_or("capacity failure was not a CONNECT-UDP error")?;
    assert_eq!(error.kind(), ConnectUdpErrorKind::DatagramCapacity);
    let _ = client_done.send(());
    join_server(server).await
}

fn proxy_endpoint(
    identity: &TestIdentity,
    datagram_receive_buffer: Option<usize>,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1_400).min_mtu(1_400);
    if let Some(size) = datagram_receive_buffer {
        transport.datagram_receive_buffer_size(Some(size));
    }
    server_endpoint_with_transport(identity, "127.0.0.1:0".parse()?, transport)
}

async fn accept_connect_udp(
    endpoint: &quinn::Endpoint,
    datagrams: bool,
) -> TestResult<(ServerConnection, ServerStream)> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let quinn = incoming.await?;
    let mut builder = h3::server::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(datagrams);
    let mut connection = builder.build(h3_quinn::Connection::new(quinn)).await?;
    let (request, mut stream) = connection
        .accept()
        .await?
        .ok_or("client closed before CONNECT-UDP")?
        .resolve_request()
        .await?;
    assert_eq!(
        request.extensions().get::<h3::ext::Protocol>(),
        Some(&h3::ext::Protocol::CONNECT_UDP)
    );
    assert_eq!(
        request
            .headers()
            .get("capsule-protocol")
            .map(|value| value.as_bytes()),
        Some(&b"?1"[..])
    );
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header("capsule-protocol", "?1")
                .body(())?,
        )
        .await?;
    Ok((connection, stream))
}

async fn open_tunnel(
    address: SocketAddr,
    identity: &TestIdentity,
) -> Result<(Arc<dyn AsyncUdpSocket>, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    let connector = Http3Connector::new_with_additional_roots(
        &chromium::v152_http3_tls(),
        &chromium::v152_quic(),
        &chromium::v152_http3(),
        &extended_request_settings(),
        [identity.root_der()],
    )?;
    let outer = timeout(
        TEST_TIMEOUT,
        connector.connect_to_addresses_with_mtu(
            vec![address],
            TEST_SERVER_NAME,
            Some(OUTER_PATH_MTU),
        ),
    )
    .await
    .map_err(|_| "outer connection timed out")??;
    let request = super::super::request::prepare_connect_udp(
        &extended_request_settings(),
        &format!("{TEST_SERVER_NAME}:{}", address.port()),
        OriginForm::parse("/.well-known/masque/udp/origin.test/443/")
            .map_err(|_| "invalid test path")?,
        Vec::new(),
    )?;
    let tunnel = timeout(
        TEST_TIMEOUT,
        connect_udp::open(outer, request, connect_udp::span()),
    )
    .await
    .map_err(|_| "CONNECT-UDP timed out")??;
    Ok(tunnel)
}

async fn recv(socket: &dyn AsyncUdpSocket) -> std::io::Result<(Vec<u8>, SocketAddr)> {
    let mut buffer = vec![0; 1500];
    let mut meta = [udp::RecvMeta::default()];
    let count = poll_fn(|context| {
        let mut bufs = [IoSliceMut::new(&mut buffer)];
        socket.poll_recv(context, &mut bufs, &mut meta)
    })
    .await?;
    assert_eq!(count, 1);
    Ok((buffer[..meta[0].len].to_vec(), meta[0].addr))
}

fn transmit(destination: SocketAddr, contents: &[u8]) -> udp::Transmit<'_> {
    udp::Transmit {
        destination,
        ecn: None,
        contents,
        segment_size: None,
        src_ip: None,
    }
}

fn extended_request_settings() -> Http3RequestSettings {
    let mut settings = chromium::v152_http3_request();
    settings.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    settings
}
