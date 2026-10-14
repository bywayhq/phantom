//! Reliable capsule pressure on genuine verified shared HTTP/3 tunnels.

use std::{
    future::{Future, poll_fn},
    io::IoSliceMut,
    net::{Ipv4Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use phantom_profile::{Http3PseudoHeader, browser::chrome};
use quinn::{AsyncUdpSocket, udp};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{sync::oneshot, time::timeout};

use super::*;
use crate::{
    http3::{Http3Connector, datagram::MAX_QUEUED_FLOW_DATAGRAMS},
    request::OriginForm,
    tls::test_support::TestIdentity,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
const DEADLINE: Duration = Duration::from_secs(30);
const NAME: &str = "127.0.0.1";

#[derive(Clone, Copy)]
enum Failure {
    Truncated,
    Oversized,
}

fn endpoint(identity: &TestIdentity) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let cert = CertificateDer::from(identity.leaf_der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1400).min_mtu(1400);
    config.transport_config(Arc::new(transport));
    let socket = phantom_testkit::udp::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    Ok((endpoint.local_addr()?, endpoint))
}

async fn accept_tunnel(
    connection: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    path: &str,
) -> TestResult<ServerStream> {
    let (request, mut stream) = connection
        .accept()
        .await?
        .ok_or("outer closed before CONNECT")?
        .resolve_request()
        .await?;
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().path(), path);
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
    Ok(stream)
}

async fn open_tunnel(
    outer: &Http3Connection,
    authority: &str,
    path: &str,
) -> TestResult<Arc<ConnectUdpSocket>> {
    let mut settings = chrome::v154_http3_request();
    settings.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    let request = crate::http3::request::prepare_connect_udp(
        &settings,
        authority,
        OriginForm::parse(path)?,
        Vec::new(),
    )?;
    match open(outer.clone(), request, span("h3"), false).await? {
        OpenOutcome::Tunnel(socket, _) => Ok(socket),
        OpenOutcome::Retry => {
            Err("anonymous tunnel unexpectedly requested authentication retry".into())
        }
    }
}

fn transport(socket: &ConnectUdpSocket) -> TestResult<&DatagramTransport> {
    match &socket.transport {
        Transport::Datagram(transport) => Ok(transport),
        Transport::Stream(_) => Err("test did not open a native HTTP/3 tunnel".into()),
    }
}

async fn receive(socket: &ConnectUdpSocket) -> TestResult<Vec<u8>> {
    let mut buffer = [0; 1500];
    let mut meta = [udp::RecvMeta::default()];
    let count = poll_fn(|context| {
        socket.poll_recv(context, &mut [IoSliceMut::new(&mut buffer)], &mut meta)
    })
    .await?;
    assert_eq!(count, 1);
    assert_eq!(meta[0].addr, socket.logical_peer);
    Ok(buffer[..meta[0].len].to_vec())
}

async fn checked<F: Future<Output = TestResult>>(future: F) -> TestResult {
    let mut future = std::pin::pin!(future);
    poll_fn(
        |context| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(poll) => poll,
            Err(payload) => {
                let text = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("shared capsule peer assertion panicked");
                Poll::Ready(Err(std::io::Error::other(text.to_owned()).into()))
            }
        },
    )
    .await
}

async fn run_case(failure: Failure) -> TestResult {
    let identity = TestIdentity::generate_for_names(&[NAME])?;
    let (address, endpoint) = endpoint(&identity)?;
    let (drained, drain_received) = oneshot::channel();
    let (done, done_received) = oneshot::channel();
    let body = async {
        let peer = async {
            let incoming = endpoint.accept().await.ok_or("peer endpoint closed")?;
            let native = incoming.await?;
            let mut builder = h3::server::builder();
            builder.enable_extended_connect(true).enable_datagram(true);
            let mut connection = builder.build(h3_quinn::Connection::new(native)).await?;
            let mut affected = accept_tunnel(&mut connection, "/affected").await?;
            let mut sibling = accept_tunnel(&mut connection, "/sibling").await?;
            assert_eq!(affected.id().into_inner(), 0);
            assert_eq!(sibling.id().into_inner(), 4);
            let work = async {
                let mut reliable = Vec::new();
                for index in 0_u16..259 {
                    let mut value = vec![0];
                    value.extend_from_slice(&index.to_be_bytes());
                    reliable.extend(capsule::encode(capsule::DATAGRAM, &value));
                }
                affected.send_data(Bytes::from(reliable)).await?;
                sibling
                    .send_data(Bytes::from(capsule::encode(
                        capsule::DATAGRAM,
                        b"\0sibling-first",
                    )))
                    .await?;
                drain_received.await?;
                match failure {
                    Failure::Truncated => {
                        // Type 0, length 4, only Context ID zero: FIN cuts the value.
                        affected
                            .send_data(Bytes::from_static(b"\x00\x04\x00"))
                            .await?;
                        affected.finish().await?;
                    }
                    Failure::Oversized => {
                        // Valid capsule length, prohibited Context ID zero UDP payload.
                        let mut value = vec![0; MAX_UDP_PAYLOAD_LEN + 2];
                        value[0] = 0;
                        affected
                            .send_data(Bytes::from(capsule::encode(capsule::DATAGRAM, &value)))
                            .await?;
                    }
                }
                sibling
                    .send_data(Bytes::from(capsule::encode(
                        capsule::DATAGRAM,
                        b"\0sibling-second",
                    )))
                    .await?;
                done_received.await?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            };
            tokio::pin!(work);
            tokio::select! {
                biased;
                result = &mut work => result,
                request = connection.accept() => {
                    request?;
                    Err::<(), Box<dyn std::error::Error + Send + Sync>>("unexpected additional CONNECT or outer closure".into())
                }
            }
        };
        let client = async {
            let connector = Http3Connector::new_with_additional_roots(
                &chrome::v154_quic_tls(),
                &chrome::v154_quic(),
                &chrome::v154_http3(),
                &chrome::v154_http3_request(),
                [identity.root_der()],
            )?;
            let outer = connector
                .connect_to_addresses_with_mtu(vec![address], NAME, Some(OUTER_PATH_MTU))
                .await?;
            let outer_id = outer.quinn().stable_id();
            let authority = format!("{NAME}:{}", address.port());
            let affected = open_tunnel(&outer, &authority, "/affected").await?;
            let sibling = open_tunnel(&outer, &authority, "/sibling").await?;
            let affected_transport = transport(&affected)?;
            assert_eq!(affected_transport.flow.stream_id(), 0);
            assert_eq!(transport(&sibling)?.flow.stream_id(), 4);
            assert_eq!(affected_transport.quinn.stable_id(), outer_id);
            assert_eq!(transport(&sibling)?.quinn.stable_id(), outer_id);
            assert_eq!(MAX_QUEUED_FLOW_DATAGRAMS, 256);
            // Poll only the real receive-stream capsule decoder, never flow delivery.
            // Reliable data plus receiver counters prove all 259 were processed;
            // transport chunk boundaries and unreliable DATAGRAM counts are irrelevant.
            poll_fn(|context| {
                let progress = affected_transport
                    .lock_stream()
                    .poll_capsules(context, &affected_transport.flow);
                if affected_transport.flow.counters().dropped_overflow == 3 {
                    Poll::Ready(Ok::<(), Box<dyn std::error::Error + Send + Sync>>(()))
                } else if matches!(progress, Poll::Ready(false)) {
                    Poll::Ready(Err(
                        "affected stream ended before receiver-observed pressure".into(),
                    ))
                } else {
                    Poll::Pending
                }
            })
            .await?;
            let counters = affected_transport.flow.counters();
            assert_eq!(counters.delivered, 0);
            assert_eq!(counters.dropped_overflow, 3);
            assert_eq!(counters.dropped_malformed, 0);
            assert_eq!(receive(&sibling).await?, b"sibling-first");
            for index in 0_u16..256 {
                assert_eq!(receive(&affected).await?, index.to_be_bytes());
            }
            assert_eq!(affected_transport.flow.counters().delivered, 256);
            assert_eq!(affected_transport.flow.counters().dropped_overflow, 3);
            drained
                .send(())
                .map_err(|_| "peer stopped before malformed capsule")?;
            let error = receive(&affected)
                .await
                .err()
                .ok_or("malformed affected flow unexpectedly produced a payload")?;
            let error = error
                .downcast_ref::<std::io::Error>()
                .ok_or("affected flow error lost I/O type")?;
            assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
            let cause = error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<TunnelClosed>())
                .ok_or("affected flow error lost tunnel cause")?;
            match failure {
                Failure::Truncated => assert!(matches!(
                    cause,
                    TunnelClosed::Stream(TunnelEnd::Malformed(CapsuleError::Truncated))
                )),
                Failure::Oversized => assert!(matches!(
                    cause,
                    TunnelClosed::Flow(FlowEnd::OversizedPayload)
                )),
            }
            assert_eq!(receive(&sibling).await?, b"sibling-second");
            assert_eq!(transport(&sibling)?.quinn.stable_id(), outer_id);
            assert!(outer.quinn().close_reason().is_none());
            done.send(())
                .map_err(|_| "peer stopped before sibling verification")?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        Ok(())
    };
    // Both peer futures are directly owned: all error/panic/deadline paths drop
    // their streams. Endpoint cleanup remains outside the assertion catcher.
    let primary = checked(async { timeout(DEADLINE, body).await? }).await;
    endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    let cleanup = timeout(DEADLINE, endpoint.wait_idle()).await;
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(primary), Err(cleanup)) => {
            Err(std::io::Error::other(format!("{primary}; peer cleanup: {cleanup}")).into())
        }
    }
}

#[tokio::test]
async fn reliable_flow_pressure_and_truncated_fin_leave_shared_sibling_usable() -> TestResult {
    run_case(Failure::Truncated).await
}

#[tokio::test]
async fn reliable_flow_pressure_and_oversized_context_zero_leave_shared_sibling_usable()
-> TestResult {
    run_case(Failure::Oversized).await
}
