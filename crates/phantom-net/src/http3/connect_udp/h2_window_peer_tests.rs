//! Real HTTP/2 stream-credit pressure through the native capsule driver.

use std::{
    future::{Future, poll_fn},
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use phantom_profile::{Http2PseudoHeader, browser::chrome};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
    time::timeout,
};

use super::*;
use crate::{
    http2::{Http2Connection, Http2ExtendedConnectOutcome, Http2ExtendedConnectStream},
    request::OriginForm,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(30);
const STREAM_WINDOW: usize = 32;
const CONNECTION_WINDOW: u32 = 1_048_576;
const CAPSULE_LEN: usize = 63;

/// Observes results from the real HTTP/2 capacity-controlled writer; no result
/// or bytes are changed. Drop acknowledgement observes the real driver ending.
struct ObservedStream {
    inner: Http2ExtendedConnectStream,
    written: usize,
    blocked: Option<oneshot::Sender<usize>>,
    complete: Option<oneshot::Sender<usize>>,
    dropped: Option<oneshot::Sender<()>>,
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}
impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, bytes);
        match &result {
            Poll::Pending if self.written == STREAM_WINDOW => {
                if let Some(sender) = self.blocked.take() {
                    let _ = sender.send(self.written);
                }
            }
            Poll::Ready(Ok(count)) => {
                self.written += count;
                if self.written == CAPSULE_LEN
                    && let Some(sender) = self.complete.take()
                {
                    let _ = sender.send(self.written);
                }
            }
            _ => {}
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
impl Drop for ObservedStream {
    fn drop(&mut self) {
        if let Some(sender) = self.dropped.take() {
            let _ = sender.send(());
        }
    }
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
                    .unwrap_or("HTTP/2 window peer assertion panicked");
                Poll::Ready(Err(io::Error::other(text.to_owned()).into()))
            }
        },
    )
    .await
}

async fn accept_tunnel(
    connection: &mut ::http2::server::Connection<tokio::io::DuplexStream, Bytes>,
    path: &str,
) -> TestResult<(::http2::RecvStream, ::http2::SendStream<Bytes>)> {
    let (request, mut response) = connection
        .accept()
        .await
        .ok_or("H2 outer closed before CONNECT")??;
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().path(), path);
    assert_eq!(
        request
            .extensions()
            .get::<::http2::ext::Protocol>()
            .map(|protocol| protocol.as_str()),
        Some("connect-udp")
    );
    let send = response.send_response(
        Response::builder()
            .status(StatusCode::OK)
            .header("capsule-protocol", "?1")
            .body(())?,
        false,
    )?;
    Ok((request.into_body(), send))
}

async fn receive_capsule(body: &mut ::http2::RecvStream, expected: &[u8]) -> TestResult {
    let mut bytes = Vec::new();
    while bytes.len() < expected.len() {
        let chunk = body
            .data()
            .await
            .ok_or("peer request ended inside capsule")??;
        bytes.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len())?;
    }
    assert_eq!(bytes, expected);
    Ok(())
}

async fn receive(socket: &dyn AsyncUdpSocket) -> TestResult<Vec<u8>> {
    let mut buffer = [0; 1500];
    let mut meta = [udp::RecvMeta::default()];
    let count = poll_fn(|context| {
        socket.poll_recv(context, &mut [io::IoSliceMut::new(&mut buffer)], &mut meta)
    })
    .await?;
    assert_eq!(count, 1);
    Ok(buffer[..meta[0].len].to_vec())
}

fn transmit(peer: SocketAddr, payload: &[u8]) -> udp::Transmit<'_> {
    udp::Transmit {
        destination: peer,
        ecn: None,
        contents: payload,
        segment_size: None,
        src_ip: None,
    }
}

#[tokio::test]
async fn exhausted_real_h2_stream_credit_blocks_capsule_writer_but_not_shared_sibling() -> TestResult
{
    let (client_io, peer_io) = tokio::io::duplex(128 * 1024);
    let (blocked, blocked_received) = oneshot::channel();
    let (completed, completed_received) = oneshot::channel();
    let (release, release_received) = oneshot::channel();
    let (done, done_received) = oneshot::channel();
    let (dropped_a, dropped_a_received) = oneshot::channel();
    let (dropped_b, dropped_b_received) = oneshot::channel();
    let body = async {
        let peer = async {
            let mut builder = ::http2::server::Builder::new();
            builder
                .initial_window_size(STREAM_WINDOW as u32)
                .initial_connection_window_size(CONNECTION_WINDOW)
                .enable_connect_protocol();
            let mut connection = builder.handshake(peer_io).await?;
            let (mut affected, mut affected_send) =
                accept_tunnel(&mut connection, "/affected").await?;
            let (mut sibling, mut sibling_send) =
                accept_tunnel(&mut connection, "/sibling").await?;
            assert_eq!(affected.stream_id().as_u32(), 1);
            assert_eq!(sibling.stream_id().as_u32(), 3);
            let work = async {
                let mut held = Vec::new();
                while held.len() < STREAM_WINDOW {
                    let chunk = affected
                        .data()
                        .await
                        .ok_or("affected stream ended before window exhausted")??;
                    held.extend_from_slice(&chunk);
                }
                assert_eq!(held.len(), STREAM_WINDOW);
                assert_eq!(&held[..3], b"\x00\x3d\x00");
                assert!(held[3..].iter().all(|byte| *byte == b'A'));
                // Do not release this stream's32 bytes. The large genuine
                // connection window still has credit for the sibling stream.
                receive_capsule(
                    &mut sibling,
                    &capsule::encode(capsule::DATAGRAM, b"\0sibling-first"),
                )
                .await?;
                sibling_send.send_data(
                    Bytes::from(capsule::encode(capsule::DATAGRAM, b"\0sibling-first")),
                    false,
                )?;
                release_received.await?;
                affected.flow_control().release_capacity(held.len())?;
                while held.len() < CAPSULE_LEN {
                    let chunk = affected
                        .data()
                        .await
                        .ok_or("affected stream ended before released writer completed")??;
                    held.extend_from_slice(&chunk);
                    affected.flow_control().release_capacity(chunk.len())?;
                }
                assert_eq!(
                    held,
                    capsule::encode(capsule::DATAGRAM, &[&[0][..], &[b'A'; 60][..]].concat())
                );
                affected_send.send_data(
                    Bytes::from(capsule::encode(capsule::DATAGRAM, b"\0affected-complete")),
                    false,
                )?;
                receive_capsule(
                    &mut sibling,
                    &capsule::encode(capsule::DATAGRAM, b"\0sibling-second"),
                )
                .await?;
                sibling_send.send_data(
                    Bytes::from(capsule::encode(capsule::DATAGRAM, b"\0sibling-second")),
                    false,
                )?;
                done_received.await?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            };
            tokio::pin!(work);
            tokio::select! {
                biased;
                result = &mut work => result,
                request = connection.accept() => { request.transpose()?; Err::<(), Box<dyn std::error::Error + Send + Sync>>("unexpected third CONNECT or outer closure".into()) }
            }
        };
        let client = async {
            let mut settings = chrome::v154_http2();
            settings.extended_connect_pseudo_header_order = Some(vec![
                Http2PseudoHeader::Method,
                Http2PseudoHeader::Authority,
                Http2PseudoHeader::Scheme,
                Http2PseudoHeader::Path,
                Http2PseudoHeader::Protocol,
            ]);
            let connection = Http2Connection::connect_extended(client_io, &settings).await?;
            let a = crate::http2::prepare_connect_udp(
                "proxy.test",
                OriginForm::parse("/affected")?,
                Vec::new(),
            )?;
            let b = crate::http2::prepare_connect_udp(
                "proxy.test",
                OriginForm::parse("/sibling")?,
                Vec::new(),
            )?;
            let Http2ExtendedConnectOutcome::Accepted {
                stream: a,
                response,
            } = connection.send_connect_udp(a).await?
            else {
                return Err("affected CONNECT rejected".into());
            };
            assert_eq!(response.status(), StatusCode::OK);
            let Http2ExtendedConnectOutcome::Accepted {
                stream: b,
                response,
            } = connection.send_connect_udp(b).await?
            else {
                return Err("sibling CONNECT rejected".into());
            };
            assert_eq!(response.status(), StatusCode::OK);
            let (affected, affected_peer) = open_stream(
                ObservedStream {
                    inner: a,
                    written: 0,
                    blocked: Some(blocked),
                    complete: Some(completed),
                    dropped: Some(dropped_a),
                },
                span("h2"),
            )?;
            let (sibling, sibling_peer) = open_stream(
                ObservedStream {
                    inner: b,
                    written: 0,
                    blocked: None,
                    complete: None,
                    dropped: Some(dropped_b),
                },
                span("h2"),
            )?;
            affected.try_send(&transmit(affected_peer, &[b'A'; 60]))?;
            // This acknowledgement comes only from the actual HTTP/2 writer
            // returning Pending after exactly32 successfully written bytes.
            assert_eq!(blocked_received.await?, STREAM_WINDOW);
            sibling.try_send(&transmit(sibling_peer, b"sibling-first"))?;
            assert_eq!(receive(sibling.as_ref()).await?, b"sibling-first");
            assert!(!connection.is_closed());
            release
                .send(())
                .map_err(|_| "peer stopped before returning stream credit")?;
            assert_eq!(completed_received.await?, CAPSULE_LEN);
            assert_eq!(receive(affected.as_ref()).await?, b"affected-complete");
            sibling.try_send(&transmit(sibling_peer, b"sibling-second"))?;
            assert_eq!(receive(sibling.as_ref()).await?, b"sibling-second");
            assert!(!connection.is_closed());
            done.send(())
                .map_err(|_| "peer stopped before final sibling confirmation")?;
            drop(affected);
            drop(sibling);
            drop(connection);
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        Ok(())
    };
    let primary = checked(async { timeout(DEADLINE, body).await? }).await;
    // The real production capsule tasks are internal; observe both wrapped
    // streams dropping after socket-triggered abort, including failed bodies.
    let cleanup = timeout(DEADLINE, async {
        tokio::try_join!(dropped_a_received, dropped_b_received)?;
        Ok::<(), oneshot::error::RecvError>(())
    })
    .await;
    match (primary, cleanup) {
        (Ok(()), Ok(Ok(()))) => Ok(()),
        (Err(error), Ok(Ok(()))) => Err(error),
        (Ok(()), Ok(Err(error))) => Err(error.into()),
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(primary), cleanup) => {
            Err(io::Error::other(format!("{primary}; capsule cleanup: {cleanup:?}")).into())
        }
    }
}
