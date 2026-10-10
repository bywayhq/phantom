use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Request};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    sync::oneshot,
    time::timeout,
};

use super::{ExtendedConnectRecord, TestResult, echo_h2};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const DEADLINE: Duration = Duration::from_secs(2);
const HELLO: &[u8] = &[0x81, 0x85, 0, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'];
const ECHO: &[u8] = &[
    0x81, 10, b'e', b'c', b'h', b'o', b':', b'h', b'e', b'l', b'l', b'o',
];
const CLOSE: &[u8] = &[0x88, 0x82, 0, 0, 0, 0, 0x03, 0xe8];
const CLOSE_REPLY: &[u8] = &[0x88, 2, 0x03, 0xe8];

struct EchoClient {
    requests: ::http2::client::SendRequest<Bytes>,
    send: ::http2::SendStream<Bytes>,
    body: ::http2::RecvStream,
    origin: ConnectionPeer<TestResult<ExtendedConnectRecord>>,
    driver: ConnectionPeer<TestResult<()>>,
    fault: oneshot::Sender<()>,
}

impl EchoClient {
    async fn ready() -> TestResult<Self> {
        let (client, server) = duplex(16 * 1024);
        let (fault, receiver) = oneshot::channel();
        let origin = ConnectionPeer::spawn(echo_h2(FaultStream {
            inner: server,
            fault: Some(receiver),
            failed: false,
        }));
        let (mut requests, connection) =
            timeout(DEADLINE, ::http2::client::handshake(client)).await??;
        let driver = ConnectionPeer::spawn(async move {
            connection.await?;
            Ok(())
        });
        assert!(timeout(DEADLINE, requests.extended_connect_protocol_ready()).await??);
        timeout(DEADLINE, poll_fn(|context| requests.poll_ready(context))).await??;

        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://example.test/socket?encoding=json")
            .body(())?;
        request
            .extensions_mut()
            .insert(::http2::ext::Protocol::from_static("websocket"));
        let (response, send) = requests.send_request(request, false)?;
        let response = timeout(DEADLINE, response).await??;
        assert_eq!(response.status(), 200);
        let mut fixture = Self {
            requests,
            send,
            body: response.into_body(),
            origin,
            driver,
            fault,
        };

        fixture.send.send_data(Bytes::from_static(HELLO), false)?;
        read_literal(&mut fixture.body, ECHO).await?;
        Ok(fixture)
    }

    async fn close_reply(&mut self) -> TestResult<()> {
        self.send.send_data(Bytes::from_static(CLOSE), false)?;
        read_literal(&mut self.body, CLOSE_REPLY).await
    }

    async fn finish(mut self) -> TestResult<ExtendedConnectRecord> {
        let joined = timeout(DEADLINE, &mut self.origin).await;
        let primary = match joined {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(error) => finish_with_cleanup(Err(error.into()), self.origin.stop().await),
        };
        finish_with_cleanup(primary, stop_driver(self.driver).await)
    }
}

async fn stop_driver(driver: ConnectionPeer<TestResult<()>>) -> TestResult<()> {
    driver.abort();
    match timeout(DEADLINE, driver).await? {
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(error.into()),
        Ok(result) => result,
    }
}

async fn read_literal(body: &mut ::http2::RecvStream, expected: &[u8]) -> TestResult<()> {
    let wire = timeout(DEADLINE, async {
        let mut wire = Vec::new();
        while wire.len() < expected.len() {
            let chunk = body
                .data()
                .await
                .ok_or("echo stream ended before reply")??;
            body.flow_control().release_capacity(chunk.len())?;
            wire.extend_from_slice(&chunk);
            if wire.len() > expected.len() {
                return Err("echo reply exceeded literal bound".into());
            }
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(wire)
    })
    .await??;
    assert_eq!(wire, expected);
    Ok(())
}

fn assert_record(record: ExtendedConnectRecord) {
    assert_eq!(record.scheme.as_deref(), Some("https"));
    assert_eq!(record.authority.as_deref(), Some("example.test"));
    assert_eq!(record.path.as_deref(), Some("/socket?encoding=json"));
    assert_eq!(record.protocol.as_deref(), Some("websocket"));
    assert_eq!(record.message.opcode, 1);
    assert_eq!(record.message.payload, b"hello");
}

#[tokio::test]
async fn h2_echo_close_preserves_literal_frames_and_connect_fields() -> TestResult<()> {
    let mut client = EchoClient::ready().await?;
    client.close_reply().await?;
    client.send.send_data(Bytes::new(), true)?;

    assert_record(client.finish().await?);
    Ok(())
}

#[tokio::test]
async fn a_remote_cancel_after_close_is_normal_echo_teardown() -> TestResult<()> {
    let mut client = EchoClient::ready().await?;
    client.close_reply().await?;
    client.send.send_reset(::http2::Reason::CANCEL);

    assert_record(client.finish().await?);
    Ok(())
}

#[tokio::test]
async fn an_unrelated_stream_reset_after_close_keeps_its_typed_cause() -> TestResult<()> {
    let mut client = EchoClient::ready().await?;
    client.close_reply().await?;
    client.send.send_reset(::http2::Reason::INTERNAL_ERROR);

    let error = client
        .finish()
        .await
        .err()
        .ok_or("unrelated reset was accepted as successful echo")?;
    let reset = error
        .downcast_ref::<::http2::Error>()
        .ok_or("original H2 reset cause was lost")?;
    assert!(reset.is_remote());
    assert!(reset.is_reset());
    assert_eq!(reset.reason(), Some(::http2::Reason::INTERNAL_ERROR));
    Ok(())
}

#[tokio::test]
async fn an_unrelated_transport_failure_after_close_keeps_its_typed_cause() -> TestResult<()> {
    let mut client = EchoClient::ready().await?;
    client.close_reply().await?;
    client
        .fault
        .send(())
        .map_err(|_| "fault receiver disappeared before injection")?;
    // Keep the client connection/driver and stream handles alive through origin completion.
    let joined = timeout(DEADLINE, &mut client.origin).await;
    let primary = match joined {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(error) => finish_with_cleanup(Err(error.into()), client.origin.stop().await),
    };
    let result = finish_with_cleanup(primary, stop_driver(client.driver).await);

    let error = result
        .err()
        .ok_or("transport fault was accepted as successful echo")?;
    let cause = error
        .downcast_ref::<::http2::Error>()
        .and_then(|error| error.get_io())
        .ok_or("original H2 transport cause was lost")?;
    assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
    // The resolved backend retains the I/O kind and message, not its nested type.
    assert_eq!(cause.to_string(), "injected echo transport fault 913");
    Ok(())
}

#[tokio::test]
async fn cancelling_outer_echo_closes_the_live_stream() -> TestResult<()> {
    let mut client = EchoClient::ready().await?;
    client.origin.abort();
    let joined = timeout(DEADLINE, &mut client.origin).await;
    let closed = timeout(DEADLINE, client.body.data()).await;
    let cleanup = stop_driver(client.driver).await;

    let join_error = match joined? {
        Err(error) => error,
        Ok(_) => return Err("echo completed before outer cancellation".into()),
    };
    assert!(join_error.is_cancelled());
    assert_stream_closed(closed?);
    cleanup
}

#[tokio::test]
async fn a_second_stream_is_rejected_after_an_observed_echo() -> TestResult<()> {
    let mut client = EchoClient::ready().await?;
    timeout(
        DEADLINE,
        poll_fn(|context| client.requests.poll_ready(context)),
    )
    .await??;
    let request = Request::builder()
        .uri("https://example.test/extra")
        .body(())?;
    let (extra_response, extra_send) = client.requests.send_request(request, true)?;
    let joined = timeout(DEADLINE, &mut client.origin).await;
    let closed = timeout(DEADLINE, client.body.data()).await;
    let cleanup = stop_driver(client.driver).await;
    drop((extra_response, extra_send));

    let error = joined??.err().ok_or("second stream was accepted")?;
    assert_eq!(
        error.to_string(),
        "origin received an unexpected second stream"
    );
    assert_stream_closed(closed?);
    cleanup
}

fn assert_stream_closed(result: Option<Result<Bytes, ::http2::Error>>) {
    match result {
        None => {}
        Some(Err(error)) => assert!(error.get_io().is_some_and(|error| matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ))),
        Some(Ok(bytes)) => panic!("unexpected data after origin closure: {bytes:?}"),
    }
}

struct FaultStream {
    inner: DuplexStream,
    fault: Option<oneshot::Receiver<()>>,
    failed: bool,
}

impl AsyncRead for FaultStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(fault) = self.fault.as_mut() {
            match Pin::new(fault).poll(context) {
                Poll::Ready(Ok(())) => {
                    self.fault = None;
                    self.failed = true;
                }
                Poll::Ready(Err(_)) => self.fault = None,
                Poll::Pending => {}
            }
        }

        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                TransportFault(913),
            )));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for FaultStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Debug)]
struct TransportFault(u32);

impl fmt::Display for TransportFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "injected echo transport fault {}", self.0)
    }
}

impl Error for TransportFault {}
