use std::{
    fmt, io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Request, Response};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use crate::support::tunnel_proxy::ConnectionPeer;

use super::super::proxy_h2_multiplex;
use super::{Recording, TestResult, read_head};

#[derive(Default)]
struct FaultState {
    enabled: AtomicBool,
    returned: AtomicUsize,
    waker: Mutex<Option<Waker>>,
}

#[derive(Clone, Default)]
pub(crate) struct Fault(Arc<FaultState>);

impl Fault {
    pub(crate) fn observations(&self) -> usize {
        self.0.returned.load(Ordering::SeqCst)
    }

    pub(crate) fn enable(&self) -> TestResult<()> {
        self.0.enabled.store(true, Ordering::SeqCst);
        if let Some(waker) = self
            .0
            .waker
            .lock()
            .map_err(|_| "fault waker poisoned")?
            .take()
        {
            waker.wake();
        }
        Ok(())
    }

    pub(crate) fn error(&self, context: &Context<'_>) -> Option<io::Error> {
        match self.0.waker.lock() {
            Ok(mut waker) => *waker = Some(context.waker().clone()),
            Err(_) => return Some(io::Error::other("fault waker poisoned")),
        }
        if self.0.enabled.load(Ordering::SeqCst) {
            self.0.returned.fetch_add(1, Ordering::SeqCst);
            Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "controlled postexchange relay I/O",
            ))
        } else {
            None
        }
    }
}

pub(crate) struct ControlledIo<S> {
    pub(crate) inner: S,
    pub(crate) fault: Fault,
}

impl<S: AsyncRead + Unpin> AsyncRead for ControlledIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(error) = self.fault.error(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ControlledIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.fault.error(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Failure {
    HealthyEof,
    DownstreamWrite,
    UpstreamRead,
    BodyReset,
    ResponseReset,
}

#[derive(Clone, Copy)]
pub(crate) enum RelayOwner {
    Single,
    Multiplex,
}

pub(crate) async fn actual_relay(owner: RelayOwner, failure: Failure) -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut origin = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        assert_eq!(
            read_head(&mut stream).await?,
            b"GET /first HTTP/1.1\r\nHost: origin.test\r\n\r\n"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await?;
        let mut after = [0_u8; 1];
        assert_eq!(
            stream.read(&mut after).await?,
            0,
            "controlled relay wrote bytes after its failed write or END_STREAM"
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (client_io, server_io) = tokio::io::duplex(8192);
    let inbound = Arc::new(Mutex::new(Vec::new()));
    let server_io = Recording {
        inner: server_io,
        wire: inbound.clone(),
    };
    let (acquired, children) = oneshot::channel();
    let (reset, reset_observed) = oneshot::channel();
    let read_fault = Fault::default();
    let write_fault = Fault::default();
    let read_observer = read_fault.clone();
    let write_observer = write_fault.clone();
    let server = ConnectionPeer::spawn(async move {
        let mut connection = ::http2::server::handshake(server_io).await?;
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("relay peer missed CONNECT")??;
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(
            request.uri().authority().map(|value| value.as_str()),
            Some(address.to_string().as_str())
        );
        let stream_id = respond.stream_id().as_u32();
        let send = respond.send_response(Response::new(()), false)?;
        let upstream = TcpStream::connect(address).await?;
        let (read, write) = upstream.into_split();
        let down = ConnectionPeer::spawn(async move {
            let body = request.into_body();
            let write = ControlledIo {
                inner: write,
                fault: write_observer,
            };
            match owner {
                RelayOwner::Single => super::relay_downstream(body, write).await,
                RelayOwner::Multiplex => proxy_h2_multiplex::relay_downstream(body, write).await,
            }
        });
        let up = ConnectionPeer::spawn(async move {
            let read = ControlledIo {
                inner: read,
                fault: read_observer,
            };
            match owner {
                RelayOwner::Single => super::relay_upstream(read, send).await,
                RelayOwner::Multiplex => proxy_h2_multiplex::relay_upstream(read, send).await,
            }
        });
        acquired
            .send((down, up))
            .map_err(|_| "relay child receiver disappeared")?;
        if matches!(failure, Failure::BodyReset | Failure::ResponseReset) {
            // The response handle cannot poll resets after sending headers.
            // Observe the actual original stream's inbound RST_STREAM instead.
            let reason = std::future::poll_fn(|context| {
                if let Poll::Ready(Some(Err(error))) = connection.poll_accept(context) {
                    return Poll::Ready(Err(error.into()));
                }
                let observed = (|| {
                    let wire = inbound
                        .lock()
                        .map_err(|_| "relay reset recording poisoned")?;
                    received_reset(&wire, stream_id)
                })();
                match observed {
                    Ok(Some(reason)) => Poll::Ready(Ok(reason)),
                    Ok(None) => Poll::Pending,
                    Err(error) => Poll::Ready(Err(error)),
                }
            })
            .await?;
            reset
                .send(reason)
                .map_err(|_| "relay reset observer disappeared")?;
        }
        while let Some(accepted) = connection.accept().await {
            accepted?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (mut requests, driver) = timeout(
        Duration::from_secs(5),
        ::http2::client::handshake(client_io),
    )
    .await??;
    let client_driver = ConnectionPeer::spawn(async move {
        driver.await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (response, mut data) = requests.send_request(
        Request::builder()
            .method(Method::CONNECT)
            .uri(address.to_string())
            .body(())?,
        false,
    )?;
    let response = timeout(Duration::from_secs(5), response).await??;
    assert_eq!(response.status(), 200);
    data.send_data(
        Bytes::from_static(b"GET /first HTTP/1.1\r\nHost: origin.test\r\n\r\n"),
        false,
    )?;
    let mut body = response.into_body();
    let mut wire = Vec::new();
    timeout(Duration::from_secs(5), async {
        while !wire.ends_with(b"\r\n\r\nok") {
            let chunk = body
                .data()
                .await
                .ok_or("actual relay ended before its literal response")??;
            body.flow_control().release_capacity(chunk.len())?;
            wire.extend_from_slice(&chunk);
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert_eq!(wire, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let (mut down, mut up) = timeout(Duration::from_secs(5), children).await??;

    match failure {
        Failure::HealthyEof => data.send_data(Bytes::new(), true)?,
        Failure::DownstreamWrite => {
            write_fault.enable()?;
            data.send_data(Bytes::from_static(b"x"), false)?;
        }
        Failure::UpstreamRead => {
            read_fault.enable()?;
            data.send_data(Bytes::new(), true)?;
        }
        Failure::BodyReset | Failure::ResponseReset => {
            data.send_reset(::http2::Reason::INTERNAL_ERROR);
            assert_eq!(
                timeout(Duration::from_secs(5), reset_observed).await??,
                ::http2::Reason::INTERNAL_ERROR
            );
        }
    }
    let down_result = timeout(Duration::from_secs(5), &mut down).await;
    let up_result = timeout(Duration::from_secs(5), &mut up).await;
    let origin_result = timeout(Duration::from_secs(5), &mut origin).await;
    // Stop drivers while both actual peers remain owned, before causal assertions.
    client_driver.abort();
    server.abort();
    let client_stop = client_driver.stop().await;
    let server_stop = server.stop().await;
    let down_stop = if down_result.is_err() {
        down.stop().await
    } else {
        Ok(())
    };
    let up_stop = if up_result.is_err() {
        up.stop().await
    } else {
        Ok(())
    };
    let origin_stop = if origin_result.is_err() {
        origin.stop().await
    } else {
        Ok(())
    };
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(client_stop, server_stop);
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(cleanup, down_stop);
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(cleanup, up_stop);
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(cleanup, origin_stop);
    let down_result = peer_outcome(down_result);
    let up_result = peer_outcome(up_result);
    let origin_result = peer_outcome(origin_result).and_then(std::convert::identity);

    let (down_observed, up_observed) = match failure {
        Failure::HealthyEof => (
            down_result.and_then(std::convert::identity),
            up_result.and_then(std::convert::identity),
        ),
        Failure::DownstreamWrite => {
            assert_eq!(write_fault.0.returned.load(Ordering::SeqCst), 1);
            let observed = (|| {
                let error = down_result?
                    .err()
                    .ok_or("actual downstream relay discarded its postexchange PermissionDenied")?;
                assert_eq!(
                    error
                        .downcast_ref::<io::Error>()
                        .ok_or("downstream relay lost its I/O type")?
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
                Ok(())
            })();
            (observed, up_result.and_then(std::convert::identity))
        }
        Failure::UpstreamRead => {
            assert_eq!(read_fault.0.returned.load(Ordering::SeqCst), 1);
            let observed = (|| {
                let error = up_result?.err().ok_or(
                    "actual upstream relay treated its postexchange PermissionDenied as EOF",
                )?;
                assert_eq!(
                    error
                        .downcast_ref::<io::Error>()
                        .ok_or("upstream relay lost its I/O type")?
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
                Ok(())
            })();
            (down_result.and_then(std::convert::identity), observed)
        }
        Failure::BodyReset => (reset_downstream(down_result), reset_upstream(up_result)),
        Failure::ResponseReset => {
            let upstream = reset_upstream(up_result);
            let downstream = reset_downstream(down_result);
            (upstream, downstream)
        }
    };
    let observed = crate::support::tunnel_proxy::finish_with_cleanup(down_observed, up_observed);
    let observed = crate::support::tunnel_proxy::finish_with_cleanup(observed, origin_result);
    crate::support::tunnel_proxy::finish_with_cleanup(observed, cleanup)
}

#[derive(Debug)]
struct RecordedResetError(::http2::frame::Error);

impl fmt::Display for RecordedResetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid recorded RST_STREAM: {:?}", self.0)
    }
}

impl std::error::Error for RecordedResetError {}

fn received_reset(wire: &[u8], stream_id: u32) -> TestResult<Option<::http2::Reason>> {
    let mut frames = wire
        .strip_prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .ok_or("relay recording missed the actual client preface")?;
    while frames.len() >= ::http2::frame::HEADER_LEN {
        let (header, remainder) = frames.split_at(::http2::frame::HEADER_LEN);
        let length = usize::try_from(u32::from_be_bytes([0, header[0], header[1], header[2]]))?;
        let Some(payload) = remainder.get(..length) else {
            return Ok(None);
        };
        let head = ::http2::frame::Head::parse(header);
        if head.kind() == ::http2::frame::Kind::Reset && head.stream_id() == stream_id {
            let reset = ::http2::frame::Reset::load(head, payload).map_err(RecordedResetError)?;
            assert_eq!(reset.stream_id(), stream_id);
            return Ok(Some(reset.reason()));
        }
        frames = &remainder[length..];
    }
    Ok(None)
}

fn reset_downstream(outcome: TestResult<TestResult<()>>) -> TestResult<()> {
    let error = outcome?
        .err()
        .ok_or("actual relay treated INTERNAL_ERROR as ordinary END_STREAM")?;
    assert_eq!(
        error
            .downcast_ref::<::http2::Error>()
            .ok_or("relay reset lost its H2 type")?
            .reason(),
        Some(::http2::Reason::INTERNAL_ERROR)
    );
    Ok(())
}

fn reset_upstream(outcome: TestResult<TestResult<()>>) -> TestResult<()> {
    let error = outcome?
        .err()
        .ok_or("actual upstream relay discarded its rejected final send after a real reset")?;
    let error = error
        .downcast_ref::<::http2::Error>()
        .ok_or("rejected final send lost its H2 error type")?;
    assert!(
        error.get_io().is_none(),
        "actual final send became an unrelated I/O failure"
    );
    Ok(())
}

fn peer_outcome(
    outcome: Result<Result<TestResult<()>, tokio::task::JoinError>, tokio::time::error::Elapsed>,
) -> TestResult<TestResult<()>> {
    Ok(outcome??)
}

#[tokio::test]
async fn an_actual_relay_keeps_a_postexchange_write_failure() -> TestResult<()> {
    actual_relay(RelayOwner::Single, Failure::DownstreamWrite).await
}
#[tokio::test]
async fn an_actual_relay_keeps_a_postexchange_read_failure() -> TestResult<()> {
    actual_relay(RelayOwner::Single, Failure::UpstreamRead).await
}
#[tokio::test]
async fn an_actual_relay_keeps_an_internal_error_body_reset() -> TestResult<()> {
    actual_relay(RelayOwner::Single, Failure::BodyReset).await
}
#[tokio::test]
async fn an_actual_relay_keeps_its_rejected_final_send_after_a_reset() -> TestResult<()> {
    actual_relay(RelayOwner::Single, Failure::ResponseReset).await
}
#[tokio::test]
async fn an_actual_relay_finishes_after_nonzero_traffic_and_end_stream() -> TestResult<()> {
    actual_relay(RelayOwner::Single, Failure::HealthyEof).await
}
