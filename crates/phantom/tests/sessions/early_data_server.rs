//! A loopback TLS server for early data over TCP: it accepts tickets that
//! permit early data, records the bytes it read before its handshake
//! completed, and serves one HTTP/1.1 or HTTP/2 request.

use std::{
    error::Error,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use http::{Response, StatusCode};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    task::coop,
    time::timeout,
};
use tokio_btls::SslStream;

use crate::support::{
    deadline::FixtureDeadline,
    tls as tls_support,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Long enough that the client's early data is on the wire before the server
/// answers its ClientHello.
pub(super) const SERVER_DELAY: Duration = Duration::from_millis(200);
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(super) const H2_HEADERS: u8 = 0x1;

pub(super) type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub(super) async fn join<T: Send + 'static>(
    server: &mut Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult<T> {
    let result = server
        .as_mut()
        .ok_or("TLS fixture peer missing before join")?
        .await;
    drop(server.take());
    result?
}

pub(super) async fn finish<T, S: Send + 'static>(
    primary: TestResult<T>,
    server: Option<ConnectionPeer<TestResult<S>>>,
) -> TestResult<T> {
    let Some(mut server) = server else {
        return primary;
    };

    // Read an already completed outcome before requesting local cancellation.
    let ready = coop::unconstrained(poll_fn(|context| {
        match Pin::new(&mut server).poll(context) {
            Poll::Ready(result) => Poll::Ready(Some(result)),
            Poll::Pending => Poll::Ready(None),
        }
    }))
    .await;
    let requested = ready.is_none() && !server.is_finished();
    if requested {
        server.abort();
    }

    let joined = match ready {
        Some(result) => Ok(result),
        None => timeout(CLEANUP_TIMEOUT, coop::unconstrained(&mut server))
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("TLS fixture peer cleanup exceeded deadline", elapsed)
            }),
    };
    let cleanup = match joined {
        Ok(Ok(result)) => result.map(|_| ()),
        Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(error.into()),
    };

    finish_with_cleanup(primary, cleanup)
}

/// A server TLS stream that records the application bytes it read before its
/// handshake completed, which were early data.
pub(super) struct Server {
    pub(super) stream: SslStream<TcpStream>,
    early: Arc<Mutex<Vec<u8>>>,
}

impl Server {
    pub(super) fn early_bytes(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.early)
    }
}

impl AsyncRead for Server {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(context, buffer);
        if !self.stream.ssl().is_init_finished() {
            self.early
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&buffer.filled()[before..]);
        }
        result
    }
}

impl AsyncWrite for Server {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

/// Accepts one connection that issues tickets permitting early data and
/// accepts early data, starting the handshake `delay` after the TCP accept.
pub(super) async fn accept(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    delay: Duration,
) -> TestResult<Server> {
    accept_with_early_data(listener, acceptor, delay, true).await
}

pub(super) async fn accept_with_early_data(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    delay: Duration,
    enabled: bool,
) -> TestResult<Server> {
    let (tcp, _) = listener.accept().await?;
    tokio::time::sleep(delay).await;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.set_early_data_enabled(enabled);
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(Server {
        stream,
        early: Arc::default(),
    })
}

pub(super) async fn serve_http2(stream: Server, expected_path: &str) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    assert_eq!(request.uri().path(), expected_path);
    respond.send_response(Response::builder().status(StatusCode::OK).body(())?, true)?;
    connection.graceful_shutdown();
    match poll_fn(|context| connection.poll_closed(context)).await {
        Ok(()) => Ok(()),
        Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn serve_http1(mut stream: Server) -> TestResult<()> {
    tls_support::read_head(&mut stream).await?;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    stream.shutdown().await?;
    // Keep the socket open while the peer finishes TLS and closes its side.
    // Dropping it with unread handshake bytes can reset the response on Windows.
    let mut remaining = [0_u8; 1];
    match stream.read(&mut remaining).await {
        Ok(0) => Ok(()),
        Ok(_) => Err("unexpected bytes after the HTTP/1 request".into()),
        Err(error) if tls_support::is_peer_gone(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Returns frame types whose headers arrived before the handshake completed.
/// The last frame's payload, or the next header, may arrive after that point.
pub(super) fn h2_frame_types(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut frames = bytes
        .strip_prefix(H2_PREFACE)
        .ok_or("the early data does not start with the HTTP/2 preface")?;
    let mut types = Vec::new();
    while let Some(header) = frames.first_chunk::<9>() {
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        types.push(header[3]);
        let Some(rest) = frames.get(9 + length..) else {
            break;
        };
        frames = rest;
    }
    Ok(types)
}

pub(super) async fn bounded<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    timeout(TEST_TIMEOUT, future).await?
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io, net::Ipv4Addr};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
        time::{error::Elapsed, timeout},
    };

    use super::{CLEANUP_TIMEOUT, TestResult, bounded, finish, join};
    use crate::support::tunnel_proxy::{ConnectionPeer, connection_peer::FixtureFailures};

    #[tokio::test]
    async fn a_closed_channel_retains_the_completed_tcp_worker_failure() -> TestResult<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (sent, received) = oneshot::channel::<()>();
        let mut server = Some(ConnectionPeer::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut byte = [0; 1];
            socket.read_exact(&mut byte).await?;
            drop(sent);
            Err::<(), _>(Box::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                WorkerFailure,
            )) as Box<dyn Error + Send + Sync>)
        }));
        let peer = server
            .as_ref()
            .ok_or("original TCP worker missing")?
            .abort_handle();
        let target = bounded(async {
            let mut socket = TcpStream::connect(address).await?;
            socket.write_all(b"x").await?;
            received.await?;
            join(&mut server).await
        })
        .await;
        let target = finish(target, server).await;

        // Observe the original outcomes before test-runtime teardown.
        let error = target.err().ok_or("closed notification succeeded")?;
        let errors = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("missing paired causes")?;
        assert!(errors.primary.is::<oneshot::error::RecvError>());
        let serving = errors
            .cleanup
            .downcast_ref::<io::Error>()
            .ok_or("missing serving I/O cause")?;
        assert_eq!(serving.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            serving
                .get_ref()
                .is_some_and(|cause| cause.is::<WorkerFailure>())
        );
        assert!(peer.is_finished());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_tls_fixture_deadline_closes_its_original_accepted_socket() -> TestResult<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (accepted, received) = oneshot::channel();
        let mut server = Some(ConnectionPeer::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            accepted.send(()).map_err(|_| "accept observer stopped")?;
            let mut byte = [0; 1];
            socket.read_exact(&mut byte).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }));
        let peer = server
            .as_ref()
            .ok_or("original TCP worker missing")?
            .abort_handle();
        let mut socket = TcpStream::connect(address).await?;
        received.await?;
        let target = bounded(async { join(&mut server).await }).await;
        let target = finish(target, server).await;

        let error = target
            .err()
            .ok_or("the pending worker did not reach its deadline")?;
        assert!(error.is::<Elapsed>());
        assert!(peer.is_finished());

        tokio::time::resume();
        let mut byte = [0; 1];
        assert_eq!(timeout(CLEANUP_TIMEOUT, socket.read(&mut byte)).await??, 0);
        Ok(())
    }

    #[derive(Debug)]
    struct WorkerFailure;

    impl std::fmt::Display for WorkerFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("original TCP worker failure")
        }
    }

    impl Error for WorkerFailure {}
}
