//! A loopback TLS server for early data over TCP: it accepts tickets that
//! permit early data, records the bytes it read before its handshake
//! completed, and serves one HTTP/1.1 or HTTP/2 request.

use crate::support::tls as tls_support;

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
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough that the client's early data is on the wire before the server
/// answers its ClientHello.
pub(super) const SERVER_DELAY: Duration = Duration::from_millis(200);
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(super) const H2_HEADERS: u8 = 0x1;

pub(super) type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

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
    let (tcp, _) = listener.accept().await?;
    tokio::time::sleep(delay).await;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.set_early_data_enabled(true);
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
    Ok(())
}

/// Returns the type of every frame after the client preface.
pub(super) fn h2_frame_types(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut frames = bytes
        .strip_prefix(H2_PREFACE)
        .ok_or("the early data does not start with the HTTP/2 preface")?;
    let mut types = Vec::new();
    while let Some(header) = frames.first_chunk::<9>() {
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        types.push(header[3]);
        frames = frames.get(9 + length..).unwrap_or_default();
    }
    Ok(types)
}

pub(super) async fn bounded<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    timeout(TEST_TIMEOUT, future).await?
}
