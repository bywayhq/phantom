use crate::support::tls::TestResult;
use btls::ssl::{Ssl, SslAcceptor};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_btls::SslStream;

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
    ) -> Poll<io::Result<()>> {
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
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

pub(super) async fn accept(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    enabled: bool,
    delay: Duration,
) -> TestResult<Server> {
    let (tcp, _) = listener.accept().await?;
    // Same 200 ms peer scheduling used by session_tcp_early_data. Acceptance
    // and recorded native pre-handshake bytes, not this delay, are the oracle.
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

pub(super) fn frame_types(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut rest = bytes
        .strip_prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .ok_or("missing early H2 preface")?;
    let mut types = Vec::new();
    while let Some(header) = rest.first_chunk::<9>() {
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        types.push(header[3]);
        let Some(next) = rest.get(9 + length..) else {
            break;
        };
        rest = next;
    }
    Ok(types)
}

pub(super) async fn no_application(mut peer: Server) -> TestResult<()> {
    assert!(!peer.stream.ssl().early_data_accepted());
    let mut byte = [0];
    match peer.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error) if crate::support::tls::is_peer_gone(&error) => Ok(()),
        Ok(_) => Err("changed ALPN peer received application data".into()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn source_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        text.push_str(": ");
        text.push_str(&error.to_string());
        source = error.source();
    }
    text
}
