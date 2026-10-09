//! Caller-owned streams supplied to a route.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

/// An already-connected stream owned by a route.
///
/// The connector performs protocol setup but does not resolve names, open a
/// socket, apply profile socket options, or recover TCP keepalive metadata.
///
/// # Examples
///
/// You can open a Tokio socket and use it for plaintext HTTP/1.1.
/// `OriginRoute::Plaintext` selects HTTP without TLS.
///
/// ```no_run
/// use phantom_net::{
///     http1::{Http1TlsConnector, OriginForm, RequestHeader},
///     route::{ConnectedStream, Http1Route, OriginRoute, TcpRoute},
/// };
/// use phantom_profile::browser::chrome;
/// use tokio::net::TcpStream;
///
/// # async fn request() -> Result<(), Box<dyn std::error::Error>> {
/// let tls = chrome::v154_tcp_tls()
///     .with_alpn_protocols(&[Box::from(&b"http/1.1"[..])])?;
/// let connector = Http1TlsConnector::new(&tls)?;
/// let socket = TcpStream::connect("example.com:80").await?;
/// let route = Http1Route::Origin(OriginRoute::Plaintext {
///     tcp: TcpRoute::Connected(ConnectedStream::new(socket)),
///     family: None,
/// });
/// let (connection, _slower) = connector.connect(route).await?;
/// let _response = connection.send_get(
///     OriginForm::parse("/")?,
///     vec![RequestHeader::new("Host", "example.com")],
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct ConnectedStream(Box<dyn Stream>);

impl ConnectedStream {
    /// Wraps a caller-owned stream for a connection or one-shot operation.
    #[must_use]
    pub fn new(stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
        Self(Box::new(stream))
    }
}

impl fmt::Debug for ConnectedStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectedStream(..)")
    }
}

impl AsyncRead for ConnectedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_read(context, buffer)
    }
}

impl AsyncWrite for ConnectedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(context)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}
