//! Opt-in HTTP/1.1 CONNECT combined with the first origin TLS write.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use super::{
    HttpConnectError, HttpProxyAuthentication, HttpsProxyProtocol,
    http_connect::{
        MAX_CONNECT_HEAD_BYTES, MAX_INFORMATIONAL_RESPONSES, PreparedBasicConnect, PreparedConnect,
        find_head_end, parse_response,
    },
};
use crate::route::{HttpConnectRoute, ProxyTransport};

const FIRST_WRITE_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) struct ProxyFailure(pub(crate) HttpConnectError);

impl fmt::Display for ProxyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ProxyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

pub(super) fn prepare(route: HttpConnectRoute<'_>) -> Result<PreparedConnect, HttpConnectError> {
    if matches!(route.proxy, ProxyTransport::Tls { connector, .. }
        if connector.protocol() != HttpsProxyProtocol::Http1)
    {
        return Err(HttpConnectError::SpeculativeTlsUnsupported);
    }
    match route.credentials {
        None => PreparedConnect::new(route.authority, route.headers),
        Some(HttpProxyAuthentication::Basic(credentials)) => {
            Ok(
                PreparedBasicConnect::new(route.authority, route.headers, credentials)?
                    .authenticated,
            )
        }
        Some(HttpProxyAuthentication::Digest(_)) => {
            Err(HttpConnectError::SpeculativeTlsUnsupported)
        }
    }
}

pub(crate) async fn connect(
    route: HttpConnectRoute<'_>,
    dialer: crate::direct::Dialer<'_>,
) -> Result<SpeculativeConnect<super::http1_opening::ProxyStream>, HttpConnectError> {
    use super::http1_opening::ProxyStream;
    let request = prepare(route)?;
    let stream = match route.proxy {
        ProxyTransport::Tcp(endpoint) => {
            super::http_connect::connect_proxy_tcp(dialer, endpoint.host, endpoint.port)
                .await
                .map(ProxyStream::Tcp)
        }
        ProxyTransport::Tls {
            endpoint,
            server_name,
            connector,
        } => connector
            .connect_http1_proxy(endpoint.host, endpoint.port, server_name)
            .await
            .map(ProxyStream::HttpsReady),
    }?;
    Ok(SpeculativeConnect::new(stream, request))
}

/// The first write is buffered with CONNECT; reading flushes both before
/// parsing the proxy response. No origin byte reaches the TLS reader until
/// a successful final response. A failed negotiation drops the proxy socket.
pub(crate) struct SpeculativeConnect<S> {
    inner: Option<S>,
    outgoing: Zeroizing<Vec<u8>>,
    written: usize,
    first_write: bool,
    response: Vec<u8>,
    prefix: Bytes,
    informational: usize,
    accepted: bool,
}

impl<S> SpeculativeConnect<S> {
    pub(super) fn new(inner: S, request: PreparedConnect) -> Self {
        let prepared = request.into_bytes();
        // Allocate before copying credentials so appending ClientHello never
        // frees an unwiped credential-bearing allocation.
        let mut outgoing = Zeroizing::new(Vec::with_capacity(prepared.len() + FIRST_WRITE_BYTES));
        outgoing.extend_from_slice(&prepared);
        Self {
            inner: Some(inner),
            outgoing,
            written: 0,
            first_write: true,
            response: Vec::new(),
            prefix: Bytes::new(),
            informational: 0,
            accepted: false,
        }
    }

    fn fail(&mut self, error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
        self.inner.take();
        self.outgoing = Zeroizing::new(Vec::new());
        self.response.clear();
        io::Error::other(error)
    }

    fn closed() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "speculative CONNECT is closed")
    }

    fn fail_proxy(&mut self, error: HttpConnectError) -> io::Error {
        self.fail(ProxyFailure(error))
    }
}

impl<S: AsyncWrite + Unpin> SpeculativeConnect<S> {
    fn poll_drain(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.outgoing.len() {
            let Some(inner) = self.inner.as_mut() else {
                return Poll::Ready(Err(Self::closed()));
            };
            match ready!(Pin::new(inner).poll_write(context, &self.outgoing[self.written..])) {
                Ok(0) => {
                    let error = io::Error::new(io::ErrorKind::WriteZero, "CONNECT write stopped");
                    return Poll::Ready(Err(self.fail_proxy(HttpConnectError::Write(error))));
                }
                Ok(written) => self.written += written,
                Err(error) => {
                    return Poll::Ready(Err(self.fail_proxy(HttpConnectError::Write(error))));
                }
            }
        }
        if !self.outgoing.is_empty() {
            self.outgoing = Zeroizing::new(Vec::new());
            self.written = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> fmt::Debug for SpeculativeConnect<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpeculativeConnect")
            .field("accepted", &self.accepted)
            .field("closed", &self.inner.is_none())
            .finish_non_exhaustive()
    }
}

impl<S: crate::tcp::TcpKeepaliveSource> crate::tcp::TcpKeepaliveSource for SpeculativeConnect<S> {
    fn tcp_keepalive(&self) -> Option<crate::tcp::TcpKeepaliveControl> {
        self.inner.as_ref().and_then(S::tcp_keepalive)
    }
}

impl<S: crate::connection_diagnostics::ConnectionMetadataSource>
    crate::connection_diagnostics::ConnectionMetadataSource for SpeculativeConnect<S>
{
    fn connection_metadata(&self) -> crate::connection_diagnostics::ConnectionMetadata {
        self.inner
            .as_ref()
            .map(S::connection_metadata)
            .unwrap_or_default()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SpeculativeConnect<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !this.accepted {
            ready!(Pin::new(&mut *this).poll_flush(context))?;
        }
        while !this.accepted {
            if let Some(end) = find_head_end(&this.response) {
                let status = match parse_response(&this.response[..end], false) {
                    Ok(response) => response.status,
                    Err(error) => return Poll::Ready(Err(this.fail_proxy(error))),
                };
                if status != 101 && (100..200).contains(&status) {
                    this.informational += 1;
                    if this.informational > MAX_INFORMATIONAL_RESPONSES {
                        return Poll::Ready(Err(this.fail_proxy(
                            HttpConnectError::TooManyInformationalResponses {
                                maximum: MAX_INFORMATIONAL_RESPONSES,
                            },
                        )));
                    }
                    this.response.drain(..end);
                    continue;
                }
                if !(200..300).contains(&status) {
                    return Poll::Ready(
                        Err(this.fail_proxy(HttpConnectError::Rejected { status })),
                    );
                }
                this.prefix = Bytes::from(std::mem::take(&mut this.response)).slice(end..);
                this.accepted = true;
                break;
            }
            if this.response.len() == MAX_CONNECT_HEAD_BYTES {
                return Poll::Ready(Err(this.fail_proxy(
                    HttpConnectError::ResponseHeadTooLarge {
                        maximum: MAX_CONNECT_HEAD_BYTES,
                    },
                )));
            }
            let mut chunk = [0_u8; 4096];
            let limit = chunk
                .len()
                .min(MAX_CONNECT_HEAD_BYTES - this.response.len());
            let mut input = ReadBuf::new(&mut chunk[..limit]);
            let Some(inner) = this.inner.as_mut() else {
                return Poll::Ready(Err(Self::closed()));
            };
            match ready!(Pin::new(inner).poll_read(context, &mut input)) {
                Err(error) => {
                    return Poll::Ready(Err(this.fail_proxy(HttpConnectError::Read(error))));
                }
                Ok(()) if input.filled().is_empty() => {
                    return Poll::Ready(Err(this.fail_proxy(HttpConnectError::InvalidResponse)));
                }
                Ok(()) => this.response.extend_from_slice(input.filled()),
            }
        }
        if !this.prefix.is_empty() {
            let length = this.prefix.len().min(output.remaining());
            output.put_slice(&this.prefix.split_to(length));
            return Poll::Ready(Ok(()));
        }
        match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_read(context, output),
            None => Poll::Ready(Err(Self::closed())),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SpeculativeConnect<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.inner.is_none() {
            return Poll::Ready(Err(Self::closed()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.first_write {
            this.first_write = false;
            if !this.accepted {
                let length = bytes.len().min(FIRST_WRITE_BYTES);
                this.outgoing.extend_from_slice(&bytes[..length]);
                return Poll::Ready(Ok(length));
            }
        }
        ready!(this.poll_drain(context))?;
        let result = match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_write(context, bytes),
            None => Poll::Ready(Err(Self::closed())),
        };
        match result {
            Poll::Ready(Err(error)) if !this.accepted => {
                Poll::Ready(Err(this.fail_proxy(HttpConnectError::Write(error))))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        let result = match this.inner.as_mut() {
            Some(inner) => ready!(Pin::new(inner).poll_flush(context)),
            None => return Poll::Ready(Err(Self::closed())),
        };
        Poll::Ready(result.map_err(|error| {
            if this.accepted {
                error
            } else {
                this.fail_proxy(HttpConnectError::Write(error))
            }
        }))
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.accepted {
            this.inner.take();
            this.outgoing = Zeroizing::new(Vec::new());
            return Poll::Ready(Ok(()));
        }
        match this.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_shutdown(context),
            None => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests;
