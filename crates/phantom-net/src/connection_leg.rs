//! TCP and proxy connection setup shared by the HTTP connectors.

use std::{
    error::Error,
    fmt,
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    direct::{Dialer, DirectConnectError, connect_tcp},
    proxy::{
        HttpConnectError, HttpsProxyTunnel, ProxyCredentialCache, Socks5Error, TunnelStream,
        http_connect_tunnel, http_connect_tunnel_with_basic_auth, socks5_tunnel_local_dns,
        socks5_tunnel_remote_dns,
    },
    route::{ConnectedStream, ProxyTransport, Socks5Target, TcpRoute},
    tcp::{ProfileTcpStream, TcpKeepaliveControl, TcpKeepaliveSource},
};

/// Owns the connected stream, including buffered tunnel bytes and proxy leases.
#[derive(Debug)]
pub(crate) enum ConnectionLeg {
    Tcp(ProfileTcpStream),
    HttpConnect(TunnelStream<ProfileTcpStream>),
    HttpsConnect(HttpsProxyTunnel),
    Connected(ConnectedStream),
}

/// Failure before origin TLS or HTTP setup.
pub(crate) enum ConnectionLegError {
    Direct(DirectConnectError),
    HttpProxy(HttpConnectError),
    Socks5(Socks5Error),
}

impl fmt::Debug for ConnectionLegError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(DirectConnectError::RuntimeUnavailable) => {
                formatter.write_str("Direct(RuntimeUnavailable)")
            }
            Self::Direct(DirectConnectError::Connect(error)) => {
                formatter.debug_tuple("Direct").field(error).finish()
            }
            Self::HttpProxy(error) => formatter.debug_tuple("HttpProxy").field(error).finish(),
            Self::Socks5(error) => formatter.debug_tuple("Socks5").field(error).finish(),
        }
    }
}

impl fmt::Display for ConnectionLegError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(DirectConnectError::RuntimeUnavailable) => {
                formatter.write_str("TCP connections require a Tokio I/O runtime")
            }
            Self::Direct(DirectConnectError::Connect(error)) => {
                write!(formatter, "TCP connection failed: {error}")
            }
            Self::HttpProxy(error) => write!(formatter, "HTTP proxy failed: {error}"),
            Self::Socks5(error) => write!(formatter, "SOCKS5 proxy failed: {error}"),
        }
    }
}

impl Error for ConnectionLegError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Direct(DirectConnectError::RuntimeUnavailable) => None,
            Self::Direct(DirectConnectError::Connect(error)) => Some(error),
            Self::HttpProxy(error) => Some(error),
            Self::Socks5(error) => Some(error),
        }
    }
}

pub(crate) async fn connect(
    route: TcpRoute<'_>,
    dialer: Dialer<'_>,
    cache: Option<&ProxyCredentialCache>,
) -> Result<ConnectionLeg, ConnectionLegError> {
    match route {
        TcpRoute::Connected(stream) => Ok(ConnectionLeg::Connected(stream)),
        TcpRoute::Direct(endpoint) => connect_tcp(endpoint.host, endpoint.port, dialer)
            .await
            .map(ConnectionLeg::Tcp)
            .map_err(ConnectionLegError::Direct),
        TcpRoute::HttpConnect(route) => match route.proxy {
            ProxyTransport::Tcp(endpoint) => {
                let tunnel = match route.credentials {
                    Some(credentials) => {
                        http_connect_tunnel_with_basic_auth(
                            dialer,
                            cache,
                            endpoint.host,
                            endpoint.port,
                            route.authority,
                            route.headers,
                            credentials,
                        )
                        .await
                    }
                    None => {
                        http_connect_tunnel(
                            dialer,
                            endpoint.host,
                            endpoint.port,
                            route.authority,
                            route.headers,
                        )
                        .await
                    }
                };
                tunnel
                    .map(ConnectionLeg::HttpConnect)
                    .map_err(ConnectionLegError::HttpProxy)
            }
            ProxyTransport::Tls {
                endpoint,
                server_name,
                connector,
            } => {
                let tunnel = match route.credentials {
                    Some(credentials) => {
                        connector
                            .connect_tunnel_with_basic_auth(
                                endpoint.host,
                                endpoint.port,
                                server_name,
                                route.authority,
                                route.headers,
                                credentials,
                            )
                            .await
                    }
                    None => {
                        connector
                            .connect_tunnel(
                                endpoint.host,
                                endpoint.port,
                                server_name,
                                route.authority,
                                route.headers,
                            )
                            .await
                    }
                };
                tunnel
                    .map(ConnectionLeg::HttpsConnect)
                    .map_err(ConnectionLegError::HttpProxy)
            }
        },
        TcpRoute::Socks5 {
            proxy,
            target,
            auth,
        } => {
            let stream = match target {
                Socks5Target::LocalDns(target) => {
                    socks5_tunnel_local_dns(
                        dialer,
                        proxy.host,
                        proxy.port,
                        target.host,
                        target.port,
                        auth,
                    )
                    .await
                }
                Socks5Target::RemoteDns(target) => {
                    socks5_tunnel_remote_dns(
                        dialer,
                        proxy.host,
                        proxy.port,
                        target.host,
                        target.port,
                        auth,
                    )
                    .await
                }
            };
            stream
                .map(ConnectionLeg::Tcp)
                .map_err(ConnectionLegError::Socks5)
        }
    }
}

impl AsyncRead for ConnectionLeg {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::HttpConnect(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::HttpsConnect(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Connected(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for ConnectionLeg {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::HttpConnect(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::HttpsConnect(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Connected(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            Self::HttpConnect(stream) => Pin::new(stream).poll_flush(context),
            Self::HttpsConnect(stream) => Pin::new(stream).poll_flush(context),
            Self::Connected(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            Self::HttpConnect(stream) => Pin::new(stream).poll_shutdown(context),
            Self::HttpsConnect(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Connected(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write_vectored(context, buffers),
            Self::HttpConnect(stream) => Pin::new(stream).poll_write_vectored(context, buffers),
            Self::HttpsConnect(stream) => Pin::new(stream).poll_write_vectored(context, buffers),
            Self::Connected(stream) => Pin::new(stream).poll_write_vectored(context, buffers),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(stream) => stream.is_write_vectored(),
            Self::HttpConnect(stream) => stream.is_write_vectored(),
            Self::HttpsConnect(stream) => stream.is_write_vectored(),
            Self::Connected(stream) => stream.is_write_vectored(),
        }
    }
}

impl TcpKeepaliveSource for ConnectionLeg {
    fn tcp_keepalive(&self) -> Option<TcpKeepaliveControl> {
        match self {
            Self::Tcp(stream) => stream.tcp_keepalive(),
            Self::HttpConnect(stream) => stream.tcp_keepalive(),
            Self::HttpsConnect(stream) => stream.tcp_keepalive(),
            Self::Connected(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_leg_preserves_stream_and_keepalive_traits() {
        fn assert_traits<T: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource>() {}
        assert_traits::<ConnectionLeg>();
    }
}
