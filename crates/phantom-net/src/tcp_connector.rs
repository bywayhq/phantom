//! Caller-supplied byte streams for direct HTTP connections.

use std::{fmt, future::Future, io, pin::Pin, sync::Arc};

use crate::route::{ConnectedStream, DirectTlsSetup, OriginRoute, TcpRoute};

/// The URL host and port for a new connection, before TLS or HTTP setup.
///
/// The host has no IPv6 brackets. It remains the HTTP authority and TLS
/// server identity even when the connector reaches a different address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectTarget {
    /// URL host, without IPv6 brackets.
    pub host: String,
    /// URL port, including the scheme's default when omitted in the URL.
    pub port: u16,
}

type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<ConnectedStream>> + Send>>;
type Connect = dyn Fn(ConnectTarget) -> ConnectFuture + Send + Sync;

/// Opens caller-owned streams while Phantom retains TLS and HTTP setup.
///
/// The caller owns DNS, address selection, socket options and source binding.
/// Phantom does not apply TCP recipes to the returned stream. Return a fresh
/// plaintext stream for each invocation, including for HTTPS URLs. TLS still
/// verifies the URL host with the client's configured trust and pin policies.
/// Dropping a connection attempt drops its future; the callback must not leave
/// background connection work running after cancellation.
///
/// Only direct HTTP/1.1, HTTP/2 and ALPN negotiation are supported. Proxy
/// routes, HTTP/3 and DNS-based ECH discovery are unsupported. Reusing a
/// connector across clients does not share their connection pools.
/// Low-level connectors reject an additional host resolver or source binding.
#[derive(Clone)]
pub struct TcpConnector(Arc<Connect>);

impl TcpConnector {
    /// Builds a connector from an asynchronous stream-opening function.
    ///
    /// Errors retain their typed I/O source. Debug output omits the callback.
    #[must_use]
    pub fn from_fn<F, Fut>(connect: F) -> Self
    where
        F: Fn(ConnectTarget) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<ConnectedStream>> + Send + 'static,
    {
        Self(Arc::new(move |target| Box::pin(connect(target))))
    }

    /// Opens every connection through the specified Unix-domain socket.
    ///
    /// The request URL still supplies HTTP authority and TLS identity. The
    /// path is copied without opening a socket and is omitted from Debug.
    #[cfg(unix)]
    #[must_use]
    pub fn unix_socket(path: impl Into<std::path::PathBuf>) -> Self {
        let path = Arc::new(path.into());
        Self::from_fn(move |_| {
            let path = Arc::clone(&path);
            async move {
                tokio::net::UnixStream::connect(path.as_path())
                    .await
                    .map(ConnectedStream::new)
            }
        })
    }

    pub(crate) fn check_socket_policy(
        &self,
        source: Option<&crate::SourceBinding>,
        resolver: Option<&crate::host_resolver::HostResolver>,
    ) -> io::Result<()> {
        if source.is_some() || resolver.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "custom TCP connectors own source binding and DNS",
            ));
        }
        Ok(())
    }

    pub(crate) async fn prepare<'a>(&self, route: OriginRoute<'a>) -> io::Result<OriginRoute<'a>> {
        route.validate(true, true)?;
        let endpoint = match &route {
            OriginRoute::Plaintext {
                tcp: TcpRoute::Direct(endpoint),
                ..
            }
            | OriginRoute::Tls {
                tcp: TcpRoute::Direct(endpoint),
                setup: DirectTlsSetup::Default | DirectTlsSetup::KeepSlower(_),
                ..
            } => *endpoint,
            _ => return Err(unsupported()),
        };
        let stream = (self.0)(ConnectTarget {
            host: endpoint.host.to_owned(),
            port: endpoint.port,
        })
        .await?;
        Ok(match route {
            OriginRoute::Plaintext { .. } => OriginRoute::Plaintext {
                tcp: TcpRoute::Connected(stream),
                family: None,
            },
            OriginRoute::Tls { server_name, .. } => OriginRoute::Tls {
                tcp: TcpRoute::Connected(stream),
                server_name,
                setup: DirectTlsSetup::Default,
            },
        })
    }
}

impl fmt::Debug for TcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TcpConnector(..)")
    }
}

pub(crate) fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "custom TCP connectors require a direct TCP route without DNS-based ECH discovery",
    )
}
