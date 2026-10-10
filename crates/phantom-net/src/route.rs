//! Borrowed routes used to connect to an origin.

use crate::proxy::{HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector, Socks5Auth};
use crate::{
    request::{AbsoluteForm, OriginForm},
    tcp::AddressFamilyMemory,
};

pub use connected::ConnectedStream;
pub use datagram::{ConnectUdpRoute, ConnectUdpTransport, DatagramRoute};

mod connected;
mod datagram;

/// Pinned HTTPS-record lookup borrowed for one connection setup.
#[cfg(feature = "https-records")]
pub type EchLookup<'a> = std::pin::Pin<
    &'a mut (dyn std::future::Future<Output = Option<crate::dns::EchConfigList>> + Send + 'a),
>;

/// A host and port to connect to or ask a proxy to reach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint<'a> {
    /// Host name or IP address, without IPv6 brackets.
    pub host: &'a str,
    /// Target port.
    pub port: u16,
}

/// Transport used to reach an HTTP proxy.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ProxyTransport<'a> {
    /// A plaintext TCP connection to the proxy.
    Tcp(Endpoint<'a>),
    /// TLS to the proxy with its independent connector and server identity.
    Tls {
        /// Proxy host and port to connect to.
        endpoint: Endpoint<'a>,
        /// Proxy name used for TLS authentication.
        server_name: &'a str,
        /// Connector that owns proxy TLS, socket, and authentication policy.
        connector: &'a HttpsProxyConnector,
    },
}

/// An HTTP CONNECT tunnel, with ordered headers and optional Basic credentials.
///
/// The authority and headers are validated before proxy I/O. Credentials use
/// the proxy's challenge and credential-cache policy. Debug output redacts
/// the credential values.
#[derive(Clone, Copy, Debug)]
pub struct HttpConnectRoute<'a> {
    /// Transport to the proxy.
    pub proxy: ProxyTransport<'a>,
    /// CONNECT authority, including the target port and any IPv6 brackets.
    pub authority: &'a str,
    /// CONNECT headers in their wire order.
    pub headers: &'a [HttpConnectHeader],
    /// Credentials for challenge-driven Basic authentication.
    pub credentials: Option<&'a HttpBasicCredentials>,
}

/// A SOCKS5 CONNECT target with explicit DNS ownership.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Socks5Target<'a> {
    /// Resolve the target locally before opening a tunnel.
    LocalDns(Endpoint<'a>),
    /// Send the target to the proxy without resolving it locally.
    RemoteDns(Endpoint<'a>),
}

/// Route that supplies a TCP byte stream to an origin.
///
/// Origin TLS and HTTP setup follow the route's connection setup. A proxy
/// failure does not cause a direct connection or a change of route.
#[derive(Debug)]
#[non_exhaustive]
pub enum TcpRoute<'a> {
    /// Connect directly to this host and port.
    Direct(Endpoint<'a>),
    /// Use a stream already opened by the caller, without applying socket options.
    Connected(ConnectedStream),
    /// Open an HTTP CONNECT tunnel through a plaintext or TLS proxy.
    HttpConnect(HttpConnectRoute<'a>),
    /// Open a SOCKS5 CONNECT tunnel with the selected DNS and auth policy.
    Socks5 {
        /// SOCKS5 proxy host and port.
        proxy: Endpoint<'a>,
        /// Target host and port, with the selected DNS owner.
        target: Socks5Target<'a>,
        /// Authentication offered to the proxy.
        auth: Socks5Auth<'a>,
    },
}

/// Setup policy for a new direct origin TLS connection.
///
/// ECH and retaining a slower address attempt are separate policies. Both
/// require a direct route. Retaining a slower attempt is supported only by
/// HTTP/1.1 and negotiated connection openings.
#[non_exhaustive]
pub enum DirectTlsSetup<'a> {
    /// Use the connector's normal TLS setup.
    Default,
    /// Overlap TCP setup with an HTTPS-record lookup, then apply its bounded wait.
    #[cfg(feature = "https-records")]
    Ech(EchLookup<'a>),
    /// Retain the slower address attempt and update the origin's address family.
    KeepSlower(&'a AddressFamilyMemory),
}

impl std::fmt::Debug for DirectTlsSetup<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => formatter.write_str("Default"),
            #[cfg(feature = "https-records")]
            Self::Ech(_) => formatter.write_str("Ech(..)"),
            Self::KeepSlower(_) => formatter.write_str("KeepSlower(..)"),
        }
    }
}

/// Transport and authentication used to reach the origin through a TCP route.
#[derive(Debug)]
#[non_exhaustive]
pub enum OriginRoute<'a> {
    /// Plaintext HTTP/1.1, with optional family memory for a direct connection.
    Plaintext {
        /// Byte-stream route to the origin.
        tcp: TcpRoute<'a>,
        /// Retain the slower direct attempt for an HTTP/1.1 connection opening.
        family: Option<&'a AddressFamilyMemory>,
    },
    /// Origin TLS, independent of any TLS used to reach a proxy.
    Tls {
        /// Byte-stream route to the origin.
        tcp: TcpRoute<'a>,
        /// Origin name used for TLS authentication.
        server_name: &'a str,
        /// Direct-connection setup policy.
        setup: DirectTlsSetup<'a>,
    },
}

impl OriginRoute<'_> {
    /// Reject unsupported setup before lookup polling or connection I/O.
    pub(crate) fn validate(&self, plaintext: bool, slower: bool) -> Result<(), std::io::Error> {
        let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
        match self {
            Self::Plaintext { tcp, family } => {
                if !plaintext {
                    return Err(invalid("this protocol requires origin TLS"));
                }
                if family.is_some() && (!slower || !matches!(tcp, TcpRoute::Direct(_))) {
                    return Err(invalid(
                        "retaining a slower attempt requires a direct connection opening",
                    ));
                }
            }
            Self::Tls { tcp, setup, .. } => {
                if !matches!(setup, DirectTlsSetup::Default) && !matches!(tcp, TcpRoute::Direct(_))
                {
                    return Err(invalid("direct TLS setup requires a direct TCP route"));
                }
                if matches!(setup, DirectTlsSetup::KeepSlower(_)) && !slower {
                    return Err(invalid("this operation cannot retain a slower connection"));
                }
            }
        }
        Ok(())
    }
}

/// HTTP/1.1 origin transport or explicit forward-proxy transport.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1Route<'a> {
    /// Reach the origin directly or through a byte-stream tunnel.
    Origin(OriginRoute<'a>),
    /// Reach a forwarding proxy, with no origin TLS or CONNECT exchange.
    Forward(ProxyTransport<'a>),
}

/// HTTP/2 origin transport or explicit TLS forward-proxy transport.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http2Route<'a> {
    /// Reach an origin with TLS over a direct connection or a tunnel.
    Origin(OriginRoute<'a>),
    /// Use the supplied proxy connector's HTTP/2 connection and TLS policy.
    Forward {
        /// Requires TLS to a proxy configured for exact HTTP/2.
        proxy: ProxyTransport<'a>,
        /// Credential partition for the proxy connection pool.
        credentials: Option<&'a HttpBasicCredentials>,
    },
}

/// HTTP/1.1 request target, with forwarding selected explicitly.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Http1Target {
    /// Origin-form target for an origin route.
    Origin(OriginForm),
    /// Absolute-form target for a forwarding route.
    Absolute(AbsoluteForm),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_route_debug_redacts_basic_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let password = format!("{:?}", std::time::Instant::now());
        let credentials = HttpBasicCredentials::new("private-user", &password)?;
        let route = TcpRoute::HttpConnect(HttpConnectRoute {
            proxy: ProxyTransport::Tcp(Endpoint {
                host: "proxy.example",
                port: 8080,
            }),
            authority: "origin.example:443",
            headers: &[],
            credentials: Some(&credentials),
        });
        let debug = format!("{route:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains(&password));
        assert!(debug.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn socks5_route_debug_redacts_credentials() {
        let route = TcpRoute::Socks5 {
            proxy: Endpoint {
                host: "proxy.example",
                port: 1080,
            },
            target: Socks5Target::RemoteDns(Endpoint {
                host: "origin.example",
                port: 443,
            }),
            auth: Socks5Auth::UsernamePassword {
                username: "private-user",
                password: "private-password",
            },
        };
        let debug = format!("{route:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
        assert!(debug.contains("redacted"));
    }
}
