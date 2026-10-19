//! Borrowed routes used to connect to an origin.

use crate::proxy::{
    HttpConnectHeader, HttpProxyAuthentication, HttpsProxyConnector, Socks4UserId, Socks5Auth,
};
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

/// An HTTP CONNECT tunnel, with ordered headers and explicit authentication.
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
    /// Credentials for the selected challenge-driven authentication scheme.
    pub credentials: Option<HttpProxyAuthentication<'a>>,
    /// Send CONNECT with the origin's first TLS write, before proxy acceptance.
    ///
    /// Requires origin TLS and an HTTP/1.1 proxy leg. Basic credentials are
    /// sent preemptively. Digest and challenge retries are unsupported.
    pub speculative_tls: bool,
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

/// A SOCKS4 CONNECT target with explicit DNS ownership.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Socks4Target<'a> {
    /// Resolve locally and use the first IPv4 answer; IPv6-only answers fail.
    LocalDns(Endpoint<'a>),
    /// Send a domain to the SOCKS4a proxy; IPv4 literals need no lookup.
    /// Callers supply canonical ASCII names, NUL-free, nonempty and at most
    /// 253 bytes. Non-ASCII names fail before proxy I/O.
    /// Port zero and IPv4 addresses in the reserved 0.0.0.1–255 marker range
    /// fail before proxy I/O, as do IPv6 literals.
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
    /// Open a SOCKS4 or SOCKS4a TCP tunnel; IPv6 targets are unsupported.
    Socks4 {
        /// Proxy endpoint, which may itself use IPv6.
        proxy: Endpoint<'a>,
        /// Target with explicit DNS ownership.
        target: Socks4Target<'a>,
        /// Identification sent to the proxy; debug output redacts it.
        user_id: Socks4UserId<'a>,
    },
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
/// ECH and retaining a slower address attempt can be used together. Both
/// require a direct route. HTTP/1.1, negotiated and exact HTTP/2 openings
/// support retention. After HTTP/2 selection, only an already-connected
/// slower attempt is retained.
#[non_exhaustive]
pub enum DirectTlsSetup<'a> {
    /// Use the connector's normal TLS setup.
    Default,
    /// Overlap TCP setup with an HTTPS-record lookup, then apply its bounded wait.
    #[cfg(feature = "https-records")]
    Ech(EchLookup<'a>),
    /// Offer the selected HTTPS-record ECH configuration on both address attempts.
    ///
    /// Retain the slower attempt and update the origin's address family.
    #[cfg(feature = "https-records")]
    EchKeepingSlower {
        /// Pinned lookup shared with this connection's discovery operation.
        lookup: EchLookup<'a>,
        /// Origin family memory owned by the connection pool.
        family: &'a AddressFamilyMemory,
    },
    /// Retain the slower address attempt and update the origin's address family.
    KeepSlower(&'a AddressFamilyMemory),
}

impl std::fmt::Debug for DirectTlsSetup<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => formatter.write_str("Default"),
            #[cfg(feature = "https-records")]
            Self::Ech(_) => formatter.write_str("Ech(..)"),
            #[cfg(feature = "https-records")]
            Self::EchKeepingSlower { .. } => formatter.write_str("EchKeepingSlower(..)"),
            Self::KeepSlower(_) => formatter.write_str("KeepSlower(..)"),
        }
    }
}

/// Transport and authentication used to reach the origin through a TCP route.
#[derive(Debug)]
#[non_exhaustive]
pub enum OriginRoute<'a> {
    /// Plaintext HTTP, with optional family memory for HTTP/1.1.
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
                if matches!(tcp, TcpRoute::HttpConnect(route) if route.speculative_tls) {
                    return Err(invalid("speculative CONNECT requires origin TLS"));
                }
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

                let retains_slower = matches!(setup, DirectTlsSetup::KeepSlower(_));
                #[cfg(feature = "https-records")]
                let retains_slower =
                    retains_slower || matches!(setup, DirectTlsSetup::EchKeepingSlower { .. });
                if retains_slower && !slower {
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
    /// Reach an origin with TLS over a direct connection or a tunnel, or use
    /// direct plaintext with HTTP/2 prior knowledge.
    Origin(OriginRoute<'a>),
    /// Use the supplied proxy connector's HTTP/2 connection and TLS policy.
    Forward {
        /// Requires TLS to a proxy configured for exact HTTP/2.
        proxy: ProxyTransport<'a>,
        /// Credential partition for the proxy connection pool.
        credentials: Option<HttpProxyAuthentication<'a>>,
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
        let credentials = crate::proxy::HttpBasicCredentials::new("private-user", &password)?;
        let route = TcpRoute::HttpConnect(HttpConnectRoute {
            speculative_tls: false,
            proxy: ProxyTransport::Tcp(Endpoint {
                host: "proxy.example",
                port: 8080,
            }),
            authority: "origin.example:443",
            headers: &[],
            credentials: Some(HttpProxyAuthentication::Basic(&credentials)),
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

    #[cfg(feature = "https-records")]
    #[test]
    fn ech_retention_requires_a_direct_opening_without_polling_the_lookup() {
        let family = AddressFamilyMemory::new();
        let polled = std::sync::atomic::AtomicBool::new(false);
        let mut lookup = std::pin::pin!(std::future::poll_fn(|_| {
            polled.store(true, std::sync::atomic::Ordering::Relaxed);
            std::task::Poll::Ready(None)
        }));
        {
            let route = OriginRoute::Tls {
                tcp: TcpRoute::Direct(Endpoint {
                    host: "origin.test",
                    port: 443,
                }),
                server_name: "origin.test",
                setup: DirectTlsSetup::EchKeepingSlower {
                    lookup: lookup.as_mut(),
                    family: &family,
                },
            };
            assert!(route.validate(false, true).is_ok());
            assert_eq!(
                route.validate(false, false).err().map(|error| error.kind()),
                Some(std::io::ErrorKind::InvalidInput)
            );
            assert!(format!("{route:?}").contains("EchKeepingSlower(..)"));
        }
        let route = OriginRoute::Tls {
            tcp: TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: "proxy.test",
                    port: 1080,
                },
                target: Socks5Target::RemoteDns(Endpoint {
                    host: "origin.test",
                    port: 443,
                }),
                auth: Socks5Auth::None,
            },
            server_name: "origin.test",
            setup: DirectTlsSetup::EchKeepingSlower {
                lookup: lookup.as_mut(),
                family: &family,
            },
        };
        assert_eq!(
            route.validate(false, true).err().map(|error| error.kind()),
            Some(std::io::ErrorKind::InvalidInput)
        );
        assert!(!polled.load(std::sync::atomic::Ordering::Relaxed));
    }
}
