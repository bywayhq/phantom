//! Borrowed routes used to open TCP connections to an origin.

use crate::proxy::{HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector, Socks5Auth};

/// A host and port to connect to or ask a proxy to reach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint<'a> {
    /// Host name or IP address, without IPv6 brackets.
    pub host: &'a str,
    /// TCP port.
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
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum TcpRoute<'a> {
    /// Connect directly to this host and port.
    Direct(Endpoint<'a>),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::HttpConnectError;

    #[test]
    fn http_route_debug_redacts_basic_credentials() -> Result<(), HttpConnectError> {
        let credentials = HttpBasicCredentials::new("private-user", "private-password")?;
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
        assert!(!debug.contains("private-password"));
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
