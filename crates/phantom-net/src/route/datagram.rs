//! Datagram routes for an origin QUIC connection.

use super::{Endpoint, Socks5Target};
use crate::{
    http3::Http3Connector,
    proxy::{HttpBasicCredentials, HttpsProxyConnector, HttpsProxyProtocol, Socks5Auth},
    request::{OriginForm, RequestHeader},
};

/// Transport used to reach a CONNECT-UDP proxy.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectUdpTransport<'a> {
    /// HTTP/3 with the proxy's independent QUIC connector.
    Http3(&'a Http3Connector),
    /// TLS with explicit HTTP/1.1 or HTTP/2 proxy setup.
    Tls {
        /// Connector that owns proxy trust, TLS, sockets, and resolution.
        connector: &'a HttpsProxyConnector,
        /// Protocol used for the CONNECT-UDP exchange.
        protocol: HttpsProxyProtocol,
    },
}

/// An explicit CONNECT-UDP exchange, independent of origin TLS identity.
///
/// The first request omits Basic credentials. A valid challenge permits one
/// authenticated attempt on a fresh proxy connection. Debug omits the path
/// and header values because they may contain secrets.
pub struct ConnectUdpRoute<'a> {
    /// Proxy host and port; the host also supplies its TLS server name.
    pub proxy: Endpoint<'a>,
    /// Outer transport and independent proxy connector.
    pub transport: ConnectUdpTransport<'a>,
    /// Proxy request authority, independent of its dial host.
    pub authority: &'a str,
    /// CONNECT-UDP path that names the selected origin transport target.
    pub path: OriginForm,
    /// Additional proxy headers, in wire order.
    pub headers: Vec<RequestHeader>,
    /// Optional challenge-driven Basic credentials.
    pub credentials: Option<&'a HttpBasicCredentials>,
}

impl std::fmt::Debug for ConnectUdpRoute<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectUdpRoute")
            .field("proxy", &self.proxy)
            .field("transport", &self.transport)
            .field("header_count", &self.headers.len())
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

/// Route that supplies datagrams for one origin QUIC connection.
///
/// The origin TLS name and request authority are supplied separately from
/// the dial target. No proxy failure changes the route or HTTP protocol.
#[non_exhaustive]
pub enum DatagramRoute<'a> {
    /// Resolve and connect to the selected dial target directly.
    Direct(Endpoint<'a>),
    /// Direct QUIC setup with the bounded HTTPS-record lookup.
    #[cfg(feature = "https-records")]
    DirectEch {
        /// Dial target, independent of origin TLS authentication.
        endpoint: Endpoint<'a>,
        /// Pinned lookup whose answer supplies an ECH configuration list.
        lookup: super::EchLookup<'a>,
    },
    /// Open a SOCKS5 UDP association with explicit DNS ownership.
    Socks5 {
        /// SOCKS5 proxy host and port.
        proxy: Endpoint<'a>,
        /// Target with the selected DNS owner.
        target: Socks5Target<'a>,
        /// Authentication offered to the proxy.
        auth: Socks5Auth<'a>,
    },
    /// Open the selected CONNECT-UDP proxy transport.
    ConnectUdp(ConnectUdpRoute<'a>),
}

impl std::fmt::Debug for DatagramRoute<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(endpoint) => formatter.debug_tuple("Direct").field(endpoint).finish(),
            #[cfg(feature = "https-records")]
            Self::DirectEch { endpoint, .. } => formatter
                .debug_struct("DirectEch")
                .field("endpoint", endpoint)
                .finish_non_exhaustive(),
            Self::Socks5 {
                proxy,
                target,
                auth,
            } => formatter
                .debug_struct("Socks5")
                .field("proxy", proxy)
                .field("target", target)
                .field("auth", auth)
                .finish(),
            Self::ConnectUdp(route) => formatter.debug_tuple("ConnectUdp").field(route).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_udp_debug_omits_unmarked_headers_and_path() -> Result<(), Box<dyn std::error::Error>>
    {
        use phantom_profile::browser::chrome;

        let proxy = Http3Connector::new(
            &chrome::v154_quic_tls(),
            &chrome::v154_quic(),
            &chrome::v154_http3(),
            &chrome::v154_http3_request(),
        )?;
        let password = format!("{:?}", std::time::Instant::now());
        let credentials = HttpBasicCredentials::new("private-user", &password)?;
        let route = DatagramRoute::ConnectUdp(ConnectUdpRoute {
            proxy: Endpoint {
                host: "proxy.example",
                port: 443,
            },
            transport: ConnectUdpTransport::Http3(&proxy),
            authority: "proxy.example",
            path: OriginForm::parse("/private-path-token/")?,
            headers: vec![RequestHeader::new("authorization", "private-header-token")],
            credentials: Some(&credentials),
        });
        let debug = format!("{route:?}");
        for secret in [
            "private-path-token",
            "private-header-token",
            "private-user",
            &password,
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("header_count: 1"));
        Ok(())
    }
}
