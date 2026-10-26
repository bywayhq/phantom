use std::sync::Arc;

use phantom_net::{
    ClientCertificate,
    host_resolver::HostResolver,
    http1::Http1TlsConnector,
    http1_or_2::Http1Or2TlsConnector,
    http2::Http2TlsConnector,
    http3::Http3Connector,
    proxy::{Http2ProxyPool, HttpsProxyConnector, ProxyCredentialCache},
};
use phantom_profile::Http2ProxyConnections;

use super::connection_policy::ConnectionPolicy;
use crate::{authority::Endpoint, session::http3_pool::ConnectUdpConnectors};

/// Prepared connectors and the resources they share.
#[derive(Clone, Debug)]
pub(crate) struct PreparedTransport {
    pub(crate) ticket_preparation:
        Result<Arc<crate::session::PreparedTicketPolicy>, crate::session::PreparationError>,
    pub(crate) http1: Option<Http1TlsConnector>,
    pub(crate) http1_or_2: Option<Http1Or2TlsConnector>,
    pub(crate) http2: Option<Http2TlsConnector>,
    pub(crate) http3: Option<Arc<Http3Connector>>,
    /// Proxy-leg connectors for CONNECT-UDP proxies, using proxy trust.
    pub(crate) connect_udp_proxy: Option<Arc<ConnectUdpConnectors>>,
    /// Opens CONNECT tunnels through an HTTPS proxy, sharing HTTP/2 proxy
    /// connections from the client's pool.
    pub(crate) https_proxy: Option<HttpsProxyConnector>,
    /// `https_proxy` for `http://` requests forwarded over HTTP/2, with the
    /// pool the profile's [`Http2ProxyConnections`] gives them.
    pub(crate) forward_https_proxy: Option<HttpsProxyConnector>,
    /// `https_proxy` for WebSocket tunnels, with the pool the profile's
    /// [`Http2ProxyConnections`] gives them.
    #[cfg(feature = "websocket")]
    pub(crate) websocket_https_proxy: Option<HttpsProxyConnector>,
    /// Proxies that accepted Basic credentials, shared with the connectors.
    pub(crate) proxy_credentials: Option<ProxyCredentialCache>,
    /// Host overrides, the address resolver, and the address cache, shared
    /// with the connectors. `None` when the client asks the operating system
    /// for every connection.
    pub(crate) host_resolver: Option<HostResolver>,
    /// HTTP/1.1 connector with the policy's Upgrade-connection ALPN offer.
    #[cfg(feature = "websocket")]
    pub(crate) websocket_http1: Option<Http1TlsConnector>,
    /// Origin connectors for each host and port with a certificate of its
    /// own; [`Self::connectors_for`] picks among them and the fields above.
    pub(super) certificate_origins: Box<[CertificateOrigin]>,
    #[cfg(feature = "diagnostics")]
    pub(crate) key_log: Option<Arc<crate::KeyLog>>,
}

/// The origin connectors that present one host and port's client
/// certificate, from [`ClientBuilder::client_certificate_for`](super::ClientBuilder::client_certificate_for).
///
/// Each connector is a clone of the client's connector for its protocol, so
/// it shares the TLS context and settings, with an empty session cache and,
/// for HTTP/3, a connection identity of its own.
#[derive(Clone, Debug)]
pub(super) struct CertificateOrigin {
    /// Canonical host, as [`Endpoint::host`] gives it.
    host: Box<str>,
    port: u16,
    http1: Option<Http1TlsConnector>,
    http1_or_2: Option<Http1Or2TlsConnector>,
    http2: Option<Http2TlsConnector>,
    http3: Option<Arc<Http3Connector>>,
    #[cfg(feature = "websocket")]
    websocket_http1: Option<Http1TlsConnector>,
}

/// The origin connectors that open connections to one host and port.
///
/// Every connection to an origin, including one to its Alt-Svc alternative
/// or through a proxy tunnel, takes its connector from here, so that it
/// presents the origin's client certificate. Whether a protocol is
/// configured at all does not depend on the origin.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OriginConnectors<'a> {
    pub(crate) http1: Option<&'a Http1TlsConnector>,
    pub(crate) http1_or_2: Option<&'a Http1Or2TlsConnector>,
    pub(crate) http2: Option<&'a Http2TlsConnector>,
    pub(crate) http3: Option<&'a Arc<Http3Connector>>,
    #[cfg(feature = "websocket")]
    pub(crate) websocket_http1: Option<&'a Http1TlsConnector>,
}

impl PreparedTransport {
    pub(crate) fn refresh_proxy_connections(&self) {
        for connector in [&self.https_proxy, &self.forward_https_proxy]
            .into_iter()
            .flatten()
        {
            connector.refresh_connections();
        }
        #[cfg(feature = "websocket")]
        if let Some(connector) = &self.websocket_https_proxy {
            connector.refresh_connections();
        }
    }

    pub(crate) fn close_idle_proxy_connections(&self) {
        for connector in [&self.https_proxy, &self.forward_https_proxy]
            .into_iter()
            .flatten()
        {
            connector.close_idle_connections();
        }
        #[cfg(feature = "websocket")]
        if let Some(connector) = &self.websocket_https_proxy {
            connector.close_idle_connections();
        }
    }

    /// Returns the origin connectors for `endpoint`'s host and port: those
    /// with the certificate [`ClientBuilder::client_certificate_for`](super::ClientBuilder::client_certificate_for) mapped
    /// to it, or otherwise the client-wide ones.
    ///
    /// The host matches without regard to ASCII case, as the connection
    /// pools' keys do.
    pub(crate) fn connectors_for(&self, endpoint: &Endpoint) -> OriginConnectors<'_> {
        let mapped = self.certificate_origins.iter().find(|origin| {
            origin.port == endpoint.port() && origin.host.eq_ignore_ascii_case(endpoint.host())
        });
        match mapped {
            Some(origin) => OriginConnectors {
                http1: origin.http1.as_ref(),
                http1_or_2: origin.http1_or_2.as_ref(),
                http2: origin.http2.as_ref(),
                http3: origin.http3.as_ref(),
                #[cfg(feature = "websocket")]
                websocket_http1: origin.websocket_http1.as_ref(),
            },
            None => OriginConnectors {
                http1: self.http1.as_ref(),
                http1_or_2: self.http1_or_2.as_ref(),
                http2: self.http2.as_ref(),
                http3: self.http3.as_ref(),
                #[cfg(feature = "websocket")]
                websocket_http1: self.websocket_http1.as_ref(),
            },
        }
    }

    /// Derives one set of origin connectors per mapped host and port from
    /// the client-wide connectors.
    ///
    /// Call it after every other change to the origin connectors, whose
    /// clones it makes, so that each set has the same resolver, proxy
    /// credentials, and early-data choice.
    pub(super) fn bind_certificate_origins(&mut self, origins: &[(Endpoint, ClientCertificate)]) {
        self.certificate_origins = origins
            .iter()
            .map(|(endpoint, certificate)| CertificateOrigin {
                host: endpoint.host().into(),
                port: endpoint.port(),
                http1: self
                    .http1
                    .clone()
                    .map(|connector| connector.with_client_certificate(certificate)),
                http1_or_2: self
                    .http1_or_2
                    .clone()
                    .map(|connector| connector.with_client_certificate(certificate)),
                http2: self
                    .http2
                    .clone()
                    .map(|connector| connector.with_client_certificate(certificate)),
                http3: self
                    .http3
                    .as_deref()
                    .map(|connector| Arc::new(connector.with_client_certificate(certificate))),
                #[cfg(feature = "websocket")]
                websocket_http1: self
                    .websocket_http1
                    .clone()
                    .map(|connector| connector.with_client_certificate(certificate)),
            })
            .collect();
    }

    /// Gives the HTTPS proxy connectors new HTTP/2 connection pools: one for
    /// every purpose, or one per purpose, as the profile says.
    ///
    /// Call it after every other change to `https_proxy`, whose clones it
    /// makes.
    pub(super) fn bind_http2_proxy_pools(&mut self, policy: &ConnectionPolicy) {
        let Some(base) = self.https_proxy.take() else {
            return;
        };
        let per_route = policy.http2_proxy_connections_per_route;
        let new_pool = || Http2ProxyPool::with_max_connections_per_route(per_route);
        let tunnels = new_pool();
        let separate = policy.http2_proxy_connections == Http2ProxyConnections::ByPurpose;
        let own_pool = || {
            if separate {
                new_pool()
            } else {
                tunnels.clone()
            }
        };
        self.forward_https_proxy = Some(base.clone().with_http2_proxy_pool(own_pool()));
        #[cfg(feature = "websocket")]
        {
            self.websocket_https_proxy = Some(base.clone().with_http2_proxy_pool(own_pool()));
        }
        self.https_proxy = Some(base.with_http2_proxy_pool(tunnels));
    }

    /// Gives every connector that resolves host names the same resolver.
    pub(super) fn bind_host_resolver(&mut self, resolver: HostResolver, policy: &ConnectionPolicy) {
        if policy.custom_tcp_connector {
            self.host_resolver = Some(resolver);
            return;
        }
        let bind = |connector: Http1TlsConnector| connector.with_host_resolver(resolver.clone());
        self.http1 = self.http1.take().map(bind);
        self.http1_or_2 = self
            .http1_or_2
            .take()
            .map(|connector| connector.with_host_resolver(resolver.clone()));
        self.http2 = self
            .http2
            .take()
            .map(|connector| connector.with_host_resolver(resolver.clone()));
        self.http3 = self
            .http3
            .take()
            .map(|connector| Arc::new(connector.with_host_resolver(resolver.clone())));
        self.https_proxy = self
            .https_proxy
            .take()
            .map(|connector| connector.with_host_resolver(resolver.clone()));
        self.connect_udp_proxy = self.connect_udp_proxy.take().map(|connectors| {
            Arc::new(ConnectUdpConnectors {
                http3: connectors
                    .http3
                    .as_ref()
                    .map(|connector| connector.with_host_resolver(resolver.clone())),
                tcp: connectors
                    .tcp
                    .clone()
                    .map(|connector| connector.with_host_resolver(resolver.clone())),
            })
        });
        #[cfg(feature = "websocket")]
        {
            self.websocket_http1 = self.websocket_http1.take().map(bind);
        }
        for origin in &mut self.certificate_origins {
            origin.http1 = origin
                .http1
                .take()
                .map(|connector| connector.with_host_resolver(resolver.clone()));
            origin.http1_or_2 = origin
                .http1_or_2
                .take()
                .map(|connector| connector.with_host_resolver(resolver.clone()));
            origin.http2 = origin
                .http2
                .take()
                .map(|connector| connector.with_host_resolver(resolver.clone()));
            origin.http3 = origin
                .http3
                .take()
                .map(|connector| Arc::new(connector.with_host_resolver(resolver.clone())));
            #[cfg(feature = "websocket")]
            {
                origin.websocket_http1 = origin
                    .websocket_http1
                    .take()
                    .map(|connector| connector.with_host_resolver(resolver.clone()));
            }
        }
        self.host_resolver = Some(resolver);
    }

    /// Gives every connector that can open an authenticated proxy tunnel the
    /// same record.
    pub(super) fn bind_proxy_credentials(&mut self, cache: &ProxyCredentialCache) {
        let bind =
            |connector: Http1TlsConnector| connector.with_proxy_credential_cache(cache.clone());
        self.http1 = self.http1.take().map(bind);
        self.http1_or_2 = self
            .http1_or_2
            .take()
            .map(|connector| connector.with_proxy_credential_cache(cache.clone()));
        self.http2 = self
            .http2
            .take()
            .map(|connector| connector.with_proxy_credential_cache(cache.clone()));
        self.https_proxy = self
            .https_proxy
            .take()
            .map(|connector| connector.with_proxy_credential_cache(cache.clone()));
        #[cfg(feature = "websocket")]
        {
            self.websocket_http1 = self.websocket_http1.take().map(bind);
        }
        for origin in &mut self.certificate_origins {
            origin.http1 = origin.http1.take().map(bind);
            origin.http1_or_2 = origin
                .http1_or_2
                .take()
                .map(|connector| connector.with_proxy_credential_cache(cache.clone()));
            origin.http2 = origin
                .http2
                .take()
                .map(|connector| connector.with_proxy_credential_cache(cache.clone()));
            #[cfg(feature = "websocket")]
            {
                origin.websocket_http1 = origin.websocket_http1.take().map(bind);
            }
        }
    }
}
