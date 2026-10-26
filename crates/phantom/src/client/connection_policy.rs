use std::{num::NonZeroUsize, time::Duration};

use phantom_profile::Http2ProxyConnections;

use crate::Route;

/// Route restrictions and profile connection limits.
#[derive(Clone, Debug)]
pub(crate) struct ConnectionPolicy {
    pub(crate) custom_tcp_connector: bool,
    pub(crate) destination_policy: bool,
    pub(crate) server_spki_pins: bool,
    pub(crate) proxy_server_spki_pins: bool,
    /// Which HTTP/2 proxy requests share a connection.
    pub(crate) http2_proxy_connections: Http2ProxyConnections,
    /// HTTP/2 connections each proxy route may open; one unless the caller
    /// opted into more.
    pub(crate) http2_proxy_connections_per_route: NonZeroUsize,
    /// How many times per redirect hop a request is sent again after its
    /// HTTP/2 connection's PING failed; see
    /// [`phantom_profile::Http2Settings::ping_failure_retries`].
    pub(crate) http2_ping_failure_retries: u8,
    /// The profile's HTTP/1.1 connection bound per origin and route.
    pub(crate) http1_connections_per_origin: NonZeroUsize,
    /// How long the profile reuses an idle HTTP/1.1 connection.
    pub(crate) http1_used_idle_timeout: Option<Duration>,
    /// The idle limit the profile also enforces on a timer between requests.
    pub(crate) http1_idle_timer: Option<Duration>,
    /// The limit after which the profile stops reusing an HTTP/2 connection
    /// that reads nothing, also enforced on a timer between requests.
    pub(crate) http2_idle_timer: Option<Duration>,
}

impl ConnectionPolicy {
    pub(crate) fn ensure_pinned_route(
        &self,
        scheme: &str,
        route: &Route,
    ) -> Result<(), crate::RequestError> {
        if self.destination_policy && !matches!(route, Route::Direct) {
            return Err(crate::RequestError::unsupported_destination_policy_route());
        }
        if self.custom_tcp_connector && !matches!(route, Route::Direct) {
            return Err(crate::RequestError::unsupported_custom_connector_route());
        }
        if self.server_spki_pins && !matches!(scheme, "https" | "wss") {
            return Err(crate::RequestError::server_pin_policy(
                "server SPKI pins require a TLS origin",
            ));
        }
        if self.proxy_server_spki_pins
            && match route {
                Route::HttpProxy(proxy) => !proxy.uses_tls(),
                Route::Socks4(_) | Route::Socks5(_) => true,
                Route::Direct | Route::ConnectUdp(_) => false,
            }
        {
            return Err(crate::RequestError::server_pin_policy(
                "proxy SPKI pins require a TLS proxy",
            ));
        }
        Ok(())
    }
}
