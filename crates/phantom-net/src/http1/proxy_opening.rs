//! A quiet proxy TCP socket whose CONNECT belongs to its claimant.

use std::{fmt, io};

use super::{Http1Connection, Http1TlsConnector, Http1TlsError};
use crate::{
    proxy::{HttpProxyAuthentication, HttpProxyCredentials},
    route::{HttpConnectRoute, ProxyTransport},
    tcp::ProfileTcpStream,
};

/// A connected plaintext proxy socket with no CONNECT or origin TLS sent.
///
/// Drop closes the socket. The claiming request supplies its current CONNECT
/// fields to [`Self::finish`]; endpoint, authority and credentials stay bound
/// to the route that opened it. The origin TLS connector is retained internally.
pub struct Http1ProxyOpening {
    state: Box<ProxyOpeningState>,
}

struct ProxyOpeningState {
    stream: ProfileTcpStream,
    connector: Http1TlsConnector,
    binding: ProxyBinding,
}

pub(super) struct ProxyBinding {
    host: Box<str>,
    port: u16,
    authority: Box<str>,
    server_name: Box<str>,
    credentials: Option<HttpProxyCredentials>,
}

impl fmt::Debug for Http1ProxyOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1ProxyOpening")
            .finish_non_exhaustive()
    }
}

impl ProxyBinding {
    pub(super) fn new(
        route: HttpConnectRoute<'_>,
        server_name: &str,
    ) -> Result<Self, Http1TlsError> {
        let ProxyTransport::Tcp(endpoint) = route.proxy else {
            return Err(binding_error());
        };
        crate::proxy::validate_http_tunnel(route.authority, route.headers, route.credentials)?;
        let credentials = route.credentials.map(|credentials| match credentials {
            HttpProxyAuthentication::Basic(value) => HttpProxyCredentials::Basic(value.clone()),
            HttpProxyAuthentication::Digest(value) => HttpProxyCredentials::Digest(value.clone()),
        });
        Ok(Self {
            host: endpoint.host.into(),
            port: endpoint.port,
            authority: route.authority.into(),
            server_name: server_name.into(),
            credentials,
        })
    }

    fn matches(&self, route: HttpConnectRoute<'_>) -> bool {
        matches!(route.proxy, ProxyTransport::Tcp(endpoint)
            if endpoint.host.eq_ignore_ascii_case(&self.host) && endpoint.port == self.port)
            && route.authority == self.authority.as_ref()
            && route.credentials == self.credentials.as_ref().map(HttpProxyCredentials::as_ref)
    }
}

impl Http1ProxyOpening {
    pub(super) fn new(
        stream: ProfileTcpStream,
        connector: Http1TlsConnector,
        binding: ProxyBinding,
    ) -> Self {
        Self {
            state: Box::new(ProxyOpeningState {
                stream,
                connector,
                binding,
            }),
        }
    }

    /// Sends this request's CONNECT, authenticates the origin and starts HTTP/1.
    ///
    /// Headers may differ from the opening request's profile-derived fields.
    /// Cancellation once polled closes the opening; it never returns a partly
    /// authenticated tunnel to a pool.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input connection error for another route binding,
    /// or the existing CONNECT, authentication, TLS and HTTP/1 setup errors.
    pub async fn finish(
        self,
        route: HttpConnectRoute<'_>,
    ) -> Result<Http1Connection, Http1TlsError> {
        if !self.state.binding.matches(route) {
            return Err(binding_error());
        }
        let ProxyOpeningState {
            stream,
            connector,
            binding,
        } = *self.state;
        connector
            .finish_http_connect(stream, route, &binding.server_name)
            .await
    }
}

fn binding_error() -> Http1TlsError {
    Http1TlsError::Connect(io::Error::new(
        io::ErrorKind::InvalidInput,
        "retained HTTP CONNECT opening requires its original plaintext proxy route",
    ))
}
