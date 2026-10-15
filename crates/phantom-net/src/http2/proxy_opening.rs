//! A quiet HTTP/1 CONNECT proxy opening for http2 origin setup.

use std::fmt;

use super::{Http2Connection, Http2TlsConnector, Http2TlsError};
use crate::{
    proxy::http1_opening::{ProxyBinding, ProxyOpeningError, ProxyStream},
    route::HttpConnectRoute,
    tcp::ProfileTcpStream,
};

/// A proxy socket that has sent no CONNECT or origin TLS.
///
/// The opening retains its original origin connector, proxy TLS context and
/// route credentials. Its claimant supplies current ordered CONNECT headers.
/// An HTTPS backup may finish outer HTTP/1 TLS while it waits. Dropping the
/// opening closes its socket.
pub struct Http2ProxyOpening {
    state: Box<ProxyOpeningState>,
}

struct ProxyOpeningState {
    stream: ProxyStream,
    connector: Http2TlsConnector,
    binding: ProxyBinding,
}

impl fmt::Debug for Http2ProxyOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2ProxyOpening")
            .finish_non_exhaustive()
    }
}

impl Http2ProxyOpening {
    pub(super) fn new(
        stream: ProfileTcpStream,
        connector: Http2TlsConnector,
        binding: ProxyBinding,
    ) -> Self {
        Self {
            state: Box::new(ProxyOpeningState {
                stream: binding.stream(stream),
                connector,
                binding,
            }),
        }
    }

    pub(super) async fn complete_proxy_tls(mut self) -> Result<Self, Http2TlsError> {
        self.state.stream = self
            .state
            .binding
            .complete_proxy_tls(self.state.stream)
            .await?;
        Ok(self)
    }

    /// Sends this claimant's CONNECT and starts the actual origin protocol.
    ///
    /// Binding validation precedes proxy TLS or CONNECT. Once polled,
    /// cancellation closes the opening instead of returning a partial tunnel.
    ///
    /// # Errors
    ///
    /// Returns invalid input for a changed route, and the existing proxy,
    /// authentication, origin TLS and protocol negotiation errors.
    pub async fn finish(
        self,
        route: HttpConnectRoute<'_>,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.state.binding.validate_connect(route)?;
        let opening = self.complete_proxy_tls().await?;
        let ProxyOpeningState {
            stream,
            connector,
            binding,
        } = *opening.state;
        connector.finish_proxy_opening(stream, binding, route).await
    }
}

impl From<ProxyOpeningError> for Http2TlsError {
    fn from(error: ProxyOpeningError) -> Self {
        match error {
            ProxyOpeningError::Binding(error) => Self::Connect(error),
            ProxyOpeningError::Proxy(error) => Self::Proxy(error),
        }
    }
}
