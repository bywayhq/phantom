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
    state: Box<dyn OpeningOwner>,
}

struct ProxyOpeningState {
    stream: ProxyStream,
    connector: Http2TlsConnector,
    binding: ProxyBinding,
}

// Keep the pool's Send/Sync proof at this existing allocation. Setup takes
// the concrete box back without copying the state or allocating again.
trait OpeningOwner: Send + Sync {
    fn state(&self) -> &ProxyOpeningState;
    fn into_state(self: Box<Self>) -> Box<ProxyOpeningState>;
}

impl OpeningOwner for ProxyOpeningState {
    fn state(&self) -> &ProxyOpeningState {
        self
    }

    fn into_state(self: Box<Self>) -> Box<ProxyOpeningState> {
        self
    }
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

    pub(super) async fn complete_proxy_tls(self) -> Result<Self, Http2TlsError> {
        let mut state = self.state.into_state();
        state.stream = state.binding.complete_proxy_tls(state.stream).await?;
        Ok(Self { state })
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
        self.state.state().binding.validate_connect(route)?;
        let opening = self.complete_proxy_tls().await?;
        let ProxyOpeningState {
            stream,
            connector,
            binding,
        } = *opening.state.into_state();
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
