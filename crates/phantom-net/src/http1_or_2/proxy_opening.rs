//! A quiet HTTP/1 CONNECT proxy opening for http1_or_2 origin setup.

use std::fmt;

use super::{Http1Or2Connection, Http1Or2TlsConnector, Http1Or2TlsError};
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
pub struct Http1Or2ProxyOpening {
    state: Box<dyn OpeningOwner>,
}

struct ProxyOpeningState {
    stream: ProxyStream,
    connector: Http1Or2TlsConnector,
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

impl fmt::Debug for Http1Or2ProxyOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1Or2ProxyOpening")
            .finish_non_exhaustive()
    }
}

impl Http1Or2ProxyOpening {
    pub(super) fn new(
        stream: ProfileTcpStream,
        connector: Http1Or2TlsConnector,
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

    pub(super) async fn complete_proxy_tls(self) -> Result<Self, Http1Or2TlsError> {
        let mut state = self.state.into_state();
        state.stream = state.binding.complete_proxy_tls(state.stream).await?;
        Ok(Self { state })
    }

    /// Finishes CONNECT and origin TLS for a dedicated HTTP/1 Upgrade.
    ///
    /// `protocols` is the claimant's WebSocket ALPN offer. Conversion retains
    /// the original origin TLS session cache and proxy TLS/authentication
    /// binding. No GET is sent until the returned opening is consumed.
    ///
    /// # Errors
    ///
    /// Returns invalid input for a changed binding or invalid Upgrade fields,
    /// and the existing proxy, TLS and HTTP/1 ALPN errors.
    pub async fn finish_upgrade(
        self,
        route: HttpConnectRoute<'_>,
        protocols: &[Box<[u8]>],
        target: crate::request::OriginForm,
        headers: Vec<crate::request::RequestHeader>,
    ) -> Result<crate::http1::Http1UpgradeOpening, crate::http1::Http1TlsError> {
        self.state.state().binding.validate_connect(route)?;
        let ProxyOpeningState {
            stream,
            connector,
            binding,
        } = *self.state.into_state();
        let connector = connector.http1_connector(protocols)?;
        connector
            .finish_proxy_upgrade(stream, binding, route, target, headers)
            .await
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
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.state.state().binding.validate_connect(route)?;
        let opening = self.complete_proxy_tls().await?;
        let ProxyOpeningState {
            stream,
            connector,
            binding,
        } = *opening.state.into_state();
        connector.finish_proxy_opening(stream, binding, route).await
    }

    /// Finishes this claimant's tunnel and verified origin H2 setup without
    /// emitting WebSocket HEADERS. Uses the extended-CONNECT settings and
    /// retains the original origin TLS, proxy TLS and credential contexts.
    ///
    /// # Errors
    ///
    /// Rejects a changed binding or invalid extended-CONNECT fields before
    /// I/O, and returns the existing proxy, authentication and TLS errors.
    pub async fn finish_extended_connect(
        self,
        route: HttpConnectRoute<'_>,
        authority: &str,
        target: crate::request::OriginForm,
        headers: Vec<crate::request::RequestHeader>,
    ) -> Result<crate::http2::Http2ExtendedConnectOpening, crate::http2::Http2TlsError> {
        self.state.state().binding.validate_connect(route)?;
        let ProxyOpeningState {
            stream,
            connector,
            binding,
        } = *self.state.into_state();
        connector
            .http2_connector()
            .finish_proxy_extended_connect(stream, binding, route, authority, target, headers)
            .await
    }
}

impl From<ProxyOpeningError> for Http1Or2TlsError {
    fn from(error: ProxyOpeningError) -> Self {
        match error {
            ProxyOpeningError::Binding(error) => Self::Connect(error),
            ProxyOpeningError::Proxy(error) => Self::Proxy(error),
        }
    }
}
