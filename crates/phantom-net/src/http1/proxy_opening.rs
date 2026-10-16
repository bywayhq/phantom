//! A proxy opening whose application protocol belongs to its claimant.

use std::fmt;

use super::{Http1Connection, Http1TlsConnector, Http1TlsError};
use crate::{
    proxy::http1_opening::{ProxyBinding, ProxyOpeningError, ProxyStream, binding_error},
    route::{HttpConnectRoute, ProxyTransport},
    tcp::ProfileTcpStream,
};

/// A connected proxy opening with no CONNECT, origin TLS or request sent.
///
/// Drop closes the socket. CONNECT openings retain their authority, credentials
/// and origin TLS connector. Their claimant supplies current CONNECT fields to
/// [`Self::finish`]. Forward openings use [`Self::finish_forward`] and receive
/// each request only after setup. The two purposes cannot be interchanged.
/// An HTTPS spare may finish proxy TLS before claim. Its original proxy TLS
/// context and ticket cache are retained; application early data is not offered.
pub struct Http1ProxyOpening {
    state: Box<dyn OpeningOwner>,
}

struct ProxyOpeningState {
    stream: ProxyStream,
    connector: Http1TlsConnector,
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

impl fmt::Debug for Http1ProxyOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1ProxyOpening")
            .finish_non_exhaustive()
    }
}

impl Http1ProxyOpening {
    /// Completes only outer TLS and starts HTTP/1 absolute-form forwarding.
    ///
    /// The original proxy endpoint, SNI, TLS cache and credential-cache scope
    /// must match. No CONNECT or origin TLS is sent. The caller supplies each
    /// request's current ordered headers and credentials after this returns.
    ///
    /// # Errors
    ///
    /// Rejects another opening purpose or proxy context before TLS, and returns
    /// the existing proxy TLS and HTTP/1 setup errors.
    pub async fn finish_forward(
        self,
        transport: ProxyTransport<'_>,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.state.state().binding.validate_forward(transport)?;
        let opening = self.complete_proxy_tls().await?;
        match opening.state.into_state().stream {
            ProxyStream::HttpsReady(stream) => super::tls::connect_plaintext(stream)
                .await
                .map_err(Into::into),
            ProxyStream::Tcp(_) | ProxyStream::HttpsPending(_) => Err(binding_error().into()),
        }
    }

    pub(super) fn new(
        stream: ProfileTcpStream,
        connector: Http1TlsConnector,
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

    /// Completes only outer TLS. The existing slower owner calls this before claim.
    pub(super) async fn complete_proxy_tls(self) -> Result<Self, Http1TlsError> {
        let mut state = self.state.into_state();
        state.stream = state.binding.complete_proxy_tls(state.stream).await?;
        Ok(Self { state })
    }

    /// Finishes this claimant's CONNECT and origin TLS without sending its GET.
    ///
    /// `protocols` is this claimant's ALPN offer, with the original ticket cache.
    /// Route and Upgrade fields are validated before proxy TLS or CONNECT.
    /// The returned opening owns the tunnel until `send` or drop; cancellation
    /// after polling closes it. Current CONNECT and Upgrade fields are used.
    ///
    /// # Errors
    ///
    /// Returns invalid input for changed bindings or invalid fields, and the
    /// existing proxy, authentication, TLS and ALPN errors.
    pub async fn finish_upgrade(
        self,
        route: HttpConnectRoute<'_>,
        protocols: &[Box<[u8]>],
        target: crate::request::OriginForm,
        headers: Vec<crate::request::RequestHeader>,
    ) -> Result<super::Http1UpgradeOpening, Http1TlsError> {
        self.state.state().binding.validate_connect(route)?;
        let ProxyOpeningState {
            stream,
            connector,
            binding,
        } = *self.state.into_state();
        let connector = connector.with_alpn_protocols(protocols)?;
        connector
            .finish_proxy_upgrade(stream, binding, route, target, headers)
            .await
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

impl From<ProxyOpeningError> for Http1TlsError {
    fn from(error: ProxyOpeningError) -> Self {
        match error {
            ProxyOpeningError::Binding(error) => Self::Connect(error),
            ProxyOpeningError::Proxy(error) => Self::Proxy(error),
        }
    }
}
