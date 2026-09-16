use std::{fmt, sync::Arc};

use phantom_net::{http1::Http1TlsConnector, http2::Http2TlsConnector, http3::Http3Connector};
use phantom_profile::ClientProfile;

use crate::{BuildError, RequestBuilder, Route, Session, SessionBuilder};
#[cfg(feature = "websocket")]
use crate::{WebSocketError, WebSocketRequestBuilder};

/// HTTP protocol selected for one request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum HttpProtocol {
    /// HTTP/1.1 over TLS.
    Http1,
    /// HTTP/2 over TLS.
    Http2,
    /// HTTP/3 over QUIC.
    Http3,
}

impl HttpProtocol {
    pub(crate) const fn trace_name(self) -> &'static str {
        match self {
            Self::Http1 => "http/1.1",
            Self::Http2 => "h2",
            Self::Http3 => "h3",
        }
    }
}

/// Immutable transport configuration for routed, exact-protocol HTTPS requests.
///
/// Clones share validated protocol connectors but no mutable request state.
/// Use [`Client::session`] when requests should share cookies or connections.
#[derive(Clone, Debug)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
}

#[derive(Debug)]
pub(crate) struct ClientInner {
    pub(crate) http1: Option<Http1TlsConnector>,
    pub(crate) http2: Option<Http2TlsConnector>,
    pub(crate) http3: Option<Http3Connector>,
    pub(crate) route: Route,
}

impl Client {
    /// Starts a client builder for one owned wire profile.
    #[must_use]
    pub fn builder(profile: ClientProfile) -> ClientBuilder {
        ClientBuilder {
            profile,
            additional_roots: Vec::new(),
            route: Route::Direct,
        }
    }

    /// Starts one empty-body GET using exactly `protocol`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::RequestError`] when the protocol is absent from the
    /// profile or the URI, authority, or request target is invalid.
    pub fn get(
        &self,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        RequestBuilder::new_client(self.clone(), protocol, uri)
    }

    /// Starts one ordered secure WebSocket opening handshake over HTTP/1.1.
    #[cfg(feature = "websocket")]
    pub fn websocket(&self, uri: &str) -> Result<WebSocketRequestBuilder, WebSocketError> {
        WebSocketRequestBuilder::new_client(self.clone(), uri)
    }

    /// Creates an isolated session with default bounded state.
    #[must_use]
    pub fn session(&self) -> Session {
        self.session_builder().build()
    }

    /// Starts a builder for an isolated session over this client.
    #[must_use]
    pub fn session_builder(&self) -> SessionBuilder {
        SessionBuilder::new(self.clone())
    }
}

/// Builds an immutable [`Client`].
pub struct ClientBuilder {
    profile: ClientProfile,
    additional_roots: Vec<Box<[u8]>>,
    route: Route,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientBuilder")
            .field("http2_configured", &self.profile.http2().is_some())
            .field("http3_configured", &self.profile.http3().is_some())
            .field("additional_root_count", &self.additional_roots.len())
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// Adds a DER-encoded certificate to the bundled public trust roots.
    ///
    /// Certificate and hostname verification remain enabled.
    #[must_use]
    pub fn add_root_certificate_der(mut self, certificate: impl Into<Box<[u8]>>) -> Self {
        self.additional_roots.push(certificate.into());
        self
    }

    /// Sets the default route for requests made by this client.
    #[must_use]
    pub fn route(mut self, route: Route) -> Self {
        self.route = route;
        self
    }

    /// Validates the profile and builds reusable protocol connectors.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the profile is invalid, a trust root cannot
    /// be loaded, a protocol connector cannot represent the profile, or the
    /// profile enables no supported protocol. Use [`BuildError::kind`] for the
    /// stable category.
    pub fn build(self) -> Result<Client, BuildError> {
        self.profile
            .tls()
            .validate()
            .map_err(BuildError::invalid_tls_profile)?;

        let roots = || self.additional_roots.iter().map(AsRef::as_ref);
        let supports_http1 = self
            .profile
            .tls()
            .alpn_protocols
            .iter()
            .any(|protocol| protocol.as_ref() == b"http/1.1");
        let http1 = supports_http1
            .then(|| Http1TlsConnector::new_with_additional_roots(self.profile.tls(), roots()))
            .transpose()
            .map_err(BuildError::http1)?;
        let http2 = self
            .profile
            .http2()
            .map(|settings| {
                Http2TlsConnector::new_with_additional_roots(self.profile.tls(), settings, roots())
            })
            .transpose()
            .map_err(BuildError::http2)?;
        let http3 = self
            .profile
            .http3()
            .map(|settings| {
                Http3Connector::new_with_additional_roots(
                    settings.tls(),
                    settings.quic_transport(),
                    settings.http3(),
                    settings.request(),
                    roots(),
                )
            })
            .transpose()
            .map_err(BuildError::http3)?;

        if http1.is_none() && http2.is_none() && http3.is_none() {
            return Err(BuildError::no_supported_protocol());
        }

        Ok(Client {
            inner: Arc::new(ClientInner {
                http1,
                http2,
                http3,
                route: self.route,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::HttpProtocol;

    #[test]
    fn protocol_trace_names_match_negotiated_tokens() {
        assert_eq!(HttpProtocol::Http1.trace_name(), "http/1.1");
        assert_eq!(HttpProtocol::Http2.trace_name(), "h2");
        assert_eq!(HttpProtocol::Http3.trace_name(), "h3");
    }
}
