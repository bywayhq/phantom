use std::{fmt, sync::Arc};

use http::Method;
use phantom_net::{
    ServerAuthentication, http1::Http1TlsConnector, http1_or_2::Http1Or2TlsConnector,
    http2::Http2TlsConnector, http3::Http3Connector,
};
use phantom_profile::{ClientHintSettings, ClientProfile};

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
/// Use [`Client::session`] when requests should share connections, cookies, or
/// negotiated client-hint state.
#[derive(Clone, Debug)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
}

#[derive(Debug)]
pub(crate) struct ClientInner {
    pub(crate) http1: Option<Http1TlsConnector>,
    pub(crate) http1_or_2: Option<Http1Or2TlsConnector>,
    pub(crate) http2: Option<Http2TlsConnector>,
    pub(crate) http3: Option<Http3Connector>,
    pub(crate) client_hints: Option<ClientHintSettings>,
    pub(crate) route: Route,
}

impl Client {
    /// Starts a client builder for one owned wire profile.
    #[must_use]
    pub fn builder(profile: ClientProfile) -> ClientBuilder {
        ClientBuilder {
            profile,
            additional_roots: Vec::new(),
            server_authentication: ServerAuthentication::default(),
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
        self.request(protocol, Method::GET, uri)
    }

    /// Starts one request using exactly `protocol`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::RequestError`] when the protocol is absent from the
    /// profile or the URI, authority, or request target is invalid.
    pub fn request(
        &self,
        protocol: HttpProtocol,
        method: Method,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        RequestBuilder::new_client(self.clone(), protocol, method, uri)
    }

    /// Starts one direct GET that selects HTTP/2 or HTTP/1.1 from TLS ALPN.
    ///
    /// The request performs one TCP connection and one TLS handshake. Exact
    /// `h2` selects HTTP/2; exact `http/1.1` or absent ALPN selects HTTP/1.1.
    /// It does not race, retry, or consult Alt-Svc. Any non-direct configured
    /// or per-request route is rejected before I/O. [`crate::ResponseInfo::protocol`]
    /// reports the selected protocol.
    ///
    /// # Errors
    ///
    /// Returns [`crate::RequestError`] when the profile cannot negotiate both
    /// protocols or the URI, authority, or request target is invalid.
    pub fn get_negotiated(&self, uri: &str) -> Result<RequestBuilder, crate::RequestError> {
        self.request_negotiated(Method::GET, uri)
    }

    /// Starts one direct request that selects HTTP/2 or HTTP/1.1 from TLS ALPN.
    ///
    /// This has the same one-connection selection contract as
    /// [`Self::get_negotiated`]. The request must be representable by both HTTP
    /// versions so validation can finish before network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`crate::RequestError`] when the profile cannot negotiate both
    /// protocols or the URI, authority, or request target is invalid.
    pub fn request_negotiated(
        &self,
        method: Method,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        RequestBuilder::new_client_negotiated(self.clone(), method, uri)
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
    server_authentication: ServerAuthentication,
    route: Route,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientBuilder")
            .field("http2_configured", &self.profile.http2().is_some())
            .field(
                "negotiated_http1_or_2_configured",
                &(self.profile.http2().is_some()
                    && self
                        .profile
                        .tls()
                        .alpn_protocols
                        .iter()
                        .any(|protocol| protocol.as_ref() == b"http/1.1")),
            )
            .field("http3_configured", &self.profile.http3().is_some())
            .field(
                "client_hints_configured",
                &self.profile.client_hints().is_some(),
            )
            .field("additional_root_count", &self.additional_roots.len())
            .field("server_authentication", &self.server_authentication)
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

    /// Sets how TLS servers are authenticated.
    ///
    /// The default is [`ServerAuthentication::WebPki`]. Disabling
    /// authentication is explicit and is supported for HTTP/1.1 and HTTP/2;
    /// it cannot be combined with additional roots or HTTP/3.
    #[must_use]
    pub fn server_authentication(mut self, policy: ServerAuthentication) -> Self {
        self.server_authentication = policy;
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
        if let Some(client_hints) = self.profile.client_hints() {
            client_hints
                .validate()
                .map_err(BuildError::invalid_client_hint_profile)?;
        }

        let authentication_disabled = match self.server_authentication {
            ServerAuthentication::WebPki => false,
            ServerAuthentication::Disabled => true,
            _ => {
                return Err(BuildError::invalid_policy(
                    "unsupported server-authentication policy",
                ));
            }
        };
        if authentication_disabled {
            if !self.additional_roots.is_empty() {
                return Err(BuildError::invalid_policy(
                    "disabled server authentication cannot be combined with additional roots",
                ));
            }
            if self.profile.http3().is_some() {
                return Err(BuildError::invalid_policy(
                    "disabled server authentication is not supported for HTTP/3",
                ));
            }
        }

        let roots = || self.additional_roots.iter().map(AsRef::as_ref);
        let supports_http1 = self
            .profile
            .tls()
            .alpn_protocols
            .iter()
            .any(|protocol| protocol.as_ref() == b"http/1.1");
        let http1 = supports_http1
            .then(|| {
                if authentication_disabled {
                    Http1TlsConnector::new_with_server_authentication(
                        self.profile.tls(),
                        self.server_authentication,
                    )
                } else {
                    Http1TlsConnector::new_with_additional_roots(self.profile.tls(), roots())
                }
            })
            .transpose()
            .map_err(BuildError::http1)?;
        let http2 = self
            .profile
            .http2()
            .map(|settings| {
                if authentication_disabled {
                    Http2TlsConnector::new_with_server_authentication(
                        self.profile.tls(),
                        settings,
                        self.server_authentication,
                    )
                } else {
                    Http2TlsConnector::new_with_additional_roots(
                        self.profile.tls(),
                        settings,
                        roots(),
                    )
                }
            })
            .transpose()
            .map_err(BuildError::http2)?;
        let http1_or_2 = http2
            .as_ref()
            .filter(|_| supports_http1)
            .map(Http1Or2TlsConnector::from_http2)
            .transpose()
            .map_err(BuildError::http1_or_2)?;
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
        let client_hints = self.profile.client_hints().cloned();

        if http1.is_none() && http2.is_none() && http3.is_none() {
            return Err(BuildError::no_supported_protocol());
        }

        Ok(Client {
            inner: Arc::new(ClientInner {
                http1,
                http1_or_2,
                http2,
                http3,
                client_hints,
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
