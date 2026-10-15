//! A proxy opening whose application protocol belongs to its claimant.

use std::{fmt, io};

use super::{Http1Connection, Http1TlsConnector, Http1TlsError};
use crate::{
    proxy::{HttpProxyAuthentication, HttpProxyCredentials},
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

enum ProxyStream {
    Tcp(ProfileTcpStream),
    HttpsPending(ProfileTcpStream),
    HttpsReady(crate::tls::TlsStream<ProfileTcpStream>),
}

pub(super) struct ProxyBinding {
    host: Box<str>,
    port: u16,
    proxy_tls: Option<(Box<str>, crate::proxy::HttpsProxyConnector)>,
    purpose: ProxyPurpose,
}

enum ProxyPurpose {
    Connect {
        authority: Box<str>,
        server_name: Box<str>,
        credentials: Option<HttpProxyCredentials>,
    },
    Forward,
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
        let (endpoint, proxy_tls) = match route.proxy {
            ProxyTransport::Tcp(endpoint) => (endpoint, None),
            ProxyTransport::Tls {
                endpoint,
                server_name,
                connector,
            } if connector.protocol() == crate::proxy::HttpsProxyProtocol::Http1 => {
                (endpoint, Some((server_name.into(), connector.clone())))
            }
            ProxyTransport::Tls { .. } => return Err(binding_error()),
        };
        crate::proxy::validate_http_tunnel(route.authority, route.headers, route.credentials)?;
        let credentials = route.credentials.map(|credentials| match credentials {
            HttpProxyAuthentication::Basic(value) => HttpProxyCredentials::Basic(value.clone()),
            HttpProxyAuthentication::Digest(value) => HttpProxyCredentials::Digest(value.clone()),
        });
        Ok(Self {
            host: endpoint.host.into(),
            port: endpoint.port,
            proxy_tls,
            purpose: ProxyPurpose::Connect {
                authority: route.authority.into(),
                server_name: server_name.into(),
                credentials,
            },
        })
    }

    pub(super) fn forward(transport: ProxyTransport<'_>) -> Result<Self, Http1TlsError> {
        let ProxyTransport::Tls {
            endpoint,
            server_name,
            connector,
        } = transport
        else {
            return Err(binding_error());
        };
        if connector.protocol() != crate::proxy::HttpsProxyProtocol::Http1 {
            return Err(crate::proxy::HttpConnectError::ForwardingRequiresHttp1.into());
        }
        Ok(Self {
            host: endpoint.host.into(),
            port: endpoint.port,
            proxy_tls: Some((server_name.into(), connector.clone())),
            purpose: ProxyPurpose::Forward,
        })
    }

    fn matches_transport(&self, transport: ProxyTransport<'_>) -> bool {
        match (transport, &self.proxy_tls) {
            (ProxyTransport::Tcp(endpoint), None) => {
                endpoint.host.eq_ignore_ascii_case(&self.host) && endpoint.port == self.port
            }
            (
                ProxyTransport::Tls {
                    endpoint,
                    server_name,
                    connector,
                },
                Some((name, original)),
            ) => {
                endpoint.host.eq_ignore_ascii_case(&self.host)
                    && endpoint.port == self.port
                    && server_name.eq_ignore_ascii_case(name)
                    && original.same_http1_opening_context(connector)
            }
            _ => false,
        }
    }

    fn matches(&self, route: HttpConnectRoute<'_>) -> bool {
        let ProxyPurpose::Connect {
            authority,
            credentials,
            ..
        } = &self.purpose
        else {
            return false;
        };
        self.matches_transport(route.proxy)
            && route.authority == authority.as_ref()
            && route.credentials == credentials.as_ref().map(HttpProxyCredentials::as_ref)
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
        let state = self.state.state();
        if !matches!(&state.binding.purpose, ProxyPurpose::Forward)
            || !state.binding.matches_transport(transport)
        {
            return Err(binding_error());
        }
        let opening = self.complete_proxy_tls().await?;
        match opening.state.into_state().stream {
            ProxyStream::HttpsReady(stream) => super::tls::connect_plaintext(stream)
                .await
                .map_err(Into::into),
            ProxyStream::Tcp(_) | ProxyStream::HttpsPending(_) => Err(binding_error()),
        }
    }

    pub(super) fn new(
        stream: ProfileTcpStream,
        connector: Http1TlsConnector,
        binding: ProxyBinding,
    ) -> Self {
        Self {
            state: Box::new(ProxyOpeningState {
                stream: if binding.proxy_tls.is_some() {
                    ProxyStream::HttpsPending(stream)
                } else {
                    ProxyStream::Tcp(stream)
                },
                connector,
                binding,
            }),
        }
    }

    /// Completes only outer TLS. The existing slower owner calls this before claim.
    pub(super) async fn complete_proxy_tls(self) -> Result<Self, Http1TlsError> {
        let mut state = self.state.into_state();
        state.stream = match state.stream {
            ProxyStream::HttpsPending(stream) => {
                let Some((server_name, proxy)) = &state.binding.proxy_tls else {
                    return Err(binding_error());
                };
                ProxyStream::HttpsReady(proxy.finish_http1_proxy_tls(stream, server_name).await?)
            }
            stream => stream,
        };
        Ok(Self { state })
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
        if !self.state.state().binding.matches(route) {
            return Err(binding_error());
        }
        crate::proxy::validate_http_tunnel(route.authority, route.headers, route.credentials)?;
        let opening = self.complete_proxy_tls().await?;
        let ProxyOpeningState {
            stream,
            connector,
            binding,
        } = *opening.state.into_state();
        let ProxyPurpose::Connect { server_name, .. } = binding.purpose else {
            return Err(binding_error());
        };
        match stream {
            ProxyStream::Tcp(stream) => {
                connector
                    .finish_http_connect(stream, route, &server_name)
                    .await
            }
            ProxyStream::HttpsReady(stream) => {
                let Some((proxy_server_name, proxy)) = binding.proxy_tls else {
                    return Err(binding_error());
                };
                connector
                    .finish_https_connect(stream, &proxy, &proxy_server_name, route, &server_name)
                    .await
            }
            ProxyStream::HttpsPending(_) => Err(binding_error()),
        }
    }
}

fn binding_error() -> Http1TlsError {
    Http1TlsError::Connect(io::Error::new(
        io::ErrorKind::InvalidInput,
        "retained HTTP proxy opening requires its original purpose, route and TLS context",
    ))
}
