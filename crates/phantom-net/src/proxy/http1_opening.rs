//! Quiet HTTP/1 proxy transport before claimant-owned CONNECT and origin TLS.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    HttpConnectError, HttpProxyAuthentication, HttpProxyCredentials, ProxyCredentialCache,
};
use crate::{
    connection_leg::ConnectionLeg,
    direct::{Dialer, DirectConnectError, connect_tcp_keeping_slower},
    route::{HttpConnectRoute, ProxyTransport},
    tcp::{AddressFamilyMemory, ProfileTcpStream, SlowerAttempt},
};

#[derive(Debug)]
pub(crate) enum ProxyOpeningError {
    Binding(io::Error),
    Proxy(HttpConnectError),
}

impl From<HttpConnectError> for ProxyOpeningError {
    fn from(error: HttpConnectError) -> Self {
        Self::Proxy(error)
    }
}

pub(crate) struct ProxyTcpOpening {
    pub(crate) stream: ProfileTcpStream,
    pub(crate) binding: ProxyBinding,
    pub(crate) slower: Option<(SlowerAttempt, ProxyBinding)>,
}

pub(crate) async fn open_connect(
    route: HttpConnectRoute<'_>,
    server_name: &str,
    dialer: Dialer<'_>,
    family: &AddressFamilyMemory,
) -> Result<ProxyTcpOpening, ProxyOpeningError> {
    let binding = ProxyBinding::new(route, server_name)?;
    let slower_binding = ProxyBinding::new(route, server_name)?;
    let (stream, slower) = match route.proxy {
        ProxyTransport::Tcp(endpoint) => {
            connect_tcp_keeping_slower(endpoint.host, endpoint.port, dialer, Some(family))
                .await
                .map_err(|error| {
                    ProxyOpeningError::Proxy(match error {
                        DirectConnectError::RuntimeUnavailable => {
                            HttpConnectError::RuntimeUnavailable
                        }
                        DirectConnectError::Connect(error) => HttpConnectError::Connect(error),
                    })
                })?
        }
        ProxyTransport::Tls {
            endpoint,
            connector,
            ..
        } => {
            connector
                .open_http1_proxy_retaining(endpoint.host, endpoint.port, family)
                .await?
        }
    };
    Ok(ProxyTcpOpening {
        stream,
        binding,
        slower: slower.map(|attempt| (attempt, slower_binding)),
    })
}

pub(crate) enum ProxyStream {
    Tcp(ProfileTcpStream),
    HttpsPending(ProfileTcpStream),
    HttpsReady(crate::tls::TlsStream<ProfileTcpStream>),
}

pub(crate) struct ProxyBinding {
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
        speculative_tls: bool,
    },
    Forward,
}

impl ProxyBinding {
    pub(crate) fn new(
        route: HttpConnectRoute<'_>,
        server_name: &str,
    ) -> Result<Self, ProxyOpeningError> {
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
        validate_request(route)?;
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
                speculative_tls: route.speculative_tls,
            },
        })
    }

    pub(crate) fn forward(transport: ProxyTransport<'_>) -> Result<Self, ProxyOpeningError> {
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
            speculative_tls,
            ..
        } = &self.purpose
        else {
            return false;
        };
        self.matches_transport(route.proxy)
            && route.authority == authority.as_ref()
            && route.credentials == credentials.as_ref().map(HttpProxyCredentials::as_ref)
            && route.speculative_tls == *speculative_tls
    }
}

impl ProxyBinding {
    pub(crate) fn stream(&self, stream: ProfileTcpStream) -> ProxyStream {
        if self.proxy_tls.is_some() {
            ProxyStream::HttpsPending(stream)
        } else {
            ProxyStream::Tcp(stream)
        }
    }

    pub(crate) fn validate_forward(
        &self,
        transport: ProxyTransport<'_>,
    ) -> Result<(), ProxyOpeningError> {
        if matches!(self.purpose, ProxyPurpose::Forward) && self.matches_transport(transport) {
            Ok(())
        } else {
            Err(binding_error())
        }
    }

    pub(crate) fn validate_connect(
        &self,
        route: HttpConnectRoute<'_>,
    ) -> Result<(), ProxyOpeningError> {
        if !self.matches(route) {
            return Err(binding_error());
        }
        validate_request(route)?;
        Ok(())
    }

    pub(crate) fn server_name(&self) -> Result<&str, ProxyOpeningError> {
        match &self.purpose {
            ProxyPurpose::Connect { server_name, .. } => Ok(server_name),
            ProxyPurpose::Forward => Err(binding_error()),
        }
    }

    pub(crate) async fn complete_proxy_tls(
        &self,
        stream: ProxyStream,
    ) -> Result<ProxyStream, ProxyOpeningError> {
        match stream {
            ProxyStream::HttpsPending(stream) => {
                let Some((server_name, proxy)) = &self.proxy_tls else {
                    return Err(binding_error());
                };
                Ok(ProxyStream::HttpsReady(
                    proxy.finish_http1_proxy_tls(stream, server_name).await?,
                ))
            }
            stream => Ok(stream),
        }
    }

    pub(crate) async fn finish_connect(
        self,
        stream: ProxyStream,
        route: HttpConnectRoute<'_>,
        dialer: Dialer<'_>,
        cache: Option<&ProxyCredentialCache>,
    ) -> Result<(ConnectionLeg, Box<str>), ProxyOpeningError> {
        self.validate_connect(route)?;
        let stream = self.complete_proxy_tls(stream).await?;
        let ProxyPurpose::Connect { server_name, .. } = self.purpose else {
            return Err(binding_error());
        };
        if route.speculative_tls {
            let request = super::speculative::prepare(route)?;
            let leg = ConnectionLeg::Speculative(Box::new(
                super::speculative::SpeculativeConnect::new(stream, request),
            ));
            return Ok((leg, server_name));
        }
        let leg = match stream {
            ProxyStream::Tcp(stream) => ConnectionLeg::HttpConnect(
                super::connect_http_tunnel_from_stream(
                    stream,
                    dialer,
                    cache,
                    &self.host,
                    self.port,
                    route.authority,
                    route.headers,
                    route.credentials,
                )
                .await?,
            ),
            ProxyStream::HttpsReady(stream) => {
                let Some((proxy_name, proxy)) = self.proxy_tls else {
                    return Err(binding_error());
                };
                ConnectionLeg::HttpsConnect(
                    proxy
                        .connect_http1_tunnel_from_stream(
                            stream,
                            &self.host,
                            self.port,
                            &proxy_name,
                            route.authority,
                            route.headers,
                            route.credentials,
                        )
                        .await?,
                )
            }
            ProxyStream::HttpsPending(_) => return Err(binding_error()),
        };
        Ok((leg, server_name))
    }
}

fn validate_request(route: HttpConnectRoute<'_>) -> Result<(), HttpConnectError> {
    if route.speculative_tls {
        super::speculative::prepare(route).map(drop)
    } else {
        super::validate_http_tunnel(route.authority, route.headers, route.credentials)
    }
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) | Self::HttpsPending(stream) => {
                Pin::new(stream).poll_read(context, output)
            }
            Self::HttpsReady(stream) => Pin::new(stream).poll_read(context, output),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) | Self::HttpsPending(stream) => {
                Pin::new(stream).poll_write(context, bytes)
            }
            Self::HttpsReady(stream) => Pin::new(stream).poll_write(context, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) | Self::HttpsPending(stream) => Pin::new(stream).poll_flush(context),
            Self::HttpsReady(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) | Self::HttpsPending(stream) => {
                Pin::new(stream).poll_shutdown(context)
            }
            Self::HttpsReady(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

impl crate::tcp::TcpKeepaliveSource for ProxyStream {
    fn tcp_keepalive(&self) -> Option<crate::tcp::TcpKeepaliveControl> {
        match self {
            Self::Tcp(stream) | Self::HttpsPending(stream) => stream.tcp_keepalive(),
            Self::HttpsReady(stream) => stream.tcp_keepalive(),
        }
    }
}

pub(crate) fn binding_error() -> ProxyOpeningError {
    ProxyOpeningError::Binding(io::Error::new(
        io::ErrorKind::InvalidInput,
        "retained HTTP proxy opening requires its original purpose, route and TLS context",
    ))
}
