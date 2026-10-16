//! HTTP/2 WebSocket opening handshakes over extended CONNECT (RFC 8441).

#[cfg(feature = "cookies")]
use std::sync::Arc;

use http::Response;
use phantom_net::{
    http2::{
        Http2ExtendedConnectOpening, Http2ExtendedConnectOutcome, Http2TlsConnector, Http2TlsError,
    },
    request::{OriginForm, RequestHeader},
};
use phantom_profile::WebSocketRefusedStreamRetry;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::Span;

#[cfg(feature = "websocket-deflate")]
use super::NegotiatedPerMessageDeflate;
use super::{
    AdmissionGuard, Http2Target, ResolvedWebSocket, WebSocket, WebSocketError, WebSocketLimits,
    WebSocketRequestBuilder, WebSocketSelection, WebSocketTransport,
    error::refused_extended_connect_stream,
    handshake::{prepare_extended_connect, validate_extended_connect_response},
};
#[cfg(feature = "cookies")]
use crate::CookieJar;
use crate::{
    Client, HttpProtocol, RequestError, ResponseBody, Route, Socks5DnsMode, authority::Endpoint,
};

/// Opens the extended CONNECT stream on a new direct TLS connection.
///
/// With a profile that takes ECH from HTTPS records, the connection offers
/// the `ech` value of the origin's record, picked for the connection's own
/// ALPN offer, as every other direct TLS connection does.
async fn extended_connect_direct(
    #[cfg_attr(not(feature = "https-records"), allow(unused_variables))] client: &Client,
    connector: &Http2TlsConnector,
    family: &phantom_net::tcp::AddressFamilyMemory,
    endpoint: &Endpoint,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<
    (
        Http2ExtendedConnectOpening,
        Option<phantom_net::tcp::SlowerConnection<phantom_net::http2::Http2Connection>>,
    ),
    Http2TlsError,
> {
    let (host, port, authority) = (
        endpoint.host(),
        endpoint.port(),
        endpoint.authority().as_str(),
    );
    #[cfg(feature = "https-records")]
    if let Some(ech) = client.direct_tcp_ech(endpoint, connector.ech_from_https_records(), || {
        connector.alpn_protocols()
    }) {
        let mut ech = std::pin::pin!(ech);
        return connector
            .open_extended_connect(
                phantom_net::route::Http2Route::Origin(phantom_net::route::OriginRoute::Tls {
                    tcp: phantom_net::route::TcpRoute::Direct(phantom_net::route::Endpoint {
                        host,
                        port,
                    }),
                    server_name: host,
                    setup: phantom_net::route::DirectTlsSetup::EchKeepingSlower {
                        lookup: ech.as_mut(),
                        family,
                    },
                }),
                authority,
                target,
                headers,
            )
            .await;
    }
    connector
        .open_extended_connect(
            phantom_net::route::Http2Route::Origin(phantom_net::route::OriginRoute::Tls {
                tcp: phantom_net::route::TcpRoute::Direct(phantom_net::route::Endpoint {
                    host,
                    port,
                }),
                server_name: host,
                setup: phantom_net::route::DirectTlsSetup::KeepSlower(family),
            }),
            authority,
            target,
            headers,
        )
        .await
}

enum OpeningOwner {
    Exact(crate::session::http2_pool::OriginHttp2Opening),
    Negotiated(crate::session::http1_or_2_pool::OriginHttp2Opening),
}

impl OpeningOwner {
    fn family(&self) -> &phantom_net::tcp::AddressFamilyMemory {
        match self {
            Self::Exact(owner) => owner.family(),
            Self::Negotiated(owner) => owner.family(),
        }
    }

    fn connected(
        self,
        connection: &phantom_net::http2::Http2Connection,
        slower: Option<phantom_net::tcp::SlowerConnection<phantom_net::http2::Http2Connection>>,
    ) -> Box<dyn Send + Sync> {
        match self {
            Self::Exact(owner) => Box::new(owner.connected(connection, slower)),
            Self::Negotiated(owner) => Box::new(owner.connected(connection, slower)),
        }
    }
}

// Only the physical proxy's applied Backup policy selects staged ownership.
fn keeps_proxy_backup(
    client: &Client,
    proxy: &crate::HttpProxy,
    connector: &Http2TlsConnector,
) -> bool {
    let settings = if proxy.uses_tls() {
        if proxy.uses_http2() {
            return false;
        }
        client
            .inner
            .websocket_https_proxy
            .as_ref()
            .map(|base| proxy.https_connector(base))
            .and_then(|connector| connector.tcp_settings().cloned())
    } else {
        connector.tcp_settings().cloned()
    };
    settings.is_some_and(|settings| {
        matches!(
            settings.address_selection,
            phantom_profile::TcpAddressSelection::Backup(_)
        )
    })
}

async fn extended_connect_proxy(
    client: &Client,
    owner: &OpeningOwner,
    endpoint: &Endpoint,
    route: &Route,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Http2ExtendedConnectOpening, WebSocketError> {
    let proxy = route.as_http_proxy().ok_or_else(|| {
        WebSocketError::request(RequestError::unsupported_route(HttpProtocol::Http2))
    })?;
    let proxy_connector = if proxy.uses_tls() {
        let base = client
            .inner
            .websocket_https_proxy
            .as_ref()
            .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?;
        Some(
            match owner {
                OpeningOwner::Exact(owner) => owner.proxy_connector(base, endpoint, route),
                OpeningOwner::Negotiated(owner) => owner.proxy_connector(base, endpoint, route),
            }
            .map_err(WebSocketError::request)?,
        )
    } else {
        None
    };
    let proxy_endpoint = phantom_net::route::Endpoint {
        host: proxy.host(),
        port: proxy.port(),
    };
    let transport = match &proxy_connector {
        Some(connector) => phantom_net::route::ProxyTransport::Tls {
            endpoint: proxy_endpoint,
            server_name: proxy.host(),
            connector,
        },
        None => phantom_net::route::ProxyTransport::Tcp(proxy_endpoint),
    };
    let authority = endpoint.tunnel_authority();
    let connect = phantom_net::route::HttpConnectRoute {
        proxy: transport,
        authority: &authority,
        headers: proxy.ordered_connect_headers(),
        credentials: proxy.authentication(),
    };
    let connectors = client.inner.connectors_for(endpoint);
    let result = match owner {
        OpeningOwner::Exact(owner) => {
            let base = connectors
                .http2
                .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?;
            let connector = owner
                .proxy_origin_connector(base, endpoint, route)
                .map_err(WebSocketError::request)?;
            owner
                .open_proxy_extended_connect(&connector, connect, endpoint, target, headers)
                .await
        }
        OpeningOwner::Negotiated(owner) => {
            let base = connectors
                .http1_or_2
                .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?;
            let connector = owner
                .proxy_origin_connector(base, endpoint, route)
                .map_err(WebSocketError::request)?;
            owner
                .open_proxy_extended_connect(&connector, connect, endpoint, target, headers)
                .await
        }
    };
    result.map_err(WebSocketError::request)
}

fn keeps_socks_backup(connector: &Http2TlsConnector) -> bool {
    connector.tcp_settings().is_some_and(|settings| {
        matches!(
            settings.address_selection,
            phantom_profile::TcpAddressSelection::Backup(_)
        )
    })
}

async fn extended_connect_socks(
    client: &Client,
    owner: &OpeningOwner,
    endpoint: &Endpoint,
    route: &Route,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Http2ExtendedConnectOpening, WebSocketError> {
    let destination = phantom_net::route::Endpoint {
        host: endpoint.host(),
        port: endpoint.port(),
    };
    let tcp = match route {
        Route::Socks4(proxy) => proxy.tcp_route(destination).map_err(|source| {
            WebSocketError::request(RequestError::http2_connection_setup(source.into()))
        })?,
        Route::Socks5(proxy) => phantom_net::route::TcpRoute::Socks5 {
            proxy: phantom_net::route::Endpoint {
                host: proxy.host(),
                port: proxy.port(),
            },
            target: match proxy.dns_mode() {
                Socks5DnsMode::Local => phantom_net::route::Socks5Target::LocalDns(destination),
                Socks5DnsMode::Remote => phantom_net::route::Socks5Target::RemoteDns(destination),
            },
            auth: proxy.auth(),
        },
        _ => {
            return Err(WebSocketError::request(RequestError::unsupported_route(
                HttpProtocol::Http2,
            )));
        }
    };
    let origin = phantom_net::route::OriginRoute::Tls {
        tcp,
        server_name: endpoint.host(),
        setup: phantom_net::route::DirectTlsSetup::Default,
    };
    let connectors = client.inner.connectors_for(endpoint);
    match owner {
        OpeningOwner::Exact(owner) => {
            let connector = owner
                .proxy_origin_connector(
                    connectors
                        .http2
                        .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?,
                    endpoint,
                    route,
                )
                .map_err(WebSocketError::request)?;
            owner
                .open_socks_extended_connect(&connector, origin, endpoint, target, headers)
                .await
        }
        OpeningOwner::Negotiated(owner) => {
            let connector = owner
                .proxy_origin_connector(
                    connectors
                        .http1_or_2
                        .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?,
                    endpoint,
                    route,
                )
                .map_err(WebSocketError::request)?;
            owner
                .open_socks_extended_connect(&connector, origin, endpoint, target, headers)
                .await
        }
    }
    .map_err(WebSocketError::request)
}

impl WebSocketRequestBuilder {
    pub(super) async fn connect_http2(
        self,
        target: Http2Target,
        request_span: &Span,
    ) -> Result<WebSocket, WebSocketError> {
        let Self {
            client,
            selection,
            request,
            headers,
            http2_headers: _,
            replaced_policy_headers: _,
            limits,
            route,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate,
            handshake_timeout: _,
            retry_policy: _,
            #[cfg(feature = "cookies")]
            retry_cookies,
        } = self;
        let selected_route = request.selected_route(&client, route.as_ref());
        let route = &selected_route;
        // RFC 8441 carries only `wss://` here: plaintext H2 (h2c) is not
        // spoken to any origin, so `ws://` fails before route or origin I/O.
        if request.transport != WebSocketTransport::Tls {
            return Err(WebSocketError::request(RequestError::unsupported_route(
                HttpProtocol::Http2,
            )));
        }

        #[cfg(feature = "cookies")]
        let cookie_jar = client.state.cookies.as_ref().map(Arc::clone);
        // Read lazily: `prepare` calls this only after validation and only
        // when the opening carries the jar's cookies, because a send-path
        // read counts as a use for eviction.
        #[cfg(feature = "cookies")]
        let cookie_value = || {
            let read = || {
                cookie_jar
                    .as_deref()
                    .and_then(|jar| jar.request_value_for_url(&request.cookie_url))
            };
            match retry_cookies.as_ref() {
                Some(snapshot) => snapshot.get_or_init(read).clone(),
                None => read(),
            }
        };
        #[cfg(not(feature = "cookies"))]
        let cookie_value = || None;

        let engine_config = WebSocket::engine_config(limits);
        #[cfg(feature = "websocket-deflate")]
        let compress_empty_messages = permessage_deflate
            .as_ref()
            .is_none_or(super::PerMessageDeflate::compresses_empty_messages);
        #[cfg(feature = "websocket-deflate")]
        let engine_config =
            permessage_deflate.map_or(Ok(engine_config), |policy| policy.apply(engine_config))?;
        #[cfg(feature = "websocket-deflate")]
        let extension_offer = engine_config.deflate_offer();
        #[cfg(not(feature = "websocket-deflate"))]
        let extension_offer: Option<http::HeaderValue> = None;
        let connectors = client.inner.connectors_for(&request.endpoint);
        let base = connectors
            .http2
            .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?;
        let prepared = prepare_extended_connect(
            headers,
            cookie_value,
            extension_offer.as_ref().map(http::HeaderValue::as_bytes),
        )?;
        let direct_opening = if matches!(
            (&target, route),
            (Http2Target::NewConnection, Route::Direct)
        ) {
            Some(match (selection, connectors.http1_or_2) {
                (WebSocketSelection::ProfilePolicy, Some(negotiated)) => {
                    let owner = client
                        .state
                        .http1_or_2
                        .origin_http2_opening(&request.endpoint)
                        .await;
                    let connector = owner
                        .connector(negotiated, &request.endpoint)
                        .map_err(WebSocketError::request)?;
                    (OpeningOwner::Negotiated(owner), connector)
                }
                _ => {
                    let owner = client
                        .state
                        .http2
                        .origin_http2_opening(&request.endpoint)
                        .await;
                    let connector = owner
                        .connector(base, &request.endpoint)
                        .map_err(WebSocketError::request)?;
                    (OpeningOwner::Exact(owner), connector)
                }
            })
        } else {
            None
        };
        // A new connection shares the TLS session tickets of a request pool
        // key, as `pooled_tls_connector` in `http1.rs` describes, looked up
        // only for a valid opening since creating a key can evict another; a
        // pooled session makes no handshake, and CONNECT-UDP is rejected
        // below before any I/O and creates no pool key.
        let pooled = match (&target, route) {
            (Http2Target::Session(..), _) | (_, Route::ConnectUdp(_) | Route::Direct) => None,
            (Http2Target::NewConnection, _) => Some(match (selection, connectors.http1_or_2) {
                (WebSocketSelection::ProfilePolicy, Some(negotiated)) => client
                    .state
                    .http1_or_2
                    .tls_origin_connector(negotiated, &request.endpoint, route)
                    .await
                    .map_err(WebSocketError::request)?
                    .http2_connector(),
                _ => client
                    .state
                    .http2
                    .tls_origin_connector(base, &request.endpoint, route)
                    .await
                    .map_err(WebSocketError::request)?,
            }),
        };
        let connector = pooled.as_ref().unwrap_or(base);
        let host = request.endpoint.host();
        let port = request.endpoint.port();
        let authority = request.endpoint.authority().as_str();
        // SameSessionOnce reopens a refused stream here. ReacquireTwice
        // returns the refusal to the outer profile selector, which releases
        // this admission before selecting another opening. Other stream
        // failures remain terminal.
        if let Http2Target::Session(session, admission, refused_stream_retry) = target {
            // Kept only for the one reopening the profile allows, so the
            // ordinary path still moves the fields into the first attempt.
            let retry_headers = match refused_stream_retry {
                WebSocketRefusedStreamRetry::SameSessionOnce => Some(prepared.headers.clone()),
                WebSocketRefusedStreamRetry::None | WebSocketRefusedStreamRetry::ReacquireTwice => {
                    None
                }
                // Both profile enums are `non_exhaustive`, so an unknown
                // variant is a profile this build cannot honour, not a
                // silent "do nothing".
                _ => {
                    return Err(WebSocketError::invalid_request(
                        "profile names an unsupported refused-stream rule",
                    ));
                }
            };
            let first = connector
                .send_extended_connect_on(
                    &session,
                    authority,
                    request.target.clone(),
                    prepared.headers,
                )
                .await;
            let outcome = match first {
                Ok(outcome) => outcome,
                Err(error) => {
                    let Some(headers) =
                        retry_headers.filter(|_| refused_extended_connect_stream(&error))
                    else {
                        return Err(WebSocketError::request(RequestError::http2(error)));
                    };
                    // RFC 9113, section 8.7: the peer processed nothing on the
                    // refused stream, and the opening fields were the only
                    // bytes written to it, so nothing already sent is
                    // replayed. A second refusal is returned.
                    request_span.record("refused_stream_retry", true);
                    connector
                        .send_extended_connect_on(
                            &session,
                            authority,
                            request.target.clone(),
                            headers,
                        )
                        .await
                        .map_err(RequestError::http2)
                        .map_err(WebSocketError::request)?
                }
            };
            return finish_http2(
                outcome,
                &request,
                &prepared.offered_protocols,
                extension_offer.as_ref(),
                limits,
                engine_config,
                #[cfg(feature = "websocket-deflate")]
                compress_empty_messages,
                #[cfg(feature = "cookies")]
                cookie_jar.as_deref(),
                Some(admission),
            )
            .await;
        }
        // Every route opens a dedicated origin connection; proxy failure is
        // terminal and never retried directly or as an H1 Upgrade.
        let outcome = match route {
            Route::ConnectUdp(_) => {
                return Err(WebSocketError::request(RequestError::unsupported_route(
                    HttpProtocol::Http2,
                )));
            }
            Route::Direct => {
                let Some((owner, connector)) = direct_opening else {
                    return Err(WebSocketError::request(
                        RequestError::unsupported_transport_outcome(),
                    ));
                };
                crate::session::box_send(async {
                    let (opening, slower) = extended_connect_direct(
                        &client,
                        &connector,
                        owner.family(),
                        &request.endpoint,
                        request.target.clone(),
                        prepared.headers,
                    )
                    .await
                    .map_err(RequestError::http2_connection_setup)
                    .map_err(WebSocketError::request)?;
                    let owner = owner.connected(opening.connection(), slower);
                    let mut outcome = opening.send().await;
                    if let Ok(outcome) = &mut outcome {
                        retain_opening_owner(outcome, owner);
                    }
                    Ok::<_, WebSocketError>(outcome)
                })
                .await?
            }
            Route::Socks4(_) | Route::Socks5(_) if keeps_socks_backup(connector) => {
                let owner = match (selection, connectors.http1_or_2) {
                    (WebSocketSelection::ProfilePolicy, Some(_)) => OpeningOwner::Negotiated(
                        client
                            .state
                            .http1_or_2
                            .proxy_http2_opening(&request.endpoint, route)
                            .await,
                    ),
                    _ => OpeningOwner::Exact(
                        client
                            .state
                            .http2
                            .proxy_http2_opening(&request.endpoint, route)
                            .await,
                    ),
                };
                crate::session::box_send(async {
                    let opening = extended_connect_socks(
                        &client,
                        &owner,
                        &request.endpoint,
                        route,
                        request.target.clone(),
                        prepared.headers,
                    )
                    .await?;
                    // Verified H2 retires quiet SOCKS backups before WebSocket HEADERS.
                    let owner = owner.connected(opening.connection(), None);
                    let mut outcome = opening.send().await;
                    if let Ok(outcome) = &mut outcome {
                        retain_opening_owner(outcome, owner);
                    }
                    Ok::<_, WebSocketError>(outcome)
                })
                .await?
            }
            Route::HttpProxy(proxy) if keeps_proxy_backup(&client, proxy, connector) => {
                let owner = match (selection, connectors.http1_or_2) {
                    (WebSocketSelection::ProfilePolicy, Some(_)) => OpeningOwner::Negotiated(
                        client
                            .state
                            .http1_or_2
                            .proxy_http2_opening(&request.endpoint, route)
                            .await,
                    ),
                    _ => OpeningOwner::Exact(
                        client
                            .state
                            .http2
                            .proxy_http2_opening(&request.endpoint, route)
                            .await,
                    ),
                };
                crate::session::box_send(async {
                    let opening = extended_connect_proxy(
                        &client,
                        &owner,
                        &request.endpoint,
                        route,
                        request.target.clone(),
                        prepared.headers,
                    )
                    .await?;
                    // Publish the dedicated H2 owner and retire raw backups before HEADERS.
                    let owner = owner.connected(opening.connection(), None);
                    let mut outcome = opening.send().await;
                    if let Ok(outcome) = &mut outcome {
                        retain_opening_owner(outcome, owner);
                    }
                    Ok::<_, WebSocketError>(outcome)
                })
                .await?
            }
            Route::HttpProxy(proxy) => {
                let connect_authority = request.endpoint.tunnel_authority();
                if proxy.uses_tls() {
                    let proxy_connector = &proxy.https_connector(
                        client.inner.websocket_https_proxy.as_ref().ok_or_else(|| {
                            WebSocketError::request(RequestError::unsupported_route(
                                HttpProtocol::Http2,
                            ))
                        })?,
                    );
                    if let Some(credentials) = proxy.authentication() {
                        // Keep the challenge/retry state machine out of the
                        // ordinary WebSocket connection future's stack frame.
                        crate::session::box_send(connector.extended_connect(
                            phantom_net::route::Http2Route::Origin(
                                phantom_net::route::OriginRoute::Tls {
                                    tcp: phantom_net::route::TcpRoute::HttpConnect(
                                        phantom_net::route::HttpConnectRoute {
                                            proxy: phantom_net::route::ProxyTransport::Tls {
                                                endpoint: phantom_net::route::Endpoint {
                                                    host: proxy.host(),
                                                    port: proxy.port(),
                                                },
                                                server_name: proxy.host(),
                                                connector: proxy_connector,
                                            },
                                            authority: &connect_authority,
                                            headers: proxy.ordered_connect_headers(),
                                            credentials: Some(credentials),
                                        },
                                    ),
                                    server_name: host,
                                    setup: phantom_net::route::DirectTlsSetup::Default,
                                },
                            ),
                            authority,
                            request.target.clone(),
                            prepared.headers,
                        ))
                        .await
                    } else {
                        crate::session::box_send(connector.extended_connect(
                            phantom_net::route::Http2Route::Origin(
                                phantom_net::route::OriginRoute::Tls {
                                    tcp: phantom_net::route::TcpRoute::HttpConnect(
                                        phantom_net::route::HttpConnectRoute {
                                            proxy: phantom_net::route::ProxyTransport::Tls {
                                                endpoint: phantom_net::route::Endpoint {
                                                    host: proxy.host(),
                                                    port: proxy.port(),
                                                },
                                                server_name: proxy.host(),
                                                connector: proxy_connector,
                                            },
                                            authority: &connect_authority,
                                            headers: proxy.ordered_connect_headers(),
                                            credentials: None,
                                        },
                                    ),
                                    server_name: host,
                                    setup: phantom_net::route::DirectTlsSetup::Default,
                                },
                            ),
                            authority,
                            request.target.clone(),
                            prepared.headers,
                        ))
                        .await
                    }
                } else if let Some(credentials) = proxy.authentication() {
                    crate::session::box_send(connector.extended_connect(
                        phantom_net::route::Http2Route::Origin(
                            phantom_net::route::OriginRoute::Tls {
                                tcp: phantom_net::route::TcpRoute::HttpConnect(
                                    phantom_net::route::HttpConnectRoute {
                                        proxy: phantom_net::route::ProxyTransport::Tcp(
                                            phantom_net::route::Endpoint {
                                                host: proxy.host(),
                                                port: proxy.port(),
                                            },
                                        ),
                                        authority: &connect_authority,
                                        headers: proxy.ordered_connect_headers(),
                                        credentials: Some(credentials),
                                    },
                                ),
                                server_name: host,
                                setup: phantom_net::route::DirectTlsSetup::Default,
                            },
                        ),
                        authority,
                        request.target.clone(),
                        prepared.headers,
                    ))
                    .await
                } else {
                    crate::session::box_send(connector.extended_connect(
                        phantom_net::route::Http2Route::Origin(
                            phantom_net::route::OriginRoute::Tls {
                                tcp: phantom_net::route::TcpRoute::HttpConnect(
                                    phantom_net::route::HttpConnectRoute {
                                        proxy: phantom_net::route::ProxyTransport::Tcp(
                                            phantom_net::route::Endpoint {
                                                host: proxy.host(),
                                                port: proxy.port(),
                                            },
                                        ),
                                        authority: &connect_authority,
                                        headers: proxy.ordered_connect_headers(),
                                        credentials: None,
                                    },
                                ),
                                server_name: host,
                                setup: phantom_net::route::DirectTlsSetup::Default,
                            },
                        ),
                        authority,
                        request.target.clone(),
                        prepared.headers,
                    ))
                    .await
                }
            }
            Route::Socks4(proxy) => {
                crate::session::box_send(
                    connector.extended_connect(
                        phantom_net::route::Http2Route::Origin(
                            phantom_net::route::OriginRoute::Tls {
                                tcp: proxy
                                    .tcp_route(phantom_net::route::Endpoint { host, port })
                                    .map_err(|source| {
                                        WebSocketError::request(
                                            RequestError::http2_connection_setup(source.into()),
                                        )
                                    })?,
                                server_name: host,
                                setup: phantom_net::route::DirectTlsSetup::Default,
                            },
                        ),
                        authority,
                        request.target.clone(),
                        prepared.headers,
                    ),
                )
                .await
            }
            Route::Socks5(proxy) => match proxy.dns_mode() {
                Socks5DnsMode::Local => {
                    crate::session::box_send(connector.extended_connect(
                        phantom_net::route::Http2Route::Origin(
                            phantom_net::route::OriginRoute::Tls {
                                tcp: phantom_net::route::TcpRoute::Socks5 {
                                    proxy: phantom_net::route::Endpoint {
                                        host: proxy.host(),
                                        port: proxy.port(),
                                    },
                                    target: phantom_net::route::Socks5Target::LocalDns(
                                        phantom_net::route::Endpoint { host, port },
                                    ),
                                    auth: proxy.auth(),
                                },
                                server_name: host,
                                setup: phantom_net::route::DirectTlsSetup::Default,
                            },
                        ),
                        authority,
                        request.target.clone(),
                        prepared.headers,
                    ))
                    .await
                }
                Socks5DnsMode::Remote => {
                    crate::session::box_send(connector.extended_connect(
                        phantom_net::route::Http2Route::Origin(
                            phantom_net::route::OriginRoute::Tls {
                                tcp: phantom_net::route::TcpRoute::Socks5 {
                                    proxy: phantom_net::route::Endpoint {
                                        host: proxy.host(),
                                        port: proxy.port(),
                                    },
                                    target: phantom_net::route::Socks5Target::RemoteDns(
                                        phantom_net::route::Endpoint { host, port },
                                    ),
                                    auth: proxy.auth(),
                                },
                                server_name: host,
                                setup: phantom_net::route::DirectTlsSetup::Default,
                            },
                        ),
                        authority,
                        request.target.clone(),
                        prepared.headers,
                    ))
                    .await
                }
            },
        }
        .map_err(RequestError::http2_connection_setup)
        .map_err(WebSocketError::request)?;

        finish_http2(
            outcome,
            &request,
            &prepared.offered_protocols,
            extension_offer.as_ref(),
            limits,
            engine_config,
            #[cfg(feature = "websocket-deflate")]
            compress_empty_messages,
            #[cfg(feature = "cookies")]
            cookie_jar.as_deref(),
            None,
        )
        .await
    }
}

fn retain_opening_owner(outcome: &mut Http2ExtendedConnectOutcome, owner: Box<dyn Send + Sync>) {
    match outcome {
        Http2ExtendedConnectOutcome::Accepted { stream, .. } => {
            stream.retain_until_stream_complete(owner)
        }
        Http2ExtendedConnectOutcome::Rejected(response) => {
            response.body_mut().retain_until_stream_complete(owner)
        }
        _ => {}
    }
}

/// Validates the CONNECT response and installs the frame engine.
#[allow(clippy::too_many_arguments)]
async fn finish_http2(
    outcome: Http2ExtendedConnectOutcome,
    request: &ResolvedWebSocket,
    offered_protocols: &[Box<str>],
    extension_offer: Option<&http::HeaderValue>,
    limits: WebSocketLimits,
    engine_config: WebSocketConfig,
    #[cfg(feature = "websocket-deflate")] compress_empty_messages: bool,
    #[cfg(feature = "cookies")] cookie_jar: Option<&CookieJar>,
    admission: Option<AdmissionGuard>,
) -> Result<WebSocket, WebSocketError> {
    #[cfg(not(feature = "cookies"))]
    let _ = request;
    match outcome {
        Http2ExtendedConnectOutcome::Rejected(response) => {
            let (parts, body) = response.into_parts();
            let response = Response::from_parts(parts, ResponseBody::http2(body));
            #[cfg(feature = "cookies")]
            if let Some(jar) = cookie_jar {
                jar.store_response_headers(&request.cookie_url, response.headers());
            }
            Err(WebSocketError::rejected(response))
        }
        Http2ExtendedConnectOutcome::Accepted { response, stream } => {
            let selected_protocol = validate_extended_connect_response(
                http::Version::HTTP_2,
                response.version(),
                response.headers(),
                offered_protocols,
                extension_offer.is_some(),
            )?;
            #[cfg(feature = "websocket-deflate")]
            let engine_config = engine_config
                .accept_deflate_response(response.headers())
                .map_err(WebSocketError::invalid_handshake_source)?;
            #[cfg(feature = "websocket-deflate")]
            let negotiated = engine_config
                .permessage_deflate()
                .map(NegotiatedPerMessageDeflate::from_engine);
            #[cfg(feature = "cookies")]
            if let Some(jar) = cookie_jar {
                jar.store_response_headers(&request.cookie_url, response.headers());
            }
            Ok(WebSocket::new_http2(
                stream,
                admission,
                response,
                selected_protocol,
                limits,
                engine_config,
                #[cfg(feature = "websocket-deflate")]
                super::connection::DeflateState {
                    negotiated,
                    compress_empty_messages,
                },
            )
            .await)
        }
        _ => Err(WebSocketError::request(
            RequestError::unsupported_transport_outcome(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Released(Arc<AtomicBool>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    async fn outcome_owner(rejected: bool) -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (io, peer) = tokio::io::duplex(65536);
            let settings = phantom_profile::browser::firefox::v157_http2();
            let connection = phantom_net::http2::Http2Connection::connect(io, &settings).await?;
            let released = Arc::new(AtomicBool::new(false));
            let (done, completed) = tokio::sync::oneshot::channel();
            let caller = async {
                let mut outcome = connection
                    .send_extended_connect_with_settings(
                        &settings,
                        "origin.test",
                        OriginForm::parse("/events")?,
                        Vec::new(),
                    )
                    .await?;
                retain_opening_owner(&mut outcome, Box::new(Released(Arc::clone(&released))));
                assert!(!released.load(Ordering::SeqCst));
                match outcome {
                    Http2ExtendedConnectOutcome::Rejected(response) if rejected => {
                        assert_eq!(response.status(), 403);
                        assert_eq!(
                            response.into_body().collect().await?.to_bytes(),
                            b"denied".as_slice()
                        );
                    }
                    Http2ExtendedConnectOutcome::Accepted { stream, .. } if !rejected => {
                        drop(stream)
                    }
                    _ => return Err("unexpected opening outcome".into()),
                }
                assert!(released.load(Ordering::SeqCst));
                done.send(())
                    .map_err(|_| "peer ended before owner release")?;
                Result::<_, Box<dyn std::error::Error>>::Ok(())
            };
            let server = async {
                let mut builder = ::http2::server::Builder::new();
                builder.enable_connect_protocol();
                let mut connection = builder.handshake::<_, Bytes>(peer).await?;
                let (_request, mut respond) =
                    connection.accept().await.ok_or("missing CONNECT")??;
                let response = http::Response::builder()
                    .status(if rejected { 403 } else { 200 })
                    .body(())?;
                let mut body = respond.send_response(response, false)?;
                if rejected {
                    body.send_data(Bytes::from_static(b"denied"), true)?;
                }
                tokio::select! {
                    biased;
                    result = completed => result?,
                    next = connection.accept() => match next {
                        Some(Ok(_)) => return Err("unexpected second application stream".into()),
                        Some(Err(error)) => return Err(error.into()),
                        None => return Err("peer ended before owner release".into()),
                    }
                }
                Result::<_, Box<dyn std::error::Error>>::Ok(())
            };
            tokio::try_join!(caller, server)?;
            Ok(())
        })
        .await?
    }

    #[tokio::test]
    async fn rejected_connect_body_retains_dedicated_owner_until_body_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        outcome_owner(true).await
    }

    #[tokio::test]
    async fn accepted_connect_stream_retains_dedicated_owner_until_transport_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        outcome_owner(false).await
    }
}
