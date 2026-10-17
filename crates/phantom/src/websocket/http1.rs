//! HTTP/1.1 WebSocket opening handshakes over `Upgrade` (RFC 6455).

#[cfg(feature = "cookies")]
use std::sync::Arc;

use http::Response;
use phantom_net::route::{
    DirectTlsSetup, Http1Route, Http1Target, HttpConnectRoute, OriginRoute, ProxyTransport,
    Socks5Target, TcpRoute,
};

use phantom_net::{
    http1::{
        Http1Connection, Http1TlsConnector, Http1TlsError, Http1UpgradeOpening, Http1UpgradeOutcome,
    },
    request::{OriginForm, RequestHeader},
    tcp::{AddressFamilyMemory, SlowerConnection},
};

#[cfg(feature = "websocket-deflate")]
use super::NegotiatedPerMessageDeflate;
use super::{
    Http1UpgradeConnector, WebSocket, WebSocketError, WebSocketRequestBuilder, WebSocketTransport,
    handshake::{prepare, validate_response},
};
use crate::{Client, HttpProtocol, RequestError, ResponseBody, Route, authority::Endpoint};

/// Sends the opening over a new direct TLS connection.
///
/// With a profile that takes ECH from HTTPS records, the connection offers
/// the `ech` value of the origin's record: Chrome 154 opens a `wss://`
/// connection through the same `SSLConnectJob` as an `https://` one, with
/// `http/1.1` as its only ALPN protocol (`ClientSocketPool::CreateConnectJob`,
/// `net/socket/client_socket_pool.cc` lines 244-256 at `154.0.8037.58`).
async fn upgrade_direct(
    #[cfg_attr(not(feature = "https-records"), allow(unused_variables))] client: &Client,
    connector: &Http1TlsConnector,
    endpoint: &Endpoint,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    family: &AddressFamilyMemory,
) -> Result<
    (
        Http1UpgradeOpening,
        Option<SlowerConnection<Http1Connection>>,
    ),
    Http1TlsError,
> {
    let tcp = || {
        TcpRoute::Direct(phantom_net::route::Endpoint {
            host: endpoint.host(),
            port: endpoint.port(),
        })
    };
    // Bound the connector's `Send` proof separately from WebSocket setup;
    // see `box_send`.
    #[cfg(feature = "https-records")]
    if let Some(ech) = client.direct_tcp_ech(endpoint, connector.ech_from_https_records(), || {
        connector.alpn_protocols()
    }) {
        let mut ech = std::pin::pin!(ech);
        return crate::session::box_send(connector.open_upgrade(
            OriginRoute::Tls {
                tcp: tcp(),
                server_name: endpoint.host(),
                setup: DirectTlsSetup::EchKeepingSlower {
                    lookup: ech.as_mut(),
                    family,
                },
            },
            target,
            headers,
        ))
        .await;
    }
    crate::session::box_send(connector.open_upgrade(
        OriginRoute::Tls {
            tcp: tcp(),
            server_name: endpoint.host(),
            setup: DirectTlsSetup::KeepSlower(family),
        },
        target,
        headers,
    ))
    .await
}

enum OpeningOwner {
    Exact(crate::session::http1_pool::OriginOpening),
    Negotiated(crate::session::http1_or_2_pool::OriginOpening),
}

impl OpeningOwner {
    fn family(&self) -> &AddressFamilyMemory {
        match self {
            Self::Exact(owner) => owner.family(),
            Self::Negotiated(owner) => owner.family(),
        }
    }

    fn adopt(&self, slower: SlowerConnection<Http1Connection>) {
        match self {
            Self::Exact(owner) => owner.adopt(slower),
            Self::Negotiated(owner) => owner.adopt(slower),
        }
    }
}

async fn direct_opening(
    client: &Client,
    upgrade_connector: Http1UpgradeConnector,
    endpoint: &Endpoint,
    plaintext: bool,
    base: &Http1TlsConnector,
) -> Result<(Http1TlsConnector, OpeningOwner), WebSocketError> {
    let setup = |error| WebSocketError::request(RequestError::http1_connection_setup(error));
    let connectors = client.inner.connectors_for(endpoint);
    // Cleartext profile-policy requests use the exact HTTP/1 pool.
    if !plaintext
        && matches!(upgrade_connector, Http1UpgradeConnector::PolicyAlpn)
        && let Some(negotiated) = connectors.http1_or_2
    {
        let owner = client.state.http1_or_2.origin_opening(endpoint).await;
        let websocket = client
            .inner
            .websocket
            .as_ref()
            .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?;
        let connector = owner
            .connector(negotiated, endpoint)
            .map_err(WebSocketError::request)?
            .http1_connector(&websocket.connection.http1_alpn_protocols)
            .map_err(setup)?;
        return Ok((connector, OpeningOwner::Negotiated(owner)));
    }
    let owner = client.state.http1.origin_opening(endpoint, plaintext).await;
    let mut connector = if plaintext {
        base.clone()
    } else {
        owner
            .connector(
                connectors
                    .http1
                    .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?,
                endpoint,
            )
            .map_err(WebSocketError::request)?
    };
    if !plaintext && matches!(upgrade_connector, Http1UpgradeConnector::PolicyAlpn) {
        let websocket = client
            .inner
            .websocket
            .as_ref()
            .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?;
        connector = connector
            .with_alpn_protocols(&websocket.connection.http1_alpn_protocols)
            .map_err(setup)?;
    }
    Ok((connector, OpeningOwner::Exact(owner)))
}

/// The connector of the request pool whose TLS session tickets a `wss://`
/// opening shares, or `None` when no request pool shares the connector's
/// TLS context.
///
/// An exact opening shares the exact HTTP/1.1 pool's key for its origin and
/// route; a profile-policy opening shares the negotiated pool's, or without
/// one the exact HTTP/1.1 pool's, with the policy's ALPN offer. Chrome 154
/// keys its session cache by host and port, network anonymization key,
/// privacy mode, and proxy chain, not by ALPN
/// (`SSLClientSocketImpl::GetSessionCacheKey`,
/// `net/socket/ssl_client_socket_impl.cc` lines 1631-1644 at
/// `154.0.8037.58`), and Firefox 157 resumed the page's ticket on its
/// WebSocket connections in the retained captures.
async fn pooled_tls_connector(
    client: &Client,
    upgrade_connector: Http1UpgradeConnector,
    endpoint: &Endpoint,
    route: &Route,
) -> Result<Option<Http1TlsConnector>, WebSocketError> {
    let setup = |error| WebSocketError::request(RequestError::http1_connection_setup(error));
    let state = &client.state;
    let connectors = client.inner.connectors_for(endpoint);
    match upgrade_connector {
        Http1UpgradeConnector::Profile => match connectors.http1 {
            Some(base) => Ok(Some(
                state
                    .http1
                    .tls_origin_connector(base, endpoint, route)
                    .await
                    .map_err(WebSocketError::request)?,
            )),
            None => Ok(None),
        },
        Http1UpgradeConnector::PolicyAlpn => {
            let Some(websocket) = &client.inner.websocket else {
                return Ok(None);
            };
            let protocols = &websocket.connection.http1_alpn_protocols;
            if let Some(base) = connectors.http1_or_2 {
                return state
                    .http1_or_2
                    .tls_origin_connector(base, endpoint, route)
                    .await
                    .map_err(WebSocketError::request)?
                    .http1_connector(protocols)
                    .map(Some)
                    .map_err(setup);
            }
            match connectors.http1 {
                Some(base) => state
                    .http1
                    .tls_origin_connector(base, endpoint, route)
                    .await
                    .map_err(WebSocketError::request)?
                    .with_alpn_protocols(protocols)
                    .map(Some)
                    .map_err(setup),
                None => Ok(None),
            }
        }
    }
}

// Only the physical proxy's configured backup selector enables staged setup.
// Other routes retain their existing connector and protocol selection.
fn retains_proxy(client: &Client, connector: &Http1TlsConnector, route: &Route) -> bool {
    let Route::HttpProxy(proxy) = route else {
        return false;
    };
    if proxy.uses_http2() {
        return false;
    }
    let settings = if proxy.uses_tls() {
        client
            .inner
            .websocket_https_proxy
            .as_ref()
            .and_then(|connector| connector.tcp_settings())
    } else {
        connector.tcp_settings()
    };
    settings.is_some_and(|settings| {
        matches!(
            settings.address_selection,
            phantom_profile::TcpAddressSelection::Backup(_)
        )
    })
}

async fn upgrade_proxy(
    client: &Client,
    selection: Http1UpgradeConnector,
    endpoint: &Endpoint,
    route: &Route,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<(Http1UpgradeOpening, OpeningOwner), WebSocketError> {
    let setup = |error| WebSocketError::request(RequestError::http1_connection_setup(error));
    let proxy = route.as_http_proxy().ok_or_else(|| {
        WebSocketError::request(RequestError::unsupported_route(HttpProtocol::Http1))
    })?;
    let connectors = client.inner.connectors_for(endpoint);
    let owner = if matches!(selection, Http1UpgradeConnector::PolicyAlpn)
        && connectors.http1_or_2.is_some()
    {
        OpeningOwner::Negotiated(
            client
                .state
                .http1_or_2
                .proxy_upgrade_opening(endpoint, route)
                .await,
        )
    } else {
        OpeningOwner::Exact(
            client
                .state
                .http1
                .proxy_upgrade_opening(endpoint, route)
                .await,
        )
    };
    let outer = if proxy.uses_tls() {
        let base = client.inner.websocket_https_proxy.as_ref().ok_or_else(|| {
            WebSocketError::request(RequestError::unsupported_route(HttpProtocol::Http1))
        })?;
        Some(
            match &owner {
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
    let transport = match &outer {
        Some(connector) => ProxyTransport::Tls {
            endpoint: proxy_endpoint,
            server_name: proxy.host(),
            connector,
        },
        None => ProxyTransport::Tcp(proxy_endpoint),
    };
    let authority = endpoint.tunnel_authority();
    let connect = HttpConnectRoute {
        speculative_tls: proxy.speculative_tls(),
        proxy: transport,
        authority: &authority,
        headers: proxy.ordered_connect_headers(),
        credentials: proxy.authentication(),
    };
    let opening = match &owner {
        OpeningOwner::Exact(owner) => {
            let base = connectors
                .http1
                .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?;
            let mut connector = owner
                .proxy_origin_connector(base, endpoint, route)
                .map_err(WebSocketError::request)?;
            if matches!(selection, Http1UpgradeConnector::PolicyAlpn) {
                let websocket = client
                    .inner
                    .websocket
                    .as_ref()
                    .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?;
                connector = connector
                    .with_alpn_protocols(&websocket.connection.http1_alpn_protocols)
                    .map_err(setup)?;
            }
            let protocols = connector.alpn_protocols();
            crate::session::box_send(
                owner
                    .open_proxy_upgrade(&connector, connect, &protocols, endpoint, target, headers),
            )
            .await
        }
        OpeningOwner::Negotiated(owner) => {
            let base = connectors
                .http1_or_2
                .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?;
            let connector = owner
                .proxy_origin_connector(base, endpoint, route)
                .map_err(WebSocketError::request)?;
            let websocket = client
                .inner
                .websocket
                .as_ref()
                .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?;
            crate::session::box_send(owner.open_proxy_upgrade(
                &connector,
                connect,
                &websocket.connection.http1_alpn_protocols,
                endpoint,
                target,
                headers,
            ))
            .await
        }
    }
    .map_err(WebSocketError::request)?;
    Ok((opening, owner))
}

fn retains_socks(connector: &Http1TlsConnector, route: &Route) -> bool {
    matches!(route, Route::Socks4(_) | Route::Socks5(_))
        && connector.tcp_settings().is_some_and(|settings| {
            matches!(
                settings.address_selection,
                phantom_profile::TcpAddressSelection::Backup(_)
            )
        })
}

async fn upgrade_socks(
    client: &Client,
    selection: Http1UpgradeConnector,
    endpoint: &Endpoint,
    route: &Route,
    plaintext: bool,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<(Http1UpgradeOpening, OpeningOwner), WebSocketError> {
    let connectors = client.inner.connectors_for(endpoint);
    let owner = if !plaintext
        && matches!(selection, Http1UpgradeConnector::PolicyAlpn)
        && connectors.http1_or_2.is_some()
    {
        OpeningOwner::Negotiated(
            client
                .state
                .http1_or_2
                .proxy_upgrade_opening(endpoint, route)
                .await,
        )
    } else {
        OpeningOwner::Exact(
            client
                .state
                .http1
                .socks_upgrade_opening(endpoint, route, plaintext)
                .await,
        )
    };
    let destination = phantom_net::route::Endpoint {
        host: endpoint.host(),
        port: endpoint.port(),
    };
    let tcp = match route {
        Route::Socks4(proxy) => proxy.tcp_route(destination).map_err(|source| {
            WebSocketError::request(RequestError::http1_connection_setup(source.into()))
        })?,
        Route::Socks5(proxy) => TcpRoute::Socks5 {
            proxy: phantom_net::route::Endpoint {
                host: proxy.host(),
                port: proxy.port(),
            },
            target: match proxy.dns_mode() {
                crate::Socks5DnsMode::Local => Socks5Target::LocalDns(destination),
                crate::Socks5DnsMode::Remote => Socks5Target::RemoteDns(destination),
            },
            auth: proxy.auth(),
        },
        _ => {
            return Err(WebSocketError::request(RequestError::unsupported_route(
                HttpProtocol::Http1,
            )));
        }
    };
    let origin = if plaintext {
        OriginRoute::Plaintext { tcp, family: None }
    } else {
        OriginRoute::Tls {
            tcp,
            server_name: endpoint.host(),
            setup: DirectTlsSetup::Default,
        }
    };
    let websocket = client
        .inner
        .websocket
        .as_ref()
        .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?;
    let opening = match &owner {
        OpeningOwner::Exact(owner) => {
            let connector = if plaintext {
                match selection {
                    Http1UpgradeConnector::Profile => connectors.http1,
                    Http1UpgradeConnector::PolicyAlpn => connectors.websocket_http1,
                }
                .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?
                .clone()
            } else {
                owner
                    .proxy_origin_connector(
                        connectors.http1.ok_or_else(|| {
                            WebSocketError::protocol_unavailable(HttpProtocol::Http1)
                        })?,
                        endpoint,
                        route,
                    )
                    .map_err(WebSocketError::request)?
            };
            let protocols = if matches!(selection, Http1UpgradeConnector::PolicyAlpn) {
                websocket.connection.http1_alpn_protocols.clone()
            } else {
                connector.alpn_protocols()
            };
            crate::session::box_send(
                owner.open_socks_upgrade(&connector, origin, &protocols, target, headers),
            )
            .await
        }
        OpeningOwner::Negotiated(owner) => {
            let connector = owner
                .proxy_origin_connector(
                    connectors
                        .http1_or_2
                        .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?,
                    endpoint,
                    route,
                )
                .map_err(WebSocketError::request)?;
            crate::session::box_send(owner.open_socks_upgrade(
                &connector,
                origin,
                &websocket.connection.http1_alpn_protocols,
                target,
                headers,
            ))
            .await
        }
    }
    .map_err(WebSocketError::request)?;
    Ok((opening, owner))
}

impl WebSocketRequestBuilder {
    pub(super) async fn connect_http1(
        self,
        upgrade_connector: Http1UpgradeConnector,
    ) -> Result<WebSocket, WebSocketError> {
        let Self {
            client,
            selection: _,
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
        let base = match upgrade_connector {
            Http1UpgradeConnector::Profile => connectors.http1,
            Http1UpgradeConnector::PolicyAlpn => connectors.websocket_http1,
        }
        .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http1))?;
        let prepared = prepare(
            headers,
            request.endpoint.authority().as_str(),
            cookie_value,
            extension_offer.as_ref().map(http::HeaderValue::as_bytes),
        )?;
        // Looked up only for a valid opening, since creating a pool key can
        // evict another. CONNECT-UDP is rejected below before any I/O, and
        // creates no pool key.
        let pooled = if request.transport == WebSocketTransport::Tls
            && !matches!(route, Route::Direct | Route::ConnectUdp(_))
        {
            pooled_tls_connector(&client, upgrade_connector, &request.endpoint, route).await?
        } else {
            None
        };
        let connector = pooled.as_ref().unwrap_or(base);
        let retain_proxy = request.transport == WebSocketTransport::Tls
            && retains_proxy(&client, connector, route);
        let mut opening_owner = None;
        let outcome = if matches!(route, Route::Direct) {
            let plaintext = request.transport == WebSocketTransport::Plaintext;
            let (connector, owner) = direct_opening(
                &client,
                upgrade_connector,
                &request.endpoint,
                plaintext,
                base,
            )
            .await?;
            let opened = if plaintext {
                crate::session::box_send(connector.open_upgrade(
                    OriginRoute::Plaintext {
                        tcp: TcpRoute::Direct(phantom_net::route::Endpoint {
                            host: request.endpoint.host(),
                            port: request.endpoint.port(),
                        }),
                        family: Some(owner.family()),
                    },
                    request.target,
                    prepared.headers,
                ))
                .await
            } else {
                upgrade_direct(
                    &client,
                    &connector,
                    &request.endpoint,
                    request.target,
                    prepared.headers,
                    owner.family(),
                )
                .await
            };
            match opened {
                Ok((opening, slower)) => {
                    if let Some(slower) = slower {
                        owner.adopt(slower);
                    }
                    opening_owner = Some(owner);
                    opening.send().await
                }
                Err(error) => Err(error),
            }
        } else if retains_socks(connector, route) {
            let (opening, owner) = upgrade_socks(
                &client,
                upgrade_connector,
                &request.endpoint,
                route,
                request.transport == WebSocketTransport::Plaintext,
                request.target,
                prepared.headers,
            )
            .await?;
            opening_owner = Some(owner);
            opening.send().await
        } else if retain_proxy {
            let (opening, owner) = upgrade_proxy(
                &client,
                upgrade_connector,
                &request.endpoint,
                route,
                request.target,
                prepared.headers,
            )
            .await?;
            opening_owner = Some(owner);
            opening.send().await
        } else {
            let authority = request.endpoint.tunnel_authority();
            let proxy_connector = if let Route::HttpProxy(proxy) = route
                && proxy.uses_tls()
            {
                Some(proxy.https_connector(
                    client.inner.websocket_https_proxy.as_ref().ok_or_else(|| {
                        WebSocketError::request(RequestError::unsupported_route(
                            HttpProtocol::Http1,
                        ))
                    })?,
                ))
            } else {
                None
            };
            let endpoint = phantom_net::route::Endpoint {
                host: request.endpoint.host(),
                port: request.endpoint.port(),
            };
            let tcp = match route {
                Route::Direct => TcpRoute::Direct(endpoint),
                Route::HttpProxy(proxy) => {
                    // Plain WebSockets also use CONNECT and an origin-form Upgrade.
                    let endpoint = phantom_net::route::Endpoint {
                        host: proxy.host(),
                        port: proxy.port(),
                    };
                    let transport = match &proxy_connector {
                        Some(connector) => ProxyTransport::Tls {
                            endpoint,
                            server_name: proxy.host(),
                            connector,
                        },
                        None => ProxyTransport::Tcp(endpoint),
                    };
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        speculative_tls: proxy.speculative_tls()
                            && matches!(request.transport, WebSocketTransport::Tls),
                        proxy: transport,
                        authority: &authority,
                        headers: proxy.ordered_connect_headers(),
                        credentials: proxy.authentication(),
                    })
                }
                Route::Socks4(proxy) => proxy.tcp_route(endpoint).map_err(|source| {
                    WebSocketError::request(RequestError::http1_connection_setup(source.into()))
                })?,
                Route::Socks5(proxy) => TcpRoute::Socks5 {
                    proxy: phantom_net::route::Endpoint {
                        host: proxy.host(),
                        port: proxy.port(),
                    },
                    target: match proxy.dns_mode() {
                        crate::Socks5DnsMode::Local => Socks5Target::LocalDns(endpoint),
                        crate::Socks5DnsMode::Remote => Socks5Target::RemoteDns(endpoint),
                    },
                    auth: proxy.auth(),
                },
                Route::ConnectUdp(_) => {
                    return Err(WebSocketError::request(RequestError::unsupported_route(
                        HttpProtocol::Http1,
                    )));
                }
            };
            let origin = match request.transport {
                WebSocketTransport::Plaintext => OriginRoute::Plaintext { tcp, family: None },
                WebSocketTransport::Tls => OriginRoute::Tls {
                    tcp,
                    server_name: request.endpoint.host(),
                    setup: DirectTlsSetup::Default,
                },
            };
            let operation = connector.upgrade(
                Http1Route::Origin(origin),
                Http1Target::Origin(request.target),
                prepared.headers,
            );
            crate::session::box_send(operation).await
        }
        .map_err(RequestError::http1_connection_setup)
        .map_err(WebSocketError::request)?;

        match outcome {
            Http1UpgradeOutcome::Rejected(response) => {
                let (parts, body) = response.into_parts();
                let response = Response::from_parts(
                    parts,
                    ResponseBody::http1_with_guard(body, opening_owner.take()),
                );
                #[cfg(feature = "cookies")]
                if let Some(jar) = cookie_jar.as_deref() {
                    jar.store_response_headers(&request.cookie_url, response.headers());
                }
                Err(WebSocketError::rejected(response))
            }
            Http1UpgradeOutcome::Upgraded(response) => {
                drop(opening_owner.take());
                let selected_protocol = validate_response(
                    response.version(),
                    response.headers(),
                    &prepared.expected_accept,
                    &prepared.offered_protocols,
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
                if let Some(jar) = cookie_jar.as_deref() {
                    jar.store_response_headers(&request.cookie_url, response.headers());
                }
                let (parts, stream) = response.into_parts();
                let handshake = Response::from_parts(parts, ());
                Ok(WebSocket::new_http1(
                    stream,
                    handshake,
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
}
