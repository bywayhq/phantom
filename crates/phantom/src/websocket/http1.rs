//! HTTP/1.1 WebSocket opening handshakes over `Upgrade` (RFC 6455).

#[cfg(feature = "cookies")]
use std::sync::Arc;

use http::Response;
use phantom_net::route::{
    DirectTlsSetup, Http1Route, Http1Target, HttpConnectRoute, OriginRoute, ProxyTransport,
    Socks5Target, TcpRoute,
};

use phantom_net::http1::{
    Http1TlsConnector, Http1TlsError, Http1UpgradeOutcome, OriginForm, RequestHeader,
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
) -> Result<Http1UpgradeOutcome, Http1TlsError> {
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
        return crate::session::box_send(connector.upgrade(
            Http1Route::Origin(OriginRoute::Tls {
                tcp: tcp(),
                server_name: endpoint.host(),
                setup: DirectTlsSetup::Ech(ech.as_mut()),
            }),
            Http1Target::Origin(target),
            headers,
        ))
        .await;
    }
    crate::session::box_send(connector.upgrade(
        Http1Route::Origin(OriginRoute::Tls {
            tcp: tcp(),
            server_name: endpoint.host(),
            setup: DirectTlsSetup::Default,
        }),
        Http1Target::Origin(target),
        headers,
    ))
    .await
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
                    .await,
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
                    .http1_connector(protocols)
                    .map(Some)
                    .map_err(setup);
            }
            match connectors.http1 {
                Some(base) => state
                    .http1
                    .tls_origin_connector(base, endpoint, route)
                    .await
                    .with_alpn_protocols(protocols)
                    .map(Some)
                    .map_err(setup),
                None => Ok(None),
            }
        }
    }
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
            cookie_jar
                .as_deref()
                .and_then(|jar| jar.request_value_for_url(&request.cookie_url))
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
            && !matches!(route, Route::ConnectUdp(_))
        {
            pooled_tls_connector(&client, upgrade_connector, &request.endpoint, route).await?
        } else {
            None
        };
        let connector = pooled.as_ref().unwrap_or(base);
        let outcome =
            if request.transport == WebSocketTransport::Tls && matches!(route, Route::Direct) {
                upgrade_direct(
                    &client,
                    connector,
                    &request.endpoint,
                    request.target,
                    prepared.headers,
                )
                .await
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
                            proxy: transport,
                            authority: &authority,
                            headers: proxy.ordered_connect_headers(),
                            credentials: proxy.basic_credentials(),
                        })
                    }
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
                let response = Response::from_parts(parts, ResponseBody::http1(body));
                #[cfg(feature = "cookies")]
                if let Some(jar) = cookie_jar.as_deref() {
                    jar.store_response_headers(&request.cookie_url, response.headers());
                }
                Err(WebSocketError::rejected(response))
            }
            Http1UpgradeOutcome::Upgraded(response) => {
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
