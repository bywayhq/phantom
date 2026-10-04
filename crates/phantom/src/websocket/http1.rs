//! HTTP/1.1 WebSocket opening handshakes over `Upgrade` (RFC 6455).

#[cfg(feature = "cookies")]
use std::sync::Arc;

use http::Response;
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
    #[cfg(feature = "https-records")]
    if let Some(ech) = client.direct_tcp_ech(endpoint, connector.ech_from_https_records(), || {
        connector.alpn_protocols()
    }) {
        return connector
            .upgrade_get_direct_with_ech(
                endpoint.host(),
                endpoint.port(),
                endpoint.host(),
                target,
                headers,
                ech,
            )
            .await;
    }
    connector
        .upgrade_get_direct(
            endpoint.host(),
            endpoint.port(),
            endpoint.host(),
            target,
            headers,
        )
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
        let route = route.as_ref().unwrap_or(&client.inner.route);

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
        let outcome = match request.transport {
            WebSocketTransport::Plaintext => match route {
                // CONNECT-UDP carries only QUIC; reject before any I/O.
                Route::ConnectUdp(_) => {
                    return Err(WebSocketError::request(RequestError::unsupported_route(
                        HttpProtocol::Http1,
                    )));
                }
                Route::Direct => {
                    connector
                        .upgrade_get_plaintext_direct(
                            request.endpoint.host(),
                            request.endpoint.port(),
                            request.target,
                            prepared.headers,
                        )
                        .await
                }
                Route::HttpProxy(proxy) => {
                    // Browsers tunnel `ws://` with CONNECT and send the same
                    // origin-form Upgrade as a direct connection inside it;
                    // see the proxy route captures under `fixtures/proxy/`.
                    let authority = request.endpoint.tunnel_authority();
                    if proxy.uses_tls() {
                        let proxy_connector = &proxy.https_connector(
                            client.inner.websocket_https_proxy.as_ref().ok_or_else(|| {
                                WebSocketError::request(RequestError::unsupported_route(
                                    HttpProtocol::Http1,
                                ))
                            })?,
                        );
                        if let Some(credentials) = proxy.basic_credentials() {
                            crate::session::box_send(
                                connector.upgrade_get_plaintext_https_connect_with_basic_auth(
                                    proxy_connector,
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.host(),
                                    &authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    request.target,
                                    prepared.headers,
                                ),
                            )
                            .await
                        } else {
                            connector
                                .upgrade_get_plaintext_https_connect(
                                    proxy_connector,
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.host(),
                                    &authority,
                                    proxy.ordered_connect_headers(),
                                    request.target,
                                    prepared.headers,
                                )
                                .await
                        }
                    } else if let Some(credentials) = proxy.basic_credentials() {
                        crate::session::box_send(
                            connector.upgrade_get_plaintext_http_connect_with_basic_auth(
                                proxy.host(),
                                proxy.port(),
                                &authority,
                                proxy.ordered_connect_headers(),
                                credentials,
                                request.target,
                                prepared.headers,
                            ),
                        )
                        .await
                    } else {
                        connector
                            .upgrade_get_plaintext_http_connect(
                                proxy.host(),
                                proxy.port(),
                                &authority,
                                proxy.ordered_connect_headers(),
                                request.target,
                                prepared.headers,
                            )
                            .await
                    }
                }
                Route::Socks5(proxy) => match proxy.dns_mode() {
                    crate::Socks5DnsMode::Local => {
                        connector
                            .upgrade_get_plaintext_socks5_local_with_auth(
                                proxy.host(),
                                proxy.port(),
                                proxy.auth(),
                                request.endpoint.host(),
                                request.endpoint.port(),
                                request.target,
                                prepared.headers,
                            )
                            .await
                    }
                    crate::Socks5DnsMode::Remote => {
                        connector
                            .upgrade_get_plaintext_socks5_remote_with_auth(
                                proxy.host(),
                                proxy.port(),
                                proxy.auth(),
                                request.endpoint.host(),
                                request.endpoint.port(),
                                request.target,
                                prepared.headers,
                            )
                            .await
                    }
                },
            },
            WebSocketTransport::Tls => match route {
                Route::ConnectUdp(_) => {
                    return Err(WebSocketError::request(RequestError::unsupported_route(
                        HttpProtocol::Http1,
                    )));
                }
                Route::Direct => {
                    upgrade_direct(
                        &client,
                        connector,
                        &request.endpoint,
                        request.target,
                        prepared.headers,
                    )
                    .await
                }
                Route::HttpProxy(proxy) => {
                    let authority = request.endpoint.tunnel_authority();
                    if proxy.uses_tls() {
                        let proxy_connector = &proxy.https_connector(
                            client.inner.websocket_https_proxy.as_ref().ok_or_else(|| {
                                WebSocketError::request(RequestError::unsupported_route(
                                    HttpProtocol::Http1,
                                ))
                            })?,
                        );
                        if let Some(credentials) = proxy.basic_credentials() {
                            // Keep the challenge/retry state machine out of the
                            // ordinary WebSocket connection future's stack frame.
                            crate::session::box_send(
                                connector.upgrade_get_https_connect_with_basic_auth(
                                    proxy_connector,
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.host(),
                                    &authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    request.endpoint.host(),
                                    request.target,
                                    prepared.headers,
                                ),
                            )
                            .await
                        } else {
                            connector
                                .upgrade_get_https_connect(
                                    proxy_connector,
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.host(),
                                    &authority,
                                    proxy.ordered_connect_headers(),
                                    request.endpoint.host(),
                                    request.target,
                                    prepared.headers,
                                )
                                .await
                        }
                    } else {
                        if let Some(credentials) = proxy.basic_credentials() {
                            crate::session::box_send(
                                connector.upgrade_get_http_connect_with_basic_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    &authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    request.endpoint.host(),
                                    request.target,
                                    prepared.headers,
                                ),
                            )
                            .await
                        } else {
                            connector
                                .upgrade_get_http_connect(
                                    proxy.host(),
                                    proxy.port(),
                                    &authority,
                                    proxy.ordered_connect_headers(),
                                    request.endpoint.host(),
                                    request.target,
                                    prepared.headers,
                                )
                                .await
                        }
                    }
                }
                Route::Socks5(proxy) => match proxy.dns_mode() {
                    crate::Socks5DnsMode::Local => {
                        connector
                            .upgrade_get_socks5_local_with_auth(
                                proxy.host(),
                                proxy.port(),
                                proxy.auth(),
                                request.endpoint.host(),
                                request.endpoint.port(),
                                request.endpoint.host(),
                                request.target,
                                prepared.headers,
                            )
                            .await
                    }
                    crate::Socks5DnsMode::Remote => {
                        connector
                            .upgrade_get_socks5_remote_with_auth(
                                proxy.host(),
                                proxy.port(),
                                proxy.auth(),
                                request.endpoint.host(),
                                request.endpoint.port(),
                                request.endpoint.host(),
                                request.target,
                                prepared.headers,
                            )
                            .await
                    }
                },
            },
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
        }
    }
}
