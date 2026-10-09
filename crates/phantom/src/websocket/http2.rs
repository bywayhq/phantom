//! HTTP/2 WebSocket opening handshakes over extended CONNECT (RFC 8441).

#[cfg(feature = "cookies")]
use std::sync::Arc;

use http::Response;
use phantom_net::http2::{
    Http2ExtendedConnectOutcome, Http2TlsConnector, Http2TlsError, OriginForm, RequestHeader,
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
    endpoint: &Endpoint,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
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
            .extended_connect(
                phantom_net::route::Http2Route::Origin(phantom_net::route::OriginRoute::Tls {
                    tcp: phantom_net::route::TcpRoute::Direct(phantom_net::route::Endpoint {
                        host,
                        port,
                    }),
                    server_name: host,
                    setup: phantom_net::route::DirectTlsSetup::Ech(ech.as_mut()),
                }),
                authority,
                target,
                headers,
            )
            .await;
    }
    connector
        .extended_connect(
            phantom_net::route::Http2Route::Origin(phantom_net::route::OriginRoute::Tls {
                tcp: phantom_net::route::TcpRoute::Direct(phantom_net::route::Endpoint {
                    host,
                    port,
                }),
                server_name: host,
                setup: phantom_net::route::DirectTlsSetup::Default,
            }),
            authority,
            target,
            headers,
        )
        .await
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
        let base = connectors
            .http2
            .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?;
        let prepared = prepare_extended_connect(
            headers,
            cookie_value,
            extension_offer.as_ref().map(http::HeaderValue::as_bytes),
        )?;
        // A new connection shares the TLS session tickets of a request pool
        // key, as `pooled_tls_connector` in `http1.rs` describes, looked up
        // only for a valid opening since creating a key can evict another; a
        // pooled session makes no handshake, and CONNECT-UDP is rejected
        // below before any I/O and creates no pool key.
        let pooled = match (&target, route) {
            (Http2Target::Session(..), _) | (_, Route::ConnectUdp(_)) => None,
            (Http2Target::NewConnection, _) => Some(match (selection, connectors.http1_or_2) {
                (WebSocketSelection::ProfilePolicy, Some(negotiated)) => client
                    .state
                    .http1_or_2
                    .tls_origin_connector(negotiated, &request.endpoint, route)
                    .await
                    .http2_connector(),
                _ => {
                    client
                        .state
                        .http2
                        .tls_origin_connector(base, &request.endpoint, route)
                        .await
                }
            }),
        };
        let connector = pooled.as_ref().unwrap_or(base);
        let host = request.endpoint.host();
        let port = request.endpoint.port();
        let authority = request.endpoint.authority().as_str();
        // A pooled session already carries its route; a stream failure there
        // is terminal and never retried on another connection. The one
        // exception is a refused stream, which the profile may reopen on this
        // same session.
        if let Http2Target::Session(session, admission, refused_stream_retry) = target {
            // Kept only for the one reopening the profile allows, so the
            // ordinary path still moves the fields into the first attempt.
            let retry_headers = match refused_stream_retry {
                WebSocketRefusedStreamRetry::SameSessionOnce => Some(prepared.headers.clone()),
                WebSocketRefusedStreamRetry::None => None,
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
                extended_connect_direct(
                    &client,
                    connector,
                    &request.endpoint,
                    request.target.clone(),
                    prepared.headers,
                )
                .await
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
                    if let Some(credentials) = proxy.basic_credentials() {
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
                } else if let Some(credentials) = proxy.basic_credentials() {
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
                    connector
                        .extended_connect(
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
                        )
                        .await
                }
            }
            Route::Socks5(proxy) => match proxy.dns_mode() {
                Socks5DnsMode::Local => {
                    connector
                        .extended_connect(
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
                        )
                        .await
                }
                Socks5DnsMode::Remote => {
                    connector
                        .extended_connect(
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
                        )
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
    }
}
