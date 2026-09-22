//! HTTP/2 WebSocket opening handshakes over extended CONNECT (RFC 8441).

#[cfg(feature = "cookies")]
use std::sync::Arc;

use http::Response;
use phantom_net::http2::Http2ExtendedConnectOutcome;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

#[cfg(feature = "websocket-deflate")]
use super::NegotiatedPerMessageDeflate;
use super::{
    AdmissionGuard, Http2Target, ResolvedWebSocket, WebSocket, WebSocketError, WebSocketLimits,
    WebSocketRequestBuilder, WebSocketTransport,
    handshake::{prepare_http2, validate_http2_response},
};
#[cfg(feature = "cookies")]
use crate::CookieJar;
use crate::{HttpProtocol, RequestError, ResponseBody, Route, Socks5DnsMode};

impl WebSocketRequestBuilder {
    pub(super) async fn connect_http2(
        self,
        target: Http2Target,
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
        } = self;
        let route = route.as_ref().unwrap_or(&client.inner.route);
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
        let engine_config =
            permessage_deflate.map_or(Ok(engine_config), |policy| policy.apply(engine_config))?;
        #[cfg(feature = "websocket-deflate")]
        let extension_offer = engine_config.deflate_offer();
        #[cfg(not(feature = "websocket-deflate"))]
        let extension_offer: Option<http::HeaderValue> = None;
        let connector = client
            .inner
            .http2
            .as_ref()
            .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?;
        let prepared = prepare_http2(
            headers,
            cookie_value,
            extension_offer.as_ref().map(http::HeaderValue::as_bytes),
        )?;
        let host = request.endpoint.host();
        let port = request.endpoint.port();
        let authority = request.endpoint.authority().as_str();
        // A pooled session already carries its route; a stream failure there
        // is terminal and never retried on another connection.
        if let Http2Target::Session(session, admission) = target {
            let outcome = connector
                .send_extended_connect_on(
                    &session,
                    authority,
                    request.target.clone(),
                    prepared.headers,
                )
                .await
                .map_err(RequestError::http2)
                .map_err(WebSocketError::request)?;
            return finish_http2(
                outcome,
                &request,
                &prepared.offered_protocols,
                extension_offer.as_ref(),
                limits,
                engine_config,
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
                connector
                    .send_extended_connect_direct(
                        host,
                        port,
                        host,
                        authority,
                        request.target.clone(),
                        prepared.headers,
                    )
                    .await
            }
            Route::HttpProxy(proxy) => {
                let connect_authority = request.endpoint.tunnel_authority();
                if proxy.uses_tls() {
                    let proxy_connector = &proxy.https_connector(
                        client.inner.https_proxy.as_ref().ok_or_else(|| {
                            WebSocketError::request(RequestError::unsupported_route(
                                HttpProtocol::Http2,
                            ))
                        })?,
                    );
                    if let Some(credentials) = proxy.basic_credentials() {
                        // Keep the challenge/retry state machine out of the
                        // ordinary WebSocket connection future's stack frame.
                        Box::pin(
                            connector.send_extended_connect_https_connect_with_basic_auth(
                                proxy_connector,
                                proxy.host(),
                                proxy.port(),
                                proxy.host(),
                                &connect_authority,
                                proxy.ordered_connect_headers(),
                                credentials,
                                host,
                                authority,
                                request.target.clone(),
                                prepared.headers,
                            ),
                        )
                        .await
                    } else {
                        Box::pin(connector.send_extended_connect_https_connect(
                            proxy_connector,
                            proxy.host(),
                            proxy.port(),
                            proxy.host(),
                            &connect_authority,
                            proxy.ordered_connect_headers(),
                            host,
                            authority,
                            request.target.clone(),
                            prepared.headers,
                        ))
                        .await
                    }
                } else if let Some(credentials) = proxy.basic_credentials() {
                    Box::pin(
                        connector.send_extended_connect_http_connect_with_basic_auth(
                            proxy.host(),
                            proxy.port(),
                            &connect_authority,
                            proxy.ordered_connect_headers(),
                            credentials,
                            host,
                            authority,
                            request.target.clone(),
                            prepared.headers,
                        ),
                    )
                    .await
                } else {
                    connector
                        .send_extended_connect_http_connect(
                            proxy.host(),
                            proxy.port(),
                            &connect_authority,
                            proxy.ordered_connect_headers(),
                            host,
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
                        .send_extended_connect_socks5_local_with_auth(
                            proxy.host(),
                            proxy.port(),
                            proxy.auth(),
                            host,
                            port,
                            host,
                            authority,
                            request.target.clone(),
                            prepared.headers,
                        )
                        .await
                }
                Socks5DnsMode::Remote => {
                    connector
                        .send_extended_connect_socks5_remote_with_auth(
                            proxy.host(),
                            proxy.port(),
                            proxy.auth(),
                            host,
                            port,
                            host,
                            authority,
                            request.target.clone(),
                            prepared.headers,
                        )
                        .await
                }
            },
        }
        .map_err(RequestError::http2)
        .map_err(WebSocketError::request)?;

        finish_http2(
            outcome,
            &request,
            &prepared.offered_protocols,
            extension_offer.as_ref(),
            limits,
            engine_config,
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
            let selected_protocol = validate_http2_response(
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
                negotiated,
            )
            .await)
        }
    }
}
