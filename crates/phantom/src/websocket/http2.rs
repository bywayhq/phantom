//! HTTP/2 WebSocket opening handshakes over extended CONNECT (RFC 8441).

#[cfg(feature = "cookies")]
use std::sync::Arc;

use http::Response;
use phantom_net::http2::Http2ExtendedConnectOutcome;

#[cfg(feature = "websocket-deflate")]
use super::NegotiatedPerMessageDeflate;
use super::{
    WebSocket, WebSocketError, WebSocketRequestBuilder, WebSocketTransport,
    handshake::{prepare_http2, validate_http2_response},
};
use crate::{HttpProtocol, RequestError, ResponseBody, Route};

impl WebSocketRequestBuilder {
    pub(super) async fn connect_http2(self) -> Result<WebSocket, WebSocketError> {
        let Self {
            client,
            protocol: _,
            request,
            headers,
            limits,
            route,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate,
        } = self;
        let route = route.as_ref().unwrap_or(&client.inner.route);
        if !matches!(route, Route::Direct) || request.transport != WebSocketTransport::Tls {
            return Err(WebSocketError::request(RequestError::unsupported_route(
                HttpProtocol::Http2,
            )));
        }

        #[cfg(feature = "cookies")]
        let cookie_jar = client.state.cookies.as_ref().map(Arc::clone);
        #[cfg(feature = "cookies")]
        let cookie_value = cookie_jar
            .as_deref()
            .and_then(|jar| jar.request_value_for_url(&request.cookie_url));
        #[cfg(not(feature = "cookies"))]
        let cookie_value: Option<String> = None;

        let engine_config = WebSocket::engine_config(limits);
        #[cfg(feature = "websocket-deflate")]
        let engine_config =
            permessage_deflate.map_or(Ok(engine_config), |policy| policy.apply(engine_config))?;
        #[cfg(feature = "websocket-deflate")]
        let extension_offer = engine_config.deflate_offer();
        #[cfg(not(feature = "websocket-deflate"))]
        let extension_offer: Option<http::HeaderValue> = None;
        let prepared = prepare_http2(
            headers,
            cookie_value.as_deref(),
            extension_offer.as_ref().map(http::HeaderValue::as_bytes),
        )?;
        let connector = client
            .inner
            .http2
            .as_ref()
            .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http2))?;
        let outcome = connector
            .send_extended_connect_direct(
                request.endpoint.host(),
                request.endpoint.port(),
                request.endpoint.host(),
                request.endpoint.authority().as_str(),
                request.target,
                prepared.headers,
            )
            .await
            .map_err(RequestError::http2)
            .map_err(WebSocketError::request)?;

        match outcome {
            Http2ExtendedConnectOutcome::Rejected(response) => {
                let (parts, body) = response.into_parts();
                let response = Response::from_parts(parts, ResponseBody::http2(body));
                #[cfg(feature = "cookies")]
                if let Some(jar) = cookie_jar.as_deref() {
                    jar.store_response_headers(&request.cookie_url, response.headers());
                }
                Err(WebSocketError::rejected(response))
            }
            Http2ExtendedConnectOutcome::Accepted { response, stream } => {
                let selected_protocol = validate_http2_response(
                    response.version(),
                    response.headers(),
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
                Ok(WebSocket::new_http2(
                    stream,
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
}
