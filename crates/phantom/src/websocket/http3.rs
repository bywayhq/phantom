//! HTTP/3 WebSocket opening handshakes over extended CONNECT (RFC 9220).

#[cfg(feature = "cookies")]
use std::sync::Arc;

use phantom_net::http3::{Http3ConnectorErrorKind, Http3ExtendedProtocol};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::Span;

#[cfg(feature = "websocket-deflate")]
use super::NegotiatedPerMessageDeflate;
use super::{
    ResolvedWebSocket, WebSocket, WebSocketError, WebSocketLimits, WebSocketRequestBuilder,
    WebSocketTransport,
    handshake::{prepare_extended_connect, validate_extended_connect_response},
};
#[cfg(feature = "cookies")]
use crate::CookieJar;
use crate::{
    HttpProtocol, RequestError, RequestTimeouts, RetryPolicy, Route,
    retry::ConnectionSetupRetryState,
    session::http3_pool::{Http3ExtendedConnect, Http3SetupControl, Http3TransportTarget},
    timeout::TimeoutBudget,
};

impl WebSocketRequestBuilder {
    /// Opens the WebSocket as an extended CONNECT stream on a connection
    /// from the client's HTTP/3 pool, reusing one to the same origin and
    /// route when it has room.
    ///
    /// Everything that can be checked without the network is checked first:
    /// the scheme, the route, the profile's extended CONNECT pseudo-header
    /// order, and the opening fields. A failure after the stream was sent is
    /// returned without another attempt or protocol.
    pub(super) async fn connect_http3(
        self,
        request_span: &Span,
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
        // RFC 9220 tunnels over QUIC, which always carries TLS, so `ws://`
        // has no HTTP/3 form; an HTTP proxy route cannot carry QUIC.
        if request.transport != WebSocketTransport::Tls || matches!(route, Route::HttpProxy(_)) {
            return Err(WebSocketError::request(RequestError::unsupported_route(
                HttpProtocol::Http3,
            )));
        }
        let connector = client
            .inner
            .connectors_for(&request.endpoint)
            .http3
            .ok_or_else(|| WebSocketError::protocol_unavailable(HttpProtocol::Http3))?;
        let authority = request.endpoint.authority().as_str();
        // A profile without an extended CONNECT pseudo-header order fails
        // here, before the cookie jar is read or any I/O starts.
        connector
            .validate_extended_connect(
                Http3ExtendedProtocol::WebSocket,
                authority,
                &request.target,
                &[],
            )
            .map_err(|error| match error.kind() {
                Http3ConnectorErrorKind::ProtocolConfiguration => {
                    WebSocketError::protocol_unavailable(HttpProtocol::Http3)
                }
                _ => WebSocketError::request(RequestError::http3(error)),
            })?;

        #[cfg(feature = "cookies")]
        let cookie_jar = client.state.cookies.as_ref().map(Arc::clone);
        // Read lazily, as on HTTP/2: only a valid opening that emits the
        // jar's cookies reads it, because a read counts as a use for eviction.
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
        let prepared = prepare_extended_connect(
            headers,
            cookie_value,
            extension_offer.as_ref().map(http::HeaderValue::as_bytes),
        )?;
        connector
            .validate_extended_connect(
                Http3ExtendedProtocol::WebSocket,
                authority,
                &request.target,
                &prepared.headers,
            )
            .map_err(|error| WebSocketError::request(RequestError::http3(error)))?;

        // The handshake timeout bounds the whole attempt, and a
        // `WebSocketRetryPolicy` retries a failed setup with a new attempt,
        // so the pool runs without timeouts or retries of its own.
        let timeout_budget =
            TimeoutBudget::new(RequestTimeouts::new()).map_err(WebSocketError::request)?;
        let mut retries = ConnectionSetupRetryState::new(RetryPolicy::none(), request_span.clone());
        let endpoint = &request.endpoint;
        let leased = client
            .state
            .http3
            .admit(endpoint, route, timeout_budget)
            .await
            .map_err(WebSocketError::request)?
            .connect(
                connector,
                client.inner.connect_udp_proxy.as_deref(),
                endpoint,
                route,
                Http3TransportTarget::for_origin(endpoint),
                timeout_budget,
                &mut retries,
                // A new connection resumes as an ordinary exact H3 request's
                // would, so a pooled connection's ClientHello does not depend
                // on which caller opened it. The CONNECT is not replay-safe
                // and still waits for the handshake.
                Http3SetupControl {
                    early_data: connector.sends_early_data(),
                    ..Http3SetupControl::default()
                },
            )
            .await
            .map_err(WebSocketError::request)?;
        let outcome = leased
            .send_extended_connect(
                connector,
                Http3ExtendedProtocol::WebSocket,
                authority,
                request.target.clone(),
                prepared.headers,
                timeout_budget,
            )
            .await
            .map_err(WebSocketError::request)?;

        finish_http3(
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
        )
        .await
    }
}

/// Validates the CONNECT response and installs the frame engine.
#[allow(clippy::too_many_arguments)]
async fn finish_http3(
    outcome: Http3ExtendedConnect,
    request: &ResolvedWebSocket,
    offered_protocols: &[Box<str>],
    extension_offer: Option<&http::HeaderValue>,
    limits: WebSocketLimits,
    engine_config: WebSocketConfig,
    #[cfg(feature = "websocket-deflate")] compress_empty_messages: bool,
    #[cfg(feature = "cookies")] cookie_jar: Option<&CookieJar>,
) -> Result<WebSocket, WebSocketError> {
    #[cfg(not(feature = "cookies"))]
    let _ = request;
    match outcome {
        Http3ExtendedConnect::Rejected(response) => {
            #[cfg(feature = "cookies")]
            if let Some(jar) = cookie_jar {
                jar.store_response_headers(&request.cookie_url, response.headers());
            }
            Err(WebSocketError::rejected(*response))
        }
        Http3ExtendedConnect::Accepted { response, stream } => {
            let selected_protocol = validate_extended_connect_response(
                http::Version::HTTP_3,
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
            Ok(WebSocket::new_http3(
                stream,
                *response,
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
