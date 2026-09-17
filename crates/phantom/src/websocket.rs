//! Ordered WebSocket opening handshakes and bounded message I/O.

use std::fmt;

#[cfg(feature = "cookies")]
use std::sync::Arc;

use http::Response;
use phantom_net::{
    http1::{Http1UpgradeOutcome, OriginForm},
    request::RequestHeader,
};
use tracing::{Instrument, debug_span, field};

use crate::{
    Client, RequestError, ResponseBody, Route, Session,
    authority::{Endpoint, ParseUriError, parse_absolute_uri},
};

#[cfg(feature = "websocket-deflate")]
mod compression;
mod connection;
mod error;
mod handshake;
mod message;
mod trace;

#[cfg(feature = "websocket-deflate")]
pub use compression::{
    NegotiatedPerMessageDeflate, PerMessageDeflate, PerMessageDeflateOfferParameter,
};
pub use connection::WebSocket;
pub use error::{WebSocketError, WebSocketErrorKind};
pub use handshake::WebSocketHeader;
pub use message::{WebSocketCloseFrame, WebSocketLimits, WebSocketMessage};

use handshake::{default_headers, prepare, validate_response};
use trace::OperationOutcome;

/// Builder for one ordered secure WebSocket opening handshake.
#[must_use = "WebSocket builders do nothing until connect is awaited"]
pub struct WebSocketRequestBuilder {
    context: WebSocketContext,
    request: ResolvedWebSocket,
    headers: Vec<WebSocketHeader>,
    limits: WebSocketLimits,
    route: Option<Route>,
    #[cfg(feature = "websocket-deflate")]
    permessage_deflate: Option<PerMessageDeflate>,
}

impl fmt::Debug for WebSocketRequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("WebSocketRequestBuilder");
        debug
            .field("header_count", &self.headers.len())
            .field("limits", &self.limits)
            .field("route_override", &self.route.is_some());
        #[cfg(feature = "websocket-deflate")]
        debug.field("permessage_deflate", &self.permessage_deflate.is_some());
        debug
            .field("session", &self.context.session().is_some())
            .finish_non_exhaustive()
    }
}

impl WebSocketRequestBuilder {
    pub(crate) fn new_client(client: Client, uri: &str) -> Result<Self, WebSocketError> {
        Self::new(WebSocketContext::Client(client), uri)
    }

    pub(crate) fn new_session(session: Session, uri: &str) -> Result<Self, WebSocketError> {
        Self::new(WebSocketContext::Session(session), uri)
    }

    fn new(context: WebSocketContext, uri: &str) -> Result<Self, WebSocketError> {
        if context.client().inner.http1.is_none() {
            return Err(WebSocketError::protocol_unavailable());
        }
        Ok(Self {
            context,
            request: ResolvedWebSocket::new(uri)?,
            headers: default_headers(),
            limits: WebSocketLimits::default(),
            route: None,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate: None,
        })
    }

    /// Appends one literal ordered opening-handshake field.
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(WebSocketHeader::field(header));
        self
    }

    /// Replaces the complete ordered opening-handshake field sequence.
    ///
    /// The sequence must contain one authority placeholder, one random-key
    /// placeholder, and the mandatory WebSocket fields. Validation completes
    /// before DNS, proxy, or origin I/O.
    pub fn headers(mut self, headers: Vec<WebSocketHeader>) -> Self {
        self.headers = headers;
        self
    }

    /// Sets validated frame and message bounds for the resulting connection.
    pub fn limits(mut self, limits: WebSocketLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Overrides the client's route for this connection.
    pub fn route(mut self, route: Route) -> Self {
        self.route = Some(route);
        self
    }

    /// Enables `permessage-deflate` with the supplied wire and codec policy.
    #[cfg(feature = "websocket-deflate")]
    pub fn permessage_deflate(mut self, policy: PerMessageDeflate) -> Self {
        self.permessage_deflate = Some(policy);
        self
    }

    /// Performs the ordered H1 Upgrade handshake over the selected TLS route.
    ///
    /// Dropping this future cancels the in-flight operation. There are no
    /// implicit redirects, retries, reconnects, or protocol fallbacks.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] for invalid pre-I/O configuration, route or
    /// TLS failure, HTTP rejection, invalid `101` fields, or framing setup.
    pub async fn connect(self) -> Result<WebSocket, WebSocketError> {
        let route = self
            .route
            .as_ref()
            .unwrap_or(&self.context.client().inner.route);
        let span = debug_span!(
            "websocket.connect",
            protocol = "http/1.1",
            route = route.trace_name(),
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = self.connect_inner().instrument(span.clone()).await;
        match &result {
            Ok(_) => outcome.finish("ok", None),
            Err(error) => outcome.finish("error", Some(error.kind())),
        }
        result
    }

    async fn connect_inner(self) -> Result<WebSocket, WebSocketError> {
        let Self {
            context,
            request,
            headers,
            limits,
            route,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate,
        } = self;
        let client = context.client();
        let route = route.as_ref().unwrap_or(&client.inner.route);

        #[cfg(feature = "cookies")]
        let cookie_jar = context
            .session()
            .and_then(|session| session.state.cookies.as_ref())
            .map(Arc::clone);
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

        let prepared = prepare(
            headers,
            request.endpoint.authority().as_str(),
            cookie_value.as_deref(),
            extension_offer.as_ref().map(http::HeaderValue::as_bytes),
        )?;
        let connector = client
            .inner
            .http1
            .as_ref()
            .ok_or_else(WebSocketError::protocol_unavailable)?;
        let outcome = match route {
            Route::Direct => {
                connector
                    .upgrade_get_direct(
                        request.endpoint.host(),
                        request.endpoint.port(),
                        request.endpoint.host(),
                        request.target,
                        prepared.headers,
                    )
                    .await
            }
            Route::HttpProxy(proxy) => {
                let authority = request.endpoint.tunnel_authority();
                if proxy.uses_tls() {
                    let proxy_connector = client.inner.https_proxy.as_ref().ok_or_else(|| {
                        WebSocketError::request(RequestError::unsupported_route(
                            crate::HttpProtocol::Http1,
                        ))
                    })?;
                    if let Some(credentials) = proxy.basic_credentials() {
                        // Keep the challenge/retry state machine out of the
                        // ordinary WebSocket connection future's stack frame.
                        Box::pin(connector.upgrade_get_https_connect_with_basic_auth(
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
                        ))
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
                        Box::pin(connector.upgrade_get_http_connect_with_basic_auth(
                            proxy.host(),
                            proxy.port(),
                            &authority,
                            proxy.ordered_connect_headers(),
                            credentials,
                            request.endpoint.host(),
                            request.target,
                            prepared.headers,
                        ))
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
        }
        .map_err(RequestError::http1)
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
                Ok(WebSocket::new(
                    stream,
                    handshake,
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

enum WebSocketContext {
    Client(Client),
    Session(Session),
}

impl WebSocketContext {
    fn client(&self) -> &Client {
        match self {
            Self::Client(client) => client,
            Self::Session(session) => &session.client,
        }
    }

    fn session(&self) -> Option<&Session> {
        match self {
            Self::Client(_) => None,
            Self::Session(session) => Some(session),
        }
    }
}

struct ResolvedWebSocket {
    endpoint: Endpoint,
    target: OriginForm,
    #[cfg(feature = "cookies")]
    cookie_url: url::Url,
}

impl ResolvedWebSocket {
    fn new(value: &str) -> Result<Self, WebSocketError> {
        let uri = parse_absolute_uri(value).map_err(|error| match error {
            ParseUriError::Syntax(error) => WebSocketError::invalid_uri(error),
            ParseUriError::Authority(error) => WebSocketError::invalid_authority(error.message()),
            ParseUriError::Fragment => {
                WebSocketError::invalid_request("WebSocket URI must not contain a fragment")
            }
        })?;
        if uri.scheme_str() != Some("wss") {
            return Err(WebSocketError::unsupported_scheme());
        }
        let authority = uri.authority().cloned().ok_or_else(|| {
            WebSocketError::invalid_authority("WebSocket URI must include an authority")
        })?;
        let endpoint = Endpoint::new(authority, 443)
            .map_err(|error| WebSocketError::invalid_authority(error.message()))?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(|_| WebSocketError::invalid_request("invalid WebSocket request target"))?;
        #[cfg(feature = "cookies")]
        let cookie_url = {
            let mut url = url::Url::parse(&uri.to_string()).map_err(|_| {
                WebSocketError::invalid_request(
                    "WebSocket URI cannot be represented for cookie policy",
                )
            })?;
            url.set_scheme("https").map_err(|()| {
                WebSocketError::invalid_request(
                    "WebSocket URI cannot be represented for cookie policy",
                )
            })?;
            url
        };

        Ok(Self {
            endpoint,
            target,
            #[cfg(feature = "cookies")]
            cookie_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{OriginForm, ResolvedWebSocket};

    #[test]
    fn canonicalizes_websocket_host_without_reserializing_the_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = ResolvedWebSocket::new("wss://BÜCHER.Example:443/a/%2e%2e/final?value=%2f")?;

        assert_eq!(request.endpoint.host(), "xn--bcher-kva.example");
        assert_eq!(
            request.endpoint.authority().as_str(),
            "xn--bcher-kva.example:443"
        );
        assert_eq!(
            request.target,
            OriginForm::parse("/a/%2e%2e/final?value=%2f")?
        );
        Ok(())
    }
}
