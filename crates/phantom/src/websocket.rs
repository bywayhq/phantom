//! Ordered WebSocket opening handshakes and bounded message I/O.

use std::fmt;

use phantom_net::{
    http1::{AbsoluteForm, OriginForm},
    request::RequestHeader,
};
use tracing::{Instrument, Span, debug_span, field};

use crate::{
    Client, HttpProtocol, Route,
    authority::{Endpoint, ParseUriError, parse_absolute_uri},
};

#[cfg(feature = "websocket-deflate")]
mod compression;
mod connection;
mod error;
mod handshake;
mod http1;
mod http2;
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

use handshake::{default_headers, default_http2_headers};
use trace::OperationOutcome;

/// Builder for one ordered WebSocket opening handshake.
#[must_use = "WebSocket builders do nothing until connect is awaited"]
pub struct WebSocketRequestBuilder {
    client: Client,
    protocol: HttpProtocol,
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
            .field("protocol", &self.protocol)
            .field("limits", &self.limits)
            .field("route_override", &self.route.is_some());
        #[cfg(feature = "websocket-deflate")]
        debug.field("permessage_deflate", &self.permessage_deflate.is_some());
        debug.finish_non_exhaustive()
    }
}

impl WebSocketRequestBuilder {
    pub(crate) fn new_client(client: Client, uri: &str) -> Result<Self, WebSocketError> {
        Self::new(client, HttpProtocol::Http1, uri)
    }

    pub(crate) fn new_client_with_protocol(
        client: Client,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<Self, WebSocketError> {
        Self::new(client, protocol, uri)
    }

    fn new(client: Client, protocol: HttpProtocol, uri: &str) -> Result<Self, WebSocketError> {
        let available = match protocol {
            HttpProtocol::Http1 => client.inner.http1.is_some(),
            HttpProtocol::Http2 => client.inner.http2.is_some(),
            HttpProtocol::Http3 => false,
        };
        if !available {
            return Err(WebSocketError::protocol_unavailable(protocol));
        }
        Ok(Self {
            client,
            protocol,
            request: ResolvedWebSocket::new(uri)?,
            headers: match protocol {
                HttpProtocol::Http1 => default_headers(),
                HttpProtocol::Http2 => default_http2_headers(),
                HttpProtocol::Http3 => return Err(WebSocketError::protocol_unavailable(protocol)),
            },
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
    /// For HTTP/1.1 the sequence must contain exactly one authority
    /// placeholder, one random-key placeholder, one `Upgrade: websocket`
    /// field, one `Connection` field containing `Upgrade`, and
    /// `Sec-WebSocket-Version: 13`. For HTTP/2 the pseudo-fields come from the
    /// request and profile, so authority and key placeholders, `Host`,
    /// `Upgrade`, `Connection`, `Sec-WebSocket-Key`, and uppercase names are
    /// rejected. Both reject literal `Proxy-Authorization` and extension
    /// fields. Validation completes before DNS, proxy, or origin I/O.
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

    /// Performs the ordered opening handshake over the selected exact protocol.
    ///
    /// HTTP/1.1 sends an Upgrade and requires `101`; HTTP/2 sends RFC 8441
    /// extended CONNECT on a dedicated connection, requires a profile with an
    /// extended-CONNECT pseudo-header order and a peer that enables it, and
    /// accepts a 2xx response.
    ///
    /// The client's [`RequestTimeouts`](crate::RequestTimeouts),
    /// [`RetryPolicy`](crate::RetryPolicy), and
    /// [`RedirectPolicy`](crate::RedirectPolicy) do not apply; bound the
    /// future with a timer if needed. Dropping this future cancels the
    /// in-flight operation. There are no implicit redirects, reconnects, or
    /// protocol fallbacks. Configured Basic proxy authentication permits one
    /// challenge-driven retry on a fresh connection.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] for invalid pre-I/O configuration, route or
    /// TLS failure, HTTP rejection, invalid `101` fields, or framing setup.
    pub async fn connect(self) -> Result<WebSocket, WebSocketError> {
        let route = self.route.as_ref().unwrap_or(&self.client.inner.route);
        let span = debug_span!(
            "websocket.connect",
            protocol = self.protocol.trace_name(),
            route = self.request.route_trace_name(route),
            proxy_authentication_retry = field::Empty,
            proxy_attempts = field::Empty,
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = self.connect_inner(&span).instrument(span.clone()).await;
        match &result {
            Ok(_) => outcome.finish("ok", None),
            Err(error) => outcome.finish("error", Some(error.kind())),
        }
        result
    }

    async fn connect_inner(self, request_span: &Span) -> Result<WebSocket, WebSocketError> {
        match self.protocol {
            HttpProtocol::Http1 => self.connect_http1(request_span).await,
            HttpProtocol::Http2 => self.connect_http2().await,
            HttpProtocol::Http3 => Err(WebSocketError::protocol_unavailable(HttpProtocol::Http3)),
        }
    }
}

struct ResolvedWebSocket {
    endpoint: Endpoint,
    target: OriginForm,
    absolute_target: AbsoluteForm,
    transport: WebSocketTransport,
    #[cfg(feature = "cookies")]
    cookie_url: url::Url,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebSocketTransport {
    Plaintext,
    Tls,
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
        let (transport, default_port, cookie_scheme) = match uri.scheme_str() {
            Some("ws") => (WebSocketTransport::Plaintext, 80, "http"),
            Some("wss") => (WebSocketTransport::Tls, 443, "https"),
            _ => return Err(WebSocketError::unsupported_scheme()),
        };
        let authority = uri.authority().cloned().ok_or_else(|| {
            WebSocketError::invalid_authority("WebSocket URI must include an authority")
        })?;
        let endpoint = Endpoint::new(authority, default_port)
            .map_err(|error| WebSocketError::invalid_authority(error.message()))?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(|_| WebSocketError::invalid_request("invalid WebSocket request target"))?;
        let absolute_target = format!(
            "{cookie_scheme}://{}{}",
            endpoint.authority(),
            uri.path_and_query().map_or("/", |value| value.as_str())
        );
        let absolute_target = AbsoluteForm::parse(&absolute_target).map_err(|_| {
            WebSocketError::invalid_request("invalid WebSocket proxy request target")
        })?;
        #[cfg(feature = "cookies")]
        let cookie_url = {
            let mut url = url::Url::parse(&uri.to_string()).map_err(|_| {
                WebSocketError::invalid_request(
                    "WebSocket URI cannot be represented for cookie policy",
                )
            })?;
            url.set_scheme(cookie_scheme).map_err(|()| {
                WebSocketError::invalid_request(
                    "WebSocket URI cannot be represented for cookie policy",
                )
            })?;
            url
        };

        Ok(Self {
            endpoint,
            target,
            absolute_target,
            transport,
            #[cfg(feature = "cookies")]
            cookie_url,
        })
    }

    fn route_trace_name(&self, route: &Route) -> &'static str {
        route.request_trace_name(Some(match self.transport {
            WebSocketTransport::Plaintext => "http",
            WebSocketTransport::Tls => "https",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{OriginForm, ResolvedWebSocket, WebSocketTransport};

    #[test]
    fn resolves_plaintext_websocket_with_default_port() -> Result<(), Box<dyn std::error::Error>> {
        let request = ResolvedWebSocket::new("ws://example.com/events")?;

        assert_eq!(request.transport, WebSocketTransport::Plaintext);
        assert_eq!(request.endpoint.port(), 80);
        assert_eq!(request.endpoint.authority().as_str(), "example.com");
        #[cfg(feature = "cookies")]
        assert_eq!(request.cookie_url.scheme(), "http");
        Ok(())
    }

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
