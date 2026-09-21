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

use handshake::{default_headers, default_http2_headers, fill_or_append, profile_headers};
use phantom_net::http2::Http2Connection;
use phantom_profile::WebSocketNewConnection;
use trace::OperationOutcome;

/// Builder for one ordered WebSocket opening handshake.
#[must_use = "WebSocket builders do nothing until connect is awaited"]
pub struct WebSocketRequestBuilder {
    client: Client,
    selection: WebSocketSelection,
    request: ResolvedWebSocket,
    /// Opening fields for the exact protocol, or HTTP/1.1 under profile policy.
    headers: Vec<WebSocketHeader>,
    /// HTTP/2 opening fields under profile policy; empty otherwise.
    http2_headers: Vec<WebSocketHeader>,
    /// Set when the caller replaced a sequence that profile policy must choose.
    replaced_policy_headers: bool,
    limits: WebSocketLimits,
    route: Option<Route>,
    #[cfg(feature = "websocket-deflate")]
    permessage_deflate: Option<PerMessageDeflate>,
}

/// How the connect step chooses the protocol and connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebSocketSelection {
    /// Exactly this protocol on a dedicated connection.
    Exact(HttpProtocol),
    /// The profile's [`phantom_profile::WebSocketConnectionPolicy`].
    ProfilePolicy,
}

/// The HTTP/1.1 connector used for an Upgrade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Http1UpgradeConnector {
    /// The profile's ordinary TLS offer.
    Profile,
    /// The WebSocket policy's Upgrade-connection ALPN offer.
    PolicyAlpn,
}

/// Where an HTTP/2 extended CONNECT is sent.
enum Http2Target {
    /// A new connection dedicated to this WebSocket.
    NewConnection,
    /// A pooled session whose peer enabled extended CONNECT, with the
    /// per-origin admission the WebSocket holds for its whole lifetime.
    Session(Http2Connection, AdmissionGuard),
}

/// A pool admission permit held until the WebSocket transport is released.
type AdmissionGuard = Box<dyn Send + Sync>;

impl fmt::Debug for WebSocketRequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("WebSocketRequestBuilder");
        debug
            .field("header_count", &self.headers.len())
            .field("selection", &self.selection)
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

    pub(crate) fn new_client_with_profile_policy(
        client: Client,
        uri: &str,
    ) -> Result<Self, WebSocketError> {
        let settings = client
            .inner
            .websocket
            .as_ref()
            .ok_or_else(WebSocketError::profile_policy_unavailable)?;
        let headers = profile_headers(&settings.http1_fields)?;
        let http2_headers = profile_headers(&settings.http2_fields)?;
        Ok(Self {
            request: ResolvedWebSocket::new(uri)?,
            client,
            selection: WebSocketSelection::ProfilePolicy,
            headers,
            http2_headers,
            replaced_policy_headers: false,
            limits: WebSocketLimits::default(),
            route: None,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate: None,
        })
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
        let headers = match (protocol, client.inner.websocket.as_ref()) {
            (HttpProtocol::Http1, Some(settings)) => profile_headers(&settings.http1_fields)?,
            (HttpProtocol::Http2, Some(settings)) => profile_headers(&settings.http2_fields)?,
            (HttpProtocol::Http1, None) => default_headers(),
            (HttpProtocol::Http2, None) => default_http2_headers(),
            (HttpProtocol::Http3, _) => {
                return Err(WebSocketError::protocol_unavailable(protocol));
            }
        };
        Ok(Self {
            request: ResolvedWebSocket::new(uri)?,
            client,
            selection: WebSocketSelection::Exact(protocol),
            headers,
            http2_headers: Vec::new(),
            replaced_policy_headers: false,
            limits: WebSocketLimits::default(),
            route: None,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate: None,
        })
    }

    /// Adds one ordered opening-handshake field.
    ///
    /// The value fills the first unfilled [`WebSocketHeader::CallerField`]
    /// slot with the same case-insensitive name, keeping the slot's position
    /// and spelling. Otherwise the field is appended. Under
    /// [`Client::websocket_with_profile_policy`] the field is added to both
    /// the HTTP/1.1 and HTTP/2 sequences, and an appended HTTP/2 name is
    /// lowercased as HTTP/2 requires.
    pub fn header(mut self, header: RequestHeader) -> Self {
        if self.selection == WebSocketSelection::ProfilePolicy {
            let lowercase = RequestHeader::new(header.name().to_ascii_lowercase(), header.value());
            let lowercase = if header.is_sensitive() {
                lowercase.sensitive()
            } else {
                lowercase
            };
            fill_or_append(&mut self.http2_headers, lowercase);
        }
        fill_or_append(&mut self.headers, header);
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
    ///
    /// Under [`Client::websocket_with_profile_policy`] the protocol is chosen
    /// at connect time, so one replacement sequence cannot fit it; `connect`
    /// then fails before I/O. Fill the profile's slots with [`Self::header`].
    pub fn headers(mut self, headers: Vec<WebSocketHeader>) -> Self {
        self.replaced_policy_headers = self.selection == WebSocketSelection::ProfilePolicy;
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
    /// HTTP/1.1 sends an Upgrade and requires `101`. HTTP/2 sends RFC 8441
    /// extended CONNECT on a dedicated connection, opened directly or through
    /// an HTTP CONNECT or SOCKS5 tunnel; it requires `wss://`, a profile with
    /// an extended-CONNECT pseudo-header order, and a peer that enables it,
    /// and accepts a 2xx response.
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
            protocol = match self.selection {
                WebSocketSelection::Exact(protocol) => protocol.trace_name(),
                WebSocketSelection::ProfilePolicy => "profile_policy",
            },
            connection = field::Empty,
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
        match self.selection {
            WebSocketSelection::Exact(HttpProtocol::Http1) => {
                self.connect_http1(Http1UpgradeConnector::Profile, request_span)
                    .await
            }
            WebSocketSelection::Exact(HttpProtocol::Http2) => {
                self.connect_http2(Http2Target::NewConnection).await
            }
            WebSocketSelection::Exact(protocol) => {
                Err(WebSocketError::protocol_unavailable(protocol))
            }
            WebSocketSelection::ProfilePolicy => self.connect_by_profile_policy(request_span).await,
        }
    }

    /// Chooses the connection from pooled session state and profile policy.
    ///
    /// The choice is final: a failure on the chosen connection is returned
    /// without trying another connection or protocol.
    async fn connect_by_profile_policy(
        mut self,
        request_span: &Span,
    ) -> Result<WebSocket, WebSocketError> {
        if self.replaced_policy_headers {
            return Err(WebSocketError::invalid_request(
                "profile WebSocket policy chooses the protocol at connect time; fill its template slots with header()",
            ));
        }
        let policy = &self
            .client
            .inner
            .websocket
            .as_ref()
            .ok_or_else(WebSocketError::profile_policy_unavailable)?
            .connection;
        let without_session = policy.without_http2_session;
        let with_incapable_session = policy.with_incapable_http2_session;
        self.validate_policy_templates()?;

        let choice = if self.request.transport == WebSocketTransport::Plaintext {
            WebSocketNewConnection::Http1Upgrade
        } else {
            let route = self.route.as_ref().unwrap_or(&self.client.inner.route);
            // The stream takes the same per-origin admission as an ordinary
            // request, waiting or failing with a typed capacity error.
            match self
                .client
                .admit_http2_session(&self.request.endpoint, route)
                .await
                .map_err(WebSocketError::request)?
            {
                Some((session, permit)) => match session.extended_connect_enabled().await {
                    Ok(true) => {
                        request_span.record("connection", "http2_session");
                        self.headers = std::mem::take(&mut self.http2_headers);
                        return self
                            .connect_http2(Http2Target::Session(session, Box::new(permit)))
                            .await;
                    }
                    Ok(false) => with_incapable_session,
                    // The session failed before its peer settings were known,
                    // so no usable session exists.
                    Err(_) => without_session,
                },
                None => without_session,
            }
        };
        match choice {
            WebSocketNewConnection::Http2ExtendedConnect => {
                request_span.record("connection", "new_http2");
                self.headers = std::mem::take(&mut self.http2_headers);
                self.connect_http2(Http2Target::NewConnection).await
            }
            WebSocketNewConnection::Http1Upgrade => {
                request_span.record("connection", "new_http1");
                self.connect_http1(Http1UpgradeConnector::PolicyAlpn, request_span)
                    .await
            }
            _ => Err(WebSocketError::invalid_request(
                "profile WebSocket policy names an unsupported connection",
            )),
        }
    }

    /// Validates both profile-policy sequences before any network I/O.
    fn validate_policy_templates(&self) -> Result<(), WebSocketError> {
        #[cfg(feature = "websocket-deflate")]
        let compression = self.permessage_deflate.is_some();
        #[cfg(not(feature = "websocket-deflate"))]
        let compression = false;
        handshake::validate_policy_templates(&self.headers, &self.http2_headers, compression)
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
