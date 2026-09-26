//! Ordered WebSocket opening handshakes and bounded message I/O.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use phantom_net::{http1::OriginForm, request::RequestHeader};
use tracing::{Instrument, Span, debug_span, field};

use crate::{
    Client, HttpProtocol, RequestError, Route, TimeoutPhase,
    authority::{Endpoint, ParseUriError, parse_absolute_uri},
    request::secure_context::is_potentially_trustworthy_host,
};

#[cfg(feature = "websocket-deflate")]
mod compression;
mod connection;
mod error;
mod handshake;
mod http1;
mod http2;
mod message;
mod retry;
mod trace;

#[cfg(feature = "websocket-deflate")]
pub use compression::{
    NegotiatedPerMessageDeflate, PerMessageDeflate, PerMessageDeflateOfferParameter,
};
pub use connection::WebSocket;
pub use error::{WebSocketError, WebSocketErrorKind};
pub use handshake::WebSocketHeader;
pub use message::{WebSocketCloseFrame, WebSocketLimits, WebSocketMessage};
pub use retry::WebSocketRetryPolicy;

use handshake::{default_headers, default_http2_headers, fill_or_append, profile_headers};
use phantom_net::http2::Http2Connection;
use phantom_profile::{WebSocketNewConnection, WebSocketRefusedStreamRetry};
use trace::OperationOutcome;

/// Builder for one ordered WebSocket opening handshake.
///
/// Created by [`Client::websocket`], [`Client::websocket_with_protocol`], or
/// [`Client::websocket_with_profile_policy`]. Unless changed, the builder
/// uses the profile's WebSocket field template (or Phantom's default opening
/// fields when the profile has none), [`WebSocketLimits::default`], the
/// client's route, no compression, the profile's handshake timeout (none
/// when the profile has no WebSocket recipe), and no retry.
///
/// The client's [`RequestTimeouts`](crate::RequestTimeouts),
/// [`RetryPolicy`](crate::RetryPolicy), and
/// [`RedirectPolicy`](crate::RedirectPolicy) do not apply to a WebSocket
/// connect; [`Self::handshake_timeout`] and [`Self::retry_policy`] take their
/// place. The client's profile, route, trust roots, and cookie jar do apply.
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
    handshake_timeout: Option<Duration>,
    retry_policy: WebSocketRetryPolicy,
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
    /// per-origin admission the WebSocket holds for its whole lifetime and
    /// the profile's rule for a refused stream.
    Session(Http2Connection, AdmissionGuard, WebSocketRefusedStreamRetry),
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
            .field("route_override", &self.route.is_some())
            .field("handshake_timeout", &self.handshake_timeout)
            .field("retry_policy", &self.retry_policy);
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
        let request = ResolvedWebSocket::new(uri)?;
        let handshake_timeout = settings.handshake_timeout;
        let headers = profile_headers(&settings.http1_fields, request.trustworthy)?;
        let http2_headers = profile_headers(&settings.http2_fields, request.trustworthy)?;
        Ok(Self {
            request,
            client,
            selection: WebSocketSelection::ProfilePolicy,
            headers,
            http2_headers,
            replaced_policy_headers: false,
            limits: WebSocketLimits::default(),
            route: None,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate: None,
            handshake_timeout,
            retry_policy: WebSocketRetryPolicy::none(),
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
        let request = ResolvedWebSocket::new(uri)?;
        let trustworthy = request.trustworthy;
        let handshake_timeout = client
            .inner
            .websocket
            .as_ref()
            .and_then(|settings| settings.handshake_timeout);
        let headers = match (protocol, client.inner.websocket.as_ref()) {
            (HttpProtocol::Http1, Some(settings)) => {
                profile_headers(&settings.http1_fields, trustworthy)?
            }
            (HttpProtocol::Http2, Some(settings)) => {
                profile_headers(&settings.http2_fields, trustworthy)?
            }
            (HttpProtocol::Http1, None) => default_headers(),
            (HttpProtocol::Http2, None) => default_http2_headers(),
            (HttpProtocol::Http3, _) => {
                return Err(WebSocketError::protocol_unavailable(protocol));
            }
        };
        Ok(Self {
            request,
            client,
            selection: WebSocketSelection::Exact(protocol),
            headers,
            http2_headers: Vec::new(),
            replaced_policy_headers: false,
            limits: WebSocketLimits::default(),
            route: None,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate: None,
            handshake_timeout,
            retry_policy: WebSocketRetryPolicy::none(),
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
    ///
    /// The default is [`WebSocketLimits::default`].
    pub fn limits(mut self, limits: WebSocketLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Overrides the client's route for this connection.
    ///
    /// A route that cannot carry the WebSocket's scheme and protocol, such as
    /// a CONNECT-UDP route, makes [`Self::connect`] fail before I/O with
    /// [`WebSocketErrorKind::UnsupportedRoute`].
    pub fn route(mut self, route: Route) -> Self {
        self.route = Some(route);
        self
    }

    /// Enables `permessage-deflate` with the supplied wire and codec policy.
    ///
    /// Compression is off by default, and no extension is offered.
    #[cfg(feature = "websocket-deflate")]
    pub fn permessage_deflate(mut self, policy: PerMessageDeflate) -> Self {
        self.permessage_deflate = Some(policy);
        self
    }

    /// Replaces the handshake timeout for this connect; `None` removes it.
    ///
    /// The default is the profile recipe's
    /// [`handshake_timeout`](phantom_profile::WebSocketSettings::handshake_timeout),
    /// the browser's own timer: 240 seconds in `chromium::v154_websocket` and
    /// 20 seconds in `firefox::v156_websocket`. A profile without a
    /// WebSocket recipe has none. The deadline starts when [`Self::connect`]
    /// is first polled and ends when the accepting response is validated, so
    /// it covers pooled-session admission, name resolution, proxy setup, TLS,
    /// the opening request, and its response on every route and protocol.
    /// When it passes, `connect` fails with [`WebSocketErrorKind::Timeout`]
    /// and [`WebSocketError::timeout_phase`] returns
    /// [`TimeoutPhase::WebSocketHandshake`]. A timeout needs a Tokio runtime
    /// with time enabled; without one, `connect` fails with
    /// [`WebSocketErrorKind::RuntimeUnavailable`]. `Some(Duration::ZERO)`, or
    /// a duration the runtime clock cannot represent, fails `connect` with
    /// [`WebSocketErrorKind::InvalidRequest`] before any I/O.
    pub fn handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Opens a new connection after a connection-setup failure, as `policy`
    /// allows.
    ///
    /// The default is [`WebSocketRetryPolicy::none`], which opens once as a
    /// browser does. See [`WebSocketRetryPolicy`] for which failures are
    /// retried; none that follows a response from the server is.
    pub fn retry_policy(mut self, policy: WebSocketRetryPolicy) -> Self {
        self.retry_policy = policy;
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
    /// [`RedirectPolicy`](crate::RedirectPolicy) do not apply;
    /// [`Self::handshake_timeout`] bounds each attempt, and
    /// [`Self::retry_policy`] allows new attempts after connection-setup
    /// failures. Dropping this future cancels the in-flight operation. There
    /// are no implicit redirects, reconnects, or protocol fallbacks.
    /// Configured Basic proxy authentication permits one challenge-driven
    /// retry on a fresh connection.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] with kind:
    ///
    /// - [`WebSocketErrorKind::InvalidRequest`] for invalid opening fields or
    ///   compression offer, or a replaced field sequence under profile
    ///   policy, before I/O;
    /// - [`WebSocketErrorKind::ProtocolUnavailable`] when the profile lacks
    ///   the selected protocol or, under profile policy, a WebSocket recipe;
    /// - [`WebSocketErrorKind::UnsupportedRoute`] when the route or scheme
    ///   cannot carry the protocol, such as `ws://` over HTTP/2, before I/O;
    /// - [`WebSocketErrorKind::Connect`], [`WebSocketErrorKind::Proxy`],
    ///   [`WebSocketErrorKind::Tls`], [`WebSocketErrorKind::Http1`], or
    ///   [`WebSocketErrorKind::Http2`] when resolution, connection, proxy
    ///   setup, TLS, or the HTTP exchange fails;
    /// - [`WebSocketErrorKind::Capacity`] when a pooled HTTP/2 session's
    ///   per-origin waiting bound is full;
    /// - [`WebSocketErrorKind::Timeout`] when the handshake timeout passes;
    /// - [`WebSocketErrorKind::HandshakeRejected`] when the server answers
    ///   with an ordinary response, including a redirect; read it with
    ///   [`WebSocketError::response`];
    /// - [`WebSocketErrorKind::InvalidHandshake`] when the accepting response
    ///   breaks the handshake rules, for example with a wrong
    ///   `Sec-WebSocket-Accept`, an unsupported extension, or a subprotocol
    ///   that was not offered;
    /// - [`WebSocketErrorKind::RuntimeUnavailable`] or
    ///   [`WebSocketErrorKind::Random`] when the runtime cannot do network I/O
    ///   or the handshake nonce cannot be generated.
    pub async fn connect(self) -> Result<WebSocket, WebSocketError> {
        let route = self.route.as_ref().unwrap_or(&self.client.inner.route);
        let span = debug_span!(
            "websocket.connect",
            protocol = match self.selection {
                WebSocketSelection::Exact(protocol) => protocol.trace_name(),
                WebSocketSelection::ProfilePolicy => "profile_policy",
            },
            connection = field::Empty,
            route = route.trace_name(),
            refused_stream_retry = field::Empty,
            handshake_retries = field::Empty,
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = self.connect_with_retries(&span).await;
        match &result {
            Ok(_) => outcome.finish("ok", None),
            Err(error) => outcome.finish("error", Some(error.kind())),
        }
        result
    }

    /// Opens the WebSocket, and again after each connection-setup failure
    /// the retry policy allows.
    async fn connect_with_retries(self, span: &Span) -> Result<WebSocket, WebSocketError> {
        if let Some(timeout) = self.handshake_timeout {
            if timeout.is_zero() {
                return Err(WebSocketError::invalid_request(
                    "a WebSocket handshake timeout must be positive; None sets no limit",
                ));
            }
            if tokio::time::Instant::now().checked_add(timeout).is_none() {
                return Err(WebSocketError::request(RequestError::invalid_timeout()));
            }
        }
        let policy = self.retry_policy;
        if policy.max_connection_failures().is_none() {
            return Box::pin(self.connect_within_timeout(span))
                .instrument(span.clone())
                .await;
        }
        // Each attempt consumes a builder, so the next one is copied before it
        // starts; the copy draws a fresh opening key when it is prepared.
        let mut next = Some(self);
        retry::open_with_retries(policy, span, |_| {
            let builder = next.take();
            next = builder.as_ref().map(Self::copy_for_retry);
            let span = span.clone();
            async move {
                let builder = builder.ok_or_else(|| {
                    WebSocketError::invalid_request("WebSocket retry has no attempt left")
                })?;
                Box::pin(builder.connect_within_timeout(&span))
                    .instrument(span.clone())
                    .await
            }
        })
        .await
    }

    /// Runs one opening attempt within the handshake timeout, when set.
    async fn connect_within_timeout(self, span: &Span) -> Result<WebSocket, WebSocketError> {
        let Some(limit) = self.handshake_timeout else {
            return self.connect_inner(span).await;
        };
        let protocol = match self.selection {
            WebSocketSelection::Exact(protocol) => Some(protocol),
            WebSocketSelection::ProfilePolicy => None,
        };
        // Pinned here and passed by reference, so the attempt is stored once
        // in this future rather than again inside `within`'s.
        let attempt = std::pin::pin!(self.connect_inner(span));
        match crate::timeout::within(limit, attempt).await {
            Ok(Some(result)) => result,
            Ok(None) => {
                tracing::debug!(
                    timeout_phase = TimeoutPhase::WebSocketHandshake.trace_name(),
                    protocol = protocol.map(HttpProtocol::trace_name),
                    "WebSocket opening handshake timed out"
                );
                Err(WebSocketError::request(RequestError::timeout(
                    TimeoutPhase::WebSocketHandshake,
                    protocol,
                )))
            }
            Err(error) => Err(WebSocketError::request(error)),
        }
    }

    /// Copies everything one attempt needs, for the attempt after it.
    fn copy_for_retry(&self) -> Self {
        Self {
            client: self.client.clone(),
            selection: self.selection,
            request: self.request.clone(),
            headers: self.headers.clone(),
            http2_headers: self.http2_headers.clone(),
            replaced_policy_headers: self.replaced_policy_headers,
            limits: self.limits,
            route: self.route.clone(),
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate: self.permessage_deflate.clone(),
            handshake_timeout: self.handshake_timeout,
            retry_policy: self.retry_policy,
        }
    }

    async fn connect_inner(mut self, request_span: &Span) -> Result<WebSocket, WebSocketError> {
        // A tunnel's CONNECT copies fields such as `User-Agent` from the
        // opening, as browsers do.
        let route = self.route.as_ref().unwrap_or(&self.client.inner.route);
        if let Some(route) = route
            .with_profile_connect(self.client.inner.proxy_connect.as_deref(), |name| {
                opening_field_value(&self.headers, name)
            })
        {
            self.route = Some(route);
        }
        match self.selection {
            WebSocketSelection::Exact(HttpProtocol::Http1) => {
                self.connect_http1(Http1UpgradeConnector::Profile).await
            }
            WebSocketSelection::Exact(HttpProtocol::Http2) => {
                self.connect_http2(Http2Target::NewConnection, request_span)
                    .await
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
        let refused_stream_retry = policy.refused_stream_retry;
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
                            .connect_http2(
                                Http2Target::Session(
                                    session,
                                    Box::new(permit),
                                    refused_stream_retry,
                                ),
                                request_span,
                            )
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
                self.connect_http2(Http2Target::NewConnection, request_span)
                    .await
            }
            WebSocketNewConnection::Http1Upgrade => {
                request_span.record("connection", "new_http1");
                self.connect_http1(Http1UpgradeConnector::PolicyAlpn).await
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

/// Returns the opening field `name`, from the caller or the profile recipe,
/// with its sensitive marking.
fn opening_field_value(headers: &[WebSocketHeader], name: &str) -> Option<RequestHeader> {
    headers.iter().find_map(|header| match header {
        WebSocketHeader::Field(field) | WebSocketHeader::DefaultField(field)
            if field.name().eq_ignore_ascii_case(name) =>
        {
            Some(field.clone())
        }
        _ => None,
    })
}

#[derive(Clone)]
struct ResolvedWebSocket {
    endpoint: Endpoint,
    target: OriginForm,
    transport: WebSocketTransport,
    /// Whether the URL is potentially trustworthy, which chooses the value of
    /// each trust-dependent recipe field. A WebSocket follows no redirect, so
    /// the opening URL is the only one.
    trustworthy: bool,
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
        let (transport, default_port) = match uri.scheme_str() {
            Some("ws") => (WebSocketTransport::Plaintext, 80),
            Some("wss") => (WebSocketTransport::Tls, 443),
            _ => return Err(WebSocketError::unsupported_scheme()),
        };
        let authority = uri.authority().cloned().ok_or_else(|| {
            WebSocketError::invalid_authority("WebSocket URI must include an authority")
        })?;
        let endpoint = Endpoint::new(authority, default_port)
            .map_err(|error| WebSocketError::invalid_authority(error.message()))?;
        let trustworthy = transport == WebSocketTransport::Tls || trustworthy_host(endpoint.host());
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(|_| WebSocketError::invalid_request("invalid WebSocket request target"))?;
        #[cfg(feature = "cookies")]
        let cookie_url = {
            let mut url = url::Url::parse(&uri.to_string()).map_err(|_| {
                WebSocketError::invalid_request(
                    "WebSocket URI cannot be represented for cookie policy",
                )
            })?;
            let cookie_scheme = match transport {
                WebSocketTransport::Plaintext => "http",
                WebSocketTransport::Tls => "https",
            };
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
            transport,
            trustworthy,
            #[cfg(feature = "cookies")]
            cookie_url,
        })
    }
}

/// Applies the Secure Contexts host rules to an endpoint's canonical host,
/// which holds an IPv6 literal without brackets.
fn trustworthy_host(host: &str) -> bool {
    let host = if let Ok(address) = host.parse::<Ipv4Addr>() {
        url::Host::Ipv4(address)
    } else if let Ok(address) = host.parse::<Ipv6Addr>() {
        url::Host::Ipv6(address)
    } else {
        url::Host::Domain(host)
    };
    is_potentially_trustworthy_host(&host)
}

#[cfg(test)]
mod tests {
    use super::{OriginForm, ResolvedWebSocket, WebSocketTransport};

    #[test]
    fn only_a_secure_or_local_websocket_url_is_trustworthy()
    -> Result<(), Box<dyn std::error::Error>> {
        for (uri, trustworthy) in [
            ("wss://origin.example/", true),
            ("ws://127.0.0.1:8080/", true),
            ("ws://127.9.0.1/", true),
            ("ws://[::1]:8080/", true),
            ("ws://localhost/", true),
            ("ws://app.localhost./", true),
            ("ws://origin.example/", false),
            ("ws://10.0.0.1/", false),
            ("ws://[::ffff:127.0.0.1]/", false),
        ] {
            assert_eq!(
                ResolvedWebSocket::new(uri)?.trustworthy,
                trustworthy,
                "{uri}"
            );
        }
        Ok(())
    }

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
