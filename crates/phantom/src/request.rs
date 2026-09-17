use std::fmt;

use bytes::Bytes;
use http::{Method, Response, Uri};
use phantom_net::{http1::OriginForm, request::RequestHeader};
use tracing::{Instrument, Span, debug, debug_span, field};

use crate::{
    Client, HttpProtocol, RequestError, ResponseBody, ResponseInfo, Route, Session,
    authority::{Endpoint, ParseUriError, parse_absolute_uri},
    redirect::{RedirectAction, RedirectPolicy, RedirectState},
};

mod attempt;

use attempt::send_once;

/// Builder for one exact-protocol request with an optional owned body.
#[must_use = "request builders do nothing until send is awaited"]
pub struct RequestBuilder {
    context: RequestContext,
    request: ResolvedRequest,
    selection: ProtocolSelection,
    method: Method,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    route: Option<Route>,
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("protocol_selection", &self.selection)
            .field("method", &self.method)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.as_ref().map_or(0, Bytes::len))
            .field("route_override", &self.route.is_some())
            .field("session", &self.context.session().is_some())
            .finish_non_exhaustive()
    }
}

impl RequestBuilder {
    pub(crate) fn new_client(
        client: Client,
        protocol: HttpProtocol,
        method: Method,
        uri: &str,
    ) -> Result<Self, RequestError> {
        Self::new(
            RequestContext::Client(client),
            ProtocolSelection::Exact(protocol),
            method,
            uri,
        )
    }

    pub(crate) fn new_client_negotiated(
        client: Client,
        method: Method,
        uri: &str,
    ) -> Result<Self, RequestError> {
        Self::new(
            RequestContext::Client(client),
            ProtocolSelection::Http1Or2,
            method,
            uri,
        )
    }

    pub(crate) fn new_session(
        session: Session,
        protocol: HttpProtocol,
        method: Method,
        uri: &str,
    ) -> Result<Self, RequestError> {
        Self::new(
            RequestContext::Session(session),
            ProtocolSelection::Exact(protocol),
            method,
            uri,
        )
    }

    fn new(
        context: RequestContext,
        selection: ProtocolSelection,
        method: Method,
        uri: &str,
    ) -> Result<Self, RequestError> {
        let client = context.client();
        match selection {
            ProtocolSelection::Exact(HttpProtocol::Http1) if client.inner.http1.is_none() => {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http1));
            }
            ProtocolSelection::Exact(HttpProtocol::Http2) if client.inner.http2.is_none() => {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http2));
            }
            ProtocolSelection::Exact(HttpProtocol::Http3) if client.inner.http3.is_none() => {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http3));
            }
            ProtocolSelection::Http1Or2 if client.inner.http1_or_2.is_none() => {
                return Err(RequestError::unsupported_negotiation());
            }
            ProtocolSelection::Exact(
                HttpProtocol::Http1 | HttpProtocol::Http2 | HttpProtocol::Http3,
            )
            | ProtocolSelection::Http1Or2 => {}
        }
        let uri = parse_absolute_uri(uri).map_err(request_uri_error)?;
        Ok(Self {
            context,
            request: ResolvedRequest::new(&uri)?,
            selection,
            method,
            headers: Vec::new(),
            body: None,
            route: None,
        })
    }

    /// Appends one ordered request field.
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(header);
        self
    }

    /// Replaces the complete ordered request-field list.
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.headers = headers;
        self
    }

    /// Sets the complete owned request body.
    ///
    /// Non-empty bodies receive a trailing `Content-Length` field when the
    /// caller did not supply one. Caller-supplied lengths must be canonical
    /// and exact.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Overrides the client's route for this request.
    pub fn route(mut self, route: Route) -> Self {
        self.route = Some(route);
        self
    }

    /// Sends the request using the selected route and owner.
    ///
    /// A session may reuse compatible HTTP/1.1, HTTP/2, and direct HTTP/3
    /// connections. A bodyless HTTP/2 GET rejected by `GOAWAY(NO_ERROR)` is
    /// retried once on the session's replacement connection. A bare client
    /// remains one-shot. Dropping this future cancels the in-flight operation;
    /// returned bodies retain protocol cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] for invalid ordered fields, a missing or
    /// I/O-disabled Tokio runtime, connection or TLS failure, and protocol
    /// failure. Inspect
    /// [`RequestError::kind`](crate::RequestError::kind) for the stable
    /// category.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use phantom::{Client, HttpProtocol, RequestError};
    /// # async fn example(client: &Client) -> Result<(), RequestError> {
    /// let response = client
    ///     .get(HttpProtocol::Http2, "https://example.com/")?
    ///     .send()
    ///     .await?;
    /// assert!(response.status().is_success());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send(self) -> Result<Response<ResponseBody>, RequestError> {
        let route = self
            .route
            .as_ref()
            .unwrap_or(&self.context.client().inner.route);
        let span = debug_span!(
            "client.request",
            method = %self.method,
            body_bytes = self.body.as_ref().map_or(0, Bytes::len),
            protocol = self.selection.trace_name(),
            selected_protocol = field::Empty,
            route = route.trace_name(),
            outcome = field::Empty,
        );
        let outcome = RequestOutcome::new(&span);
        if let ProtocolSelection::Exact(protocol) = self.selection {
            span.record("selected_protocol", protocol.trace_name());
        }
        let result = self.send_inner(&span).instrument(span.clone()).await;
        outcome.finish(if result.is_ok() { "ok" } else { "error" });
        result
    }

    async fn send_inner(self, request_span: &Span) -> Result<Response<ResponseBody>, RequestError> {
        if self
            .headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("host"))
        {
            return Err(RequestError::authority_header());
        }

        let Self {
            context,
            request,
            selection,
            method,
            headers: request_headers,
            body,
            route,
        } = self;
        let client = context.client();
        let session = context.session();
        let route = route.as_ref().unwrap_or(&client.inner.route);
        ensure_route_supported(selection, route)?;
        let policy = session.map_or(RedirectPolicy::none(), |session| {
            session.state.redirect_policy
        });

        if policy.max_hops().is_none() {
            let outcome = send_once(
                &context,
                &request,
                selection,
                method,
                request_headers,
                body,
                route,
                request_span,
            )
            .await?;
            let mut response = outcome.response;
            response
                .extensions_mut()
                .insert(ResponseInfo::new(request.uri, 0, outcome.protocol));
            return Ok(response);
        }

        let mut redirect =
            RedirectState::new(policy, request.url.clone(), method, request_headers, body);
        let mut resolved = request;

        loop {
            let outcome = send_once(
                &context,
                &resolved,
                selection,
                redirect.method().clone(),
                redirect.headers().to_vec(),
                redirect.body().cloned(),
                route,
                request_span,
            )
            .await?;
            let mut response = outcome.response;
            match redirect.follow(&response)? {
                RedirectAction::Stop => {
                    response.extensions_mut().insert(ResponseInfo::new(
                        resolved.uri.clone(),
                        redirect.followed(),
                        outcome.protocol,
                    ));
                    return Ok(response);
                }
                RedirectAction::Follow { same_origin } => {
                    if !same_origin {
                        if let Some(settings) = client.inner.client_hints.as_ref() {
                            redirect.strip_client_hints(settings);
                        }
                    }
                    debug!(
                        hop = redirect.followed(),
                        status = response.status().as_u16(),
                        same_origin,
                        "following redirect"
                    );
                    drop(response);
                    resolved = ResolvedRequest::from_redirect_url(redirect.current_url())?;
                }
            }
        }
    }
}

fn request_uri_error(error: ParseUriError) -> RequestError {
    match error {
        ParseUriError::Syntax(error) => RequestError::invalid_uri(error),
        ParseUriError::Authority(error) => RequestError::invalid_authority(error.message()),
    }
}

enum RequestContext {
    Client(Client),
    Session(Session),
}

impl RequestContext {
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

fn ensure_route_supported(selection: ProtocolSelection, route: &Route) -> Result<(), RequestError> {
    match selection {
        ProtocolSelection::Exact(HttpProtocol::Http3) if !matches!(route, Route::Direct) => {
            return Err(RequestError::unsupported_route(HttpProtocol::Http3));
        }
        ProtocolSelection::Http1Or2 if !matches!(route, Route::Direct) => {
            return Err(RequestError::unsupported_negotiated_route());
        }
        ProtocolSelection::Exact(
            HttpProtocol::Http1 | HttpProtocol::Http2 | HttpProtocol::Http3,
        )
        | ProtocolSelection::Http1Or2 => {}
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ProtocolSelection {
    Exact(HttpProtocol),
    Http1Or2,
}

impl ProtocolSelection {
    const fn trace_name(self) -> &'static str {
        match self {
            Self::Exact(protocol) => protocol.trace_name(),
            Self::Http1Or2 => "h2_or_http/1.1",
        }
    }
}

#[derive(Debug)]
struct ResolvedRequest {
    uri: Uri,
    url: url::Url,
    endpoint: Endpoint,
    target: OriginForm,
}

impl ResolvedRequest {
    fn new(uri: &Uri) -> Result<Self, RequestError> {
        if uri.scheme_str() != Some("https") {
            return Err(RequestError::unsupported_scheme());
        }
        let authority = uri.authority().cloned().ok_or_else(|| {
            RequestError::invalid_authority("request URI must include an authority")
        })?;
        let endpoint = Endpoint::new(authority, 443)
            .map_err(|error| RequestError::invalid_authority(error.message()))?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(RequestError::invalid_target)?;
        let url = url::Url::parse(&uri.to_string()).map_err(RequestError::invalid_url)?;

        Ok(Self {
            uri: uri.clone(),
            url,
            endpoint,
            target,
        })
    }

    fn from_redirect_url(url: &url::Url) -> Result<Self, RequestError> {
        let mut wire_url = url.clone();
        wire_url.set_fragment(None);
        let uri = wire_url
            .as_str()
            .parse::<Uri>()
            .map_err(RequestError::invalid_redirect_uri)?;
        let authority = uri.authority().cloned().ok_or_else(|| {
            RequestError::invalid_redirect_target("redirect target must include an authority")
        })?;
        let endpoint = Endpoint::new(authority, 443).map_err(|_| {
            RequestError::invalid_redirect_target("redirect target authority is invalid")
        })?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(|_| {
                RequestError::invalid_redirect_target(
                    "redirect target cannot be represented as origin-form",
                )
            })?;

        Ok(Self {
            uri,
            url: wire_url,
            endpoint,
            target,
        })
    }
}

struct RequestOutcome {
    span: tracing::Span,
    recorded: bool,
}

impl RequestOutcome {
    fn new(span: &tracing::Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }
}

impl Drop for RequestOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtocolSelection, ResolvedRequest, ensure_route_supported};
    use crate::{HttpProtocol, HttpProxy, RequestErrorKind, Route, Socks5Proxy};

    #[test]
    fn tcp_proxy_routes_reject_http3_without_network_io() -> Result<(), Box<dyn std::error::Error>>
    {
        let routes = [
            Route::http_connect(HttpProxy::new("http://127.0.0.1:9")?),
            Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:9")?),
        ];

        for route in routes {
            let error =
                match ensure_route_supported(ProtocolSelection::Exact(HttpProtocol::Http3), &route)
                {
                    Ok(()) => panic!("TCP-only proxy route accepted HTTP/3"),
                    Err(error) => error,
                };

            assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
            assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        }
        Ok(())
    }

    #[test]
    fn direct_route_accepts_each_supported_protocol() {
        for protocol in [
            HttpProtocol::Http1,
            HttpProtocol::Http2,
            HttpProtocol::Http3,
        ] {
            assert!(
                ensure_route_supported(ProtocolSelection::Exact(protocol), &Route::Direct).is_ok()
            );
        }
    }

    #[test]
    fn initial_uri_is_not_reserialized_through_whatwg_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let uri = "https://example.test/a/%2e%2e/final?value=%2f".parse()?;
        let request = ResolvedRequest::new(&uri)?;

        assert_eq!(request.uri, uri);
        Ok(())
    }

    #[test]
    fn initial_uri_uses_one_canonical_host_for_wire_and_url_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let uri = super::parse_absolute_uri("https://BÜCHER.Example:443/a/%2e%2e/final?value=%2f")?;
        let request = ResolvedRequest::new(&uri)?;

        assert_eq!(request.endpoint.host(), "xn--bcher-kva.example");
        assert_eq!(
            request.endpoint.authority().as_str(),
            "xn--bcher-kva.example:443"
        );
        assert_eq!(
            request.uri,
            "https://xn--bcher-kva.example:443/a/%2e%2e/final?value=%2f".parse::<http::Uri>()?
        );
        assert_eq!(
            request.url.origin().ascii_serialization(),
            "https://xn--bcher-kva.example"
        );
        Ok(())
    }

    #[test]
    fn redirect_fragments_are_not_sent() -> Result<(), Box<dyn std::error::Error>> {
        let url = url::Url::parse("https://example.test/final?value=yes#section")?;
        let request = ResolvedRequest::from_redirect_url(&url)?;

        assert_eq!(
            request.uri,
            "https://example.test/final?value=yes".parse::<http::Uri>()?
        );
        Ok(())
    }

    #[test]
    fn redirect_url_retains_the_same_canonical_endpoint() -> Result<(), Box<dyn std::error::Error>>
    {
        let url = url::Url::parse("https://BÜCHER.Example:8443/next")?;
        let request = ResolvedRequest::from_redirect_url(&url)?;

        assert_eq!(request.endpoint.host(), "xn--bcher-kva.example");
        assert_eq!(
            request.endpoint.authority().as_str(),
            "xn--bcher-kva.example:8443"
        );
        assert_eq!(request.url, url);
        Ok(())
    }
}
