use std::fmt;

use bytes::Bytes;
use http::{Method, Response, Uri};
use phantom_net::{
    http1::{AbsoluteForm, OriginForm},
    request::RequestHeader,
};
use tracing::{Instrument, Span, debug, debug_span, field};

use crate::{
    Client, HttpProtocol, RequestError, RequestTimeouts, ResponseBody, ResponseInfo, Route,
    authority::{Endpoint, ParseUriError, parse_absolute_uri},
    redirect::{RedirectAction, RedirectState},
};

mod attempt;

use attempt::{AttemptRequest, send_once};

/// Builder for one exact-protocol request with an optional owned body.
#[must_use = "request builders do nothing until send is awaited"]
pub struct RequestBuilder {
    client: Client,
    request: ResolvedRequest,
    selection: ProtocolSelection,
    method: Method,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    route: Option<Route>,
    timeouts: Option<RequestTimeouts>,
    response_body_timeouts: bool,
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
            .field("timeout_override", &self.timeouts.is_some())
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
        Self::new(client, ProtocolSelection::Exact(protocol), method, uri)
    }

    pub(crate) fn new_client_negotiated(
        client: Client,
        method: Method,
        uri: &str,
    ) -> Result<Self, RequestError> {
        Self::new(client, ProtocolSelection::Http1Or2, method, uri)
    }

    fn new(
        client: Client,
        selection: ProtocolSelection,
        method: Method,
        uri: &str,
    ) -> Result<Self, RequestError> {
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
            client,
            request: ResolvedRequest::new(&uri)?,
            selection,
            method,
            headers: Vec::new(),
            body: None,
            route: None,
            timeouts: None,
            response_body_timeouts: true,
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

    /// Replaces the client's timeout policy for this operation.
    ///
    /// [`RequestTimeouts::default`] explicitly disables every client default.
    pub fn timeouts(mut self, timeouts: RequestTimeouts) -> Self {
        self.timeouts = Some(timeouts);
        self
    }

    #[cfg(feature = "sse")]
    pub(crate) fn without_response_body_timeouts(mut self) -> Self {
        self.response_body_timeouts = false;
        self
    }

    /// Sends the request using the selected route and owner.
    ///
    /// The client may reuse compatible HTTP/1.1, HTTP/2, and direct HTTP/3
    /// connections. A bodyless HTTP/2 GET rejected by `GOAWAY(NO_ERROR)` is
    /// retried once on the client's replacement connection. Dropping this
    /// future cancels the in-flight operation; returned bodies retain protocol
    /// cancellation.
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
        let route = self.route.as_ref().unwrap_or(&self.client.inner.route);
        let span = debug_span!(
            "client.request",
            method = %self.method,
            body_bytes = self.body.as_ref().map_or(0, Bytes::len),
            protocol = self.selection.trace_name(),
            selected_protocol = field::Empty,
            route = route.request_trace_name(self.request.uri.scheme_str()),
            timeout_phase = field::Empty,
            outcome = field::Empty,
        );
        let outcome = RequestOutcome::new(&span);
        if let ProtocolSelection::Exact(protocol) = self.selection {
            span.record("selected_protocol", protocol.trace_name());
        }
        // Keep the public future small when callers join many requests.
        let result = Box::pin(self.send_inner(&span).instrument(span.clone())).await;
        if let Err(error) = &result {
            if let Some(phase) = error.timeout_phase() {
                span.record("timeout_phase", phase.trace_name());
            }
        }
        outcome.finish(match &result {
            Ok(_) => "ok",
            Err(error) if error.timeout_phase().is_some() => "timeout",
            Err(_) => "error",
        });
        result
    }

    async fn send_inner(self, request_span: &Span) -> Result<Response<ResponseBody>, RequestError> {
        let timeout_budget = crate::timeout::TimeoutBudget::new(
            self.timeouts.unwrap_or(self.client.state.request_timeouts),
        )?;
        if self
            .headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("host"))
        {
            return Err(RequestError::authority_header());
        }

        let Self {
            client,
            request,
            selection,
            method,
            headers: request_headers,
            body,
            route,
            timeouts: _,
            response_body_timeouts,
        } = self;
        let route = route.as_ref().unwrap_or(&client.inner.route);
        ensure_request_supported(selection, route, &request)?;
        let is_forwarded = request.uri.scheme_str() == Some("http");
        if is_forwarded
            && request_headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case("proxy-authorization"))
        {
            return Err(RequestError::forward_proxy_authorization_header());
        }
        let policy = client.state.redirect_policy;
        if is_forwarded && policy.max_hops().is_some() {
            return Err(RequestError::forward_redirect_policy());
        }

        if policy.max_hops().is_none() {
            let outcome = send_once(
                &client,
                &request,
                selection,
                AttemptRequest {
                    method,
                    headers: request_headers,
                    body,
                },
                route,
                request_span,
                timeout_budget,
            )
            .await?;
            let mut response = outcome.response;
            if response_body_timeouts {
                response
                    .body_mut()
                    .apply_timeouts(timeout_budget, outcome.protocol)?;
            }
            response
                .extensions_mut()
                .insert(ResponseInfo::new(request.uri, 0, outcome.protocol));
            return Ok(response);
        }

        let mut redirect =
            RedirectState::new(policy, request.url.clone(), method, request_headers, body);
        let mut resolved = request;

        loop {
            ensure_request_supported(selection, route, &resolved)?;
            let outcome = send_once(
                &client,
                &resolved,
                selection,
                AttemptRequest {
                    method: redirect.method().clone(),
                    headers: redirect.headers().to_vec(),
                    body: redirect.body().cloned(),
                },
                route,
                request_span,
                timeout_budget,
            )
            .await?;
            let mut response = outcome.response;
            match redirect.follow(&response)? {
                RedirectAction::Stop => {
                    if response_body_timeouts {
                        response
                            .body_mut()
                            .apply_timeouts(timeout_budget, outcome.protocol)?;
                    }
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
        ParseUriError::Fragment => RequestError::fragment_target(),
    }
}

fn ensure_request_supported(
    selection: ProtocolSelection,
    route: &Route,
    request: &ResolvedRequest,
) -> Result<(), RequestError> {
    match request.uri.scheme_str() {
        Some("http") => match (selection, route) {
            (ProtocolSelection::Exact(HttpProtocol::Http1), Route::HttpProxy(proxy))
                if proxy.supports_plaintext_forwarding() =>
            {
                Ok(())
            }
            (ProtocolSelection::Exact(protocol), Route::HttpProxy(_)) => {
                Err(RequestError::unsupported_route(protocol))
            }
            (ProtocolSelection::Http1Or2, Route::HttpProxy(_)) => {
                Err(RequestError::unsupported_negotiated_route())
            }
            _ => Err(RequestError::unsupported_scheme()),
        },
        Some("https") => match selection {
            ProtocolSelection::Exact(protocol)
                if protocol == HttpProtocol::Http3 && !matches!(route, Route::Direct) =>
            {
                Err(RequestError::unsupported_route(protocol))
            }
            ProtocolSelection::Http1Or2 if !matches!(route, Route::Direct) => {
                Err(RequestError::unsupported_negotiated_route())
            }
            ProtocolSelection::Exact(
                HttpProtocol::Http1 | HttpProtocol::Http2 | HttpProtocol::Http3,
            )
            | ProtocolSelection::Http1Or2 => Ok(()),
        },
        _ => Err(RequestError::unsupported_scheme()),
    }
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
    absolute_target: AbsoluteForm,
}

impl ResolvedRequest {
    fn new(uri: &Uri) -> Result<Self, RequestError> {
        let default_port = match uri.scheme_str() {
            Some("http") => 80,
            Some("https") => 443,
            _ => return Err(RequestError::unsupported_scheme()),
        };
        let authority = uri.authority().cloned().ok_or_else(|| {
            RequestError::invalid_authority("request URI must include an authority")
        })?;
        let endpoint = Endpoint::new(authority, default_port)
            .map_err(|error| RequestError::invalid_authority(error.message()))?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(RequestError::invalid_target)?;
        let absolute_target =
            AbsoluteForm::from_uri(uri.clone()).map_err(RequestError::invalid_absolute_target)?;
        let url = url::Url::parse(&uri.to_string()).map_err(RequestError::invalid_url)?;

        Ok(Self {
            uri: uri.clone(),
            url,
            endpoint,
            target,
            absolute_target,
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
        let default_port = match uri.scheme_str() {
            Some("http") => 80,
            Some("https") => 443,
            _ => return Err(RequestError::redirect_scheme()),
        };
        let endpoint = Endpoint::new(authority, default_port).map_err(|_| {
            RequestError::invalid_redirect_target("redirect target authority is invalid")
        })?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(|_| {
                RequestError::invalid_redirect_target(
                    "redirect target cannot be represented as origin-form",
                )
            })?;
        let absolute_target = AbsoluteForm::from_uri(uri.clone()).map_err(|_| {
            RequestError::invalid_redirect_target(
                "redirect target cannot be represented as absolute-form",
            )
        })?;

        Ok(Self {
            uri,
            url: wire_url,
            endpoint,
            target,
            absolute_target,
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
    use super::{ProtocolSelection, ResolvedRequest, ensure_request_supported};
    use crate::{HttpProtocol, HttpProxy, RequestErrorKind, Route, Socks5Proxy};

    #[test]
    fn tcp_proxy_routes_reject_http3_without_network_io() -> Result<(), Box<dyn std::error::Error>>
    {
        let routes = [
            Route::http_connect(HttpProxy::new("http://127.0.0.1:9")?),
            Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:9")?),
        ];
        let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;

        for route in routes {
            let error = match ensure_request_supported(
                ProtocolSelection::Exact(HttpProtocol::Http3),
                &route,
                &request,
            ) {
                Ok(()) => panic!("TCP-only proxy route accepted HTTP/3"),
                Err(error) => error,
            };

            assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
            assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        }
        Ok(())
    }

    #[test]
    fn direct_route_accepts_each_supported_protocol() -> Result<(), Box<dyn std::error::Error>> {
        let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;
        for protocol in [
            HttpProtocol::Http1,
            HttpProtocol::Http2,
            HttpProtocol::Http3,
        ] {
            assert!(
                ensure_request_supported(
                    ProtocolSelection::Exact(protocol),
                    &Route::Direct,
                    &request,
                )
                .is_ok()
            );
        }
        Ok(())
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
