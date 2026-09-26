use std::{error::Error as StdError, fmt};

use bytes::Bytes;
use http::{Method, Response, Uri};
use http_body::Body;
use phantom_net::{
    http1::{AbsoluteForm, OriginForm},
    request::{RequestBody, RequestHeader, RequestTrailerName},
};
use tracing::{Instrument, Span, debug, debug_span, field};

use crate::{
    Client, ContentCoding, ContentDecoding, HttpProtocol, RequestError, RequestTimeouts,
    ResponseBody, ResponseInfo, RetryPolicy, Route,
    authority::{Endpoint, ParseUriError, parse_absolute_uri},
    content_coding::{self, AdvertisedContentCodings, ContentDecodingPlan},
    redirect::{RedirectAction, RedirectState},
    retry::ConnectionSetupRetryState,
};

mod alt_svc_attempt;
mod attempt;
mod replay;
pub(crate) mod secure_context;
pub(crate) mod template;

pub use template::PreparedRequestTemplate;

use attempt::{AttemptLifecycle, AttemptRequest, send_once};
use replay::ReplayState;

/// Builder for one request with an owned, streaming, or absent body.
///
/// [`Client::get`] and [`Client::request`] build exact-protocol requests;
/// [`Client::get_negotiated`] and [`Client::request_negotiated`] build requests
/// whose H1 or H2 selection is made by ALPN. Fields, route, and policies are
/// validated when [`Self::send`] runs, before any I/O.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
///
/// use phantom::{Client, HttpProtocol, Method, RequestError, RequestHeader, RequestTimeouts};
///
/// async fn post(client: &Client) -> Result<(), RequestError> {
///     let response = client
///         .request(HttpProtocol::Http2, Method::POST, "https://example.com/api")?
///         .header(RequestHeader::new("content-type", "application/json"))
///         .body(r#"{"name":"phantom"}"#)
///         .timeouts(RequestTimeouts::new().total(Duration::from_secs(30)))
///         .send()
///         .await?;
///     let body = response.into_body().collect_with_limit(1 << 20).await?;
///     println!("{} bytes", body.len());
///     Ok(())
/// }
/// ```
#[must_use = "request builders do nothing until send is awaited"]
pub struct RequestBuilder {
    client: Client,
    request: ResolvedRequest,
    selection: ProtocolSelection,
    method: Method,
    headers: Vec<RequestHeader>,
    trailers: Vec<RequestHeader>,
    body: RequestBodySource,
    route: Option<Route>,
    timeouts: Option<RequestTimeouts>,
    retry_policy: Option<RetryPolicy>,
    content_decoding: ContentDecoding,
    response_body_timeouts: bool,
    body_declares_alt_used_trailer: bool,
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("protocol_selection", &self.selection)
            .field("method", &self.method)
            .field("header_count", &self.headers.len())
            .field("template", &self.request.template.is_some())
            .field("trailer_count", &self.trailers.len())
            .field("body_kind", &self.body.trace_kind())
            .field("body_len", &self.body.exact_length().unwrap_or(0))
            .field("route_override", &self.route.is_some())
            .field("timeout_override", &self.timeouts.is_some())
            .field("retry_policy_override", &self.retry_policy.is_some())
            .field("content_decoding", &self.content_decoding)
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
            trailers: Vec::new(),
            body: RequestBodySource::Absent,
            route: None,
            timeouts: None,
            retry_policy: None,
            content_decoding: ContentDecoding::none(),
            response_body_timeouts: true,
            body_declares_alt_used_trailer: false,
        })
    }

    /// Appends one ordered request field.
    ///
    /// A new builder has no caller fields. The URI supplies the authority, so
    /// a `Host` field fails [`Self::send`] with
    /// [`RequestErrorKind::InvalidHeader`](crate::RequestErrorKind::InvalidHeader).
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(header);
        self
    }

    /// Replaces the complete ordered request-field list.
    ///
    /// The same rules apply as for [`Self::header`].
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.headers = headers;
        self
    }

    /// Sends the request with a browser request template's fields and order.
    ///
    /// By default no template is used. Each attempt emits the template's list
    /// for the protocol it uses, after `Host` on HTTP/1.1 or the pseudo-header
    /// fields on HTTP/2 and HTTP/3. A caller field whose name matches a
    /// template entry takes that entry's position and spelling and keeps its
    /// value; a literal entry without one
    /// emits its captured value. Other caller fields follow the template.
    /// Templates carry no `Cookie` entry: the cookie jar's field is then
    /// inserted among those fields by the profile's
    /// [`CookiePlacement`](crate::profile::CookiePlacement), last by default,
    /// unless the caller supplies a `Cookie` field. Profile client hints then
    /// fill the template's client-hint slots. On HTTP/2, the template's
    /// [`http2_priority`](crate::profile::RequestTemplate::http2_priority)
    /// replaces the connection's HEADERS priority for this request's stream.
    /// Every redirect hop uses the same template. A
    /// [`RequestField::ByTrust`](crate::profile::RequestField::ByTrust) entry
    /// sends the value for whether each hop's URL is potentially trustworthy:
    /// `https`, or `http` to a loopback address, `localhost`, or a
    /// `.localhost` name. Automatic client hints go only to such URLs.
    ///
    /// The template was validated when it was prepared. Sending fails before
    /// I/O with
    /// [`RequestErrorKind::RequestTemplate`](crate::RequestErrorKind::RequestTemplate)
    /// when the template lacks an HTTP/3 list for a request that may use
    /// HTTP/3 (an exact HTTP/3 request, or a negotiated one on a client with
    /// Alt-Svc enabled and a direct or SOCKS5 route), when content decoding
    /// is enabled and the protocol lists carry
    /// different `Accept-Encoding` values, when the caller leaves a required
    /// caller slot empty,
    /// when the template has no client-hint slot and the profile sends client
    /// hints by default, or when the caller supplies a client hint the profile
    /// sends only on request, with a template whose
    /// [`requested_client_hint_placement`](crate::profile::RequestTemplate::requested_client_hint_placement)
    /// is `false`. With such a template it fails before the request is sent
    /// on a connection when a hint requested through `Accept-CH` or ALPS
    /// `ACCEPT_CH` would be sent. Phantom does not compare `User-Agent` or
    /// `sec-ch-ua` values with the template.
    pub fn template(mut self, template: &PreparedRequestTemplate) -> Self {
        self.request.template = Some(template.clone());
        self
    }

    /// Replaces the complete ordered request-trailer list.
    ///
    /// A new builder has no static trailers. Static trailers are emitted only
    /// after the request body completes successfully. HTTP/1.1 preserves
    /// field-name spelling; HTTP/2 and HTTP/3 require lowercase names. Every
    /// protocol preserves field order, duplicate positions, values, and
    /// sensitivity. A nonempty static list cannot be combined with
    /// body-produced trailers; [`Self::send`] fails with
    /// [`RequestErrorKind::RequestBody`](crate::RequestErrorKind::RequestBody).
    pub fn trailers(mut self, trailers: Vec<RequestHeader>) -> Self {
        self.trailers = trailers;
        self
    }

    /// Sets the complete owned request body.
    ///
    /// A new builder has no body. An owned body can be sent again for a
    /// redirect or retry. Non-empty bodies receive a trailing `Content-Length`
    /// field when the caller did not supply one. Caller-supplied lengths must
    /// be canonical and exact.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = RequestBodySource::Bytes(body.into());
        self.body_declares_alt_used_trailer = false;
        self
    }

    /// Sets one pull-driven request body consumed by at most one wire attempt.
    ///
    /// Data frames are streamed with transport backpressure and are never
    /// collected into a complete body. The initial exact size hint, when
    /// present, controls `Content-Length` and is enforced while the body is
    /// read. Unknown-length HTTP/1.1 bodies use chunked transfer coding;
    /// HTTP/2 and HTTP/3 omit `Content-Length`.
    ///
    /// This body is not replayable. A redirect, client-hint retry, or other
    /// policy that requires a second body-bearing attempt returns a typed
    /// request-body error before starting that attempt. Trailer frames emitted
    /// by the source remain unsupported; use [`Self::streaming_body_with_trailers`]
    /// when the body produces trailers, or [`Self::trailers`] for static ones.
    pub fn streaming_body<B>(mut self, body: B) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        self.body = RequestBodySource::Streaming(Some(RequestBody::streaming(body)));
        self.body_declares_alt_used_trailer = false;
        self
    }

    /// Sets one pull-driven request body with a declared terminal trailer frame.
    ///
    /// `trailer_names` declares the exact wire order, including duplicate
    /// positions. The body's terminal `Frame::trailers` must contain exactly
    /// those normalized names and multiplicities. HTTP/1 preserves declared
    /// spelling; HTTP/2 and HTTP/3 require lowercase names. This body is
    /// one-shot and cannot be combined with nonempty [`Self::trailers`].
    pub fn streaming_body_with_trailers<B>(
        mut self,
        body: B,
        trailer_names: Vec<RequestTrailerName>,
    ) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        self.body_declares_alt_used_trailer = declares_alt_used_trailer(&trailer_names);
        self.body = RequestBodySource::Streaming(Some(RequestBody::streaming_with_trailers(
            body,
            trailer_names,
        )));
        self
    }

    /// Overrides the client's route for this request.
    ///
    /// Without this call the request uses the route set by
    /// [`ClientBuilder::route`](crate::ClientBuilder::route). [`Self::send`]
    /// fails with
    /// [`RequestErrorKind::UnsupportedRoute`](crate::RequestErrorKind::UnsupportedRoute)
    /// before I/O when the route cannot carry the selected protocol.
    pub fn route(mut self, route: Route) -> Self {
        self.route = Some(route);
        self
    }

    /// Replaces the client's timeout policy for this operation.
    ///
    /// Without this call the request uses the policy set by
    /// [`ClientBuilder::request_timeouts`](crate::ClientBuilder::request_timeouts).
    /// The whole policy is replaced, not merged: [`RequestTimeouts::default`]
    /// explicitly disables every client default. A duration the runtime clock
    /// cannot represent fails [`Self::send`] with
    /// [`RequestErrorKind::InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout).
    pub fn timeouts(mut self, timeouts: RequestTimeouts) -> Self {
        self.timeouts = Some(timeouts);
        self
    }

    /// Replaces the client's connection-establishment retry policy for this request.
    ///
    /// Without this call the request uses the policy set by
    /// [`ClientBuilder::retry_policy`](crate::ClientBuilder::retry_policy).
    /// The policy applies to exact H1, H2, or H3 connection acquisition and to
    /// negotiated H1/H2 TCP connection setup before ALPN selection, always
    /// before request dispatch. Negotiated TLS and ALPN failures are terminal.
    /// Any opt-in reused-connection replay, unprocessed-request replay, or
    /// [`StatusRetry`](crate::StatusRetry) in `policy` also replaces the
    /// client's. A delay the runtime clock cannot represent fails
    /// [`Self::send`] with
    /// [`RequestErrorKind::InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout).
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Sets the response content-decoding policy for this request.
    ///
    /// The default is [`ContentDecoding::none`], which returns the wire body.
    /// [`ContentDecoding::advertised`] decodes only codings named by this
    /// request's own ordered `Accept-Encoding` fields; Phantom never adds or
    /// moves that field. The request head is byte-identical with and without
    /// decoding. Only the response returned by [`Self::send`] is decoded;
    /// intermediate redirect bodies are dropped undecoded. HEAD, 204, 304, and
    /// already-empty bodies are never validated or decoded.
    ///
    /// A response coding that is unknown, unadvertised, stacked more than
    /// three deep, mixed with `identity`, or malformed fails the first body
    /// poll with
    /// [`RequestErrorKind::ContentDecoding`](crate::RequestErrorKind::ContentDecoding);
    /// the status and fields remain visible. With decoding enabled,
    /// [`Self::send`] fails before I/O with
    /// [`RequestErrorKind::InvalidHeader`](crate::RequestErrorKind::InvalidHeader)
    /// for a malformed `Accept-Encoding` field, and with
    /// [`RequestErrorKind::RequestTemplate`](crate::RequestErrorKind::RequestTemplate)
    /// when the template's per-protocol lists carry different
    /// `Accept-Encoding` values. With a template and no `Accept-Encoding` of
    /// your own, the template's value for the final hop's URL decides which
    /// codings are decoded.
    pub fn content_decoding(mut self, policy: ContentDecoding) -> Self {
        self.content_decoding = policy;
        self
    }

    #[cfg(feature = "sse")]
    pub(crate) fn without_response_body_timeouts(mut self) -> Self {
        self.response_body_timeouts = false;
        self
    }

    /// Sends the request using the selected route and owner.
    ///
    /// The client may reuse compatible HTTP/1.1, HTTP/2, and HTTP/3
    /// connections on the same origin and route. A bodyless HTTP/2 GET without trailers rejected by
    /// `GOAWAY(NO_ERROR)`, whether exact or negotiated, is retried once on the
    /// client's replacement connection; a negotiated replacement repeats ALPN
    /// selection under the same negotiated rule. Dropping this
    /// future cancels the in-flight operation; returned bodies retain protocol
    /// cancellation. An opt-in [`RetryPolicy`] can retry eligible exact-protocol
    /// or pre-ALPN negotiated connection setup without replaying request bytes
    /// or body frames, and can separately opt into reused-connection replay
    /// and status retries for idempotent requests, and replay requests that
    /// the H2 or H3 peer reported as not processed. When the client has a
    /// [`RedirectPolicy`](crate::RedirectPolicy), each `http://` or `https://`
    /// redirect target is checked against the request's protocol selection
    /// and route before it is sent, as the first request is.
    ///
    /// # Errors
    ///
    /// Returns a [`RequestError`]; [`RequestError::kind`] gives the category.
    /// These kinds are returned before any I/O:
    ///
    /// - [`InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout) when a
    ///   timeout or retry delay exceeds the runtime clock range;
    /// - [`InvalidHeader`](crate::RequestErrorKind::InvalidHeader) for a
    ///   caller `Host` field, a caller `Alt-Used` field while Alt-Svc learning
    ///   is enabled, a `Proxy-Authorization` field on an `http://` request
    ///   unless the route is an HTTP proxy without configured credentials, or
    ///   a malformed `Accept-Encoding` while content decoding is enabled;
    /// - [`RequestTemplate`](crate::RequestErrorKind::RequestTemplate) as
    ///   described on [`Self::template`];
    /// - [`RequestBody`](crate::RequestErrorKind::RequestBody) when static
    ///   trailers are combined with body-produced trailers;
    /// - [`UnsupportedScheme`](crate::RequestErrorKind::UnsupportedScheme) or
    ///   [`UnsupportedRoute`](crate::RequestErrorKind::UnsupportedRoute) when
    ///   the scheme, protocol selection, and route cannot be combined.
    ///
    /// These kinds are returned during the exchange:
    ///
    /// - [`RuntimeUnavailable`](crate::RequestErrorKind::RuntimeUnavailable)
    ///   without a current Tokio runtime with I/O enabled, or with time
    ///   enabled when a timeout is set;
    /// - [`Resolve`](crate::RequestErrorKind::Resolve),
    ///   [`Connect`](crate::RequestErrorKind::Connect),
    ///   [`Proxy`](crate::RequestErrorKind::Proxy), and
    ///   [`Tls`](crate::RequestErrorKind::Tls) for connection setup;
    /// - [`Capacity`](crate::RequestErrorKind::Capacity) when a pool key's
    ///   active and waiting limits are both full;
    /// - [`Timeout`](crate::RequestErrorKind::Timeout) when a phase or total
    ///   limit elapses; [`RequestError::timeout_phase`] names it;
    /// - [`Http1`](crate::RequestErrorKind::Http1),
    ///   [`Http2`](crate::RequestErrorKind::Http2), and
    ///   [`Http3`](crate::RequestErrorKind::Http3) for protocol failures;
    /// - [`RequestBody`](crate::RequestErrorKind::RequestBody) when the body
    ///   fails or a streaming body would need a second attempt; and
    /// - [`Redirect`](crate::RequestErrorKind::Redirect) when the redirect
    ///   policy rejects a response or target.
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
            body_bytes = self.body.exact_length(),
            body_kind = self.body.trace_kind(),
            trailer_fields = self.trailers.len(),
            protocol = self.selection.trace_name(),
            selected_protocol = field::Empty,
            route = route.request_trace_name(self.request.uri.scheme_str()),
            proxy_authentication_preemptive = field::Empty,
            proxy_authentication_retry = field::Empty,
            proxy_attempts = field::Empty,
            retries_performed = 0_u64,
            retry_reason = field::Empty,
            reused_connection_replays = 0_u64,
            unprocessed_replays = 0_u64,
            status_retries = 0_u64,
            timeout_phase = field::Empty,
            outcome = field::Empty,
        );
        let outcome = RequestOutcome::new(&span);
        if let ProtocolSelection::Exact(protocol) = self.selection {
            span.record("selected_protocol", protocol.trace_name());
        }
        // Keep the public future small when callers join many requests.
        let result = Box::pin(self.send_inner(&span).instrument(span.clone())).await;
        if let Err(error) = &result
            && let Some(phase) = error.timeout_phase()
        {
            span.record("timeout_phase", phase.trace_name());
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
        let retry_policy = self.retry_policy.unwrap_or(self.client.state.retry_policy);
        if !retry_policy.validate() {
            return Err(RequestError::invalid_retry_delay());
        }
        if !self.trailers.is_empty() && self.body.has_trailers() {
            return Err(RequestError::ambiguous_request_trailers());
        }
        if self
            .headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("host"))
        {
            return Err(RequestError::authority_header());
        }
        if self.client.alt_svc_enabled()
            && contains_caller_alt_used(
                &self.headers,
                &self.trailers,
                self.body_declares_alt_used_trailer,
            )
        {
            return Err(RequestError::alt_used_header());
        }
        let content_decoding = self.content_decoding;
        if let Some(template) = &self.request.template {
            let route = self.route.as_ref().unwrap_or(&self.client.inner.route);
            let scope = template::ProtocolScope {
                exact: match self.selection {
                    ProtocolSelection::Exact(protocol) => Some(protocol),
                    ProtocolSelection::Http1Or2 => None,
                },
                // A route that cannot carry QUIC never moves a negotiated
                // request to HTTP/3, so it needs no HTTP/3 list.
                alt_svc: self.client.alt_svc_enabled() && route.carries_quic_alternative(),
                content_decoding: content_decoding.is_enabled(),
            };
            template::check(
                template,
                scope,
                &self.headers,
                self.client.inner.client_hints.as_ref(),
            )?;
        }
        // A template's `Accept-Encoding` depends on whether the URL is
        // potentially trustworthy, which a redirect can change, so the final
        // hop's URL picks the codings that decide how its response is decoded.
        // Both are parsed here so that a bad caller field fails before I/O.
        let advertised = if content_decoding.is_enabled() {
            AdvertisedByTrust {
                untrustworthy: advertised_codings(
                    self.request.template.as_ref(),
                    &self.headers,
                    false,
                )?,
                trustworthy: advertised_codings(
                    self.request.template.as_ref(),
                    &self.headers,
                    true,
                )?,
            }
        } else {
            AdvertisedByTrust::default()
        };

        let Self {
            client,
            request,
            selection,
            method,
            headers: request_headers,
            trailers: request_trailers,
            body,
            route,
            timeouts: _,
            retry_policy: _,
            content_decoding: _,
            response_body_timeouts,
            body_declares_alt_used_trailer: _,
        } = self;
        let route = route.as_ref().unwrap_or(&client.inner.route);
        let mut retries = ConnectionSetupRetryState::new(retry_policy, request_span.clone());
        let mut replays = ReplayState::new();
        ensure_request_supported(selection, route, &request)?;
        // A caller's preemptive field goes to the forward proxy, as it does on
        // CONNECT. On any other route it would reach the origin, and with
        // configured credentials it would conflict with the generated field.
        let forwards_caller_proxy_authorization = route
            .as_http_proxy()
            .is_some_and(|proxy| proxy.basic_credentials().is_none());
        if request.uri.scheme_str() == Some("http")
            && !forwards_caller_proxy_authorization
            && request_headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case("proxy-authorization"))
        {
            return Err(RequestError::forward_proxy_authorization_header());
        }
        let policy = client.state.redirect_policy;

        if policy.max_hops().is_none() {
            let mut body = body;
            let decoding =
                FinalDecoding::new(content_decoding, advertised.for_url(&request.url), &method);
            let outcome = send_once(
                &client,
                &request,
                selection,
                AttemptRequest {
                    method,
                    headers: request_headers,
                    trailers: request_trailers,
                    body: &mut body,
                },
                route,
                AttemptLifecycle {
                    request_span,
                    timeout_budget,
                    retries: &mut retries,
                    replays: &mut replays,
                },
            )
            .await?;
            let mut response = outcome.response;
            if response_body_timeouts {
                response
                    .body_mut()
                    .apply_timeouts(timeout_budget, outcome.protocol)?;
            }
            let decoded_content_codings = decoding.apply(&mut response, outcome.protocol);
            response.extensions_mut().insert(ResponseInfo::new(
                request.uri,
                0,
                retries.performed(),
                outcome.protocol,
                decoded_content_codings,
            ));
            return Ok(response);
        }

        let mut redirect = RedirectState::new(
            policy,
            request.url.clone(),
            method,
            request_headers,
            request_trailers,
            body,
        );
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
                    trailers: redirect.trailers().to_vec(),
                    body: redirect.body_mut(),
                },
                route,
                AttemptLifecycle {
                    request_span,
                    timeout_budget,
                    retries: &mut retries,
                    replays: &mut replays,
                },
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
                    let decoded_content_codings = FinalDecoding::new(
                        content_decoding,
                        advertised.for_url(&resolved.url),
                        redirect.method(),
                    )
                    .apply(&mut response, outcome.protocol);
                    response.extensions_mut().insert(ResponseInfo::new(
                        resolved.uri.clone(),
                        redirect.followed(),
                        retries.performed(),
                        outcome.protocol,
                        decoded_content_codings,
                    ));
                    return Ok(response);
                }
                RedirectAction::Follow { same_origin } => {
                    if !same_origin && let Some(settings) = client.inner.client_hints.as_ref() {
                        redirect.strip_client_hints(settings);
                    }
                    debug!(
                        hop = redirect.followed(),
                        status = response.status().as_u16(),
                        same_origin,
                        "following redirect"
                    );
                    drop(response);
                    let template = resolved.template.take();
                    resolved = ResolvedRequest::from_redirect_url(redirect.current_url())?;
                    resolved.template = template;
                }
            }
        }
    }
}

/// The content codings a request advertises to each kind of URL.
#[derive(Clone, Copy, Default)]
struct AdvertisedByTrust {
    untrustworthy: AdvertisedContentCodings,
    trustworthy: AdvertisedContentCodings,
}

impl AdvertisedByTrust {
    fn for_url(self, url: &url::Url) -> AdvertisedContentCodings {
        if secure_context::is_potentially_trustworthy(url) {
            self.trustworthy
        } else {
            self.untrustworthy
        }
    }
}

/// Returns the content codings the request advertises to a URL of this
/// trust.
///
/// A template's `Accept-Encoding` for that trust is sent when the caller
/// supplies none, so it is advertised too.
fn advertised_codings(
    template: Option<&PreparedRequestTemplate>,
    headers: &[RequestHeader],
    trustworthy: bool,
) -> Result<AdvertisedContentCodings, RequestError> {
    let caller_supplied = headers
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case("accept-encoding"));
    match template.and_then(|template| template.accept_encoding(trustworthy)) {
        Some(value) if !caller_supplied => {
            AdvertisedContentCodings::from_request_headers(&[RequestHeader::new(
                "accept-encoding",
                value,
            )])
        }
        _ => AdvertisedContentCodings::from_request_headers(headers),
    }
}

/// Content-decoding inputs for the response `send` returns.
struct FinalDecoding {
    policy: ContentDecoding,
    advertised: AdvertisedContentCodings,
    method: Method,
}

impl FinalDecoding {
    fn new(policy: ContentDecoding, advertised: AdvertisedContentCodings, method: &Method) -> Self {
        Self {
            policy,
            advertised,
            method: method.clone(),
        }
    }

    fn apply(
        self,
        response: &mut Response<ResponseBody>,
        protocol: HttpProtocol,
    ) -> Box<[ContentCoding]> {
        match content_coding::plan(
            self.policy,
            self.advertised,
            &self.method,
            response.status(),
            response.headers(),
            response.body().is_end_stream(),
            protocol,
        ) {
            ContentDecodingPlan::Passthrough => Box::default(),
            ContentDecodingPlan::Decode(decoder, codings) => {
                response.body_mut().decode_content(decoder);
                codings
            }
            ContentDecodingPlan::Reject(error) => {
                response.body_mut().reject_content(error);
                Box::default()
            }
        }
    }
}

fn is_alt_used_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("alt-used")
}

fn declares_alt_used_trailer(trailers: &[RequestTrailerName]) -> bool {
    trailers
        .iter()
        .any(|trailer| is_alt_used_name(trailer.name()))
}

fn contains_caller_alt_used(
    headers: &[RequestHeader],
    trailers: &[RequestHeader],
    body_declares_alt_used_trailer: bool,
) -> bool {
    headers
        .iter()
        .chain(trailers)
        .any(|header| is_alt_used_name(header.name()))
        || body_declares_alt_used_trailer
}

pub(crate) enum RequestBodySource {
    Absent,
    Bytes(Bytes),
    Streaming(Option<RequestBody>),
}

impl RequestBodySource {
    fn has_trailers(&self) -> bool {
        match self {
            Self::Streaming(Some(body)) => body.metadata().has_trailers(),
            Self::Absent | Self::Bytes(_) | Self::Streaming(None) => false,
        }
    }

    pub(crate) fn next_attempt(&mut self) -> Result<Option<RequestBody>, RequestError> {
        match self {
            Self::Absent => Ok(None),
            Self::Bytes(body) => Ok(Some(RequestBody::from_bytes(body.clone()))),
            Self::Streaming(body) => body
                .take()
                .map(Some)
                .ok_or_else(RequestError::request_body_not_replayable),
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::Absent;
    }

    #[cfg(test)]
    pub(crate) fn replayable_bytes(&self) -> Option<&Bytes> {
        match self {
            Self::Bytes(body) => Some(body),
            Self::Absent | Self::Streaming(_) => None,
        }
    }

    fn exact_length(&self) -> Option<u64> {
        match self {
            Self::Absent | Self::Streaming(None) => None,
            Self::Bytes(body) => Some(body.len() as u64),
            Self::Streaming(Some(body)) => body.metadata().exact_length(),
        }
    }

    const fn trace_kind(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Bytes(_) => "bytes",
            Self::Streaming(_) => "stream",
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
        // Cleartext has no ALPN, so a negotiated request uses HTTP/1.1, as a
        // browser does, except through an HTTP/2 proxy, which forwards it as
        // HTTP/2; see `send_once`. Exact HTTP/1.1 through that proxy is
        // refused rather than changed.
        Some("http") => match (selection, route) {
            (ProtocolSelection::Exact(HttpProtocol::Http2) | ProtocolSelection::Http1Or2, _)
                if route.forwards_plaintext_over_http2() =>
            {
                Ok(())
            }
            (ProtocolSelection::Exact(HttpProtocol::Http1), _)
                if route.forwards_plaintext_over_http2() =>
            {
                Err(RequestError::unsupported_route(HttpProtocol::Http1))
            }
            (
                ProtocolSelection::Exact(HttpProtocol::Http1) | ProtocolSelection::Http1Or2,
                Route::Direct | Route::HttpProxy(_) | Route::Socks5(_),
            ) => Ok(()),
            (ProtocolSelection::Exact(protocol), Route::HttpProxy(_)) => {
                Err(RequestError::unsupported_route(protocol))
            }
            (ProtocolSelection::Http1Or2, Route::ConnectUdp(_)) => {
                Err(RequestError::unsupported_negotiated_route())
            }
            (ProtocolSelection::Exact(HttpProtocol::Http1), _) => {
                Err(RequestError::unsupported_route(HttpProtocol::Http1))
            }
            _ => Err(RequestError::unsupported_scheme()),
        },
        Some("https") => match selection {
            ProtocolSelection::Exact(HttpProtocol::Http3) => match route {
                Route::Direct | Route::Socks5(_) | Route::ConnectUdp(_) => Ok(()),
                Route::HttpProxy(_) => Err(RequestError::unsupported_route(HttpProtocol::Http3)),
            },
            // Negotiation needs one origin TLS stream for ALPN; see
            // `Route::carries_origin_tls_for_alpn`.
            ProtocolSelection::Http1Or2 if !route.carries_origin_tls_for_alpn() => {
                Err(RequestError::unsupported_negotiated_route())
            }
            // CONNECT-UDP carries only QUIC; TCP protocols never use it.
            ProtocolSelection::Exact(protocol @ (HttpProtocol::Http1 | HttpProtocol::Http2))
                if matches!(route, Route::ConnectUdp(_)) =>
            {
                Err(RequestError::unsupported_route(protocol))
            }
            ProtocolSelection::Exact(HttpProtocol::Http1 | HttpProtocol::Http2)
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
    template: Option<PreparedRequestTemplate>,
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
            template: None,
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
            template: None,
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
    use bytes::Bytes;
    use phantom_net::request::{RequestBody, RequestHeader, RequestTrailerName};

    use super::{
        ProtocolSelection, RequestBodySource, ResolvedRequest, contains_caller_alt_used,
        declares_alt_used_trailer, ensure_request_supported,
    };
    use crate::{HttpProtocol, HttpProxy, RequestErrorKind, Route, Socks5Proxy};

    #[test]
    fn streaming_body_cannot_be_replayed_for_a_second_attempt() {
        let mut body = RequestBodySource::Streaming(Some(RequestBody::from_bytes(
            Bytes::from_static(b"payload"),
        )));

        assert!(matches!(body.next_attempt(), Ok(Some(_))));
        let error = match body.next_attempt() {
            Ok(_) => panic!("second attempt accepted a consumed stream"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);
    }

    #[test]
    fn recognizes_alt_used_in_each_caller_controlled_field_source() {
        assert!(contains_caller_alt_used(
            &[RequestHeader::new("ALT-USED", "alt.example:443")],
            &[],
            false,
        ));
        assert!(contains_caller_alt_used(
            &[],
            &[RequestHeader::new("Alt-Used", "alt.example:443")],
            false,
        ));
        assert!(declares_alt_used_trailer(&[RequestTrailerName::new(
            "alt-used",
        )]));
        assert!(contains_caller_alt_used(&[], &[], true));
        assert!(!contains_caller_alt_used(
            &[RequestHeader::new("x-field", "value")],
            &[RequestHeader::new("x-trailer", "value")],
            false,
        ));
    }

    #[test]
    fn http_proxy_routes_reject_http3_without_network_io() -> Result<(), Box<dyn std::error::Error>>
    {
        let routes = [Route::http_connect(HttpProxy::new("http://127.0.0.1:9")?)];
        let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;

        for route in routes {
            let error = match ensure_request_supported(
                ProtocolSelection::Exact(HttpProtocol::Http3),
                &route,
                &request,
            ) {
                Ok(()) => panic!("HTTP proxy route accepted HTTP/3"),
                Err(error) => error,
            };

            assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
            assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        }
        Ok(())
    }

    #[test]
    fn local_dns_socks5_route_accepts_http3() -> Result<(), Box<dyn std::error::Error>> {
        let route = Route::socks5(Socks5Proxy::new("socks5://127.0.0.1:9")?);
        let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;

        assert!(
            ensure_request_supported(
                ProtocolSelection::Exact(HttpProtocol::Http3),
                &route,
                &request,
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn remote_dns_socks5_route_accepts_http3() -> Result<(), Box<dyn std::error::Error>> {
        let route = Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:9")?);
        let request = ResolvedRequest::new(&"https://example.test/".parse()?)?;

        assert!(
            ensure_request_supported(
                ProtocolSelection::Exact(HttpProtocol::Http3),
                &route,
                &request,
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn connect_udp_route_accepts_only_exact_http3() -> Result<(), Box<dyn std::error::Error>> {
        let route = Route::connect_udp(crate::ConnectUdpProxy::new(
            "https://127.0.0.1:9/masque/{target_host}/{target_port}/",
        )?);
        let secure = ResolvedRequest::new(&"https://example.test/".parse()?)?;
        let plaintext = ResolvedRequest::new(&"http://example.test/".parse()?)?;

        assert!(
            ensure_request_supported(
                ProtocolSelection::Exact(HttpProtocol::Http3),
                &route,
                &secure,
            )
            .is_ok()
        );
        for (selection, request, protocol) in [
            (
                ProtocolSelection::Exact(HttpProtocol::Http1),
                &secure,
                Some(HttpProtocol::Http1),
            ),
            (
                ProtocolSelection::Exact(HttpProtocol::Http2),
                &secure,
                Some(HttpProtocol::Http2),
            ),
            (ProtocolSelection::Http1Or2, &secure, None),
            (
                ProtocolSelection::Exact(HttpProtocol::Http1),
                &plaintext,
                Some(HttpProtocol::Http1),
            ),
        ] {
            let error = match ensure_request_supported(selection, &route, request) {
                Ok(()) => panic!("CONNECT-UDP route accepted {selection:?}"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
            assert_eq!(error.protocol(), protocol);
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

    /// A request's future holds every future on its path inline, and a debug
    /// build's poll frames grow with them; see `phantom_testkit::future_size`.
    #[cfg(debug_assertions)]
    #[test]
    fn request_futures_stay_within_the_stack_budget() {
        use phantom_testkit::future_size::{assert_within_budget, future_size};

        use super::{RequestBuilder, alt_svc_attempt, attempt};
        use crate::session::{
            http1_or_2_pool::Http1Or2Pool, http1_pool::Http1Pool, http2_pool::Http2Pool,
            http3_pool::Http3Pool,
        };

        assert_within_budget(&[
            ("RequestBuilder::send", future_size(&RequestBuilder::send)),
            (
                "RequestBuilder::send_inner",
                future_size(&RequestBuilder::send_inner),
            ),
            ("send_once", future_size(&attempt::send_once)),
            ("send_once_origin", future_size(&attempt::send_once_origin)),
            ("dispatch", future_size(&attempt::dispatch)),
            (
                "send_once_alt_svc",
                future_size(&alt_svc_attempt::send_once_alt_svc),
            ),
            (
                "send_once_raced",
                future_size(&alt_svc_attempt::send_once_raced),
            ),
            (
                "Http1Pool::send_request",
                future_size(&Http1Pool::send_request),
            ),
            (
                "Http2Pool::send_request",
                future_size(&Http2Pool::send_request),
            ),
            (
                "Http1Or2Pool::send_request",
                future_size(&Http1Or2Pool::send_request),
            ),
            (
                "Http3Pool::send_request",
                future_size(&Http3Pool::send_request),
            ),
            (
                "Http3Pool::send_request_on_lease",
                future_size(&Http3Pool::send_request_on_lease),
            ),
        ]);
    }
}
