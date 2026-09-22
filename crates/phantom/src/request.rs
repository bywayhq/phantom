use std::{borrow::Cow, error::Error as StdError, fmt, sync::Arc};

use bytes::Bytes;
use http::{Method, Response, Uri};
use http_body::Body;
use phantom_net::{
    http1::{AbsoluteForm, OriginForm},
    request::{RequestBody, RequestHeader, RequestTrailerName},
};
use phantom_profile::RequestTemplate;
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
pub(crate) mod template;

use attempt::{AttemptLifecycle, AttemptRequest, send_once};
use replay::ReplayState;

/// Builder for one request with an owned, streaming, or absent body.
///
/// [`Client::get`] and [`Client::request`] build exact-protocol requests;
/// [`Client::get_negotiated`] and [`Client::request_negotiated`] build requests
/// whose H1 or H2 selection is made by ALPN.
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
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(header);
        self
    }

    /// Replaces the complete ordered request-field list.
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.headers = headers;
        self
    }

    /// Sends the request with a browser request template's fields and order.
    ///
    /// Each attempt emits the template's list for the protocol it uses, after
    /// `Host` on HTTP/1.1 or the pseudo-header fields on HTTP/2 and HTTP/3.
    /// A caller field whose name matches a template entry takes that entry's
    /// position and spelling and keeps its value; a literal entry without one
    /// emits its captured value. Other caller fields, then an automatic
    /// cookie, follow the template. Profile client hints fill the template's
    /// client-hint slots. On HTTP/2, the template's
    /// [`http2_priority`](crate::profile::RequestTemplate::http2_priority)
    /// replaces the connection's HEADERS priority for this request's stream.
    /// Every redirect hop uses the same template.
    ///
    /// Sending fails before I/O with
    /// [`RequestErrorKind::RequestTemplate`](crate::RequestErrorKind::RequestTemplate)
    /// when the template is invalid or lacks an HTTP/3 list for a request that
    /// may use HTTP/3, and before the request is sent on a connection when a
    /// client hint requested through `Accept-CH` or ALPS `ACCEPT_CH`, or
    /// supplied by the caller, would be sent with a template whose
    /// [`requested_client_hint_placement`](crate::profile::RequestTemplate::requested_client_hint_placement)
    /// is `false`. It fails before I/O with
    /// [`RequestErrorKind::IdentityMismatch`](crate::RequestErrorKind::IdentityMismatch)
    /// when a caller `User-Agent`, a caller `sec-ch-ua` or
    /// `sec-ch-ua-full-version-list`, or the profile's value of those hints
    /// names another browser or major version than the template, or when the
    /// template leaves a required `User-Agent` to the caller and the caller
    /// supplies none. Phantom never rewrites such a field.
    pub fn template(mut self, template: RequestTemplate) -> Self {
        self.request.template = Some(Arc::new(template));
        self
    }

    /// Replaces the complete ordered request-trailer list.
    ///
    /// Static trailers are emitted only after the request body completes
    /// successfully. HTTP/1.1 preserves field-name spelling; HTTP/2 and
    /// HTTP/3 require lowercase names. Every protocol preserves field order,
    /// duplicate positions, values, and sensitivity. A nonempty static list
    /// cannot be combined with body-produced trailers.
    pub fn trailers(mut self, trailers: Vec<RequestHeader>) -> Self {
        self.trailers = trailers;
        self
    }

    /// Sets the complete owned request body.
    ///
    /// Non-empty bodies receive a trailing `Content-Length` field when the
    /// caller did not supply one. Caller-supplied lengths must be canonical
    /// and exact.
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

    /// Replaces the client's connection-establishment retry policy for this request.
    ///
    /// The policy applies to exact H1, H2, or H3 connection acquisition and to
    /// negotiated H1/H2 TCP connection setup before ALPN selection, always
    /// before request dispatch. Negotiated TLS and ALPN failures are terminal.
    /// Any opt-in reused-connection replay, unprocessed-request replay, or
    /// [`StatusRetry`](crate::StatusRetry) in `policy` also replaces the
    /// client's.
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Sets the response content-decoding policy for this request.
    ///
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
    /// the status and fields remain visible.
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
    /// [`RedirectPolicy`](crate::RedirectPolicy), only `https://` requests and
    /// redirect targets are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] for invalid ordered fields (including a
    /// malformed `Accept-Encoding` when content decoding is enabled), a missing or
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
            body_bytes = self.body.exact_length(),
            body_kind = self.body.trace_kind(),
            trailer_fields = self.trailers.len(),
            protocol = self.selection.trace_name(),
            selected_protocol = field::Empty,
            route = route.request_trace_name(self.request.uri.scheme_str()),
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
        if let Some(template) = self.request.template.as_deref() {
            let scope = template::ProtocolScope {
                exact: match self.selection {
                    ProtocolSelection::Exact(protocol) => Some(protocol),
                    ProtocolSelection::Http1Or2 => None,
                },
                alt_svc: self.client.alt_svc_enabled(),
                content_decoding: content_decoding.is_enabled(),
            };
            template::check(
                template,
                scope,
                &self.headers,
                self.client.inner.client_hints.as_ref(),
            )?;
        }
        if content_decoding.is_enabled() {
            AdvertisedContentCodings::from_request_headers(&decoding_headers(
                self.request.template.as_deref(),
                &self.headers,
            ))?;
        }

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
        let is_plaintext_http = request.uri.scheme_str() == Some("http");
        if is_plaintext_http
            && request_headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case("proxy-authorization"))
        {
            return Err(RequestError::forward_proxy_authorization_header());
        }
        let policy = client.state.redirect_policy;
        if is_plaintext_http && policy.max_hops().is_some() {
            return Err(RequestError::plaintext_redirect_policy());
        }

        if policy.max_hops().is_none() {
            let mut body = body;
            let decoding = FinalDecoding::new(
                content_decoding,
                &method,
                &decoding_headers(request.template.as_deref(), &request_headers),
            )?;
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
                        redirect.method(),
                        &decoding_headers(resolved.template.as_deref(), redirect.headers()),
                    )?
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

/// Returns the fields whose `Accept-Encoding` selects content decoding.
///
/// A template's literal `Accept-Encoding` is sent when the caller supplies
/// none, so it is advertised too.
fn decoding_headers<'a>(
    template: Option<&RequestTemplate>,
    headers: &'a [RequestHeader],
) -> Cow<'a, [RequestHeader]> {
    let caller_supplied = headers
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case("accept-encoding"));
    match template.and_then(template::accept_encoding) {
        Some(value) if !caller_supplied => {
            let mut headers = headers.to_vec();
            headers.push(RequestHeader::new("accept-encoding", value));
            Cow::Owned(headers)
        }
        _ => Cow::Borrowed(headers),
    }
}

/// Content-decoding inputs for the response `send` returns.
struct FinalDecoding {
    policy: ContentDecoding,
    advertised: AdvertisedContentCodings,
    method: Method,
}

impl FinalDecoding {
    fn new(
        policy: ContentDecoding,
        method: &Method,
        headers: &[RequestHeader],
    ) -> Result<Self, RequestError> {
        let advertised = if policy.is_enabled() {
            AdvertisedContentCodings::from_request_headers(headers)?
        } else {
            AdvertisedContentCodings::default()
        };
        Ok(Self {
            policy,
            advertised,
            method: method.clone(),
        })
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
        Some("http") => match (selection, route) {
            (ProtocolSelection::Exact(HttpProtocol::Http1), Route::Direct) => Ok(()),
            (ProtocolSelection::Exact(HttpProtocol::Http1), Route::HttpProxy(_)) => Ok(()),
            (ProtocolSelection::Exact(protocol), Route::HttpProxy(_)) => {
                Err(RequestError::unsupported_route(protocol))
            }
            (ProtocolSelection::Http1Or2, Route::HttpProxy(_)) => {
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
            ProtocolSelection::Http1Or2 if !matches!(route, Route::Direct) => {
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
    template: Option<Arc<RequestTemplate>>,
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
}
