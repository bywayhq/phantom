use std::{error::Error as StdError, fmt};

use bytes::Bytes;
use http::{Method, Response, Uri};
use http_body::Body;
use phantom_net::request::{
    AbsoluteForm, OriginForm, RequestBody, RequestHeader, RequestTrailerName,
};
use phantom_profile::catalog::RequestTemplateKind;
use tracing::{Instrument, Span, debug, debug_span, field};

use crate::session::alt_svc::PinnedAlternative;
use crate::{
    Client, ContentCoding, ContentDecoding, HttpProtocol, RedirectPolicy, RequestError,
    RequestTimeoutOverrides, ResponseBody, ResponseInfo, RetryPolicy, Route,
    authority::{Endpoint, ParseUriError, parse_absolute_uri},
    content_coding::{self, AdvertisedContentCodings, ContentDecodingPlan},
    redirect::{RedirectAction, RedirectState},
    retry::ConnectionSetupRetryState,
};
use attempt::{AttemptLifecycle, AttemptRequest, send_once};
use replay::ReplayState;
use replay_buffer::{NoReplay, ReplayBuffer};
pub use template::PreparedRequestTemplate;

mod alt_svc_attempt;
mod attempt;
mod coalesced_attempt;
mod field_lists;
mod replay;
mod replay_buffer;
pub(crate) mod secure_context;
pub(crate) mod template;

/// Set a request's headers, body and options before you send it.
///
/// See [Requests and responses](crate::guide::requests_and_responses) for
/// uploads, bounded body reads, and error handling.
///
/// [`Client::get_with_protocol`] and [`Client::request_with_protocol`] build exact-protocol requests;
/// [`Client::get`] and [`Client::request`] build requests
/// whose H1 or H2 selection is made by ALPN. Fields, route, and policies are
/// checked when [`Self::send`] runs, before any I/O.
/// New requests inherit the profile's default template. Use [`Self::context`]
/// to select another context, [`Self::template`] for a custom template, or
/// [`Self::without_template`] to opt out for one request.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
///
/// use phantom::{
///     Client, HttpProtocol, Method, RequestError, RequestHeader,
///     RequestTimeoutOverrides, TimeoutOverride,
/// };
///
/// async fn post(client: &Client) -> Result<(), RequestError> {
///     let response = client
///         .request_with_protocol(HttpProtocol::Http2, Method::POST, "https://example.com/api")?
///         .header(RequestHeader::new("content-type", "application/json"))
///         .body(r#"{"name":"phantom"}"#)
///         .timeouts(RequestTimeoutOverrides::new()
///             .total(TimeoutOverride::Limit(Duration::from_secs(30))))
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
    prepared_content_type: Option<Box<str>>,
    filled_slots: Vec<Box<str>>,
    header_hooks: Vec<crate::header_hook::HeaderHook>,
    request_hooks: Option<crate::request_hook::SharedRequestHooks>,
    client_header_hooks: bool,
    protected_hook_headers: &'static [&'static str],
    route: Option<Route>,
    timeouts: Option<RequestTimeoutOverrides>,
    retry_policy: Option<RetryPolicy>,
    redirect_policy: Option<RedirectPolicy>,
    redirect_history: Option<std::num::NonZeroUsize>,
    attempt_budget: Option<crate::HttpAttemptBudget>,
    diagnostics: Option<crate::RequestDiagnostics>,
    content_decoding: ContentDecoding,
    response_body_timeouts: bool,
    body_declares_alt_used_trailer: bool,
    /// The host and port of a caller-pinned alternative, checked by `send`.
    alternative: Option<(Box<str>, u16)>,
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("protocol_selection", &self.selection)
            .field("method", &self.method)
            .field("header_count", &self.headers.len())
            .field("header_hook_count", &self.header_hooks.len())
            .field("request_hooks", &self.request_hooks.is_some())
            .field("client_header_hooks", &self.client_header_hooks)
            .field("template", &self.request.template.is_some())
            .field("trailer_count", &self.trailers.len())
            .field("body_kind", &self.body.trace_kind())
            .field("body_len", &self.body.exact_length().unwrap_or(0))
            .field("route_override", &self.route.is_some())
            .field("timeout_override", &self.timeouts.is_some())
            .field("retry_policy_override", &self.retry_policy.is_some())
            .field("redirect_policy_override", &self.redirect_policy.is_some())
            .field("redirect_history_limit", &self.redirect_history)
            .field("attempt_budget", &self.attempt_budget)
            .field("content_decoding", &self.content_decoding)
            .field("pinned_alternative", &self.alternative.is_some())
            .finish_non_exhaustive()
    }
}

impl RequestBuilder {
    /// Shares optional body-byte caps, pacing and counters across all attempts.
    ///
    /// Clone the control to share its allowance with other requests. Upload
    /// counters include resends. Download caps count encoded body data before
    /// content decoding. Use decoded-body limits separately. Header placement
    /// and replay-safety rules are unchanged.
    ///
    /// ```no_run
    /// # async fn example(client: &phantom::Client) -> Result<(), phantom::RequestError> {
    /// use phantom::{HttpProtocol, TransferControl, TransferLimits};
    ///
    /// let control = TransferControl::new(TransferLimits::new().download_bytes(1 << 20));
    /// let response = client.get_with_protocol(HttpProtocol::Http2, "https://example.com/")?
    ///     .transfer_control(control.clone()).send().await?;
    /// response.into_body().collect_with_limit(1 << 20).await?;
    /// println!("{:?}", control.snapshot());
    /// # Ok(())
    /// # }
    /// ```
    pub fn transfer_control(mut self, control: crate::TransferControl) -> Self {
        self.request.transfer = Some(control);
        self
    }

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
            ProtocolSelection::Exact(HttpProtocol::Http1)
                if client.inner.transport.http1.is_none() =>
            {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http1));
            }
            ProtocolSelection::Exact(HttpProtocol::Http2)
                if client.inner.transport.http2.is_none() =>
            {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http2));
            }
            ProtocolSelection::Exact(HttpProtocol::Http3)
                if client.inner.transport.http3.is_none() =>
            {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http3));
            }
            ProtocolSelection::Http1Or2 if client.inner.transport.http1_or_2.is_none() => {
                return Err(RequestError::unsupported_negotiation());
            }
            ProtocolSelection::Exact(
                HttpProtocol::Http1 | HttpProtocol::Http2 | HttpProtocol::Http3,
            )
            | ProtocolSelection::Http1Or2 => {}
        }
        let uri = match &client.inner.defaults.base_url {
            Some(base) => base.resolve(uri)?,
            None => parse_absolute_uri(uri).map_err(request_uri_error)?,
        };
        let mut request = ResolvedRequest::new(&uri)?;
        request.template = client.inner.defaults.request_template.clone();
        Ok(Self {
            client,
            request,
            selection,
            method,
            headers: Vec::new(),
            trailers: Vec::new(),
            body: RequestBodySource::Absent,
            prepared_content_type: None,
            filled_slots: Vec::new(),
            header_hooks: Vec::new(),
            request_hooks: None,
            client_header_hooks: true,
            protected_hook_headers: &[],
            route: None,
            timeouts: None,
            retry_policy: None,
            redirect_policy: None,
            redirect_history: None,
            attempt_budget: None,
            diagnostics: None,
            content_decoding: ContentDecoding::none(),
            response_body_timeouts: true,
            body_declares_alt_used_trailer: false,
            alternative: None,
        })
    }

    /// Appends query pairs in their supplied order, including duplicate names.
    ///
    /// Existing path and query bytes stay unchanged. Only the new pairs are
    /// form-encoded: spaces become `+`, and literal `+` becomes `%2B`.
    /// Each pair adds `name=value`, including empty names or values.
    /// Repeated calls append more pairs. An empty iterator changes nothing.
    /// Templates, body settings and pinned alternatives stay attached.
    ///
    /// ```no_run
    /// # fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let request = client.get_with_protocol(phantom::HttpProtocol::Http1, "https://example.com/?tag=old")?
    ///     .query_pairs([("tag", "new"), ("tag", "last")])?;
    /// # drop(request);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] if the resulting URI or request targets cannot
    /// be represented. No network I/O or request-body polling occurs.
    pub fn query_pairs<I, K, V>(mut self, pairs: I) -> Result<Self, RequestError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        encoded.extend_pairs(pairs);
        self.request
            .append_query(&encoded.finish())
            .map_err(|error| error.with_origin(self.request.origin()))?;
        Ok(self)
    }

    /// Appends a request header to the ordered caller fields.
    ///
    /// Fields keep their spelling and position unless a request template places
    /// them. Caller cookies follow the profile's [`phantom_profile::CookiePlacement`]:
    /// their names become `Cookie` on HTTP/1.1 and `cookie` on HTTP/2 and HTTP/3.
    ///
    /// A new builder has no caller headers. The URI supplies `Host`.
    /// If you add a `Host` header, [`Self::send`] returns
    /// [`RequestErrorKind::InvalidHeader`](crate::RequestErrorKind::InvalidHeader).
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(header);
        self
    }

    /// Replaces the ordered list of caller request headers.
    ///
    /// The same rules apply as for [`Self::header`].
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.headers = headers;
        self.filled_slots.clear();
        self
    }

    /// Runs a synchronous preparation hook that fills declared caller slots.
    ///
    /// Client and request header hooks run later, when sending begins.
    ///
    /// Set a template first. The hook receives only slots declared on every
    /// protocol this request may use, including enabled HTTP/2 fallback.
    /// Filled fields keep the template's spelling and position when sent.
    /// The hook runs once here. Retries reuse its fields, and cross-origin
    /// redirects strip credential fields without invoking it again.
    ///
    /// Later template, route, or retry setters are checked at send time.
    /// Replacing all headers clears the hook's fills. The hook cannot add an
    /// undeclared field, replace literals, or reorder template fields.
    ///
    /// # Errors
    ///
    /// Returns [`crate::RequestSlotError`] for a missing template, undeclared
    /// or already filled slot, or invalid field value. No network I/O occurs.
    pub fn fill_slots<F>(mut self, fill: F) -> Result<Self, crate::RequestSlotError>
    where
        F: FnOnce(&mut crate::RequestSlots<'_>) -> Result<(), crate::RequestSlotError>,
    {
        let prepared =
            self.request.template.as_ref().ok_or_else(|| {
                crate::RequestSlotError::new(crate::RequestSlotErrorKind::Undeclared)
            })?;
        let policy = self.retry_policy.unwrap_or(self.client.state.retry_policy);
        let declared = template::caller_slots(
            prepared,
            self.slot_scope(),
            policy.http2_fallback()
                && policy.max_retries() != Some(0)
                && self.alternative.is_none(),
        );
        let first = self.headers.len();
        fill(&mut crate::RequestSlots::new(&mut self.headers, &declared))?;
        self.filled_slots.extend(
            self.headers[first..]
                .iter()
                .map(|header| Box::from(header.name())),
        );
        Ok(self)
    }

    /// Sets callbacks for this logical request, after the client's callbacks.
    ///
    /// Replaces previously configured request hooks on this builder. See
    /// [`crate::RequestHooks`] for ordering, cancellation and body semantics.
    pub fn request_hooks(mut self, hooks: impl crate::RequestHooks + 'static) -> Self {
        self.request_hooks = Some(crate::request_hook::SharedRequestHooks::new(hooks));
        self
    }

    /// Adds a header hook after this client's hooks and earlier request hooks.
    ///
    /// See [`crate::HeaderHookContext`] for timing, ordering, and redirect rules.
    /// Failures return [`crate::RequestErrorKind::HeaderHook`] before I/O.
    pub fn header_hook<F>(mut self, hook: F) -> Self
    where
        F: Fn(&mut crate::HeaderHookContext<'_>) -> Result<(), crate::HeaderHookError>
            + Send
            + Sync
            + 'static,
    {
        self.header_hooks
            .push(crate::header_hook::HeaderHook::new(hook));
        self
    }

    /// Skips client header hooks and clears this request's header hooks.
    ///
    /// Hooks added after this call still run.
    pub fn without_header_hooks(mut self) -> Self {
        self.client_header_hooks = false;
        self.header_hooks.clear();
        self
    }

    /// The template conditions of a request that can reach the wire.
    #[cfg(feature = "sse")]
    pub(crate) fn supported_template_conditions(&self) -> Option<(bool, bool)> {
        let route = self.selected_route();
        ensure_request_supported(self.selection, &route, &self.request).ok()?;
        Some((
            secure_context::is_potentially_trustworthy(&self.request.url),
            route.forwards(&self.request.uri),
        ))
    }

    #[cfg(feature = "sse")]
    pub(crate) fn protect_event_source_headers(mut self) -> Self {
        self.protected_hook_headers = &["last-event-id"];
        self.request.managed_headers = self.protected_hook_headers;
        self
    }

    fn slot_scope(&self) -> template::ProtocolScope {
        template::ProtocolScope {
            exact: match self.selection {
                ProtocolSelection::Exact(protocol) => Some(protocol),
                ProtocolSelection::Http1Or2 => None,
            },
            alt_svc: negotiated_http3_available(
                &self.client,
                &self.request,
                &self.selected_route(),
            ),
            content_decoding: false,
        }
    }

    /// Selects this request's context from the client's catalog recipe.
    ///
    /// Replaces the default template for this request, without changing other
    /// requests, connections or session state. Templates are prepared on first
    /// use and shared by later requests. A later [`Self::template`] or
    /// [`Self::without_template`] replaces this choice.
    ///
    /// # Errors
    ///
    /// Returns [`RequestErrorKind::RequestTemplate`](crate::RequestErrorKind::RequestTemplate)
    /// before I/O when the profile has no catalog association, the context is
    /// unavailable, or its template is invalid. Required caller fields such as
    /// `Referer` are checked by [`Self::send`]. Imported JSON profiles have no
    /// catalog association; use [`Self::template`] for their custom contexts.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use phantom::{Client, RequestHeader, profile::browser::chrome};
    /// use phantom::profile::catalog::RequestTemplateKind;
    ///
    /// let client = Client::builder(chrome::v154_windows()).build()?;
    /// let response = client.get("https://example.com/data")?
    ///     .context(RequestTemplateKind::Fetch)?
    ///     .header(RequestHeader::new("referer", "https://example.com/"))
    ///     .send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn context(mut self, kind: RequestTemplateKind) -> Result<Self, RequestError> {
        self.request.template = Some(self.client.inner.defaults.context_template(kind)?);
        Ok(self)
    }

    /// Sends the request with a browser template's headers and order.
    ///
    /// Replaces the profile's default template for this request. Without a
    /// profile default or an explicit template, no template is used.
    /// Each attempt emits the template's list for the protocol it uses,
    /// after `Host` on HTTP/1.1 or the pseudo-header
    /// fields on HTTP/2 and HTTP/3. A matching caller header takes the
    /// template entry's position and spelling. It keeps your value. A literal
    /// entry without a matching caller header sends the template's value.
    /// Other caller headers follow the template.
    /// Templates carry no `Cookie` entry: caller cookie fields, or the jar's
    /// field when none are supplied, follow the profile's
    /// [`CookiePlacement`](crate::profile::CookiePlacement), last by default.
    /// Caller values and duplicate order are preserved. Names become `Cookie`
    /// on HTTP/1.1 and `cookie` on HTTP/2 and HTTP/3. Profile client hints then
    /// fill the template's client-hint slots. On HTTP/2, the template's
    /// [`http2_priority`](crate::profile::RequestTemplate::http2_priority)
    /// replaces the connection's HEADERS priority for this request's stream.
    /// Every redirect hop keeps the template. Cross-origin redirects remove
    /// its credential fields for all later hops. A
    /// [`RequestField::ByTrust`](crate::profile::RequestField::ByTrust) entry
    /// sends the value for whether each hop's URL is potentially trustworthy:
    /// `https`, or `http` to a loopback address, `localhost`, or a
    /// `.localhost` name. Automatic client hints go only to such URLs.
    ///
    /// The template is checked when you prepare it. Sending returns
    /// [`RequestErrorKind::RequestTemplate`](crate::RequestErrorKind::RequestTemplate)
    /// before the affected hop's I/O for any of these cases:
    ///
    /// - The template lacks an HTTP/3 list for an exact HTTP/3 request.
    /// - It lacks that list for a negotiated request with Alt-Svc enabled on
    ///   a direct or SOCKS5 route.
    /// - Content decoding is enabled and the protocol lists have different
    ///   `Accept-Encoding` values.
    /// - You leave a required caller slot empty.
    /// - The profile sends default client hints and the template has no slots.
    /// - You supply a hint the profile sends only on request, and the template's
    ///   [`requested_client_hint_placement`](crate::profile::RequestTemplate::requested_client_hint_placement)
    ///   is `false`.
    ///
    /// With placement disabled, a hint requested through `Accept-CH` or ALPS
    /// `ACCEPT_CH` also fails before sending the request on its connection.
    /// Phantom does not compare `User-Agent` or
    /// `sec-ch-ua` values with the template.
    pub fn template(mut self, template: &PreparedRequestTemplate) -> Self {
        self.request.template = Some(template.clone());
        self
    }

    /// Sends this request without a template, including the profile default.
    ///
    /// Caller headers keep their order. Automatic client hints and cookies use
    /// the profile's usual placement. A later [`Self::template`] sets an
    /// explicit template.
    pub fn without_template(mut self) -> Self {
        self.request.template = None;
        self
    }

    /// Replaces the complete ordered request-trailer list.
    ///
    /// A new builder has no static trailers. Static trailers are emitted only
    /// after the request body completes successfully. HTTP/1.1 preserves
    /// header-name spelling. HTTP/2 and HTTP/3 require lowercase names. Every
    /// protocol preserves field order, duplicate positions, values, and
    /// sensitivity. A nonempty static list cannot be combined with
    /// body-produced trailers. [`Self::send`] returns
    /// [`RequestErrorKind::RequestBody`](crate::RequestErrorKind::RequestBody).
    pub fn trailers(mut self, trailers: Vec<RequestHeader>) -> Self {
        self.trailers = trailers;
        self
    }

    /// Enables a bounded timeline and returns a live handle for this request.
    ///
    /// Call before `send`. Timing starts when `send` is polled. Keep the handle
    /// to inspect a failed or cancelled request, or later body completion.
    /// Repeated calls return the same handle and retain the first capacity.
    /// Omitted records are counted and never affect request execution.
    /// This does not enable TLS secret logging or qlog output.
    ///
    /// ```no_run
    /// # async fn example(client: &phantom::Client) -> Result<(), phantom::RequestError> {
    /// use std::num::NonZeroUsize;
    /// use phantom::HttpProtocol;
    ///
    /// let mut request = client.get_with_protocol(HttpProtocol::Http2, "https://example.com/")?;
    /// let diagnostics = request.diagnostics(NonZeroUsize::new(128).unwrap());
    /// let response = request.send().await?;
    /// println!("{:?}", diagnostics.snapshot());
    /// response.into_body().collect_with_limit(1 << 20).await?;
    /// println!("{:?}", diagnostics.snapshot());
    /// # Ok(())
    /// # }
    /// ```
    pub fn diagnostics(
        &mut self,
        maximum_events: std::num::NonZeroUsize,
    ) -> crate::RequestDiagnostics {
        self.diagnostics
            .get_or_insert_with(|| crate::RequestDiagnostics::new(maximum_events))
            .clone()
    }

    /// Sets the complete owned request body.
    ///
    /// A new builder has no body. An owned body can be sent again for a
    /// redirect or retry. Non-empty bodies receive a trailing `Content-Length`
    /// field when the caller did not supply one. Caller-supplied lengths must
    /// be canonical and exact.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.prepared_content_type = None;
        self.body = RequestBodySource::Bytes(body.into());
        self.body_declares_alt_used_trailer = false;
        self
    }

    /// Encodes a replayable JSON body and supplies its `Content-Type` header.
    ///
    /// `maximum_bytes` bounds the encoded body. An existing content type must
    /// match `application/json`; duplicates and conflicts fail before sending.
    /// Template slots retain their configured position. Without a slot, the
    /// header follows caller headers already added to this builder.
    ///
    /// ```no_run
    /// # async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let response = client.request(phantom::Method::POST, "https://example.com/messages")?
    ///     .json(&serde_json::json!({"message": "hello"}), 4096)?
    ///     .send().await?;
    /// # drop(response);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::PreparedBodyError`] if encoding fails or exceeds the limit.
    #[cfg(feature = "json")]
    pub fn json<T: serde::Serialize + ?Sized>(
        self,
        value: &T,
        maximum_bytes: usize,
    ) -> Result<Self, crate::PreparedBodyError> {
        let body = crate::PreparedRequestBody::json(value, maximum_bytes)?;
        Ok(self.encoded_body(body))
    }

    /// Encodes ordered form pairs and supplies their `Content-Type` header.
    ///
    /// Duplicate names retain their order. `maximum_bytes` bounds the encoded
    /// body. The content type is `application/x-www-form-urlencoded;charset=UTF-8`.
    /// An existing content type must match; duplicates and conflicts fail before
    /// sending. Template slots keep their position; otherwise the header follows
    /// caller headers already added to this builder.
    ///
    /// ```no_run
    /// # async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let response = client.request(phantom::Method::POST, "https://example.com/submit")?
    ///     .form([("tag", "first"), ("tag", "last")], 4096)?
    ///     .send().await?;
    /// # drop(response);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::PreparedBodyError`] if encoding exceeds the limit.
    pub fn form<I, K, V>(
        self,
        pairs: I,
        maximum_bytes: usize,
    ) -> Result<Self, crate::PreparedBodyError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let body = crate::PreparedRequestBody::form(pairs, maximum_bytes)?;
        Ok(self.encoded_body(body))
    }

    fn encoded_body(mut self, body: crate::PreparedRequestBody) -> Self {
        if !self
            .headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("content-type"))
        {
            self.headers
                .push(RequestHeader::new("content-type", body.content_type()));
        }
        self.prepared_body(body)
    }

    /// Sets bounded, replayable bytes with an exact content type.
    ///
    /// At send time, a declared `Content-Type` caller slot receives the value.
    /// Without that slot, supply one matching header in your chosen position.
    /// Existing headers keep their order. Missing placement, duplicates, or
    /// a different value fail with [`crate::RequestErrorKind::InvalidHeader`]
    /// before I/O. Later body setters replace both bytes and this requirement.
    pub fn prepared_body(mut self, body: crate::PreparedRequestBody) -> Self {
        let (bytes, content_type) = body.into_parts();
        self.body = RequestBodySource::Bytes(bytes);
        self.prepared_content_type = Some(content_type);
        self.body_declares_alt_used_trailer = false;
        self
    }

    /// Streams multipart fields and files with ordered content-type placement.
    ///
    /// Uses the same caller-slot or matching-header rules as [`Self::prepared_body`].
    /// The body is one-shot. A required resend fails before starting another attempt.
    ///
    /// ```no_run
    /// # async fn upload(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// use phantom::{HttpProtocol, Method, RequestHeader, StreamingMultipartBody, StreamingMultipartPart};
    ///
    /// let file = tokio::fs::File::open("upload.bin").await?;
    /// let field = StreamingMultipartPart::reader("file", file)?.with_filename("upload.bin")?;
    /// let body = StreamingMultipartBody::new("caller-boundary", [field], 16 * 1024 * 1024)?;
    /// let response = client.request_with_protocol(HttpProtocol::Http2, Method::POST, "https://example.com/upload")?
    ///     .header(RequestHeader::new("content-type", body.content_type()))
    ///     .multipart_body(body).send().await?;
    /// # drop(response);
    /// # Ok(())
    /// # }
    /// ```
    pub fn multipart_body(mut self, body: crate::StreamingMultipartBody) -> Self {
        self.prepared_content_type = Some(body.content_type().into());
        self.body = RequestBodySource::Streaming(Some(RequestBody::streaming(body)));
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
    /// request-body error before starting that attempt;
    /// [`Self::buffered_streaming_body`] keeps the body so it can be sent
    /// again. Trailer frames emitted
    /// by the source remain unsupported; use [`Self::streaming_body_with_trailers`]
    /// when the body produces trailers, or [`Self::trailers`] for static ones.
    pub fn streaming_body<B>(mut self, body: B) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        self.prepared_content_type = None;
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
        self.prepared_content_type = None;
        self.body_declares_alt_used_trailer = declares_alt_used_trailer(&trailer_names);
        self.body = RequestBodySource::Streaming(Some(RequestBody::streaming_with_trailers(
            body,
            trailer_names,
        )));
        self
    }

    /// Sets a pull-driven request body that a later attempt of this request
    /// may send again, keeping at most `maximum_bytes` of its data.
    ///
    /// The body streams as [`Self::streaming_body`] does, and each nonempty
    /// data frame is kept as it is sent, so the first attempt is not delayed.
    /// When a redirect, retry, or replay needs another attempt, that attempt
    /// sends the kept frames with the same frame boundaries and then reads on
    /// from the body where the last attempt stopped. Each replay keeps its own
    /// method and policy rules: the Chromium recipes' resend after a failed
    /// HTTP/2 PING, for one, sends any method again, so a server may receive
    /// a `POST` twice.
    ///
    /// Once more than `maximum_bytes` of data has been read, the kept frames
    /// are freed and the body is one-shot: the attempt in progress still
    /// sends all of it, and a later attempt fails with
    /// [`RequestErrorKind::RequestBody`](crate::RequestErrorKind::RequestBody),
    /// or, for a replay after a failure, the request returns that failure.
    /// Empty data frames pass through as read but are not kept for replay.
    /// The limit counts data bytes; a kept frame holds the buffer its bytes
    /// come from. Once [`Self::send`] returns, the kept frames are freed, at
    /// once or, while an attempt is still uploading, as it sends them.
    pub fn buffered_streaming_body<B>(mut self, body: B, maximum_bytes: usize) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        self.prepared_content_type = None;
        self.body = RequestBodySource::Buffered(ReplayBuffer::new(body, Vec::new(), maximum_bytes));
        self.body_declares_alt_used_trailer = false;
        self
    }

    /// Sets a pull-driven request body with a declared terminal trailer
    /// frame that a later attempt may send again, keeping at most
    /// `maximum_bytes` of its data.
    ///
    /// `trailer_names` is declared as for
    /// [`Self::streaming_body_with_trailers`], and the body is kept and sent
    /// again as for [`Self::buffered_streaming_body`]. The trailer frame is
    /// kept too and does not count toward `maximum_bytes`.
    pub fn buffered_streaming_body_with_trailers<B>(
        mut self,
        body: B,
        trailer_names: Vec<RequestTrailerName>,
        maximum_bytes: usize,
    ) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        self.prepared_content_type = None;
        self.body_declares_alt_used_trailer = declares_alt_used_trailer(&trailer_names);
        self.body =
            RequestBodySource::Buffered(ReplayBuffer::new(body, trailer_names, maximum_bytes));
        self
    }

    /// Sends `Expect: 100-continue` with the body and holds the body until
    /// the server answers `100 Continue`, or until `wait` has passed since
    /// the request head was written (RFC 9110, section 10.1.1). Off by
    /// default; neither Chrome 154 nor Firefox 157 sends the expectation.
    /// A `wait` too large to add to the runtime clock fails before any I/O
    /// with [`RequestErrorKind::InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout).
    ///
    /// Every attempt of the request waits again, including a redirect that
    /// keeps the body. A request without a body, or with a body of known
    /// length zero, sends no expectation. A field of yours named `Expect` takes the
    /// generated field's position and must be `100-continue`; another value
    /// fails before any I/O with
    /// [`RequestErrorKind::InvalidHeader`](crate::RequestErrorKind::InvalidHeader).
    /// Otherwise the field follows every other field.
    ///
    /// When a final response arrives while the body still waits, such as
    /// `417 Expectation Failed` or a `401`, it is returned and the body is
    /// not sent: an HTTP/2 or
    /// HTTP/3 stream is then cancelled once the response is read, and an
    /// HTTP/1.1 connection is closed. Phantom does not send the request
    /// again without the expectation. The wait counts toward the response
    /// head and total timeouts.
    pub fn expect_continue(mut self, wait: std::time::Duration) -> Self {
        self.request.expect_continue = Some(wait);
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

    pub(crate) fn selected_route(&self) -> Route {
        self.client.inner.defaults.selected_route(
            self.route.as_ref(),
            self.request.uri.scheme_str().unwrap_or_default(),
            &self.request.endpoint,
        )
    }

    /// Sends this exact HTTP/3 request to the alternative service at `host`
    /// and `port`, as a request to an alternative learned from `Alt-Svc`
    /// goes (RFC 7838): QUIC connects to that location over the request's
    /// route, and the request keeps the origin's authority, TLS server name,
    /// and certificate check. Under a profile whose
    /// [`Http3RequestSettings::alt_used`](crate::profile::Http3RequestSettings::alt_used)
    /// is `Append` or `ValidatedMapping`, an `Alt-Used` field names the
    /// alternative at the template's generated slot, or last without a slot.
    /// An explicit pin is immediately eligible under `ValidatedMapping`,
    /// including the Firefox 157 recipe. Chromium-family recipes omit it.
    ///
    /// This needs no Alt-Svc store and no TLS connection to learn from, so it
    /// also reaches an alternative through a CONNECT-UDP proxy. Setup retries
    /// follow the request's [`RetryPolicy`], where a learned alternative has
    /// none. A failure
    /// returns the HTTP/3 error: nothing falls back to the origin, not even
    /// under [`RetryPolicy::with_http2_fallback`], and no Alt-Svc state
    /// changes. A redirect to the same origin keeps the
    /// alternative; a redirect to another origin goes to that origin's own
    /// location.
    ///
    /// `host` is a lowercase name, a dotted IPv4 address, or an IPv6 address
    /// without brackets, each in canonical form. [`send`](Self::send) fails
    /// before any I/O with
    /// [`RequestErrorKind::InvalidAuthority`](crate::RequestErrorKind::InvalidAuthority)
    /// for another form or a zero port, with
    /// [`ProtocolUnavailable`](crate::RequestErrorKind::ProtocolUnavailable)
    /// when the request is not exact HTTP/3, and with
    /// [`InvalidHeader`](crate::RequestErrorKind::InvalidHeader) for a caller
    /// `Alt-Used` field or trailer.
    pub fn alt_svc_alternative(mut self, host: &str, port: u16) -> Self {
        self.alternative = Some((host.into(), port));
        self
    }

    /// Overrides individual client time limits for this operation.
    ///
    /// Without this call the request uses the policy set by
    /// [`ClientBuilder::request_timeouts`](crate::ClientBuilder::request_timeouts).
    /// Fields left as [`TimeoutOverride::Inherit`](crate::TimeoutOverride::Inherit)
    /// keep their client limits. [`RequestTimeoutOverrides::disabled`] disables
    /// every limit. A duration the runtime clock cannot represent fails
    /// [`Self::send`] with
    /// [`RequestErrorKind::InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout).
    pub fn timeouts(mut self, timeouts: RequestTimeoutOverrides) -> Self {
        self.timeouts = Some(timeouts);
        self
    }

    /// Replaces the client's retry policy for this request.
    ///
    /// Without this call the request uses the policy set by
    /// [`ClientBuilder::retry_policy`](crate::ClientBuilder::retry_policy).
    /// The policy applies to exact H1, H2, or H3 connection acquisition and to
    /// negotiated H1/H2 TCP connection setup before ALPN selection, always
    /// before request dispatch. Negotiated TLS and ALPN failures are terminal.
    /// Any opt-in reused-connection replay, unprocessed-request replay, or
    /// [`StatusRetry`](crate::StatusRetry) in `policy` also replaces the
    /// client's. The shared [`RetryPolicy::with_max_retries`] cap also
    /// replaces the client's cap. A delay the runtime clock cannot represent fails
    /// [`Self::send`] with
    /// [`RequestErrorKind::InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout).
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Replaces the client's redirect policy for this request.
    ///
    /// Without this call the request uses
    /// [`ClientBuilder::redirect_policy`](crate::ClientBuilder::redirect_policy).
    /// Use [`RedirectPolicy::none`] to return redirects to you, or
    /// [`RedirectPolicy::limited`] to follow them up to a hop limit.
    /// [`RedirectPolicy::custom`] adds a decision callback with the same limit.
    /// The override applies to every hop of this request. Other requests and
    /// client clones keep their client policy. Redirects retain the shared
    /// deadline, retry and attempt budgets, and credential-stripping rules.
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = Some(policy);
        self
    }

    /// Retains the first `maximum_entries` followed redirects for this request.
    ///
    /// Retrieve [`crate::RedirectHistory`] from the final response's extensions.
    /// Later hops are counted without retaining their URLs. History is disabled
    /// by default and does not enable following, change its limit, or record
    /// retries. Requests returning errors have no response history.
    ///
    /// ```no_run
    /// # async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// use std::num::NonZeroUsize;
    /// use phantom::{RedirectHistory, RedirectPolicy};
    /// let response = client.get("https://example.com/")?
    ///     .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
    ///     .redirect_history(NonZeroUsize::MIN)
    ///     .send().await?;
    /// if let Some(history) = response.extensions().get::<RedirectHistory>() {
    ///     for hop in history.entries() {
    ///         println!("{} -> {}", hop.from_uri(), hop.to_uri());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn redirect_history(mut self, maximum_entries: std::num::NonZeroUsize) -> Self {
        self.redirect_history = Some(maximum_entries);
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
    /// [`Self::send`] fails before the affected hop's I/O with
    /// [`RequestErrorKind::InvalidHeader`](crate::RequestErrorKind::InvalidHeader)
    /// for a malformed `Accept-Encoding` field, and with
    /// [`RequestErrorKind::RequestTemplate`](crate::RequestErrorKind::RequestTemplate)
    /// when the template's per-protocol lists carry different
    /// `Accept-Encoding` values for that forwarding state. With a template
    /// and no `Accept-Encoding` of your own, the final hop's URL and route
    /// select the template value used for decoding. Inactive forwarding
    /// values are ignored. A redirect that activates an invalid value fails
    /// before sending that hop.
    pub fn content_decoding(mut self, policy: ContentDecoding) -> Self {
        self.content_decoding = policy;
        self
    }

    #[cfg(feature = "sse")]
    pub(crate) fn without_response_body_timeouts(mut self) -> Self {
        self.response_body_timeouts = false;
        self
    }

    /// Shares an origin HTTP attempt allowance with other requests.
    ///
    /// Initial attempts and resends consume the same allowance, including
    /// redirects, enabled retries, GOAWAY/PING replays, client-hint negotiation
    /// and rejected early data. Cloned handles cannot overspend concurrently.
    /// Exhaustion returns [`RequestErrorKind::AttemptBudgetExhausted`](crate::RequestErrorKind::AttemptBudgetExhausted)
    /// before another attempt sends. Existing replay-safety rules still apply.
    ///
    /// Admission is conservative: an admitted attempt can fail before sending
    /// bytes and is not refunded. DNS, TCP/TLS, proxy CONNECT and SOCKS setup
    /// retain their own limits and are not separately charged as HTTP attempts.
    /// Requests have no shared allowance unless you attach one. Attach a clone
    /// of this same handle when your application initiates a resend.
    ///
    /// ```no_run
    /// # async fn example(client: &phantom::Client) -> Result<(), phantom::RequestError> {
    /// let budget = phantom::HttpAttemptBudget::new(20);
    /// for url in ["https://example.com/", "https://example.com/about"] {
    ///     let response = client.get_with_protocol(phantom::HttpProtocol::Http2, url)?
    ///         .attempt_budget(budget.clone()).send().await?;
    ///     drop(response);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn attempt_budget(mut self, budget: crate::HttpAttemptBudget) -> Self {
        self.attempt_budget = Some(budget);
        self
    }

    /// Sends the request through its client and selected route.
    ///
    /// The client may reuse compatible HTTP/1.1, HTTP/2, and HTTP/3
    /// connections on the same origin and route. A bodyless HTTP/2 GET without
    /// trailers is retried once if rejected by `GOAWAY(NO_ERROR)`. This applies
    /// to exact and negotiated requests. The retry uses a replacement
    /// connection. A negotiated replacement repeats ALPN selection.
    ///
    /// Dropping this future cancels the request. Returned bodies keep their
    /// protocol's cancellation rules. Enable [`RetryPolicy`] to retry eligible
    /// connection setup without sending request bytes or body frames again.
    /// For negotiated requests, those retries happen before ALPN selection.
    /// The policy can also replay idempotent requests after a reused connection
    /// closes, or retry selected statuses for idempotent methods. It can replay
    /// requests the peer did not process.
    /// [`RetryPolicy::with_http2_fallback`] enables HTTP/2 fallback
    /// when an exact HTTP/3 request cannot open a QUIC connection.
    ///
    /// With a [`RedirectPolicy`](crate::RedirectPolicy), each `http://` or `https://`
    /// redirect target is checked against the request's protocol selection
    /// and route before it is sent, as the first request is.
    ///
    /// # Errors
    ///
    /// Returns a [`RequestError`]. [`RequestError::kind`] gives the category.
    /// Initial validation returns these kinds before any I/O. A redirect
    /// that activates an invalid template value fails before that hop's I/O:
    ///
    /// - [`InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout) when a
    ///   timeout or retry delay exceeds the runtime clock range, or a retry
    ///   backoff cap is below its initial delay;
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
    /// - [`AttemptBudgetExhausted`](crate::RequestErrorKind::AttemptBudgetExhausted)
    ///   when the supplied shared attempt allowance is exhausted;
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
    ///     .get_with_protocol(HttpProtocol::Http2, "https://example.com/")?
    ///     .send()
    ///     .await?;
    /// assert!(response.status().is_success());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send(self) -> Result<Response<ResponseBody>, RequestError> {
        let hooks = crate::request_hook::ActiveRequestHooks::start(
            &self.method,
            &self.request.uri,
            self.client.inner.defaults.request_hooks.as_ref(),
            self.request_hooks.as_ref(),
        );
        let origin = self.request.origin();
        let route = self.selected_route();
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
            http2_fallbacks = 0_u64,
            timeout_phase = field::Empty,
            outcome = field::Empty,
        );
        let outcome = RequestOutcome::new(&span);
        if let ProtocolSelection::Exact(protocol) = self.selection {
            span.record("selected_protocol", protocol.trace_name());
        }
        // Keep the public future small when callers join many requests.
        let diagnostics = self.diagnostics.clone();
        let operation =
            crate::session::box_send_unscoped(self.send_inner(&span).instrument(span.clone()));
        let result = match diagnostics {
            Some(diagnostics) => diagnostics.observe(operation).await,
            None => phantom_net::request_diagnostics::Observation::scope(None, operation).await,
        }
        .map_err(|error| error.with_origin(origin));
        if let Err(error) = &result
            && let Some(phase) = error.timeout_phase()
        {
            span.record("timeout_phase", phase.trace_name());
        }
        if let Some(hooks) = hooks {
            hooks.finish(&result);
        }
        outcome.finish(match &result {
            Ok(_) => "ok",
            Err(error) if error.timeout_phase().is_some() => "timeout",
            Err(_) => "error",
        });
        result
    }

    async fn send_inner(
        mut self,
        request_span: &Span,
    ) -> Result<Response<ResponseBody>, RequestError> {
        let activity = self.client.state.lifecycle.enter()?;
        let retry_policy = self.retry_policy.unwrap_or(self.client.state.retry_policy);
        let http2_fallback = retry_policy.http2_fallback() && retry_policy.max_retries() != Some(0);
        let initial_fallback = http2_fallback && self.alternative.is_none();
        let scope = self.slot_scope();
        let mut filled_slots = std::mem::take(&mut self.filled_slots);

        if let Some(content_type) = &self.prepared_content_type {
            if !self
                .headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case("content-type"))
                && self.request.template.as_ref().is_some_and(|prepared| {
                    template::caller_slot_is_declared(
                        prepared,
                        scope,
                        initial_fallback,
                        "content-type",
                    )
                })
                && template::place_prepared_content_type(
                    self.request.template.as_ref(),
                    template::ProtocolScope {
                        exact: match self.selection {
                            ProtocolSelection::Exact(protocol) => Some(protocol),
                            ProtocolSelection::Http1Or2 => None,
                        },
                        alt_svc: negotiated_http3_available(
                            &self.client,
                            &self.request,
                            &self.selected_route(),
                        ),
                        content_decoding: false,
                    },
                    initial_fallback,
                    &mut self.headers,
                    content_type,
                )?
            {
                filled_slots.push(Box::<str>::from("content-type"));
            }

            if self.trailers.is_empty()
                && !self.body.has_trailers()
                && let Some(length) = self.body.exact_length()
                && template::place_prepared_content_length(
                    self.request.template.as_ref(),
                    scope,
                    initial_fallback,
                    &mut self.headers,
                    length,
                )?
            {
                filled_slots.push(Box::<str>::from("content-length"));
            }
        }

        {
            let mut context = crate::HeaderHookContext {
                method: &self.method,
                uri: &self.request.uri,
                headers: &mut self.headers,
                protected: self.protected_hook_headers,
            };
            if self.client_header_hooks {
                for hook in &self.client.inner.defaults.header_hooks {
                    hook.run(&mut context).map_err(RequestError::header_hook)?;
                }
            }

            for hook in &self.header_hooks {
                hook.run(&mut context).map_err(RequestError::header_hook)?;
            }
        }

        if let Some(content_type) = &self.prepared_content_type {
            let mut fields = self
                .headers
                .iter()
                .filter(|header| header.name().eq_ignore_ascii_case("content-type"));
            if !fields
                .next()
                .is_some_and(|header| header.value() == content_type.as_bytes())
                || fields.next().is_some()
            {
                return Err(RequestError::prepared_body_content_type(
                    "prepared body needs one matching Content-Type field",
                ));
            }
        }

        template::check_filled_slots(
            self.request.template.as_ref(),
            self.slot_scope(),
            initial_fallback,
            &self.headers,
            &filled_slots,
        )?;

        let timeout_budget = crate::timeout::TimeoutBudget::new(
            self.timeouts
                .unwrap_or_default()
                .resolve(self.client.state.request_timeouts),
        )?;

        if let Err(message) = retry_policy.validate() {
            return Err(RequestError::invalid_retry_policy(message));
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

        if let Some(wait) = self.request.expect_continue {
            if std::time::Instant::now().checked_add(wait).is_none() {
                return Err(RequestError::invalid_timeout());
            }

            let mut expectations = self
                .headers
                .iter()
                .filter(|header| header.name().eq_ignore_ascii_case("expect"));
            if let Some(first) = expectations.next()
                && (expectations.next().is_some()
                    || !first
                        .value()
                        .trim_ascii()
                        .eq_ignore_ascii_case(b"100-continue"))
            {
                return Err(RequestError::expectation_header());
            }
        }

        let alternative = match &self.alternative {
            Some(_)
                if !matches!(
                    self.selection,
                    ProtocolSelection::Exact(HttpProtocol::Http3)
                ) =>
            {
                return Err(RequestError::alternative_needs_http3());
            }
            Some((host, port)) => Some(
                PinnedAlternative::parse(host, *port)
                    .ok_or_else(RequestError::invalid_alternative)?,
            ),
            None => None,
        };

        if (negotiated_http3_available(&self.client, &self.request, &self.selected_route())
            || alternative.is_some())
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
            let route = self.selected_route();
            let scope = template::ProtocolScope {
                exact: match self.selection {
                    ProtocolSelection::Exact(protocol) => Some(protocol),
                    ProtocolSelection::Http1Or2 => None,
                },
                // A route that cannot carry QUIC never moves a negotiated
                // request to HTTP/3, so it needs no HTTP/3 list.
                alt_svc: negotiated_http3_available(&self.client, &self.request, &route),
                content_decoding: content_decoding.is_enabled(),
            };
            template::check_with_managed_headers(
                template,
                scope,
                initial_fallback,
                &self.headers,
                self.client.inner.defaults.client_hints.as_ref(),
                self.request.managed_headers,
                (
                    secure_context::is_potentially_trustworthy(&self.request.url),
                    route.forwards(&self.request.uri),
                ),
            )?;
        }

        let Self {
            client,
            request,
            selection,
            method,
            headers: request_headers,
            trailers: request_trailers,
            body,
            prepared_content_type: _,
            filled_slots: _,
            header_hooks: _,
            request_hooks: _,
            client_header_hooks: _,
            protected_hook_headers: _,
            route,
            timeouts: _,
            retry_policy: _,
            redirect_policy,
            redirect_history,
            attempt_budget,
            diagnostics: _,
            content_decoding: _,
            response_body_timeouts,
            body_declares_alt_used_trailer: _,
            alternative: _,
        } = self;
        let mut request = request;
        request.alternative = alternative;
        let body = body.with_continue_wait(request.expect_continue);
        let route_override = route;
        let selected_route = client.inner.defaults.selected_route(
            route_override.as_ref(),
            request.uri.scheme_str().unwrap_or_default(),
            &request.endpoint,
        );
        let route = &selected_route;
        let mut retries = ConnectionSetupRetryState::new(retry_policy, request_span.clone());
        retries.set_attempt_budget(attempt_budget);
        let mut replays = ReplayState::new(client.inner.policy.http2_ping_failure_retries);
        client
            .inner
            .policy
            .ensure_pinned_route(request.uri.scheme_str().unwrap_or_default(), route)?;
        ensure_request_supported(selection, route, &request)?;
        if request.alternative.is_none() {
            ensure_http2_fallback_supported(&client, selection, route, retry_policy)?;
        }
        // A caller's preemptive field goes to the forward proxy, as it does on
        // CONNECT. On any other route it would reach the origin, and with
        // configured credentials it would conflict with the generated field.
        let forwards_caller_proxy_authorization = route
            .as_http_proxy()
            .is_some_and(|proxy| proxy.credentials().is_none());
        if request.uri.scheme_str() == Some("http")
            && !forwards_caller_proxy_authorization
            && request_headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case("proxy-authorization"))
        {
            return Err(RequestError::forward_proxy_authorization_header());
        }
        let policy = redirect_policy.unwrap_or_else(|| client.state.redirect_policy.clone());
        let mut history = redirect_history.map(crate::RedirectHistory::new);

        if policy.max_hops().is_none() {
            let mut body = body;
            let advertised = AdvertisedByTrust::for_route(
                content_decoding,
                request.template.as_ref(),
                &request_headers,
                route.forwards(&request.uri),
            )?;
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
            response.body_mut().finish_diagnostics_if_empty();
            response.body_mut().retain_activity(activity);
            if let Some(history) = history {
                response.extensions_mut().insert(history);
            }
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
            let selected_route = client.inner.defaults.selected_route(
                route_override.as_ref(),
                resolved.uri.scheme_str().unwrap_or_default(),
                &resolved.endpoint,
            );
            let route = &selected_route;
            template::check_filled_slots(
                resolved.template.as_ref(),
                template::ProtocolScope {
                    exact: match selection {
                        ProtocolSelection::Exact(protocol) => Some(protocol),
                        ProtocolSelection::Http1Or2 => None,
                    },
                    alt_svc: negotiated_http3_available(&client, &resolved, route),
                    content_decoding: false,
                },
                http2_fallback && resolved.alternative.is_none(),
                redirect.headers(),
                &filled_slots,
            )
            .map_err(|error| error.with_origin(resolved.origin()))?;
            client
                .inner
                .policy
                .ensure_pinned_route(resolved.uri.scheme_str().unwrap_or(""), route)
                .map_err(|error| error.with_origin(resolved.origin()))?;
            ensure_request_supported(selection, route, &resolved)
                .map_err(|error| error.with_origin(resolved.origin()))?;
            if resolved.alternative.is_none() {
                ensure_http2_fallback_supported(&client, selection, route, retry_policy)
                    .map_err(|error| error.with_origin(resolved.origin()))?;
            }
            if let Some(template) = &resolved.template {
                template::check_with_managed_headers(
                    template,
                    template::ProtocolScope {
                        exact: match selection {
                            ProtocolSelection::Exact(protocol) => Some(protocol),
                            ProtocolSelection::Http1Or2 => None,
                        },
                        alt_svc: negotiated_http3_available(&client, &resolved, route),
                        content_decoding: content_decoding.is_enabled(),
                    },
                    http2_fallback && resolved.alternative.is_none(),
                    redirect.headers(),
                    client.inner.defaults.client_hints.as_ref(),
                    resolved.managed_headers,
                    (
                        secure_context::is_potentially_trustworthy(&resolved.url),
                        route.forwards(&resolved.uri),
                    ),
                )
                .map_err(|error| error.with_origin(resolved.origin()))?;
            }
            let advertised = AdvertisedByTrust::for_route(
                content_decoding,
                resolved.template.as_ref(),
                redirect.headers(),
                route.forwards(&resolved.uri),
            )
            .map_err(|error| error.with_origin(resolved.origin()))?;
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
            let history_source = history
                .as_ref()
                .filter(|history| !history.is_full())
                .map(|_| (resolved.uri.clone(), redirect.method().clone()));
            let redirect_status = response.status();
            match redirect
                .follow(&response)
                .map_err(|error| error.with_origin(resolved.origin()))?
            {
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
                    response.body_mut().finish_diagnostics_if_empty();
                    response.body_mut().retain_activity(activity);
                    if let Some(mut history) = history {
                        history.finish(redirect.followed());
                        response.extensions_mut().insert(history);
                    }
                    return Ok(response);
                }
                RedirectAction::Follow { same_origin } => {
                    if !same_origin
                        && let Some(settings) = client.inner.defaults.client_hints.as_ref()
                    {
                        redirect.strip_client_hints(settings, resolved.managed_headers);
                    }
                    debug!(
                        hop = redirect.followed(),
                        status = response.status().as_u16(),
                        same_origin,
                        "following redirect"
                    );
                    drop(response);
                    let mut template = resolved.template.take();
                    if !same_origin {
                        template = template
                            .map(|template| template.without_credentials(redirect.policy()));
                    }
                    let expect_continue = resolved.expect_continue;
                    let transfer = resolved.transfer.take();
                    let managed_headers = resolved.managed_headers;
                    let alternative = resolved.alternative.take().filter(|_| same_origin);
                    resolved = ResolvedRequest::from_redirect_url(redirect.current_url())
                        .map_err(|error| error.with_origin(resolved.origin()))?;
                    if let (Some(history), Some((from, method))) =
                        (history.as_mut(), history_source)
                    {
                        history.push(crate::RedirectHop::new(
                            from,
                            resolved.uri.clone(),
                            method,
                            redirect.method().clone(),
                            redirect_status,
                        ));
                    }
                    resolved.template = template;
                    resolved.expect_continue = expect_continue;
                    resolved.transfer = transfer;
                    resolved.managed_headers = managed_headers;
                    resolved.alternative = alternative;
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
    /// Parses both URL-trust values for this hop's actual forwarding state.
    /// A redirect may activate another state, which is checked before its I/O.
    fn for_route(
        policy: ContentDecoding,
        template: Option<&PreparedRequestTemplate>,
        headers: &[RequestHeader],
        forwarded: bool,
    ) -> Result<Self, RequestError> {
        if !policy.is_enabled() {
            return Ok(Self::default());
        }
        Ok(Self {
            untrustworthy: advertised_codings(template, headers, false, forwarded)?,
            trustworthy: advertised_codings(template, headers, true, forwarded)?,
        })
    }

    fn for_url(self, url: &url::Url) -> AdvertisedContentCodings {
        if secure_context::is_potentially_trustworthy(url) {
            self.trustworthy
        } else {
            self.untrustworthy
        }
    }
}

/// Whether negotiated requests on this route can select HTTP/3.
fn negotiated_http3_available(client: &Client, request: &ResolvedRequest, route: &Route) -> bool {
    (client.alt_svc_enabled() && route.carries_quic_alternative())
        || (request.uri.scheme_str() == Some("https")
            && matches!(route, Route::Direct)
            && client
                .inner
                .transport
                .connectors_for(&request.endpoint)
                .http3
                .is_some_and(|connector| {
                    connector.connection_reuse_policy()
                        == phantom_profile::Http3ConnectionReuse::AuthorizedOrigins
                }))
}

/// Returns the content codings the request advertises to a URL of this
/// trust and forwarding state.
///
/// A template's `Accept-Encoding` for that trust is sent when the caller
/// supplies none, so it is advertised too.
fn advertised_codings(
    template: Option<&PreparedRequestTemplate>,
    headers: &[RequestHeader],
    trustworthy: bool,
    forwarded: bool,
) -> Result<AdvertisedContentCodings, RequestError> {
    let caller_supplied = headers
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case("accept-encoding"));
    match template.and_then(|template| template.accept_encoding(trustworthy, forwarded)) {
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

/// A request body whose framing an attempt's fields are built from, owned
/// for this purpose or borrowed from the request.
pub(crate) enum RequestBodyFraming<'a> {
    Owned(RequestBody),
    Borrowed(&'a RequestBody),
}

impl RequestBodyFraming<'_> {
    pub(crate) const fn body(&self) -> &RequestBody {
        match self {
            Self::Owned(body) => body,
            Self::Borrowed(body) => body,
        }
    }
}

pub(crate) enum RequestBodySource {
    Absent,
    Bytes(Bytes),
    Streaming(Option<RequestBody>),
    Buffered(ReplayBuffer),
}

impl RequestBodySource {
    pub(crate) fn has_credential_trailers(&self, policy: &RedirectPolicy) -> bool {
        matches!(self, Self::Buffered(body) if body.has_credential_trailers(policy))
    }

    fn has_trailers(&self) -> bool {
        match self {
            Self::Streaming(Some(body)) => body.metadata().has_trailers(),
            Self::Buffered(body) => body.has_trailers(),
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
            Self::Buffered(body) => body
                .next_attempt()
                .map(Some)
                .map_err(|reason| match reason {
                    NoReplay::Failed => RequestError::request_body_not_replayable(),
                    NoReplay::Exhausted => RequestError::request_body_replay_limit(),
                }),
        }
    }

    /// Returns whether another attempt could send this body: absent, owned
    /// bytes, or a buffered body within its limit whose source has not
    /// failed.
    pub(crate) fn can_replay(&self) -> bool {
        match self {
            Self::Absent | Self::Bytes(_) => true,
            Self::Streaming(_) => false,
            Self::Buffered(body) => body.no_replay().is_none(),
        }
    }

    /// Returns a body with this source's framing for building an attempt's
    /// fields without starting an attempt, or `None` without a body.
    ///
    /// `continue_wait` arms an owned or buffered body as its attempts are;
    /// a one-shot body was armed when the request started.
    pub(crate) fn framing(
        &self,
        continue_wait: Option<std::time::Duration>,
    ) -> Result<Option<RequestBodyFraming<'_>>, RequestError> {
        let armed = |body: RequestBody| match continue_wait {
            Some(wait) => body.expect_continue(wait),
            None => body,
        };
        match self {
            Self::Absent => Ok(None),
            Self::Bytes(bytes) => Ok(Some(RequestBodyFraming::Owned(armed(
                RequestBody::from_bytes(bytes.clone()),
            )))),
            Self::Streaming(Some(body)) => Ok(Some(RequestBodyFraming::Borrowed(body))),
            Self::Streaming(None) => Err(RequestError::request_body_not_replayable()),
            Self::Buffered(body) => {
                Ok(Some(RequestBodyFraming::Owned(armed(body.metadata_body()))))
            }
        }
    }

    /// Arms a one-shot body to wait for `100 Continue`. Owned and buffered
    /// bodies make a new body for each attempt, which is armed then.
    fn with_continue_wait(self, wait: Option<std::time::Duration>) -> Self {
        match (self, wait) {
            (Self::Streaming(Some(body)), Some(wait)) => {
                Self::Streaming(Some(body.expect_continue(wait)))
            }
            (body, _) => body,
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::Absent;
    }

    /// Takes back a streaming body that an attempt returned unpolled, so the
    /// next attempt sends it. Owned bytes are copied for each attempt and a
    /// buffered body starts each attempt over, so neither needs anything
    /// back.
    pub(crate) fn restore(&mut self, body: Option<RequestBody>) {
        if let (Self::Streaming(slot @ None), Some(body)) = (&mut *self, body) {
            *slot = Some(body);
        }
    }

    #[cfg(test)]
    pub(crate) fn replayable_bytes(&self) -> Option<&Bytes> {
        match self {
            Self::Bytes(body) => Some(body),
            Self::Absent | Self::Streaming(_) | Self::Buffered(_) => None,
        }
    }

    fn exact_length(&self) -> Option<u64> {
        match self {
            Self::Absent | Self::Streaming(None) => None,
            Self::Bytes(body) => Some(body.len() as u64),
            Self::Streaming(Some(body)) => body.metadata().exact_length(),
            Self::Buffered(body) => body.exact_length(),
        }
    }

    const fn trace_kind(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Bytes(_) => "bytes",
            Self::Streaming(_) => "stream",
            Self::Buffered(_) => "buffered",
        }
    }
}

pub(crate) fn request_uri_error(error: ParseUriError) -> RequestError {
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
            (ProtocolSelection::Exact(HttpProtocol::Http2), Route::Direct) => Ok(()),
            (
                ProtocolSelection::Exact(HttpProtocol::Http2),
                Route::Socks4(_) | Route::Socks5(_) | Route::ConnectUdp(_),
            ) => Err(RequestError::unsupported_route(HttpProtocol::Http2)),
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
                Route::Direct | Route::HttpProxy(_) | Route::Socks4(_) | Route::Socks5(_),
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
                Route::HttpProxy(_) | Route::Socks4(_) => {
                    Err(RequestError::unsupported_route(HttpProtocol::Http3))
                }
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

/// Checks before any I/O that an exact HTTP/3 request that may fall back to
/// HTTP/2 has an HTTP/2 path: an HTTP/2 profile and a route that carries TCP.
fn ensure_http2_fallback_supported(
    client: &Client,
    selection: ProtocolSelection,
    route: &Route,
    policy: RetryPolicy,
) -> Result<(), RequestError> {
    if !policy.http2_fallback()
        || policy.max_retries() == Some(0)
        || !matches!(selection, ProtocolSelection::Exact(HttpProtocol::Http3))
    {
        return Ok(());
    }
    if client.inner.transport.http2.is_none() {
        return Err(RequestError::unsupported_protocol(HttpProtocol::Http2));
    }
    // CONNECT-UDP carries only QUIC.
    if matches!(route, Route::ConnectUdp(_)) {
        return Err(RequestError::unsupported_route(HttpProtocol::Http2));
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
    transfer: Option<crate::TransferControl>,
    uri: Uri,
    url: url::Url,
    endpoint: Endpoint,
    target: OriginForm,
    absolute_target: AbsoluteForm,
    template: Option<PreparedRequestTemplate>,
    /// Fields owned by a higher-level request, excluded from hint handling.
    managed_headers: &'static [&'static str],
    /// How long each attempt waits for `100 Continue` before it sends a
    /// body, when it sends `Expect: 100-continue`.
    expect_continue: Option<std::time::Duration>,
    /// The caller-pinned alternative of an exact HTTP/3 request.
    pub(super) alternative: Option<PinnedAlternative>,
}

impl ResolvedRequest {
    fn origin(&self) -> crate::RequestOrigin {
        crate::RequestOrigin::from_endpoint(self.uri.scheme_str() == Some("https"), &self.endpoint)
    }

    fn append_query(&mut self, encoded: &str) -> Result<(), RequestError> {
        if encoded.is_empty() {
            return Ok(());
        }
        let mut target = self.uri.path().to_owned();
        target.push('?');
        if let Some(existing) = self.uri.query() {
            target.push_str(existing);
            if !existing.is_empty() {
                target.push('&');
            }
        }
        target.push_str(encoded);

        let mut parts = self.uri.clone().into_parts();
        parts.path_and_query = Some(target.parse().map_err(RequestError::invalid_uri)?);
        let uri = Uri::from_parts(parts).map_err(RequestError::invalid_uri_parts)?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(RequestError::invalid_target)?;
        let absolute_target =
            AbsoluteForm::from_uri(uri.clone()).map_err(RequestError::invalid_absolute_target)?;
        let url = url::Url::parse(&uri.to_string()).map_err(RequestError::invalid_url)?;

        self.uri = uri;
        self.url = url;
        self.target = target;
        self.absolute_target = absolute_target;
        Ok(())
    }

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
            transfer: None,
            url,
            endpoint,
            target,
            absolute_target,
            template: None,
            managed_headers: &[],
            expect_continue: None,
            alternative: None,
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
            transfer: None,
            url: wire_url,
            endpoint,
            target,
            absolute_target,
            template: None,
            managed_headers: &[],
            expect_continue: None,
            alternative: None,
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
mod tests;
