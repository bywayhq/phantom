use std::{fmt, time::Duration};

use http::{HeaderName, Response, StatusCode};
use phantom_net::request::RequestHeader;
use phantom_profile::{ClientHintDelivery, RequestField};
use tokio::time::Instant;
use tracing::{Instrument, debug, debug_span, field};

use crate::{
    Client, HttpProtocol, RequestBuilder, RequestError, RequestTimeoutOverrides, ResponseBody,
    Route,
};

use super::{ReconnectFuture, SseEventSource};
use crate::sse::{SseError, SseLimits, SseOutcome, SseStream};

const DEFAULT_INITIAL_RETRY: Duration = Duration::from_secs(3);
const DEFAULT_MAX_RECONNECTS: usize = 3;
const LAST_EVENT_ID: &str = "last-event-id";

fn default_headers(protocol: HttpProtocol) -> Vec<SseHeader> {
    let (accept, cache_control) = match protocol {
        HttpProtocol::Http1 => ("Accept", "Cache-Control"),
        HttpProtocol::Http2 | HttpProtocol::Http3 => ("accept", "cache-control"),
    };
    vec![
        SseHeader::field(RequestHeader::new(accept, "text/event-stream")),
        SseHeader::field(RequestHeader::new(cache_control, "no-cache")),
    ]
}

/// One field or reconnect-state placeholder in an EventSource request.
///
/// ```no_run
/// use phantom::{Client, HttpProtocol, RequestHeader, SseHeader};
///
/// async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
///     let response = client
///         .event_source(HttpProtocol::Http1, "https://example.com/events")?
///         .headers(vec![
///             SseHeader::field(RequestHeader::new("Accept", "text/event-stream")),
///             SseHeader::last_event_id("Last-Event-ID"),
///             SseHeader::field(RequestHeader::new("Pragma", "no-cache")),
///             SseHeader::field(RequestHeader::new("Cache-Control", "no-cache")),
///         ])
///         .connect()
///         .await?;
///     let mut events = response.into_body();
///     while let Some(event) = events.next_event().await? {
///         println!("{}", event.data());
///     }
///     Ok(())
/// }
/// ```
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum SseHeader {
    /// Inserts the committed `Last-Event-ID` at this position when it is
    /// nonempty, using the supplied field-name spelling.
    LastEventId {
        /// Exact field-name spelling to emit.
        name: Box<str>,
    },
    /// Emits one literal ordered field.
    Field(RequestHeader),
}

impl SseHeader {
    /// Creates a `Last-Event-ID` placeholder with caller-controlled spelling.
    #[must_use]
    pub fn last_event_id(name: impl Into<Box<str>>) -> Self {
        Self::LastEventId { name: name.into() }
    }

    /// Creates a literal ordered field.
    #[must_use]
    pub fn field(header: RequestHeader) -> Self {
        Self::Field(header)
    }
}

impl fmt::Debug for SseHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, name) = match self {
            Self::LastEventId { name } => ("last_event_id", name.as_ref()),
            Self::Field(header) => ("field", header.name()),
        };
        formatter
            .debug_struct("SseHeader")
            .field("kind", &kind)
            .field("name", &name)
            .finish()
    }
}

/// Builds one client-owned server-sent event source.
///
/// Created by [`Client::event_source`]. Unless changed, the builder uses:
///
/// - the fields `Accept: text/event-stream` and `Cache-Control: no-cache`,
///   lowercase on HTTP/2 and HTTP/3;
/// - the client's route and request timeouts;
/// - [`SseLimits::default`];
/// - no idle timeout;
/// - an initial reconnect delay of 3 seconds and no minimum delay; and
/// - a budget of 3 reconnect requests.
///
/// Every attempt is an ordinary GET on exactly the chosen protocol, so the
/// client's retry policy, redirect policy, and cookie jar apply to each one.
/// A redirected stream reconnects to the original URL.
#[must_use = "SSE request builders do nothing until connect is awaited"]
pub struct SseRequestBuilder {
    request: SseRequest,
    limits: SseLimits,
    idle_timeout: Option<Duration>,
    initial_retry: Duration,
    min_retry: Option<Duration>,
    max_reconnects: usize,
}

impl fmt::Debug for SseRequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SseRequestBuilder")
            .field("protocol", &self.request.protocol)
            .field("header_count", &self.request.headers.len())
            .field("route_override", &self.request.route.is_some())
            .field("timeout_override", &self.request.timeouts.is_some())
            .field("limits", &self.limits)
            .field("idle_timeout", &self.idle_timeout)
            .field("initial_retry", &self.initial_retry)
            .field("min_retry", &self.min_retry)
            .field("max_reconnects", &self.max_reconnects)
            .finish_non_exhaustive()
    }
}

impl SseRequestBuilder {
    pub(crate) fn new_client(
        client: Client,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<Self, RequestError> {
        let _ = client.get(protocol, uri)?;
        Ok(Self {
            request: SseRequest {
                client,
                protocol,
                uri: uri.into(),
                headers: default_headers(protocol),
                route: None,
                timeouts: None,
            },
            limits: SseLimits::default(),
            idle_timeout: None,
            initial_retry: DEFAULT_INITIAL_RETRY,
            min_retry: None,
            max_reconnects: DEFAULT_MAX_RECONNECTS,
        })
    }

    /// Appends one literal ordered request field after the current template.
    ///
    /// A literal `Last-Event-ID` is rejected by [`SseRequestBuilder::connect`];
    /// use [`SseHeader::last_event_id`] to position the managed field.
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.request.headers.push(SseHeader::field(header));
        self
    }

    /// Replaces the complete ordered request-field template, including the
    /// EventSource defaults.
    ///
    /// The template may contain one [`SseHeader::LastEventId`] placeholder
    /// whose name spells `Last-Event-ID` in any case, or in lowercase for
    /// HTTP/2 and HTTP/3. The placeholder emits the committed event ID at its
    /// position and nothing while the ID is empty. Without a placeholder, a
    /// nonempty ID is appended after every template field. A literal
    /// `Last-Event-ID` field is rejected. [`SseRequestBuilder::connect`]
    /// validates the template before any I/O. The client's inherited request
    /// template may position the managed field with an optional caller slot,
    /// but may not supply a default `Last-Event-ID` value on the active URL and
    /// route. A redirect that activates such a default fails before sending
    /// that hop. Automatic client hints never replace this managed field.
    pub fn headers(mut self, headers: Vec<SseHeader>) -> Self {
        self.request.headers = headers;
        self
    }

    /// Overrides the client's route for every connection attempt.
    pub fn route(mut self, route: Route) -> Self {
        self.request.route = Some(route);
        self
    }

    /// Overrides individual client time limits for every connection attempt.
    ///
    /// Unchanged fields inherit the client limits. Pool, connection, and
    /// response-head limits apply to each attempt. The
    /// generic body and total timers end after the response head; established
    /// streams use [`Self::idle_timeout`] and the finite reconnect budget.
    pub fn request_timeouts(mut self, timeouts: RequestTimeoutOverrides) -> Self {
        self.request.timeouts = Some(timeouts);
        self
    }

    /// Sets the event-stream decoding bounds; the default is
    /// [`SseLimits::default`].
    pub fn limits(mut self, limits: SseLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the maximum interval without an HTTP DATA frame.
    ///
    /// The timeout is disabled by default. Comments, partial events, and empty
    /// DATA frames count as activity. An idle response reconnects within the
    /// same finite budget as a disconnected response. A timeout too large to
    /// add to the runtime clock makes [`Self::connect`] fail with
    /// [`SseErrorKind::InvalidIdleTimeout`].
    ///
    /// [`SseErrorKind::InvalidIdleTimeout`]: crate::SseErrorKind::InvalidIdleTimeout
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Sets the delay used until the server supplies a valid `retry` field.
    ///
    /// The default is 3 seconds, as in Chrome. No jitter is added. When the
    /// reconnect budget is nonzero, a delay too large to add to the runtime
    /// clock makes [`Self::connect`] fail with
    /// [`SseErrorKind::InvalidReconnectDelay`].
    ///
    /// [`SseErrorKind::InvalidReconnectDelay`]: crate::SseErrorKind::InvalidReconnectDelay
    pub fn initial_retry(mut self, delay: Duration) -> Self {
        self.initial_retry = delay;
        self
    }

    /// Raises every reconnect delay shorter than `minimum` to `minimum`.
    ///
    /// Unset by default, so the initial delay and every valid server `retry`
    /// value are used exactly. When set, it also applies to the initial delay
    /// and to retries of the initial request; longer delays are unchanged.
    pub fn min_retry(mut self, minimum: Duration) -> Self {
        self.min_retry = Some(minimum);
        self
    }

    /// Sets the finite number of requests allowed after the initial attempt.
    ///
    /// The default is 3. Zero disables reconnects. Failed initial attempts,
    /// disconnects, and idle timeouts all draw from this one budget.
    pub fn max_reconnects(mut self, maximum: usize) -> Self {
        self.max_reconnects = maximum;
        self
    }

    /// Sends the initial request and retains its response metadata.
    ///
    /// Transport failures use the configured delay and reconnect budget until
    /// a response is received. A 204 response creates a closed event source.
    /// Other non-200 responses, an invalid event-stream content type, and
    /// unsupported content encodings fail without reconnecting.
    ///
    /// # Errors
    ///
    /// Returns [`SseError`] with kind:
    ///
    /// - [`SseErrorKind::InvalidRequestHeader`] for a literal `Last-Event-ID`
    ///   field, an invalid or repeated placeholder, or a default
    ///   `Last-Event-ID` value in the inherited request template or automatic
    ///   client hints that can emit on the initial request, before any I/O;
    /// - [`SseErrorKind::InvalidReconnectDelay`] or
    ///   [`SseErrorKind::InvalidIdleTimeout`] for a delay too large to add to
    ///   the runtime clock, before any I/O;
    /// - [`SseErrorKind::Request`] when the request fails in a way a repeat
    ///   cannot fix, or fails with no reconnect budget; this includes a
    ///   redirect that activates an inherited `Last-Event-ID` default;
    /// - [`SseErrorKind::ReconnectLimit`] when every attempt within the budget
    ///   failed;
    /// - [`SseErrorKind::UnexpectedStatus`],
    ///   [`SseErrorKind::InvalidContentType`], or
    ///   [`SseErrorKind::UnsupportedContentEncoding`][encoding] when the
    ///   response fails validation.
    ///
    /// [`SseErrorKind::InvalidRequestHeader`]: crate::SseErrorKind::InvalidRequestHeader
    /// [`SseErrorKind::InvalidReconnectDelay`]: crate::SseErrorKind::InvalidReconnectDelay
    /// [`SseErrorKind::InvalidIdleTimeout`]: crate::SseErrorKind::InvalidIdleTimeout
    /// [`SseErrorKind::Request`]: crate::SseErrorKind::Request
    /// [`SseErrorKind::ReconnectLimit`]: crate::SseErrorKind::ReconnectLimit
    /// [`SseErrorKind::UnexpectedStatus`]: crate::SseErrorKind::UnexpectedStatus
    /// [`SseErrorKind::InvalidContentType`]: crate::SseErrorKind::InvalidContentType
    /// [encoding]: crate::SseErrorKind::UnsupportedContentEncoding
    pub async fn connect(self) -> Result<Response<SseEventSource>, SseError> {
        let mut request = self
            .request
            .client
            .get(self.request.protocol, &self.request.uri)
            .map_err(SseError::request)?;
        if let Some(route) = &self.request.route {
            request = request.route(route.clone());
        }
        let route = request.selected_route();
        let span = debug_span!(
            "sse.event_source.connect",
            protocol = self.request.protocol.trace_name(),
            route = route.trace_name(),
            reconnects = field::Empty,
            outcome = field::Empty,
        );
        let outcome = SseOutcome::new(&span);
        let result = self.connect_inner().instrument(span.clone()).await;
        if let Ok(response) = &result {
            span.record("reconnects", response.body().reconnects());
        }
        outcome.finish(match &result {
            Ok(response) if response.body().is_closed() => "closed",
            Ok(_) => "open",
            Err(_) => "error",
        });
        result
    }

    async fn connect_inner(self) -> Result<Response<SseEventSource>, SseError> {
        self.request.validate_headers()?;
        self.validate_initial_retry()?;
        self.validate_idle_timeout()?;

        let mut reconnects = 0;
        let response = loop {
            match self.request.send("").await {
                Ok(response) => break response,
                Err(error) if !super::is_reconnectable(&error) => {
                    return Err(SseError::request(error));
                }
                Err(_) if reconnects < self.max_reconnects => {
                    reconnects += 1;
                    debug!(
                        attempt = reconnects,
                        maximum = self.max_reconnects,
                        "retrying initial SSE connection"
                    );
                    let deadline = Instant::now()
                        .checked_add(effective_retry(self.initial_retry, self.min_retry))
                        .ok_or_else(SseError::invalid_reconnect_delay)?;
                    crate::timeout::sleep_until(deadline)
                        .await
                        .map_err(SseError::request)?;
                }
                Err(error) if reconnects == 0 => return Err(SseError::request(error)),
                Err(error) => return Err(SseError::reconnect_limit(Some(error))),
            }
        };
        if response.status() == StatusCode::NO_CONTENT {
            let (parts, _body) = response.into_parts();
            return Ok(Response::from_parts(
                parts,
                SseEventSource::closed(
                    self.request,
                    self.limits,
                    self.idle_timeout,
                    self.initial_retry,
                    self.min_retry,
                    self.max_reconnects,
                    reconnects,
                ),
            ));
        }

        let response = SseStream::from_response_with_state(
            response,
            self.limits,
            String::new(),
            self.initial_retry,
            self.idle_timeout,
        )?;
        let (parts, stream) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            SseEventSource::open(
                self.request,
                self.limits,
                self.idle_timeout,
                self.initial_retry,
                self.min_retry,
                self.max_reconnects,
                reconnects,
                stream,
            ),
        ))
    }

    fn validate_initial_retry(&self) -> Result<(), SseError> {
        let delay = effective_retry(self.initial_retry, self.min_retry);
        if self.max_reconnects > 0 && Instant::now().checked_add(delay).is_none() {
            return Err(SseError::invalid_reconnect_delay());
        }
        Ok(())
    }

    fn validate_idle_timeout(&self) -> Result<(), SseError> {
        if self
            .idle_timeout
            .is_some_and(|timeout| Instant::now().checked_add(timeout).is_none())
        {
            return Err(SseError::invalid_idle_timeout());
        }
        Ok(())
    }
}

/// Returns `delay` raised to the optional caller minimum.
pub(super) fn effective_retry(delay: Duration, minimum: Option<Duration>) -> Duration {
    minimum.map_or(delay, |minimum| delay.max(minimum))
}

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub(super) struct SseRequest {
    client: Client,
    pub(super) protocol: HttpProtocol,
    uri: Box<str>,
    headers: Vec<SseHeader>,
    route: Option<Route>,
    timeouts: Option<RequestTimeoutOverrides>,
}

impl SseRequest {
    fn validate_headers(&self) -> Result<(), SseError> {
        validate_template(&self.headers, self.protocol)?;

        if let Some(template) = &self.client.inner.request_template {
            let retry = self.client.retry_policy();
            let fallback = self.protocol == HttpProtocol::Http3
                && retry.http2_fallback()
                && retry.max_retries() != Some(0);
            for protocol in [Some(self.protocol), fallback.then_some(HttpProtocol::Http2)]
                .into_iter()
                .flatten()
            {
                if let Some(fields) = template.fields_for(protocol) {
                    let request = self.apply_route(
                        self.client
                            .get(protocol, &self.uri)
                            .map_err(SseError::request)?,
                    );
                    if let Some(conditions) = request.supported_template_conditions() {
                        validate_client_fields(fields, conditions)?;
                    }
                }
            }
        }

        if let Some(hints) = &self.client.inner.client_hints {
            let template = self.client.inner.request_template.as_ref();
            let emits_managed_hint = hints.hints().iter().any(|hint| {
                hint.name().eq_ignore_ascii_case(LAST_EVENT_ID)
                    && (hint.delivery() == ClientHintDelivery::Default
                        || template.is_none_or(|template| {
                            template.requested_client_hint_placement()
                                && !template.client_hint_slots().is_empty()
                        }))
            });
            if emits_managed_hint {
                let request = self.apply_route(
                    self.client
                        .get(self.protocol, &self.uri)
                        .map_err(SseError::request)?,
                );
                if request
                    .supported_template_conditions()
                    .is_some_and(|(trustworthy, _)| trustworthy)
                {
                    return Err(SseError::invalid_request_header(
                        "automatic client hint supplies a managed Last-Event-ID",
                    ));
                }
            }
        }
        Ok(())
    }

    async fn send(&self, last_event_id: &str) -> Result<Response<ResponseBody>, RequestError> {
        let headers = resolve_template(&self.headers, self.protocol, last_event_id);

        let mut request = self
            .client
            .get(self.protocol, &self.uri)?
            .headers(headers)
            .protect_event_source_headers()
            .without_response_body_timeouts();
        if let Some(timeouts) = self.timeouts {
            request = request.timeouts(timeouts);
        }
        self.apply_route(request).send().await
    }

    pub(super) fn send_owned(&self, last_event_id: String) -> ReconnectFuture {
        let request = self.clone();
        Box::pin(async move { request.send(&last_event_id).await })
    }

    fn apply_route(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.route {
            Some(route) => request.route(route.clone()),
            None => request,
        }
    }
}

/// A managed ID must stay absent while empty, including after an ID reset.
fn validate_client_fields(
    fields: &[RequestField],
    conditions: (bool, bool),
) -> Result<(), SseError> {
    if crate::request::template::supplies_managed_default(fields, &[], &[LAST_EVENT_ID], conditions)
    {
        return Err(SseError::invalid_request_header(
            "inherited request template supplies a default Last-Event-ID",
        ));
    }
    Ok(())
}

/// Rejects literal `Last-Event-ID` fields and invalid or repeated placeholders.
fn validate_template(template: &[SseHeader], protocol: HttpProtocol) -> Result<(), SseError> {
    let mut placeholders = 0_usize;
    for header in template {
        match header {
            SseHeader::Field(field) if field.name().eq_ignore_ascii_case(LAST_EVENT_ID) => {
                return Err(SseError::invalid_request_header(
                    "literal Last-Event-ID is managed by the SSE event source; use the placeholder",
                ));
            }
            SseHeader::Field(_) => {}
            SseHeader::LastEventId { name } => {
                placeholders += 1;
                validate_placeholder_name(name, protocol)?;
            }
        }
    }
    if placeholders > 1 {
        return Err(SseError::invalid_request_header(
            "SSE request permits at most one Last-Event-ID placeholder",
        ));
    }
    Ok(())
}

/// Expands a validated template for one attempt.
///
/// An empty committed ID emits no field. Without a placeholder, a nonempty ID
/// is appended last using the protocol's conventional spelling.
fn resolve_template(
    template: &[SseHeader],
    protocol: HttpProtocol,
    last_event_id: &str,
) -> Vec<RequestHeader> {
    let mut headers = Vec::with_capacity(template.len() + 1);
    let mut placed = false;
    for header in template {
        match header {
            SseHeader::Field(field) => headers.push(field.clone()),
            SseHeader::LastEventId { name } => {
                placed = true;
                if !last_event_id.is_empty() {
                    headers.push(RequestHeader::new(name.as_ref(), last_event_id));
                }
            }
        }
    }
    if !placed && !last_event_id.is_empty() {
        let name = match protocol {
            HttpProtocol::Http1 => "Last-Event-ID",
            HttpProtocol::Http2 | HttpProtocol::Http3 => LAST_EVENT_ID,
        };
        headers.push(RequestHeader::new(name, last_event_id));
    }
    headers
}

fn validate_placeholder_name(name: &str, protocol: HttpProtocol) -> Result<(), SseError> {
    let spelled = HeaderName::from_bytes(name.as_bytes())
        .is_ok_and(|parsed| parsed.as_str() == LAST_EVENT_ID);
    if !spelled {
        return Err(SseError::invalid_request_header(
            "Last-Event-ID placeholder name must spell Last-Event-ID",
        ));
    }
    if protocol != HttpProtocol::Http1 && name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(SseError::invalid_request_header(
            "HTTP/2 and HTTP/3 Last-Event-ID placeholder names must be lowercase",
        ));
    }
    Ok(())
}
