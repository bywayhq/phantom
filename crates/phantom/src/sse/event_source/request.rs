use std::{fmt, time::Duration};

use http::{HeaderName, Response, StatusCode};
use phantom_net::request::RequestHeader;
use tokio::time::Instant;
use tracing::{Instrument, debug, debug_span, field};

use crate::{
    Client, HttpProtocol, RequestBuilder, RequestError, RequestTimeouts, ResponseBody, Route,
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
#[must_use = "SSE request builders do nothing until connect is awaited"]
pub struct SseRequestBuilder {
    request: SseRequest,
    limits: SseLimits,
    idle_timeout: Option<Duration>,
    initial_retry: Duration,
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
    /// validates the template before any I/O.
    pub fn headers(mut self, headers: Vec<SseHeader>) -> Self {
        self.request.headers = headers;
        self
    }

    /// Overrides the client's route for every connection attempt.
    pub fn route(mut self, route: Route) -> Self {
        self.request.route = Some(route);
        self
    }

    /// Replaces the client's request timeout policy for every connection attempt.
    ///
    /// Pool, connection, and response-head limits apply to each attempt. The
    /// generic body and total timers end after the response head; established
    /// streams use [`Self::idle_timeout`] and the finite reconnect budget.
    pub fn request_timeouts(mut self, timeouts: RequestTimeouts) -> Self {
        self.request.timeouts = Some(timeouts);
        self
    }

    /// Sets the event-stream decoding bounds.
    pub fn limits(mut self, limits: SseLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the maximum interval without an HTTP DATA frame.
    ///
    /// The timeout is disabled by default. Comments, partial events, and empty
    /// DATA frames count as activity. An idle response reconnects within the
    /// same finite budget as a disconnected response.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Sets the delay used until the server supplies a valid `retry` field.
    pub fn initial_retry(mut self, delay: Duration) -> Self {
        self.initial_retry = delay;
        self
    }

    /// Sets the finite number of requests allowed after the initial attempt.
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
    /// Returns [`SseError`] when request preparation, transport, or response
    /// validation fails.
    pub async fn connect(self) -> Result<Response<SseEventSource>, SseError> {
        let route = self
            .request
            .route
            .as_ref()
            .unwrap_or(&self.request.client.inner.route);
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
                        .checked_add(self.initial_retry)
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
                self.max_reconnects,
                reconnects,
                stream,
            ),
        ))
    }

    fn validate_initial_retry(&self) -> Result<(), SseError> {
        if self.max_reconnects > 0 && Instant::now().checked_add(self.initial_retry).is_none() {
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

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub(super) struct SseRequest {
    client: Client,
    pub(super) protocol: HttpProtocol,
    uri: Box<str>,
    headers: Vec<SseHeader>,
    route: Option<Route>,
    timeouts: Option<RequestTimeouts>,
}

impl SseRequest {
    fn validate_headers(&self) -> Result<(), SseError> {
        validate_template(&self.headers, self.protocol)
    }

    async fn send(&self, last_event_id: &str) -> Result<Response<ResponseBody>, RequestError> {
        let headers = resolve_template(&self.headers, self.protocol, last_event_id);

        let mut request = self
            .client
            .get(self.protocol, &self.uri)?
            .headers(headers)
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
