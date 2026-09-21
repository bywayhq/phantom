use std::{fmt, time::Duration};

use http::{Response, StatusCode};
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

fn default_headers(protocol: HttpProtocol) -> Vec<RequestHeader> {
    let (accept, cache_control) = match protocol {
        HttpProtocol::Http1 => ("Accept", "Cache-Control"),
        HttpProtocol::Http2 | HttpProtocol::Http3 => ("accept", "cache-control"),
    };
    vec![
        RequestHeader::new(accept, "text/event-stream"),
        RequestHeader::new(cache_control, "no-cache"),
    ]
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

    /// Appends one ordered request field after the EventSource defaults.
    ///
    /// `Last-Event-ID` is reserved for reconnects and is rejected by
    /// [`SseRequestBuilder::connect`].
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.request.headers.push(header);
        self
    }

    /// Replaces the complete ordered request-field list, including the
    /// EventSource defaults.
    ///
    /// `Last-Event-ID` is reserved for reconnects and is rejected by
    /// [`SseRequestBuilder::connect`].
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
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
    headers: Vec<RequestHeader>,
    route: Option<Route>,
    timeouts: Option<RequestTimeouts>,
}

impl SseRequest {
    fn validate_headers(&self) -> Result<(), SseError> {
        if self
            .headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("last-event-id"))
        {
            return Err(SseError::invalid_request_header());
        }
        Ok(())
    }

    async fn send(&self, last_event_id: &str) -> Result<Response<ResponseBody>, RequestError> {
        let mut headers = self.headers.clone();
        if !last_event_id.is_empty() {
            let name = match self.protocol {
                HttpProtocol::Http1 => "Last-Event-ID",
                HttpProtocol::Http2 | HttpProtocol::Http3 => "last-event-id",
            };
            headers.push(RequestHeader::new(name, last_event_id));
        }

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
