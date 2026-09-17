use std::{fmt, time::Duration};

use http::{Response, StatusCode};
use phantom_net::request::RequestHeader;
use tokio::time::{Instant, sleep_until};
use tracing::{Instrument, debug, debug_span, field};

use crate::{HttpProtocol, RequestBuilder, RequestError, ResponseBody, Route, Session};

use super::{ReconnectFuture, SseEventSource};
use crate::sse::{SseError, SseLimits, SseOutcome, SseStream};

const DEFAULT_INITIAL_RETRY: Duration = Duration::from_secs(3);
const DEFAULT_MAX_RECONNECTS: usize = 3;

/// Builds one session-owned server-sent event source.
#[must_use = "SSE request builders do nothing until connect is awaited"]
pub struct SseRequestBuilder {
    request: SseRequest,
    limits: SseLimits,
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
            .field("limits", &self.limits)
            .field("initial_retry", &self.initial_retry)
            .field("max_reconnects", &self.max_reconnects)
            .finish_non_exhaustive()
    }
}

impl SseRequestBuilder {
    pub(crate) fn new_session(
        session: Session,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<Self, RequestError> {
        let _ = session.get(protocol, uri)?;
        Ok(Self {
            request: SseRequest {
                session,
                protocol,
                uri: uri.into(),
                headers: Vec::new(),
                route: None,
            },
            limits: SseLimits::default(),
            initial_retry: DEFAULT_INITIAL_RETRY,
            max_reconnects: DEFAULT_MAX_RECONNECTS,
        })
    }

    /// Appends one ordered request field.
    ///
    /// `Last-Event-ID` is reserved for reconnects and is rejected by
    /// [`SseRequestBuilder::connect`].
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.request.headers.push(header);
        self
    }

    /// Replaces the complete ordered request-field list.
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

    /// Sets the event-stream decoding bounds.
    pub fn limits(mut self, limits: SseLimits) -> Self {
        self.limits = limits;
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
            .unwrap_or(&self.request.session.client.inner.route);
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

        let mut reconnects = 0;
        let response = loop {
            match self.request.send("").await {
                Ok(response) => break response,
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
                    sleep_until(deadline).await;
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
        )?;
        let (parts, stream) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            SseEventSource::open(
                self.request,
                self.limits,
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
}

#[derive(Clone)]
pub(super) struct SseRequest {
    session: Session,
    pub(super) protocol: HttpProtocol,
    uri: Box<str>,
    headers: Vec<RequestHeader>,
    route: Option<Route>,
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

        let request = self.session.get(self.protocol, &self.uri)?.headers(headers);
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
