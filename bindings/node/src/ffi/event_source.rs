//! Node-API projections for the core reconnecting event source.

use std::{fmt, sync::Arc, time::Duration};

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, BigInt, Buffer},
};
use napi_derive::napi;
use phantom::{HttpProtocol, RequestHeader, SseHeader, SseLimits, SseRequestBuilder};

use super::{
    buffer::copy_buffer,
    options::{PhaseTimeouts, SessionRouteOptions, WireHeader},
};
use crate::{client::ClientState, error::failure, event_source::Source};

/// One explicit literal field or managed reconnect-ID position.
#[napi(object)]
pub struct EventSourceHeader {
    /// Either field or lastEventId.
    pub kind: String,
    /// Exact protocol-specific spelling.
    pub name: String,
    /// Bytes for a literal field only.
    pub value: Option<Buffer>,
    /// Compression sensitivity for a literal field only.
    pub sensitive: Option<bool>,
}

impl fmt::Debug for EventSourceHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSourceHeader")
            .finish_non_exhaustive()
    }
}

/// Controls supported by the core SSE request builder.
#[napi(object)]
pub struct EventSourceOptions {
    /// Absolute URL, or a relative reference with a client base URL.
    pub url: String,
    /// Explicit http1, http2 or http3.
    pub protocol: String,
    /// Complete ordered template after merging caller defaults.
    pub headers: Vec<EventSourceHeader>,
    /// Encoded line bytes excluding its terminator; zero is meaningful.
    pub maximum_line_bytes: u32,
    /// Encoded event-block bytes excluding terminators; zero is meaningful.
    pub maximum_event_bytes: u32,
    /// Response-body idle limit; absence disables it.
    pub idle_timeout_ms: Option<f64>,
    /// Initial reconnect delay, including an exact zero.
    pub initial_retry_ms: f64,
    /// Lower bound on server or initial reconnect delay.
    pub minimum_retry_ms: Option<f64>,
    /// Reconnects after the first attempt; zero disables them.
    pub maximum_reconnects: u32,
    /// Per-attempt overrides; readIdle is rejected in favor of idleTimeoutMs.
    pub timeouts: Option<PhaseTimeouts>,
    /// Absence inherits the client route on every reconnect.
    pub route: Option<SessionRouteOptions>,
}

impl fmt::Debug for EventSourceOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSourceOptions")
            .finish_non_exhaustive()
    }
}

/// Initial response head; later reconnect heads remain core-owned.
#[napi(object, object_from_js = false)]
pub struct EventSourceHead {
    /// Initial status, including terminal 204.
    pub status: u32,
    /// Protocol that produced the initial response.
    pub protocol: String,
    /// Effective initial URL after redirects.
    pub url: String,
    /// Ordered initial response fields.
    pub headers: Vec<WireHeader>,
}

impl fmt::Debug for EventSourceHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSourceHead")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// One independently cancellable, pull-driven event source.
#[napi]
pub struct NativeEventSource {
    pub(super) source: Arc<Source>,
}

/// One event; retry state belongs to the reconnecting source.
#[napi(object, object_from_js = false)]
pub struct EventSourceEvent {
    /// Joined data fields, with invalid UTF-8 replaced.
    pub data: String,
    /// Event type, defaulting to message.
    pub event: String,
    /// Persistent event ID at dispatch.
    pub id: String,
}

impl fmt::Debug for EventSourceEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSourceEvent")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for NativeEventSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeEventSource")
            .finish_non_exhaustive()
    }
}

#[napi]
impl NativeEventSource {
    /// Allocates a cancellation owner before opening starts.
    #[napi(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            source: Source::new(),
        }
    }

    /// Latest persistent ID observed by a completed native read.
    #[napi(getter)]
    #[must_use]
    pub fn last_event_id(&self) -> String {
        self.source.last_event_id()
    }

    /// Effective next reconnect delay, including the configured minimum.
    #[napi(getter)]
    #[must_use]
    pub fn retry_ms(&self) -> BigInt {
        self.source.retry_delay().as_millis().into()
    }

    /// Reconnect requests started, including initial setup retries.
    #[napi(getter)]
    #[must_use]
    pub fn reconnects(&self) -> u32 {
        // The configured reconnect cap enters this boundary as u32.
        self.source.reconnects() as u32
    }

    /// Whether the source has stopped permanently.
    #[napi(getter)]
    #[must_use]
    pub fn closed(&self) -> bool {
        !self.source.is_active()
    }

    /// Pulls one event; no background event queue is created.
    #[napi]
    pub fn read(&self, env: Env) -> Result<AsyncBlock<Option<EventSourceEvent>>> {
        let source = Arc::clone(&self.source);
        AsyncBlockBuilder::new(async move {
            let event = source.read().await?;
            Ok(event.map(|event| {
                let (data, event, id) = event.into_parts();
                EventSourceEvent { data, event, id }
            }))
        })
        .build(&env)
    }

    /// Stops setup, a pending read or reconnect sleep without touching siblings.
    #[napi]
    pub fn close(&self) {
        self.source.close();
    }
}

impl Default for NativeEventSource {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NativeEventSource {
    fn drop(&mut self) {
        self.source.close();
    }
}

pub(super) fn prepare(
    env: &Env,
    client: &ClientState,
    options: EventSourceOptions,
) -> Result<SseRequestBuilder> {
    client.check_open()?;
    if options.url.is_empty() || options.url.len() > 65536 {
        return Err(failure(
            "InputLimit",
            "event source URL must contain 1..65536 UTF-8 bytes",
        ));
    }
    let protocol = match options.protocol.as_str() {
        "http1" => HttpProtocol::Http1,
        "http2" => HttpProtocol::Http2,
        "http3" => HttpProtocol::Http3,
        _ => {
            return Err(failure(
                "InvalidProtocol",
                "event source requires http1, http2 or http3",
            ));
        }
    };
    if options.headers.len() > 256 {
        return Err(failure(
            "InputLimit",
            "event source accepts at most 256 headers",
        ));
    }
    let mut remaining = 65536usize;
    let headers = options
        .headers
        .into_iter()
        .map(|field| {
            remaining = remaining
                .checked_sub(field.name.len())
                .ok_or_else(|| failure("InputLimit", "event source headers exceed 65536 bytes"))?;
            match (field.kind.as_str(), field.value, field.sensitive) {
                ("lastEventId", None, None) => Ok(SseHeader::last_event_id(field.name)),
                ("field", Some(value), sensitive) => {
                    let bytes = copy_buffer(env, value, remaining)?;
                    remaining -= bytes.len();
                    let header = RequestHeader::new(field.name, bytes);
                    Ok(SseHeader::field(if sensitive.unwrap_or(false) {
                        header.sensitive()
                    } else {
                        header
                    }))
                }
                _ => Err(failure(
                    "InvalidArgument",
                    "choose a literal header or managed Last-Event-ID slot",
                )),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let mut builder = client
        .core
        .event_source(protocol, &options.url)
        .map_err(crate::error::request)?
        .headers(headers)
        .limits(SseLimits::new(
            options.maximum_line_bytes as usize,
            options.maximum_event_bytes as usize,
        ))
        .initial_retry(milliseconds(options.initial_retry_ms)?)
        .max_reconnects(options.maximum_reconnects as usize);
    if let Some(value) = options.idle_timeout_ms {
        builder = builder.idle_timeout(milliseconds(value)?);
    }
    if let Some(value) = options.minimum_retry_ms {
        builder = builder.min_retry(milliseconds(value)?);
    }
    if let Some(timeouts) = options.timeouts {
        if timeouts.read_idle.is_some() {
            return Err(failure(
                "InvalidTimeout",
                "use idleTimeoutMs for event source body inactivity",
            ));
        }
        builder = builder.request_timeouts(timeouts.overrides()?);
    }
    if let Some(route) = options.route {
        builder = builder.route(crate::client::route(
            &route.route,
            route.proxy.as_deref(),
            route.proxy_username.as_deref(),
            route.proxy_password.as_deref(),
            route.proxy_user_id.as_deref(),
        )?);
    }
    Ok(builder)
}

fn milliseconds(value: f64) -> Result<Duration> {
    if !value.is_finite() || value < 0.0 {
        return Err(failure(
            "InvalidArgument",
            "event source delays must be finite nonnegative milliseconds",
        ));
    }
    Duration::try_from_secs_f64(value / 1000.0).map_err(|_| {
        failure(
            "InvalidArgument",
            "event source delays must be finite nonnegative milliseconds",
        )
    })
}

pub(super) fn head(
    response: &phantom::Response<phantom::SseEventSource>,
) -> Result<EventSourceHead> {
    let info = response
        .extensions()
        .get::<phantom::ResponseInfo>()
        .ok_or_else(|| failure("Internal", "event source response metadata is unavailable"))?;
    let protocol = match info.protocol() {
        HttpProtocol::Http1 => "http1",
        HttpProtocol::Http2 => "http2",
        HttpProtocol::Http3 => "http3",
        _ => {
            return Err(failure(
                "Internal",
                "event source response protocol is unsupported",
            ));
        }
    };
    let headers = response
        .extensions()
        .get::<phantom::OrderedResponseHeaders>()
        .ok_or_else(|| {
            failure(
                "Internal",
                "event source ordered response fields are unavailable",
            )
        })?
        .iter()
        .map(|header| WireHeader {
            name: header.name().to_owned(),
            value: header.value().to_vec().into(),
            sensitive: Some(header.is_sensitive()),
        })
        .collect();
    Ok(EventSourceHead {
        status: u32::from(response.status().as_u16()),
        protocol: protocol.to_owned(),
        url: info.effective_uri().to_string(),
        headers,
    })
}
