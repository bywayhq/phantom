//! Exact HTTP/2 client connections and one-shot transactions.
//!
//! The core transaction accepts an already-connected byte stream. It owns no
//! pool and does not fall back to another HTTP version.

use ::http2::{
    client,
    frame::{PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId},
};
use bytes::Bytes;
use http::{Method, Request, Response};
use phantom_profile::{Http2PseudoHeader, Http2Setting, Http2Settings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Span, debug_span, field};

mod alps;
use request::prepare_request as build_request;
#[cfg(test)]
use request::{MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS};

pub use crate::request::{OriginForm, RequestHeader};
pub use body::Http2Body;
pub use connection::Http2Connection;
pub use error::{Http2Error, Http2ProtocolError, Http2ProtocolErrorKind};

/// Validates one empty-body HTTP/2 GET without touching a connection.
///
/// This is useful when connection acquisition may perform network I/O. The
/// connection still validates again when the request is sent so direct users
/// cannot bypass the protocol boundary.
///
/// # Errors
///
/// Returns [`Http2Error`] when the authority, target, or ordered fields cannot
/// be represented by this HTTP/2 transport.
pub fn validate_get(
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
) -> Result<(), Http2Error> {
    validate_request(&Method::GET, authority, target, headers, None)
}

/// Validates one HTTP/2 request without touching a connection.
///
/// `None` emits END_STREAM on HEADERS. `Some` emits a request-body DATA
/// sequence, including an empty terminal DATA frame for an empty value.
/// Standard CONNECT is not accepted because this API requires an origin-form
/// target.
///
/// # Errors
///
/// Returns [`Http2Error`] when the method, authority, target, ordered fields,
/// or body length cannot be represented by this HTTP/2 transport.
pub fn validate_request(
    method: &Method,
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
    body: Option<&Bytes>,
) -> Result<(), Http2Error> {
    prepare_request(
        method.clone(),
        authority,
        target.clone(),
        headers.to_vec(),
        body.map_or(0, Bytes::len),
    )
    .map(drop)
}

/// Sends one empty-body HTTP/2 GET over an already-connected stream.
///
/// The profile, authority, target, and complete ordered header list are
/// validated before the supplied stream is touched. Ordinary header order and
/// duplicate positions are emitted exactly as supplied. Completing or dropping
/// the response body closes this one-shot connection after the stream reaches
/// its terminal protocol state.
pub async fn send_get<T>(
    stream: T,
    settings: &Http2Settings,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Response<Http2Body>, Http2Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_request(
        stream,
        settings,
        Method::GET,
        authority,
        target,
        headers,
        None,
    )
    .await
}

/// Sends one HTTP/2 request over an already-connected stream.
///
/// The complete request is validated before the supplied stream is touched.
/// Ordinary header order and duplicate positions are emitted exactly as
/// supplied. A missing content-length is appended for a non-empty body.
///
/// # Errors
///
/// Returns [`Http2Error`] when request validation, connection setup, upload, or
/// response processing fails.
pub async fn send_request<T>(
    stream: T,
    settings: &Http2Settings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
) -> Result<Response<Http2Body>, Http2Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let body_bytes = body.as_ref().map_or(0, Bytes::len);
    let span = debug_span!(
        "http2.request.prepare",
        method = %method,
        protocol = "h2",
        body_bytes,
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = OperationOutcome::new(&span);
    let prepared = {
        let _entered = span.enter();
        PreparedRequest::new(settings, method, authority, target, headers, body)
    };
    match &prepared {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    let prepared = prepared?;
    let connection = Http2Connection::connect_with_builder(stream, prepared.client).await?;
    connection
        .send_prepared_request(prepared.request, prepared.body)
        .await
}

struct PreparedRequest {
    request: Request<()>,
    body: Option<Bytes>,
    client: client::Builder,
}

impl PreparedRequest {
    fn new(
        settings: &Http2Settings,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Self, Http2Error> {
        settings.validate().map_err(Http2Error::InvalidSettings)?;
        let client = translate_settings(settings)?;
        let body_len = body.as_ref().map_or(0, Bytes::len);
        let request = build_request(method, authority, target, headers, body_len)?;

        Ok(Self {
            request,
            body,
            client,
        })
    }
}

fn prepare_request(
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body_len: usize,
) -> Result<Request<()>, Http2Error> {
    let span = debug_span!(
        "http2.request.prepare",
        method = %method,
        protocol = "h2",
        body_bytes = body_len,
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = OperationOutcome::new(&span);
    let request = {
        let _entered = span.enter();
        build_request(method, authority, target, headers, body_len)
    };
    match &request {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    request
}

struct OperationOutcome {
    span: Span,
    recorded: bool,
}

impl OperationOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }

    fn finish_with_error_kind(mut self, outcome: &'static str, error_kind: &'static str) {
        self.span.record("outcome", outcome);
        self.span.record("error_kind", error_kind);
        self.recorded = true;
    }
}

impl Drop for OperationOutcome {
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

pub(crate) fn translate_settings(settings: &Http2Settings) -> Result<client::Builder, Http2Error> {
    if settings
        .headers_priority
        .is_some_and(|priority| priority.dependency_stream_id == 1)
    {
        return Err(Http2Error::InvalidPriorityDependency { stream_id: 1 });
    }

    let mut client = client::Builder::new();
    client.initial_connection_window_size(settings.initial_connection_window_size);
    let mut order = SettingsOrder::builder();

    for setting in &settings.initial_settings {
        match *setting {
            Http2Setting::HeaderTableSize(value) => {
                client.header_table_size(value);
                order = order.push(SettingId::HeaderTableSize);
            }
            Http2Setting::EnablePush(value) => {
                client.enable_push(value);
                order = order.push(SettingId::EnablePush);
            }
            Http2Setting::MaxConcurrentStreams(value) => {
                client.max_concurrent_streams(value);
                order = order.push(SettingId::MaxConcurrentStreams);
            }
            Http2Setting::InitialWindowSize(value) => {
                client.initial_window_size(value);
                order = order.push(SettingId::InitialWindowSize);
            }
            Http2Setting::MaxFrameSize(value) => {
                client.max_frame_size(value);
                order = order.push(SettingId::MaxFrameSize);
            }
            Http2Setting::MaxHeaderListSize(value) => {
                client.max_header_list_size(value);
                order = order.push(SettingId::MaxHeaderListSize);
            }
            Http2Setting::EnableConnectProtocol(value) => {
                client.enable_connect_protocol(value);
                order = order.push(SettingId::EnableConnectProtocol);
            }
            Http2Setting::NoRfc7540Priorities(value) => {
                client.no_rfc7540_priorities(value);
                order = order.push(SettingId::NoRfc7540Priorities);
            }
            _ => return Err(Http2Error::UnsupportedSetting),
        }
    }

    let mut pseudo_order = PseudoOrder::builder();
    for header in &settings.pseudo_header_order {
        let id = match header {
            Http2PseudoHeader::Method => PseudoId::Method,
            Http2PseudoHeader::Authority => PseudoId::Authority,
            Http2PseudoHeader::Scheme => PseudoId::Scheme,
            Http2PseudoHeader::Path => PseudoId::Path,
            _ => return Err(Http2Error::UnsupportedSetting),
        };
        pseudo_order = pseudo_order.push(id);
    }

    client
        .settings_order(order.build())
        .headers_pseudo_order(pseudo_order.build());
    if let Some(priority) = settings.headers_priority {
        client.headers_stream_dependency(StreamDependency::new(
            StreamId::from(priority.dependency_stream_id),
            (priority.weight - 1) as u8,
            priority.exclusive,
        ));
    }
    Ok(client)
}

mod body;
mod connection;
mod driver;
mod error;
mod request;
mod tls;

pub use tls::{Http2TlsConnector, Http2TlsError, TlsError, TlsErrorKind};
pub(crate) use tls::{connect_selected, validate_http2};

#[cfg(test)]
mod tests;
