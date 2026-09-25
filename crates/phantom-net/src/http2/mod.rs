//! Exact HTTP/2 client connections and one-shot transactions.
//!
//! The core transaction accepts an already-connected byte stream. It owns no
//! pool and does not fall back to another HTTP version.

use ::http2::{
    client,
    ext::{
        CookieCrumbs, HeadersFrameOverrides, HpackEncoderProfile, HuffmanCoding, StaticNameIndex,
    },
    frame::{PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId},
};
use bytes::Bytes;
use http::{Method, Request, Response};
use phantom_profile::{
    Http2CookieCrumbs, Http2HpackSettings, Http2HuffmanCoding, Http2Priority, Http2PseudoHeader,
    Http2Setting, Http2Settings, Http2StaticNameIndex,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Span, debug_span, field};

mod alps;
mod alt_svc;
mod upload;
#[cfg(test)]
use request::{MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS};
use request::{
    PreparedRequestTrailers, prepare_extended_connect, prepare_request as build_request,
};

pub use crate::request::{OriginForm, RequestBody, RequestBodyMetadata, RequestHeader};
pub use alt_svc::{AltSvcFrame, AltSvcFrameScope, AltSvcFrames};
pub use body::Http2Body;
pub use connection::Http2Connection;
pub use error::{Http2Error, Http2ProtocolError, Http2ProtocolErrorKind};
pub(crate) use request::{prepare_classic_connect, prepare_connect_udp};
pub(crate) use tunnel::{Http2ClassicConnectOutcome, Http2ConnectStream, Http2RejectedStream};
pub use tunnel::{Http2ExtendedConnectOutcome, Http2ExtendedConnectStream};

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

/// Validates one WebSocket extended CONNECT request without I/O.
///
/// # Errors
///
/// Returns [`Http2Error`] when the authority, origin-form target, or ordered
/// HTTP/2 fields are invalid.
pub fn validate_extended_connect(
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
) -> Result<(), Http2Error> {
    prepare_extended_connect(authority, target.clone(), headers.to_vec()).map(drop)
}

/// Validates settings for an exact extended CONNECT connection without I/O.
///
/// # Errors
///
/// Returns [`Http2Error`] when settings are invalid or omit an observed
/// five-field extended CONNECT pseudo-header order.
pub fn validate_extended_connect_settings(settings: &Http2Settings) -> Result<(), Http2Error> {
    settings.validate().map_err(Http2Error::InvalidSettings)?;
    translate_extended_connect_settings(settings).map(drop)
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
    let metadata = body.map(|body| RequestBody::from_bytes(body.clone()).metadata());
    validate_request_body(method, authority, target, headers, metadata)
}

/// Validates one HTTP/2 request-body shape without touching a connection.
///
/// An exact body size validates or supplies `Content-Length`; an unknown size
/// omits an automatic length and rejects a caller-supplied one.
///
/// # Errors
///
/// Returns [`Http2Error`] when the method, authority, target, ordered fields,
/// or body metadata cannot be represented by this HTTP/2 transport.
pub fn validate_request_body(
    method: &Method,
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
    body: Option<RequestBodyMetadata>,
) -> Result<(), Http2Error> {
    validate_request_body_with_trailers(method, authority, target, headers, body, &[])
}

/// Validates one HTTP/2 request body and ordered static trailer list without I/O.
///
/// Trailer fields must have lowercase names and may not contain message framing
/// or connection-specific fields. `Content-Length` describes DATA only.
///
/// # Errors
///
/// Returns [`Http2Error`] when the request or trailer fields cannot be
/// represented by this HTTP/2 transport.
pub fn validate_request_body_with_trailers(
    method: &Method,
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
    body: Option<RequestBodyMetadata>,
    trailers: &[RequestHeader],
) -> Result<(), Http2Error> {
    if body.is_some_and(RequestBodyMetadata::has_trailers) {
        return Err(Http2Error::BodyTrailerPlanRequired);
    }
    prepare_request(
        method.clone(),
        authority,
        target.clone(),
        headers.to_vec(),
        body,
    )
    .map(drop)?;
    PreparedRequestTrailers::new(trailers.to_vec()).map(drop)
}

/// Validates an HTTP/2 request, body-produced trailer plan, and static trailers.
pub fn validate_request_body_source_with_trailers(
    method: &Method,
    authority: &str,
    target: &OriginForm,
    headers: &[RequestHeader],
    body: Option<&RequestBody>,
    trailers: &[RequestHeader],
) -> Result<(), Http2Error> {
    PreparedRequestTrailers::validate_body_plan(body, trailers)?;
    prepare_request(
        method.clone(),
        authority,
        target.clone(),
        headers.to_vec(),
        body.map(RequestBody::metadata),
    )
    .map(drop)?;
    PreparedRequestTrailers::new(trailers.to_vec()).map(drop)
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
    send_request_with_trailers(
        stream,
        settings,
        method,
        authority,
        target,
        headers,
        body,
        Vec::new(),
    )
    .await
}

/// Sends one owned request body followed by exact ordered static trailers.
///
/// # Errors
///
/// Returns [`Http2Error`] when request or trailer validation, connection
/// setup, upload, or response processing fails.
#[allow(clippy::too_many_arguments)]
pub async fn send_request_with_trailers<T>(
    stream: T,
    settings: &Http2Settings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    trailers: Vec<RequestHeader>,
) -> Result<Response<Http2Body>, Http2Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_request_body_with_trailers(
        stream,
        settings,
        method,
        authority,
        target,
        headers,
        body.map(RequestBody::from_bytes),
        trailers,
    )
    .await
}

/// Sends one HTTP/2 request with a pull-driven body over an already-connected stream.
///
/// Request validation completes before the supplied stream is touched. The
/// body is consumed once with HTTP/2 flow control and no aggregate buffering.
///
/// # Errors
///
/// Returns [`Http2Error`] when request validation, connection setup, upload,
/// or response processing fails.
#[allow(clippy::too_many_arguments)]
pub async fn send_request_body<T>(
    stream: T,
    settings: &Http2Settings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBody>,
) -> Result<Response<Http2Body>, Http2Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_request_body_with_trailers(
        stream,
        settings,
        method,
        authority,
        target,
        headers,
        body,
        Vec::new(),
    )
    .await
}

/// Sends a pull-driven request body followed by exact ordered trailers.
///
/// Request and static-trailer or body trailer-plan validation completes before
/// the stream or body is touched. Static and body-produced trailers cannot be
/// combined.
///
/// # Errors
///
/// Returns [`Http2Error`] when request or trailer validation, connection
/// setup, body production, upload, or response processing fails.
#[allow(clippy::too_many_arguments)]
pub async fn send_request_body_with_trailers<T>(
    stream: T,
    settings: &Http2Settings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBody>,
    trailers: Vec<RequestHeader>,
) -> Result<Response<Http2Body>, Http2Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let body_bytes = body
        .as_ref()
        .map(RequestBody::metadata)
        .and_then(RequestBodyMetadata::exact_length);
    let span = debug_span!(
        "http2.request.prepare",
        method = %method,
        protocol = "h2",
        body_bytes = field::debug(body_bytes),
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = OperationOutcome::new(&span);
    let prepared = {
        let _entered = span.enter();
        PreparedRequest::new_body_with_trailers(
            settings, method, authority, target, headers, body, trailers,
        )
    };
    match &prepared {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    let prepared = prepared?;
    let connection = Http2Connection::connect_with_builder(stream, prepared.client).await?;
    connection
        .send_prepared_request(prepared.request, prepared.body, prepared.trailers)
        .await
}

struct PreparedRequest {
    request: Request<()>,
    body: Option<RequestBody>,
    trailers: Option<PreparedRequestTrailers>,
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
        Self::new_body(
            settings,
            method,
            authority,
            target,
            headers,
            body.map(RequestBody::from_bytes),
        )
    }

    fn new_body(
        settings: &Http2Settings,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
    ) -> Result<Self, Http2Error> {
        Self::new_body_with_trailers(
            settings,
            method,
            authority,
            target,
            headers,
            body,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_body_with_trailers(
        settings: &Http2Settings,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
        trailers: Vec<RequestHeader>,
    ) -> Result<Self, Http2Error> {
        settings.validate().map_err(Http2Error::InvalidSettings)?;
        let client = translate_settings(settings)?;
        PreparedRequestTrailers::validate_body_plan(body.as_ref(), &trailers)?;
        let metadata = body.as_ref().map(RequestBody::metadata);
        let request = build_request(method, authority, target, headers, metadata)?;
        let trailers = PreparedRequestTrailers::new(trailers)?;

        Ok(Self {
            request,
            body,
            trailers,
            client,
        })
    }
}

fn prepare_request(
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBodyMetadata>,
) -> Result<Request<()>, Http2Error> {
    let span = debug_span!(
        "http2.request.prepare",
        method = %method,
        protocol = "h2",
        body_bytes = field::debug(body.and_then(RequestBodyMetadata::exact_length)),
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = OperationOutcome::new(&span);
    let request = {
        let _entered = span.enter();
        build_request(method, authority, target, headers, body)
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
    translate_settings_with_pseudo_order(settings, &settings.pseudo_header_order, false)
}

pub(crate) fn translate_extended_connect_settings(
    settings: &Http2Settings,
) -> Result<client::Builder, Http2Error> {
    let order = settings
        .extended_connect_pseudo_header_order
        .as_deref()
        .ok_or(Http2Error::MissingExtendedConnectPseudoHeaderOrder)?;
    translate_settings_with_pseudo_order(settings, order, true)
}

/// Builds the per-request HEADERS overrides for one extended CONNECT.
///
/// The pseudo-header order and optional priority replace the connection's
/// ordinary defaults for this stream only, so a pooled connection keeps its
/// ordinary request shape.
pub(crate) fn extended_connect_overrides(
    settings: &Http2Settings,
) -> Result<HeadersFrameOverrides, Http2Error> {
    let order = settings
        .extended_connect_pseudo_header_order
        .as_deref()
        .ok_or(Http2Error::MissingExtendedConnectPseudoHeaderOrder)?;
    let mut overrides = HeadersFrameOverrides::new().pseudo_order(pseudo_order(order, true)?);
    if let Some(priority) = settings.extended_connect_priority {
        overrides = overrides.stream_dependency(stream_dependency(priority)?);
    }
    Ok(overrides)
}

/// Builds the HEADERS override that gives one ordinary request its own
/// priority, leaving the connection's pseudo-header order in place.
pub(crate) fn priority_overrides(
    priority: Http2Priority,
) -> Result<HeadersFrameOverrides, Http2Error> {
    // Settings validation guards the connection priority; this per-request
    // value arrives unvalidated, and the backend panics on a 32-bit stream ID.
    if !(1..=256).contains(&priority.weight) || priority.dependency_stream_id > 0x7fff_ffff {
        return Err(Http2Error::InvalidPriority {
            dependency_stream_id: priority.dependency_stream_id,
            weight: priority.weight,
        });
    }
    Ok(HeadersFrameOverrides::new().stream_dependency(stream_dependency(priority)?))
}

/// Builds the connection's HPACK encoder identity from profile settings.
///
/// Each choice is part of the encoder's identity rather than a per-request
/// decision, so it belongs to the connection and applies to ordinary requests
/// and extended CONNECT alike.
///
/// # Errors
///
/// Returns [`Http2Error::UnsupportedSetting`] for a choice this backend cannot
/// express.
fn hpack_encoder_profile(hpack: &Http2HpackSettings) -> Result<HpackEncoderProfile, Http2Error> {
    let mut literal = Vec::with_capacity(hpack.literal_pseudo_headers.len());
    for header in &hpack.literal_pseudo_headers {
        literal.push(match header {
            Http2PseudoHeader::Method => PseudoId::Method,
            Http2PseudoHeader::Authority => PseudoId::Authority,
            Http2PseudoHeader::Scheme => PseudoId::Scheme,
            Http2PseudoHeader::Path => PseudoId::Path,
            Http2PseudoHeader::Protocol => PseudoId::Protocol,
            _ => return Err(Http2Error::UnsupportedSetting),
        });
    }
    let static_name_index = match hpack.static_name_index {
        Http2StaticNameIndex::Lowest => StaticNameIndex::Lowest,
        Http2StaticNameIndex::Highest => StaticNameIndex::Highest,
        _ => return Err(Http2Error::UnsupportedSetting),
    };
    let huffman_coding = match hpack.huffman_coding {
        Http2HuffmanCoding::Always => HuffmanCoding::Always,
        Http2HuffmanCoding::WhenShorter => HuffmanCoding::WhenShorter,
        Http2HuffmanCoding::WhenNotLonger => HuffmanCoding::WhenNotLonger,
        _ => return Err(Http2Error::UnsupportedSetting),
    };
    let cookie_crumbs = match hpack.cookie_crumbs {
        Http2CookieCrumbs::Whole => CookieCrumbs::Whole,
        Http2CookieCrumbs::IndexAll => CookieCrumbs::IndexAll,
        Http2CookieCrumbs::NeverIndexShort => CookieCrumbs::NeverIndexShort,
        _ => return Err(Http2Error::UnsupportedSetting),
    };
    Ok(HpackEncoderProfile::new()
        .literal_pseudo_headers(literal)
        .static_name_index(static_name_index)
        .huffman_coding(huffman_coding)
        .cookie_crumbs(cookie_crumbs))
}

fn stream_dependency(priority: Http2Priority) -> Result<StreamDependency, Http2Error> {
    // Stream 1 is the first client stream, which would then depend on itself.
    if priority.dependency_stream_id == 1 {
        return Err(Http2Error::InvalidPriorityDependency { stream_id: 1 });
    }
    Ok(StreamDependency::new(
        StreamId::from(priority.dependency_stream_id),
        (priority.weight - 1) as u8,
        priority.exclusive,
    ))
}

fn pseudo_order(
    configured: &[Http2PseudoHeader],
    extended_connect: bool,
) -> Result<PseudoOrder, Http2Error> {
    let mut order = PseudoOrder::builder();
    for header in configured {
        let id = match header {
            Http2PseudoHeader::Method => PseudoId::Method,
            Http2PseudoHeader::Authority => PseudoId::Authority,
            Http2PseudoHeader::Scheme => PseudoId::Scheme,
            Http2PseudoHeader::Path => PseudoId::Path,
            Http2PseudoHeader::Protocol if extended_connect => PseudoId::Protocol,
            Http2PseudoHeader::Protocol => return Err(Http2Error::UnsupportedSetting),
            _ => return Err(Http2Error::UnsupportedSetting),
        };
        order = order.push(id);
    }
    Ok(order.build())
}

fn translate_settings_with_pseudo_order(
    settings: &Http2Settings,
    configured_pseudo_order: &[Http2PseudoHeader],
    extended_connect: bool,
) -> Result<client::Builder, Http2Error> {
    let headers_dependency = settings
        .headers_priority
        .map(stream_dependency)
        .transpose()?;
    if let Some(priority) = settings.extended_connect_priority {
        stream_dependency(priority)?;
    }

    let mut client = client::Builder::new();
    client.initial_connection_window_size(settings.initial_connection_window_size);
    client.local_max_header_list_size(limits::MAX_RESPONSE_HEADER_LIST_BYTES);
    client.max_informational_responses(limits::MAX_INFORMATIONAL_RESPONSES);
    client.hpack_encoder_profile(hpack_encoder_profile(&settings.hpack)?);
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

    client
        .settings_order(order.build())
        .headers_pseudo_order(pseudo_order(configured_pseudo_order, extended_connect)?);
    if let Some(dependency) = headers_dependency {
        client.headers_stream_dependency(dependency);
    }
    Ok(client)
}

mod body;
mod connection;
mod driver;
mod error;
mod limits;
mod request;
mod tls;
mod tunnel;

pub use tls::{EchFailure, Http2TlsConnector, Http2TlsError, TlsError, TlsErrorKind};
pub(crate) use tls::{connect_selected, connect_selected_extended, validate_http2};

#[cfg(test)]
mod tests;
