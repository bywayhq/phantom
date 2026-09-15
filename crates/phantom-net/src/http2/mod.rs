//! A one-shot HTTP/2 client transaction.
//!
//! The core transaction accepts an already-connected byte stream. It owns no
//! pool and does not fall back to another HTTP version.

use std::{error::Error as StdError, fmt};

use ::http2::{
    client,
    frame::{PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId},
};
use http::{Request, Response};
use phantom_profile::{Http2PseudoHeader, Http2Setting, Http2Settings, InvalidHttp2Settings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

mod alps;
use body::DriverTask;
use request::prepare_get;
#[cfg(test)]
use request::{MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS};

pub use crate::request::{OriginForm, RequestHeader};
pub use body::Http2Body;

/// Error returned by a one-shot HTTP/2 transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http2Error {
    /// The HTTP/2 profile is internally inconsistent.
    InvalidSettings(InvalidHttp2Settings),
    /// The profile contains a setting this transport version cannot translate.
    UnsupportedSetting,
    /// The request stream was configured to depend on itself.
    InvalidPriorityDependency {
        /// Stream ID used by this one-shot transport.
        stream_id: u32,
    },
    /// The request authority is not a valid URI authority.
    InvalidAuthority(http::uri::InvalidUri),
    /// The request authority included forbidden URI user information.
    AuthorityContainsUserinfo,
    /// The internally composed HTTPS request URI was rejected.
    InvalidRequestUri(http::Error),
    /// The request contained more headers than the fixed safety bound.
    TooManyHeaders {
        /// Number of supplied headers.
        count: usize,
        /// Maximum accepted number of headers.
        maximum: usize,
    },
    /// The aggregate request header bytes exceeded the fixed safety bound.
    HeadersTooLarge {
        /// Number of supplied field-name and field-value bytes.
        bytes: usize,
        /// Maximum accepted aggregate bytes.
        maximum: usize,
    },
    /// A request field name was invalid or not entirely lowercase.
    InvalidHeaderName {
        /// Position in the ordered header list.
        index: usize,
    },
    /// A request field value contained bytes forbidden by HTTP.
    InvalidHeaderValue {
        /// Position in the ordered header list.
        index: usize,
        /// Field name supplied at that position.
        name: Box<str>,
    },
    /// A field forbidden in an HTTP/2 request was supplied.
    ForbiddenHeader {
        /// Forbidden field name.
        name: Box<str>,
    },
    /// `TE` had a value other than the exact token `trailers`.
    InvalidTe,
    /// The validated fields could not fit in the semantic header map.
    HeaderMapCapacity,
    /// The HTTP protocol driver failed.
    Protocol(::http2::Error),
}

impl fmt::Display for Http2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSettings(error) => error.fmt(formatter),
            Self::UnsupportedSetting => formatter.write_str(
                "HTTP/2 profile contains a setting unsupported by this transport version",
            ),
            Self::InvalidPriorityDependency { stream_id } => write!(
                formatter,
                "HTTP/2 request stream {stream_id} cannot depend on itself"
            ),
            Self::InvalidAuthority(_) => formatter.write_str("request authority is invalid"),
            Self::AuthorityContainsUserinfo => {
                formatter.write_str("request authority must not contain URI user information")
            }
            Self::InvalidRequestUri(_) => {
                formatter.write_str("failed to compose the absolute HTTPS request URI")
            }
            Self::TooManyHeaders { count, maximum } => {
                write!(
                    formatter,
                    "request has {count} headers; maximum is {maximum}"
                )
            }
            Self::HeadersTooLarge { bytes, maximum } => write!(
                formatter,
                "request field names and values total {bytes} bytes; maximum is {maximum}"
            ),
            Self::InvalidHeaderName { index } => write!(
                formatter,
                "request header at index {index} has an invalid or non-lowercase field name"
            ),
            Self::InvalidHeaderValue { index, name } => write!(
                formatter,
                "request header {name:?} at index {index} has an invalid field value"
            ),
            Self::ForbiddenHeader { name } => {
                write!(formatter, "{name} is not allowed on this HTTP/2 request")
            }
            Self::InvalidTe => {
                formatter.write_str("HTTP/2 TE must have the exact value `trailers`")
            }
            Self::HeaderMapCapacity => {
                formatter.write_str("request fields exceed the semantic header-map capacity")
            }
            Self::Protocol(error) => write!(formatter, "HTTP/2 protocol error: {error}"),
        }
    }
}

impl StdError for Http2Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidSettings(error) => Some(error),
            Self::InvalidAuthority(error) => Some(error),
            Self::InvalidRequestUri(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<::http2::Error> for Http2Error {
    fn from(error: ::http2::Error) -> Self {
        Self::Protocol(error)
    }
}

impl Http2Error {
    fn trace_kind(&self) -> &'static str {
        match self {
            Self::InvalidSettings(_) => "invalid_settings",
            Self::UnsupportedSetting => "unsupported_setting",
            Self::InvalidPriorityDependency { .. } => "invalid_priority_dependency",
            Self::InvalidAuthority(_) => "invalid_authority",
            Self::AuthorityContainsUserinfo => "authority_contains_userinfo",
            Self::InvalidRequestUri(_) => "invalid_request_uri",
            Self::TooManyHeaders { .. } => "too_many_headers",
            Self::HeadersTooLarge { .. } => "headers_too_large",
            Self::InvalidHeaderName { .. } => "invalid_header_name",
            Self::InvalidHeaderValue { .. } => "invalid_header_value",
            Self::ForbiddenHeader { .. } => "forbidden_header",
            Self::InvalidTe => "invalid_te",
            Self::HeaderMapCapacity => "header_map_capacity",
            Self::Protocol(_) => "protocol",
        }
    }
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
    let span = debug_span!(
        "http2.request.prepare",
        method = "GET",
        protocol = "h2",
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = ResponseHeadOutcome::new(&span);
    let prepared = {
        let _entered = span.enter();
        PreparedGet::new(settings, authority, target, headers)
    };
    match &prepared {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    let prepared = prepared?;
    send_prepared_get(stream, prepared).await
}

struct PreparedGet {
    request: Request<()>,
    client: client::Builder,
}

impl PreparedGet {
    fn new(
        settings: &Http2Settings,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Self, Http2Error> {
        settings.validate().map_err(Http2Error::InvalidSettings)?;
        let client = translate_settings(settings)?;
        let request = prepare_get(authority, target, headers)?;

        Ok(Self { request, client })
    }

    fn apply_initial_peer_settings(&mut self, settings: ::http2::frame::Settings) {
        self.client.initial_peer_settings(settings);
    }
}

async fn send_prepared_get<T>(
    stream: T,
    prepared: PreparedGet,
) -> Result<Response<Http2Body>, Http2Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let span = debug_span!(
        "http2.response_head",
        method = "GET",
        protocol = "h2",
        status = field::Empty,
        outcome = field::Empty,
    );
    let outcome = ResponseHeadOutcome::new(&span);
    let result = async {
        debug!("HTTP/2 transaction started");
        let (sender, connection) = prepared.client.handshake(stream).await?;
        let mut driver = DriverTask::spawn(connection, sender);

        driver.ready().await?;
        let (response, send_stream) = driver.sender_mut()?.send_request(prepared.request, true)?;
        let response = response.await?;

        span.record("status", response.status().as_u16());
        debug!("HTTP/2 response headers received");
        let (parts, incoming) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Http2Body::new(incoming, send_stream, driver),
        ))
    }
    .instrument(span.clone())
    .await;
    let terminal_outcome = match &result {
        Ok(_) => "ok",
        Err(Http2Error::Protocol(_)) => "protocol_error",
        Err(_) => "request_error",
    };
    outcome.finish(terminal_outcome);
    result
}

struct ResponseHeadOutcome {
    span: Span,
    recorded: bool,
}

impl ResponseHeadOutcome {
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

impl Drop for ResponseHeadOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            self.span.record("outcome", "cancelled");
        }
    }
}

fn translate_settings(settings: &Http2Settings) -> Result<client::Builder, Http2Error> {
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
mod request;
mod tls;

pub use tls::{Http2TlsConnector, Http2TlsError, TlsError, TlsErrorKind};

#[cfg(test)]
mod tests;
