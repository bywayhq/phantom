//! A one-shot HTTP/2 client transaction.
//!
//! The core transaction accepts an already-connected byte stream. It owns no
//! pool and does not fall back to another HTTP version.

use ::http2::{
    client,
    frame::{PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId},
};
use http::{Request, Response};
use phantom_profile::{Http2PseudoHeader, Http2Setting, Http2Settings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

mod alps;
use driver::DriverTask;
use request::prepare_get;
#[cfg(test)]
use request::{MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS};

pub use crate::request::{OriginForm, RequestHeader};
pub use body::Http2Body;
pub use error::{Http2Error, Http2ProtocolError, Http2ProtocolErrorKind};

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
    let outcome = OperationOutcome::new(&span);
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
    let outcome = OperationOutcome::new(&span);
    let result = async {
        debug!("HTTP/2 transaction started");
        let (sender, connection) = prepared
            .client
            .handshake(stream)
            .await
            .map_err(Http2Error::protocol)?;
        let mut driver = DriverTask::spawn(connection, sender);

        driver.ready().await.map_err(Http2Error::protocol)?;
        let (response, send_stream) = driver
            .sender_mut()
            .map_err(Http2Error::protocol)?
            .send_request(prepared.request, true)
            .map_err(Http2Error::protocol)?;
        let response = response.await.map_err(Http2Error::protocol)?;

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
mod driver;
mod error;
mod request;
mod shutdown_timer;
mod tls;

pub use tls::{Http2TlsConnector, Http2TlsError, TlsError, TlsErrorKind};

#[cfg(test)]
mod tests;
