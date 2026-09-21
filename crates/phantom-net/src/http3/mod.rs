use std::{
    any::Any,
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Method, Request, Response};
use phantom_profile::{Http3RequestSettings, Http3Settings};
use phantom_quic_btls::{HandshakeData, QuicClientConfig, StatelessResetKey};
use tracing::{debug, debug_span, field};

use datagram::{DatagramMonitor, DatagramRouter};
use driver::{DriverSignal, DriverTask};
use request::{
    PreparedRequest, prepare_profiled_request_body_with_trailers, prepare_request,
    prepare_request_body_with_trailers,
};
use tokio::runtime::Handle;

use crate::direct::{RuntimeUnavailable, poll_tokio_io};

mod alps;
pub use crate::request::{OriginForm, RequestHeader};
pub use body::Http3Body;
pub use connection::Http3Connection;
pub use connector::{Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind};
pub use error::{Http3Error, Http3ErrorKind};
pub use extended_connect::{
    Http3ExtendedConnectOutcome, Http3ExtendedConnectStream, Http3ExtendedProtocol,
};
#[cfg(feature = "qlog")]
pub use qlog::{QlogCapture, QlogCaptureError};

type RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type RequestSendStream = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type RequestRecvStream = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Sends one empty-body HTTP/3 GET over a new direct QUIC connection.
///
/// The profile, authority, target, and complete ordered header list are
/// validated before the UDP endpoint is created. Ordinary header order and
/// duplicate positions are emitted exactly as supplied.
#[allow(clippy::too_many_arguments)]
pub async fn send_get(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request_settings: &Http3RequestSettings,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Response<Http3Body>, Http3Error> {
    let request = prepare_traced_request(
        request_settings,
        Method::GET,
        authority,
        target,
        headers,
        None,
    )?;
    send_prepared_request(
        remote,
        server_name,
        crypto,
        settings,
        request,
        ConnectionDiagnostics::default(),
    )
    .await
}

fn prepare_traced_request(
    request_settings: &Http3RequestSettings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
) -> Result<PreparedRequest, Http3Error> {
    prepare_traced_request_body(
        request_settings,
        method,
        authority,
        target,
        headers,
        body.map(crate::request::RequestBody::from_bytes),
    )
}

fn prepare_traced_request_body(
    request_settings: &Http3RequestSettings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<crate::request::RequestBody>,
) -> Result<PreparedRequest, Http3Error> {
    prepare_traced_request_body_with_trailers(
        request_settings,
        method,
        authority,
        target,
        headers,
        body,
        Vec::new(),
    )
}

fn prepare_traced_request_body_with_trailers(
    request_settings: &Http3RequestSettings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<crate::request::RequestBody>,
    trailers: Vec<RequestHeader>,
) -> Result<PreparedRequest, Http3Error> {
    let body_bytes = body
        .as_ref()
        .and_then(|body| body.metadata().exact_length());
    let has_body = body.is_some();
    let span = debug_span!(
        "http3.request.prepare",
        method = %method,
        protocol = "h3",
        body_bytes = body_bytes.unwrap_or(0),
        body_length_known = body_bytes.is_some(),
        has_body,
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let request = {
        let _entered = span.enter();
        prepare_profiled_request_body_with_trailers(
            request_settings,
            method,
            authority,
            target,
            headers,
            body,
            trailers,
        )
    };
    match &request {
        Ok(_) => {
            span.record("outcome", "ok");
        }
        Err(error) => {
            span.record("outcome", "error");
            span.record("error_kind", error.trace_kind());
        }
    }
    request
}

/// Sends one empty-body request over a new direct QUIC and HTTP/3 connection.
///
/// The caller supplies a certificate-verifying BoringSSL-backed QUIC
/// configuration. This path uses UDP only and never falls back to HTTP/2,
/// HTTP/1.1, or TCP. Profile validation completes before any network I/O.
pub async fn send_request(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request: Request<()>,
) -> Result<Response<Http3Body>, Http3Error> {
    send_request_with_body(remote, server_name, crypto, settings, request, None).await
}

/// Sends one request with an optional owned body over a new direct QUIC and
/// HTTP/3 connection.
///
/// The caller supplies a certificate-verifying BoringSSL-backed QUIC
/// configuration. This path uses UDP only and never falls back to HTTP/2,
/// HTTP/1.1, or TCP. Profile validation completes before any network I/O.
pub async fn send_request_with_body(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request: Request<()>,
    body: Option<Bytes>,
) -> Result<Response<Http3Body>, Http3Error> {
    let request = prepare_request(request, body)?;
    send_prepared_request(
        remote,
        server_name,
        crypto,
        settings,
        request,
        ConnectionDiagnostics::default(),
    )
    .await
}

/// Sends one request with an optional owned body and exact ordered static trailers.
///
/// Trailer fields are validated before the UDP endpoint is created. Duplicate
/// fields, cross-name order, and sensitivity markers are preserved.
#[allow(clippy::too_many_arguments)]
pub async fn send_request_with_body_and_trailers(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request: Request<()>,
    body: Option<Bytes>,
    trailers: Vec<RequestHeader>,
) -> Result<Response<Http3Body>, Http3Error> {
    let request = prepare_request_body_with_trailers(
        request,
        body.map(crate::request::RequestBody::from_bytes),
        trailers,
    )?;
    send_prepared_request(
        remote,
        server_name,
        crypto,
        settings,
        request,
        ConnectionDiagnostics::default(),
    )
    .await
}

/// Sends one empty-body request over a new direct QUIC connection while
/// capturing bounded qlog output.
///
/// The capture is single-use and records only Quinn's QUIC metadata. Request
/// headers and payloads are not added to the qlog output.
#[cfg(feature = "qlog")]
pub async fn send_request_with_qlog(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request: Request<()>,
    capture: QlogCapture,
) -> Result<Response<Http3Body>, Http3Error> {
    send_request_with_body_and_qlog(
        remote,
        server_name,
        crypto,
        settings,
        request,
        None,
        capture,
    )
    .await
}

/// Sends one request with an optional owned body over a new direct QUIC
/// connection while capturing bounded qlog output.
///
/// The capture is single-use and records only Quinn's QUIC metadata. Request
/// headers and payloads are not added to the qlog output.
#[cfg(feature = "qlog")]
pub async fn send_request_with_body_and_qlog(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request: Request<()>,
    body: Option<Bytes>,
    capture: QlogCapture,
) -> Result<Response<Http3Body>, Http3Error> {
    let request = prepare_request(request, body)?;
    send_prepared_request(
        remote,
        server_name,
        crypto,
        settings,
        request,
        ConnectionDiagnostics {
            qlog: Some(capture),
        },
    )
    .await
}

async fn send_prepared_request(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request: PreparedRequest,
    diagnostics: ConnectionDiagnostics,
) -> Result<Response<Http3Body>, Http3Error> {
    Handle::try_current().map_err(|_| runtime_unavailable())?;
    poll_tokio_io(|| async {
        let connection = connect(
            remote,
            server_name,
            crypto,
            settings,
            diagnostics,
            None,
            None,
        )
        .await?;
        connection.send_prepared_request(request).await
    })
    .await
    .map_err(|RuntimeUnavailable| runtime_unavailable())?
}

fn runtime_unavailable() -> Http3Error {
    Http3Error::without_source(
        Http3ErrorKind::RuntimeUnavailable,
        "HTTP/3 network requests require a Tokio runtime with network I/O enabled",
    )
}

#[cfg(test)]
pub(super) async fn connect_direct(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
) -> Result<Http3Connection, Http3Error> {
    connect(
        remote,
        server_name,
        crypto,
        settings,
        ConnectionDiagnostics::default(),
        None,
        None,
    )
    .await
}

pub(super) async fn connect_bound(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    connector_identity: Arc<()>,
) -> Result<Http3Connection, Http3Error> {
    connect(
        remote,
        server_name,
        crypto,
        settings,
        ConnectionDiagnostics::default(),
        Some(connector_identity),
        None,
    )
    .await
}

pub(super) async fn connect_bound_with_socket(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    connector_identity: Arc<()>,
    socket: Arc<dyn quinn::AsyncUdpSocket>,
) -> Result<Http3Connection, Http3Error> {
    connect(
        remote,
        server_name,
        crypto,
        settings,
        ConnectionDiagnostics::default(),
        Some(connector_identity),
        Some(socket),
    )
    .await
}

async fn connect(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    diagnostics: ConnectionDiagnostics,
    connector_identity: Option<Arc<()>>,
    socket: Option<Arc<dyn quinn::AsyncUdpSocket>>,
) -> Result<Http3Connection, Http3Error> {
    let mut builder = settings::builder(settings, &crypto)?;
    let endpoint = endpoint_with_socket(remote, crypto, diagnostics, socket)?;

    debug!("QUIC connection started");
    let connection = endpoint
        .connect(remote, server_name)
        .map_err(|error| {
            Http3Error::with_source(
                Http3ErrorKind::Connect,
                "failed to begin QUIC connection",
                error,
            )
        })?
        .await
        .map_err(connection_error)?;
    let handshake = require_h3(&connection)?;
    let mut accept_ch = crate::accept_ch::AcceptCh::default();
    if let Some(peer_settings) = handshake.peer_application_settings() {
        accept_ch = alps::decode(peer_settings).map_err(|error| {
            Http3Error::with_source(
                Http3ErrorKind::Protocol,
                "peer HTTP/3 ALPS metadata is invalid",
                error,
            )
        })?;
        debug!(
            accept_ch_entry_count = accept_ch.len(),
            ignored_accept_ch_entry_count = accept_ch.ignored_len(),
            "HTTP/3 peer application settings decoded"
        );
        builder
            .peer_application_settings(peer_settings)
            .map_err(|error| {
                Http3Error::with_source(
                    Http3ErrorKind::Protocol,
                    "peer HTTP/3 application settings are invalid",
                    error,
                )
            })?;
    }
    debug!("QUIC connection established with exact h3 ALPN");

    let (h3_driver, sender) = builder
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| {
            Http3Error::with_source(
                Http3ErrorKind::Protocol,
                "HTTP/3 connection initialization failed",
                error,
            )
        })?;
    let datagrams = settings
        .receives_datagrams()
        .then(|| DatagramRouter::spawn(h3_driver.get_datagram_reader(), connection.rtt()));
    let driver = DriverTask::spawn(h3_driver, endpoint, connection.clone());
    Ok(Http3Connection::new(
        sender,
        driver,
        datagrams,
        connection,
        connector_identity,
        accept_ch,
    ))
}

async fn receive_response(
    stream: &mut RequestRecvStream,
    mut datagrams: Option<&mut DatagramMonitor>,
) -> Result<Response<()>, ResponseHeadError> {
    loop {
        let response = receive_response_head(stream, datagrams.as_deref_mut()).await?;
        if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            stream.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
            return Err(ResponseHeadError::SwitchingProtocols);
        }
        if !response.status().is_informational() {
            return Ok(response);
        }
    }
}

async fn receive_response_head(
    stream: &mut RequestRecvStream,
    datagrams: Option<&mut DatagramMonitor>,
) -> Result<Response<()>, ResponseHeadError> {
    let Some(datagrams) = datagrams else {
        return stream
            .recv_response()
            .await
            .map_err(ResponseHeadError::Stream);
    };

    enum Event {
        Response(Result<Response<()>, h3::error::StreamError>),
        UnsupportedDatagram,
    }

    let event = {
        let mut response = Box::pin(stream.recv_response());
        poll_fn(|context| {
            if let Poll::Ready(Some(())) = datagrams.poll_violation(context) {
                return Poll::Ready(Event::UnsupportedDatagram);
            }
            response.as_mut().poll(context).map(Event::Response)
        })
        .await
    };
    match event {
        Event::Response(response) => response.map_err(ResponseHeadError::Stream),
        Event::UnsupportedDatagram => Err(ResponseHeadError::UnsupportedDatagram),
    }
}

enum ResponseHeadError {
    RequestBody(Http3Error),
    Stream(h3::error::StreamError),
    UnsupportedDatagram,
    SwitchingProtocols,
}

#[cfg(test)]
fn endpoint(
    remote: SocketAddr,
    crypto: Arc<QuicClientConfig>,
    diagnostics: ConnectionDiagnostics,
) -> Result<quinn::Endpoint, Http3Error> {
    endpoint_with_socket(remote, crypto, diagnostics, None)
}

fn endpoint_with_socket(
    remote: SocketAddr,
    crypto: Arc<QuicClientConfig>,
    diagnostics: ConnectionDiagnostics,
    socket: Option<Arc<dyn quinn::AsyncUdpSocket>>,
) -> Result<quinn::Endpoint, Http3Error> {
    #[cfg(not(feature = "qlog"))]
    let _ = diagnostics;

    let reset_key = StatelessResetKey::generate().map_err(endpoint_error)?;
    let mut endpoint_config = quinn::EndpointConfig::new(Arc::new(reset_key));
    let mut transport_config = quinn::TransportConfig::default();
    crypto
        .configure_transport(&mut endpoint_config, &mut transport_config)
        .map_err(|error| {
            Http3Error::with_source(
                Http3ErrorKind::Configuration,
                "QUIC transport profile is incompatible with the runtime",
                error,
            )
        })?;
    #[cfg(feature = "qlog")]
    if let Some(capture) = diagnostics.qlog {
        let stream = capture.attach().map_err(|error| {
            Http3Error::with_source(
                Http3ErrorKind::Configuration,
                "failed to configure bounded QUIC qlog capture",
                error,
            )
        })?;
        transport_config.qlog_stream(Some(stream));
    }
    let mut client_config = quinn::ClientConfig::new(crypto);
    client_config.transport_config(Arc::new(transport_config));
    let runtime = Arc::new(quinn::TokioRuntime);
    let mut endpoint = match socket {
        Some(socket) => {
            quinn::Endpoint::new_with_abstract_socket(endpoint_config, None, socket, runtime)
                .map_err(endpoint_error)?
        }
        None => {
            let bind_address = match remote.ip() {
                IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            };
            let socket = UdpSocket::bind(bind_address).map_err(endpoint_error)?;
            socket.set_nonblocking(true).map_err(endpoint_error)?;
            quinn::Endpoint::new(endpoint_config, None, socket, runtime).map_err(endpoint_error)?
        }
    };
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn endpoint_error(error: impl std::error::Error + Send + Sync + 'static) -> Http3Error {
    Http3Error::with_source(
        Http3ErrorKind::Endpoint,
        "failed to initialize UDP/QUIC endpoint",
        error,
    )
}

fn connection_error(error: quinn::ConnectionError) -> Http3Error {
    let kind = if connection_error_is_tls(&error) {
        Http3ErrorKind::Handshake
    } else {
        Http3ErrorKind::Connection
    };
    Http3Error::with_source(kind, "QUIC connection failed", error)
}

fn connection_error_is_tls(error: &quinn::ConnectionError) -> bool {
    let code = match error {
        quinn::ConnectionError::TransportError(error) => error.code,
        quinn::ConnectionError::ConnectionClosed(close) => close.error_code,
        _ => return false,
    };
    (0x100..0x200).contains(&u64::from(code))
}

fn require_h3(connection: &quinn::Connection) -> Result<Box<HandshakeData>, Http3Error> {
    let metadata = connection.handshake_data().ok_or_else(|| {
        Http3Error::without_source(
            Http3ErrorKind::Handshake,
            "QUIC handshake completed without TLS metadata",
        )
    })?;
    let metadata = downcast_handshake_data(metadata)?;
    if metadata.protocol() != b"h3" {
        return Err(Http3Error::without_source(
            Http3ErrorKind::Handshake,
            "QUIC TLS did not negotiate the required `h3` ALPN",
        ));
    }
    Ok(metadata)
}

fn downcast_handshake_data(metadata: Box<dyn Any>) -> Result<Box<HandshakeData>, Http3Error> {
    metadata.downcast::<HandshakeData>().map_err(|_| {
        Http3Error::without_source(
            Http3ErrorKind::Handshake,
            "QUIC handshake returned an unexpected TLS metadata type",
        )
    })
}

struct PendingRequest {
    send: Option<RequestSendStream>,
    recv: Option<RequestRecvStream>,
}

#[derive(Default)]
struct ConnectionDiagnostics {
    #[cfg(feature = "qlog")]
    qlog: Option<QlogCapture>,
}

impl PendingRequest {
    fn new(stream: RequestStream) -> Self {
        let (send, recv) = stream.split();
        Self {
            send: Some(send),
            recv: Some(recv),
        }
    }

    fn streams_mut(
        &mut self,
    ) -> Result<(&mut RequestSendStream, &mut RequestRecvStream), Http3Error> {
        let send = self.send.as_mut().ok_or_else(|| {
            Http3Error::without_source(
                Http3ErrorKind::Local,
                "HTTP/3 request driver is unavailable",
            )
        })?;
        let recv = self.recv.as_mut().ok_or_else(|| {
            Http3Error::without_source(
                Http3ErrorKind::Local,
                "HTTP/3 request driver is unavailable",
            )
        })?;
        Ok((send, recv))
    }

    fn take_send(&mut self) -> Result<RequestSendStream, Http3Error> {
        self.send.take().ok_or_else(driver_unavailable)
    }

    fn recv_mut(&mut self) -> Result<&mut RequestRecvStream, Http3Error> {
        self.recv.as_mut().ok_or_else(driver_unavailable)
    }

    fn into_recv(mut self) -> Result<RequestRecvStream, Http3Error> {
        self.recv.take().ok_or_else(driver_unavailable)
    }

    fn into_streams(mut self) -> Result<(RequestSendStream, RequestRecvStream), Http3Error> {
        let send = self.send.take().ok_or_else(|| {
            Http3Error::without_source(
                Http3ErrorKind::Local,
                "HTTP/3 request driver is unavailable",
            )
        })?;
        let recv = self.recv.take().ok_or_else(|| {
            Http3Error::without_source(
                Http3ErrorKind::Local,
                "HTTP/3 request driver is unavailable",
            )
        })?;
        Ok((send, recv))
    }
}

fn driver_unavailable() -> Http3Error {
    Http3Error::without_source(
        Http3ErrorKind::Local,
        "HTTP/3 request driver is unavailable",
    )
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Some(recv) = self.recv.as_mut() {
            recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        }
        if let Some(send) = self.send.as_mut() {
            send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

mod body;
mod connection;
mod connector;
mod datagram;
mod driver;
mod error;
mod extended_connect;
#[cfg(feature = "qlog")]
mod qlog;
mod request;
mod settings;
mod upload;

#[cfg(test)]
mod tests;
