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
use http::{Request, Response};
use phantom_profile::{Http3RequestSettings, Http3Settings};
use phantom_quic_btls::{HandshakeData, QuicClientConfig, StatelessResetKey};
use tracing::{Instrument, debug, debug_span, field};

use datagram::DatagramMonitor;
use driver::{DriverSignal, DriverTask};
use request::{prepare_get, prepare_request};

pub use crate::request::{OriginForm, RequestHeader};
pub use body::Http3Body;
pub use connector::{Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind};
pub use error::{Http3Error, Http3ErrorKind};
#[cfg(feature = "qlog")]
pub use qlog::{QlogCapture, QlogCaptureError};

type RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

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
    let request = prepare_traced_get(request_settings, authority, target, headers)?;
    send_request(remote, server_name, crypto, settings, request).await
}

fn prepare_traced_get(
    request_settings: &Http3RequestSettings,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Request<()>, Http3Error> {
    let span = debug_span!(
        "http3.request.prepare",
        method = "GET",
        protocol = "h3",
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let request = {
        let _entered = span.enter();
        prepare_get(request_settings, authority, target, headers)
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

/// Sends one request over a new direct QUIC and HTTP/3 connection.
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
    send_request_inner(
        remote,
        server_name,
        crypto,
        settings,
        request,
        ConnectionDiagnostics::default(),
    )
    .await
}

/// Sends one request over a new direct QUIC connection while capturing bounded qlog output.
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
    send_request_inner(
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

async fn send_request_inner(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request: Request<()>,
    diagnostics: ConnectionDiagnostics,
) -> Result<Response<Http3Body>, Http3Error> {
    let span = debug_span!(
        "http3.response_head",
        method = %request.method(),
        protocol = "h3",
        status = field::Empty,
        outcome = field::Empty,
    );
    let result = async {
        let request = prepare_request(request)?;
        let mut builder = settings::builder(settings, &crypto)?;
        let endpoint = endpoint(remote, crypto, diagnostics)?;

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
        require_h3(&connection)?;
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
        let datagram_reader = settings
            .receives_datagrams()
            .then(|| h3_driver.get_datagram_reader());
        let mut driver = DriverTask::spawn(h3_driver, sender, endpoint, connection);
        let stream = driver.sender_mut()?.send_request(request).await?;
        let mut pending = PendingRequest::new(stream);
        let stream_id = pending.stream_mut()?.id();
        let mut datagrams = datagram_reader.map(|reader| DatagramMonitor::spawn(reader, stream_id));
        pending.stream_mut()?.finish().await?;
        let response = match receive_response(pending.stream_mut()?, datagrams.as_mut()).await {
            Ok(response) => response,
            Err(ResponseHeadError::Stream(error)) => return Err(error.into()),
            Err(ResponseHeadError::UnsupportedDatagram) => {
                datagrams.take();
                let stream = pending.into_stream()?;
                body::defer_datagram_abort(stream, driver);
                return Err(Http3Error::without_source(
                    Http3ErrorKind::Protocol,
                    "peer sent an HTTP Datagram for a request without datagram semantics",
                ));
            }
            Err(ResponseHeadError::SwitchingProtocols) => {
                return Err(Http3Error::without_source(
                    Http3ErrorKind::Protocol,
                    "peer sent a 101 response over HTTP/3",
                ));
            }
        };
        span.record("status", response.status().as_u16());

        let (mut parts, ()) = response.into_parts();
        let ordered_headers = parts
            .extensions
            .remove::<h3::ext::OrderedHeaders>()
            .map(|headers| {
                crate::OrderedResponseHeaders::from_normalized_fields(headers.as_slice())
            })
            .ok_or_else(|| {
                Http3Error::without_source(
                    Http3ErrorKind::Protocol,
                    "HTTP/3 response header order was not captured",
                )
            })?;
        parts.extensions.insert(ordered_headers);
        let stream = pending.into_stream()?;
        Ok(Response::from_parts(
            parts,
            Http3Body::new(stream, driver, datagrams),
        ))
    }
    .instrument(span.clone())
    .await;
    span.record("outcome", if result.is_ok() { "ok" } else { "error" });
    result
}

async fn receive_response(
    stream: &mut RequestStream,
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
    stream: &mut RequestStream,
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
    Stream(h3::error::StreamError),
    UnsupportedDatagram,
    SwitchingProtocols,
}

fn endpoint(
    remote: SocketAddr,
    crypto: Arc<QuicClientConfig>,
    diagnostics: ConnectionDiagnostics,
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
    let bind_address = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    let socket = UdpSocket::bind(bind_address).map_err(endpoint_error)?;
    socket.set_nonblocking(true).map_err(endpoint_error)?;
    let mut endpoint =
        quinn::Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))
            .map_err(endpoint_error)?;
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

fn require_h3(connection: &quinn::Connection) -> Result<(), Http3Error> {
    let metadata = connection.handshake_data().ok_or_else(|| {
        Http3Error::without_source(
            Http3ErrorKind::Handshake,
            "QUIC handshake completed without TLS metadata",
        )
    })?;
    let metadata = downcast_handshake_data(metadata)?;
    if metadata.protocol() == b"h3" {
        Ok(())
    } else {
        Err(Http3Error::without_source(
            Http3ErrorKind::Handshake,
            "QUIC TLS did not negotiate the required `h3` ALPN",
        ))
    }
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
    stream: Option<RequestStream>,
}

#[derive(Default)]
struct ConnectionDiagnostics {
    #[cfg(feature = "qlog")]
    qlog: Option<QlogCapture>,
}

impl PendingRequest {
    fn new(stream: RequestStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    fn stream_mut(&mut self) -> Result<&mut RequestStream, Http3Error> {
        self.stream.as_mut().ok_or_else(|| {
            Http3Error::without_source(
                Http3ErrorKind::Local,
                "HTTP/3 request driver is unavailable",
            )
        })
    }

    fn into_stream(mut self) -> Result<RequestStream, Http3Error> {
        self.stream.take().ok_or_else(|| {
            Http3Error::without_source(
                Http3ErrorKind::Local,
                "HTTP/3 request driver is unavailable",
            )
        })
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

mod body;
mod connector;
mod datagram;
mod driver;
mod error;
#[cfg(feature = "qlog")]
mod qlog;
mod request;
mod settings;

#[cfg(test)]
mod tests;
