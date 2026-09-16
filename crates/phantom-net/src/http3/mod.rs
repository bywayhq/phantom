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
use phantom_profile::Http3Settings;
use phantom_quic_btls::{HandshakeData, QuicClientConfig, StatelessResetKey};
use tracing::{Instrument, debug, debug_span, field};

use datagram::DatagramMonitor;
use driver::{DriverSignal, DriverTask};
use request::validate_request;

pub use body::Http3Body;
pub use error::{Http3Error, Http3ErrorKind};

type RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
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
    let span = debug_span!(
        "http3.response_head",
        method = %request.method(),
        protocol = "h3",
        status = field::Empty,
        outcome = field::Empty,
    );
    let result = async {
        validate_request(&request)?;
        let mut builder = settings::builder(settings, &crypto)?;
        let endpoint = endpoint(remote, crypto)?;

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
            .map_err(|error| {
                Http3Error::with_source(Http3ErrorKind::Connection, "QUIC connection failed", error)
            })?;
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
        };
        span.record("status", response.status().as_u16());

        let (parts, ()) = response.into_parts();
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
}

fn endpoint(
    remote: SocketAddr,
    crypto: Arc<QuicClientConfig>,
) -> Result<quinn::Endpoint, Http3Error> {
    let bind_address = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    let socket = UdpSocket::bind(bind_address).map_err(endpoint_error)?;
    socket.set_nonblocking(true).map_err(endpoint_error)?;
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
    let mut client_config = quinn::ClientConfig::new(crypto);
    client_config.transport_config(Arc::new(transport_config));
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
mod datagram;
mod driver;
mod error;
mod request;
mod settings;

#[cfg(test)]
mod tests;
