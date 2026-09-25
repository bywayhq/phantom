use std::{
    any::Any,
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Method, Response};
use phantom_profile::{Http3RequestSettings, Http3Settings};
use phantom_quic_btls::{ApplicationState, HandshakeData, QuicClientConfig, StatelessResetKey};
use tracing::{debug, debug_span, field};

use connection::Session;
use datagram::{DatagramMonitor, DatagramRouter};
use driver::{DriverSignal, DriverTask, EarlyAnswer, LateApplicationSettings};
use early_data::{EarlyData, EarlyDataOutcome, InvalidHandshake};
use early_streams::Transport;
#[cfg(test)]
use request::prepare_request;
use request::{PreparedRequest, prepare_profiled_request_body_with_trailers};
use tokio::{runtime::Handle, sync::oneshot};

use crate::accept_ch::AcceptCh;
use crate::direct::{RuntimeUnavailable, poll_tokio_io};

mod alps;
mod early_data;
mod early_streams;
pub use crate::request::{OriginForm, RequestHeader};
pub use body::Http3Body;
pub use connect_udp::{ConnectUdpError, ConnectUdpErrorKind};
pub use connection::Http3Connection;
pub use connector::{Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind};
pub use error::{Http3Error, Http3ErrorKind, Http3Unprocessed};
pub use extended_connect::{
    Http3ExtendedConnectOutcome, Http3ExtendedConnectStream, Http3ExtendedProtocol,
};
#[cfg(feature = "qlog")]
pub use qlog::{QlogCapture, QlogCaptureError};

type RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type RequestSendStream = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type RequestRecvStream = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// `H3_GENERAL_PROTOCOL_ERROR` (RFC 9114, section 8.1).
const H3_GENERAL_PROTOCOL_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x0101);
/// `H3_INTERNAL_ERROR` (RFC 9114, section 8.1).
const H3_INTERNAL_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x0102);
/// `H3_SETTINGS_ERROR` (RFC 9114, section 8.1).
const H3_SETTINGS_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x0109);
/// Matches the HTTP CONNECT proxy's bound on interim responses per request.
const MAX_INFORMATIONAL_RESPONSES: usize = 8;

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
/// configuration. Pseudo-header order comes from `request_settings`, and
/// ordinary header order and duplicate positions are emitted exactly as
/// supplied. This path uses UDP only and never falls back to HTTP/2,
/// HTTP/1.1, or TCP. Profile and request validation complete before any
/// network I/O.
#[allow(clippy::too_many_arguments)]
pub async fn send_request(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request_settings: &Http3RequestSettings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Response<Http3Body>, Http3Error> {
    send_request_with_body(
        remote,
        server_name,
        crypto,
        settings,
        request_settings,
        method,
        authority,
        target,
        headers,
        None,
    )
    .await
}

/// Sends one request with an optional owned body over a new direct QUIC and
/// HTTP/3 connection.
///
/// Ordering, transport, and validation match [`send_request`]. A nonempty
/// body without a supplied `content-length` receives one after the supplied
/// headers.
#[allow(clippy::too_many_arguments)]
pub async fn send_request_with_body(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request_settings: &Http3RequestSettings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
) -> Result<Response<Http3Body>, Http3Error> {
    let request =
        prepare_traced_request(request_settings, method, authority, target, headers, body)?;
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
/// Ordering and validation match [`send_request_with_body`]. Trailer fields
/// are validated before the UDP endpoint is created. Duplicate fields,
/// cross-name order, and sensitivity markers are preserved.
#[allow(clippy::too_many_arguments)]
pub async fn send_request_with_body_and_trailers(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request_settings: &Http3RequestSettings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    trailers: Vec<RequestHeader>,
) -> Result<Response<Http3Body>, Http3Error> {
    let request = prepare_traced_request_body_with_trailers(
        request_settings,
        method,
        authority,
        target,
        headers,
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
/// Ordering and validation match [`send_request`]. The capture is single-use
/// and records only Quinn's QUIC metadata. Request headers and payloads are
/// not added to the qlog output.
#[cfg(feature = "qlog")]
#[allow(clippy::too_many_arguments)]
pub async fn send_request_with_qlog(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request_settings: &Http3RequestSettings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    capture: QlogCapture,
) -> Result<Response<Http3Body>, Http3Error> {
    send_request_with_body_and_qlog(
        remote,
        server_name,
        crypto,
        settings,
        request_settings,
        method,
        authority,
        target,
        headers,
        None,
        capture,
    )
    .await
}

/// Sends one request with an optional owned body over a new direct QUIC
/// connection while capturing bounded qlog output.
///
/// Ordering and validation match [`send_request_with_body`]. The capture is
/// single-use and records only Quinn's QUIC metadata. Request headers and
/// payloads are not added to the qlog output.
#[cfg(feature = "qlog")]
#[allow(clippy::too_many_arguments)]
pub async fn send_request_with_body_and_qlog(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request_settings: &Http3RequestSettings,
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    capture: QlogCapture,
) -> Result<Response<Http3Body>, Http3Error> {
    let request =
        prepare_traced_request(request_settings, method, authority, target, headers, body)?;
    send_prepared_request(
        remote,
        server_name,
        crypto,
        settings,
        request,
        ConnectionDiagnostics {
            qlog: Some(capture),
            ..Default::default()
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
    path_mtu: Option<u16>,
    diagnostics: ConnectionDiagnostics,
) -> Result<Http3Connection, Http3Error> {
    connect(
        remote,
        server_name,
        crypto,
        settings,
        diagnostics,
        Some(connector_identity),
        None,
        path_mtu,
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
    diagnostics: ConnectionDiagnostics,
) -> Result<Http3Connection, Http3Error> {
    connect(
        remote,
        server_name,
        crypto,
        settings,
        diagnostics,
        Some(connector_identity),
        Some(socket),
        None,
    )
    .await
}

/// Opens one QUIC and HTTP/3 connection.
///
/// `path_mtu`, when present, is the UDP payload size the connection assumes
/// from the start and never probes below (Quinn's initial and minimum MTU).
#[allow(clippy::too_many_arguments)]
async fn connect(
    remote: SocketAddr,
    server_name: &str,
    crypto: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    diagnostics: ConnectionDiagnostics,
    connector_identity: Option<Arc<()>>,
    socket: Option<Arc<dyn quinn::AsyncUdpSocket>>,
    path_mtu: Option<u16>,
) -> Result<Http3Connection, Http3Error> {
    let mut builder = settings::builder(settings, &crypto)?;
    let sends_early_data = crypto.sends_early_data();
    // A connection whose early data is rejected starts HTTP/3 again from
    // the same profile once its handshake completes.
    let restart_profile = sends_early_data.then(|| (settings.clone(), Arc::clone(&crypto)));
    // The server's SETTINGS are kept with each ticket this connection
    // receives, and read back when a ticket is presented with early data.
    let application_state = crypto.resumes_sessions().then(ApplicationState::new);
    let crypto = match &application_state {
        Some(state) => Arc::new(crypto.with_application_state(state)),
        None => crypto,
    };
    let round_trip = RoundTripRecorder::new(&crypto, server_name);
    #[cfg(test)]
    let peer_alps_override = diagnostics.early_peer_alps.clone();
    #[cfg(test)]
    let remembered_override = diagnostics.remembered_settings.clone();
    #[cfg(test)]
    let answer_hold = diagnostics.answer_hold.clone();
    #[cfg(test)]
    let gate_delay = diagnostics.gate_delay.clone();
    let endpoint = endpoint_with_socket(remote, crypto, diagnostics, socket, path_mtu)?;

    debug!("QUIC connection started");
    let connecting = endpoint.connect(remote, server_name).map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Connect,
            "failed to begin QUIC connection",
            error,
        )
    })?;
    // A connection that sends early data is used before its handshake ends,
    // so its TLS metadata, including any peer ALPS, is checked and applied
    // when the handshake completes; see `complete_early_handshake`.
    let (connection, zero_rtt) = if sends_early_data {
        match connecting.into_0rtt() {
            Ok((connection, accepted)) => {
                debug!("QUIC connection sending early data before its handshake completes");
                (connection, Some(accepted))
            }
            Err(connecting) => (connecting.await.map_err(connection_error)?, None),
        }
    } else {
        (connecting.await.map_err(connection_error)?, None)
    };
    // Early data starts from the SETTINGS of the connection that issued the
    // ticket, as RFC 9114 section 7.2.4.2 permits and Chromium does, so a
    // request can be encoded before the server's SETTINGS arrive.
    let remembered_settings = zero_rtt
        .as_ref()
        .and(application_state.as_ref())
        .and_then(ApplicationState::remembered);
    #[cfg(test)]
    let remembered_settings =
        remembered_settings.map(|stored| remembered_override.unwrap_or(stored));
    // Only this connection's own earlier SETTINGS are stored, so state that
    // does not decode means local corruption. The connection is closed and
    // the request fails with a protocol error; it is not a handshake failure,
    // so the pool does not repeat it with a full handshake.
    if let Some(remembered) = &remembered_settings {
        if let Err(error) = builder.remembered_peer_settings(remembered) {
            connection.close(H3_INTERNAL_ERROR, b"invalid remembered SETTINGS");
            return Err(Http3Error::with_source(
                Http3ErrorKind::Protocol,
                "remembered HTTP/3 SETTINGS are invalid",
                error,
            ));
        }
        debug!("HTTP/3 connection starting from remembered SETTINGS");
    }
    let accept_ch = Arc::new(OnceLock::new());
    if zero_rtt.is_none() {
        let handshake = require_h3(&connection)?;
        let mut decoded = AcceptCh::default();
        if let Some(peer_settings) = handshake.peer_application_settings() {
            decoded = decode_accept_ch(peer_settings)?;
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
        let _ = accept_ch.set(decoded);
        if let Some(round_trip) = &round_trip {
            round_trip.after_handshake(&connection);
        }
        debug!(
            session_resumed = handshake.session_resumed(),
            "QUIC connection established with exact h3 ALPN"
        );
    }

    // The early session opens request streams only while they are 0-RTT
    // streams or once the server accepted the early data; see
    // `early_streams`.
    let early_channel = zero_rtt.as_ref().map(|_| EarlyData::channel());
    let (gate, transport) = match &early_channel {
        Some((_, early_data)) => {
            let (gate, answer) = tokio::sync::watch::channel(None);
            (
                Some(gate),
                Transport::early(connection.clone(), answer, early_data.subscribe()),
            )
        }
        None => (None, Transport::new(connection.clone())),
    };
    let (h3_driver, sender) = builder.build(transport).await.map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Protocol,
            "HTTP/3 connection initialization failed",
            error,
        )
    })?;
    let datagrams = settings
        .receives_datagrams()
        .then(|| DatagramRouter::spawn(h3_driver.get_datagram_reader(), connection.rtt()));
    let session = Session::new(sender);
    let early = zero_rtt.zip(gate).map(|(accepted, gate)| {
        let (answer, answer_receiver) = oneshot::channel();
        let (replacement, replacement_receiver) = oneshot::channel();
        let (late_settings, late_settings_receiver) = oneshot::channel();
        (
            EarlyAnswer {
                accepted,
                gate,
                #[cfg(test)]
                gate_delay: gate_delay.clone(),
                answer,
                replacement: replacement_receiver,
            },
            late_settings_receiver,
            (answer_receiver, replacement, late_settings),
        )
    });
    let (early_answer, late_settings_receiver, early_handles) = match early {
        Some((answer, late_settings, handles)) => {
            (Some(answer), Some(late_settings), Some(handles))
        }
        None => (None, None, None),
    };
    let driver = DriverTask::spawn(
        h3_driver,
        endpoint,
        connection.clone(),
        early_answer,
        late_settings_receiver,
        application_state,
        round_trip.clone(),
    );
    let early_data = early_handles.zip(restart_profile).zip(early_channel).map(
        |(((answer, replacement, late_settings), (settings, crypto)), (publisher, early_data))| {
            let accepted = EarlyHandshake {
                connection: connection.clone(),
                accept_ch: Arc::clone(&accept_ch),
                round_trip: round_trip.clone(),
                #[cfg(test)]
                peer_alps_override: peer_alps_override.clone(),
            };
            let rejected = accepted.clone();
            let session = Arc::downgrade(&session);
            let router = datagrams.clone();
            #[cfg(test)]
            let publisher = publisher.with_test_hold(answer_hold.clone());
            publisher.spawn(
                connection.clone(),
                answer,
                move || complete_early_handshake(accepted, late_settings),
                move || {
                    restart_after_rejected_early_data(
                        rejected,
                        settings,
                        crypto,
                        replacement,
                        session,
                        router,
                    )
                },
            );
            early_data
        },
    );
    Ok(Http3Connection::new(
        session,
        driver,
        datagrams,
        connection,
        connector_identity,
        accept_ch,
        early_data,
        remembered_settings.is_some(),
    ))
}

/// What an early-data connection checks once its handshake completes.
#[derive(Clone)]
struct EarlyHandshake {
    connection: quinn::Connection,
    accept_ch: Arc<OnceLock<AcceptCh>>,
    round_trip: Option<RoundTripRecorder>,
    #[cfg(test)]
    peer_alps_override: Option<Arc<[u8]>>,
}

impl EarlyHandshake {
    /// Checks the exact `h3` ALPN and decodes the peer's ALPS, returning the
    /// ALPS payload and its `ACCEPT_CH` entries. Invalid metadata closes the
    /// connection, as a normal connection refuses it before its first
    /// request.
    fn check(&self) -> Result<Option<(Vec<u8>, AcceptCh)>, EarlyDataOutcome> {
        let handshake = match require_h3(&self.connection) {
            Ok(handshake) => handshake,
            Err(error) => {
                debug!(error = %error, "early-data handshake metadata is invalid");
                self.connection
                    .close(H3_GENERAL_PROTOCOL_ERROR, b"invalid handshake metadata");
                return Err(EarlyDataOutcome::Invalid(InvalidHandshake::Alpn));
            }
        };
        #[cfg(test)]
        let peer_settings = self
            .peer_alps_override
            .as_deref()
            .or(handshake.peer_application_settings());
        #[cfg(not(test))]
        let peer_settings = handshake.peer_application_settings();
        let Some(peer_settings) = peer_settings else {
            return Ok(None);
        };
        match decode_accept_ch(peer_settings) {
            Ok(decoded) => Ok(Some((peer_settings.to_vec(), decoded))),
            Err(error) => {
                debug!(error = %error, "early-data handshake metadata is invalid");
                self.connection
                    .close(H3_GENERAL_PROTOCOL_ERROR, b"invalid ALPS metadata");
                Err(EarlyDataOutcome::Invalid(InvalidHandshake::Alps))
            }
        }
    }

    /// Publishes the checked metadata to the connection's requests.
    fn finish(&self, accept_ch: AcceptCh) {
        let _ = self.accept_ch.set(accept_ch);
        if let Some(round_trip) = &self.round_trip {
            round_trip.after_handshake(&self.connection);
        }
    }
}

/// Checks and applies the TLS metadata of an early-data connection whose
/// handshake completed with its early data accepted.
///
/// The checks match those of a connection that waited for its handshake: the
/// exact `h3` ALPN, a well-formed `ACCEPT_CH` payload, and ALPS SETTINGS that
/// the HTTP/3 driver accepts, reconciled with any control-stream SETTINGS
/// that arrived first. A connection that fails them is closed.
async fn complete_early_handshake(
    handshake: EarlyHandshake,
    late_settings: oneshot::Sender<LateApplicationSettings>,
) -> EarlyDataOutcome {
    let alps = match handshake.check() {
        Ok(alps) => alps,
        Err(outcome) => return outcome,
    };
    let mut decoded = AcceptCh::default();
    if let Some((payload, accept_ch)) = alps {
        decoded = accept_ch;
        let (applied, result) = oneshot::channel();
        let delivered = late_settings.send(LateApplicationSettings { payload, applied });
        if delivered.is_err() {
            // The driver ended, so the connection is already closing.
            return EarlyDataOutcome::Failed;
        }
        match result.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                // The HTTP/3 driver closed the connection with
                // H3_SETTINGS_ERROR.
                debug!(error = %error, "early-data peer application settings are invalid");
                return EarlyDataOutcome::Invalid(InvalidHandshake::AlpsSettings);
            }
            Err(_) => return EarlyDataOutcome::Failed,
        }
    }
    handshake.finish(decoded);
    debug!("QUIC early-data handshake completed with exact h3 ALPN");
    EarlyDataOutcome::Accepted
}

/// Starts HTTP/3 again on a connection whose early data the server rejected.
///
/// The server processed none of the early data, and Quinn discarded every
/// stream opened before the handshake (RFC 9001, section 4.6.2), so the new
/// session opens its control and QPACK streams and resends its requests on
/// the same connection, as Chromium does. It starts from the completed
/// handshake's metadata, with the checks a normal connection applies, and
/// without the SETTINGS remembered with the ticket. `replacement` hands the
/// new driver to the connection's driver task; `session` receives the new
/// sender before the outcome is published.
async fn restart_after_rejected_early_data(
    handshake: EarlyHandshake,
    settings: Http3Settings,
    crypto: Arc<QuicClientConfig>,
    replacement: oneshot::Sender<driver::ClientDriver>,
    session: std::sync::Weak<Session>,
    datagrams: Option<DatagramRouter>,
) -> EarlyDataOutcome {
    let alps = match handshake.check() {
        Ok(alps) => alps,
        Err(outcome) => return outcome,
    };
    let Ok(mut builder) = settings::builder(&settings, &crypto) else {
        handshake
            .connection
            .close(H3_INTERNAL_ERROR, b"HTTP/3 profile unavailable");
        return EarlyDataOutcome::Failed;
    };
    let mut decoded = AcceptCh::default();
    if let Some((payload, accept_ch)) = alps {
        decoded = accept_ch;
        if let Err(error) = builder.peer_application_settings(&payload) {
            debug!(error = %error, "early-data peer application settings are invalid");
            handshake
                .connection
                .close(H3_SETTINGS_ERROR, b"invalid peer application settings");
            return EarlyDataOutcome::Invalid(InvalidHandshake::AlpsSettings);
        }
    }
    let (driver, sender) = match builder
        .build(Transport::new(handshake.connection.clone()))
        .await
    {
        Ok(started) => started,
        Err(error) => {
            debug!(error = %error, "HTTP/3 did not start again after rejected early data");
            // Closing sets the reason that `early_data_settled` reports.
            handshake
                .connection
                .close(H3_INTERNAL_ERROR, b"HTTP/3 restart failed");
            return EarlyDataOutcome::Failed;
        }
    };
    // The driver task drops the discarded session when it takes this one,
    // which fails any request still waiting on it.
    if replacement.send(driver).is_err() {
        return EarlyDataOutcome::Failed;
    }
    match session.upgrade() {
        Some(session) => session.replace(sender, datagrams.as_ref()).await,
        // The connection handle is gone; dropping the sender lets the new
        // driver close HTTP/3.
        None => return EarlyDataOutcome::Failed,
    }
    handshake.finish(decoded);
    debug!("QUIC handshake completed with rejected early data; HTTP/3 restarted");
    EarlyDataOutcome::Rejected
}

/// Feeds one connection's round-trip time to its connector's ticket cache,
/// which a later resumed connection to the same server advertises as
/// `initial_rtt_us` when its profile includes that parameter.
///
/// The value is recorded once the handshake completes, then again when the
/// connection ends, so a later connection sends the latest measurement. A
/// connection whose handshake never completed has only Quinn's initial
/// estimate, which is never recorded.
#[derive(Clone)]
pub(super) struct RoundTripRecorder {
    crypto: Arc<QuicClientConfig>,
    server_name: Arc<str>,
    measured: Arc<AtomicBool>,
}

impl RoundTripRecorder {
    /// Returns a recorder, or `None` when the connector keeps no tickets.
    fn new(crypto: &Arc<QuicClientConfig>, server_name: &str) -> Option<Self> {
        crypto.resumes_sessions().then(|| Self {
            crypto: Arc::clone(crypto),
            server_name: server_name.into(),
            measured: Arc::new(AtomicBool::new(false)),
        })
    }

    fn after_handshake(&self, connection: &quinn::Connection) {
        self.measured.store(true, Ordering::Release);
        self.crypto
            .record_round_trip_time(&self.server_name, connection.rtt());
    }

    pub(super) fn at_close(&self, connection: &quinn::Connection) {
        if self.measured.load(Ordering::Acquire) {
            self.crypto
                .record_round_trip_time(&self.server_name, connection.rtt());
        }
    }
}

/// Decodes the `ACCEPT_CH` entries of a peer's HTTP/3 ALPS payload.
fn decode_accept_ch(peer_settings: &[u8]) -> Result<AcceptCh, Http3Error> {
    let accept_ch = alps::decode(peer_settings).map_err(|error| {
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
    Ok(accept_ch)
}

async fn receive_response(
    stream: &mut RequestRecvStream,
    mut datagrams: Option<&mut DatagramMonitor>,
) -> Result<Response<()>, ResponseHeadError> {
    let mut informational = 0;
    loop {
        let response = receive_response_head(stream, datagrams.as_deref_mut()).await?;
        if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            stream.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
            return Err(ResponseHeadError::SwitchingProtocols);
        }
        if !response.status().is_informational() {
            return Ok(response);
        }
        informational += 1;
        if informational > MAX_INFORMATIONAL_RESPONSES {
            stream.stop_sending(h3::error::Code::H3_EXCESSIVE_LOAD);
            return Err(ResponseHeadError::TooManyInformational);
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
    TooManyInformational,
}

fn too_many_informational() -> Http3Error {
    Http3Error::without_source(
        Http3ErrorKind::Protocol,
        "peer sent more than 8 informational HTTP/3 responses",
    )
}

#[cfg(test)]
fn endpoint(
    remote: SocketAddr,
    crypto: Arc<QuicClientConfig>,
    diagnostics: ConnectionDiagnostics,
) -> Result<quinn::Endpoint, Http3Error> {
    endpoint_with_socket(remote, crypto, diagnostics, None, None)
}

fn endpoint_with_socket(
    remote: SocketAddr,
    crypto: Arc<QuicClientConfig>,
    diagnostics: ConnectionDiagnostics,
    socket: Option<Arc<dyn quinn::AsyncUdpSocket>>,
    path_mtu: Option<u16>,
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
    #[cfg(feature = "qlog")]
    if let Some(dir) = &diagnostics.qlog_dir {
        let stream = qlog::file_stream(dir).map_err(|error| {
            Http3Error::with_source(
                Http3ErrorKind::Configuration,
                "failed to create the QUIC qlog file",
                error,
            )
        })?;
        transport_config.qlog_stream(Some(stream));
    }
    if let Some(mtu) = path_mtu {
        transport_config.initial_mtu(mtu).min_mtu(mtu);
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
            let socket =
                UdpSocket::bind(endpoint_bind_address(remote.ip())).map_err(endpoint_error)?;
            socket.set_nonblocking(true).map_err(endpoint_error)?;
            quinn::Endpoint::new(endpoint_config, None, socket, runtime).map_err(endpoint_error)?
        }
    };
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Returns the local address for a QUIC endpoint that sends to `remote`.
///
/// A loopback remote gets the loopback address of its family, so a local
/// peer never leaves a socket listening on every interface. The kernel
/// chooses that same source address for an unspecified bind, so the packets
/// on the wire do not change. Any other remote gets the unspecified address.
fn endpoint_bind_address(remote: IpAddr) -> SocketAddr {
    let ip = match remote {
        IpAddr::V4(ip) if ip.is_loopback() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_loopback() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, 0)
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
pub(super) struct ConnectionDiagnostics {
    #[cfg(feature = "qlog")]
    qlog: Option<QlogCapture>,
    /// Directory that receives this connection's qlog file.
    #[cfg(feature = "qlog")]
    pub(super) qlog_dir: Option<Arc<std::path::Path>>,
    /// Peer ALPS an early-data connection reads in place of its handshake's
    /// when the handshake completes, for tests against peers without ALPS.
    #[cfg(test)]
    pub(super) early_peer_alps: Option<Arc<[u8]>>,
    /// State an early-data connection reads in place of the SETTINGS stored
    /// with its ticket, for tests of corrupt state.
    #[cfg(test)]
    pub(super) remembered_settings: Option<Arc<[u8]>>,
    /// Holds a restart after rejected early data before its answer is
    /// published, for tests of requests sent in between.
    #[cfg(test)]
    pub(super) answer_hold: Option<Arc<tokio::sync::Semaphore>>,
    /// Delays the driver's answer to the stream gate, for stress tests.
    #[cfg(test)]
    pub(super) gate_delay: Option<GateDelay>,
}

/// Returns how long a driver waits before it passes Quinn's early-data
/// answer to the stream gate.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct GateDelay(pub(super) Arc<dyn Fn() -> std::time::Duration + Send + Sync>);

#[cfg(test)]
impl GateDelay {
    fn next(&self) -> std::time::Duration {
        (self.0)()
    }
}

#[cfg(test)]
impl std::fmt::Debug for GateDelay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GateDelay")
    }
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
mod capsule;
mod connect_udp;
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
mod varint;

#[cfg(test)]
mod tests;
