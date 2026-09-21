//! RFC 9298 CONNECT-UDP tunnels through an HTTP/3, HTTP/2, or HTTP/1.1 proxy.
//!
//! One outer proxy connection carries exactly one CONNECT-UDP request. Over
//! HTTP/3, UDP payloads travel in HTTP Datagrams (QUIC DATAGRAM frames,
//! RFC 9297 section 2.1). Over HTTP/2 and HTTP/1.1 they travel in DATAGRAM
//! capsules on the request's byte stream (RFC 9297 sections 3.2 and 3.5).
//! Every payload uses Context ID zero (RFC 9298 section 5). The inner QUIC
//! connection sees [`ConnectUdpSocket`] as one fixed logical peer.

use std::{
    error::Error as StdError,
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use h3::error::Code;
use http::{Request, StatusCode};
use quinn::{AsyncUdpSocket, SendDatagramError, UdpPoller, udp};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    runtime::Handle,
    sync::mpsc,
    task::JoinHandle,
};
use tracing::{Instrument, Span, debug_span, dispatcher, field, instrument::WithSubscriber};

use super::{
    Http3Connection, Http3Error, Http3ErrorKind, RequestRecvStream, RequestSendStream,
    capsule::{self, CapsuleDecoder, CapsuleError},
    connection::ConnectUdpExchange,
    datagram::{DatagramFlow, FlowCounters, FlowEnd, FlowShared, MAX_UDP_PAYLOAD_LEN},
    varint,
};
use crate::{
    http2::{Http2Error, Http2TlsError},
    proxy::{HttpConnectError, HttpConnectErrorKind, validate_basic_proxy_challenge},
};

/// Smallest UDP payload a QUIC client Initial occupies (RFC 9000 section 14.1).
const INNER_INITIAL_LEN: usize = 1200;
/// Quinn's conservative bound on a 1-RTT DATAGRAM frame's packet overhead:
/// short-header flags (1), the longest connection ID (20, RFC 9000 section
/// 17.3.1), the longest packet number (4), the AEAD tag (16), and the DATAGRAM
/// frame type plus length bound (9).
const OUTER_DATAGRAM_OVERHEAD: usize = 1 + 20 + 4 + 16 + 9;
/// HTTP/3 Datagram prefix on the outer connection's first request stream:
/// Quarter Stream ID zero (1) and Context ID zero (1).
const FIRST_STREAM_DATAGRAM_PREFIX: usize = 1 + 1;
/// UDP payload size the outer connection assumes from its first packet and
/// never probes below, so a full inner Initial always fits one HTTP Datagram.
pub(super) const OUTER_PATH_MTU: u16 =
    (INNER_INITIAL_LEN + FIRST_STREAM_DATAGRAM_PREFIX + OUTER_DATAGRAM_OVERHEAD) as u16;
/// Smallest local `max_datagram_frame_size` that accepts a full inner Initial
/// from the proxy: frame type (1), a two-byte length, and the datagram data
/// (RFC 9221 section 3 counts the whole frame).
pub(super) const MIN_OUTER_DATAGRAM_FRAME_SIZE: u64 =
    (1 + 2 + FIRST_STREAM_DATAGRAM_PREFIX + INNER_INITIAL_LEN) as u64;
/// Documentation-range address presented to the inner QUIC connection.
const LOGICAL_PEER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const MAX_PACKETS_PER_POLL: usize = 32;
const MAX_STREAM_READS_PER_POLL: usize = 16;
/// Encoded DATAGRAM capsules queued for a byte-stream leg before new sends
/// are dropped, like a full QUIC datagram send buffer.
const MAX_QUEUED_CAPSULES: usize = 256;
/// Bytes read from a byte-stream leg per capsule-decoder pass.
const STREAM_READ_CHUNK: usize = 16 * 1024;

/// Stable category of a CONNECT-UDP proxy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectUdpErrorKind {
    /// The CONNECT-UDP request, proxy server name, or fields are invalid.
    InvalidRequest,
    /// The outer HTTP/3 profile cannot carry a full-size inner QUIC Initial in
    /// one HTTP Datagram, or does not advertise HTTP Datagram support; or an
    /// HTTP/2 leg lacks an `h2` offer, HTTP/2 settings, or an extended
    /// CONNECT pseudo-header order.
    Configuration,
    /// No current Tokio runtime with network I/O enabled was available.
    RuntimeUnavailable,
    /// Resolving the proxy host failed.
    Resolve,
    /// The outer QUIC connection, or the TCP connection of an HTTP/1.1 or
    /// HTTP/2 leg, could not be established.
    Connect,
    /// The outer TLS handshake failed, or an HTTP/3 leg did not negotiate `h3`.
    Handshake,
    /// The TLS handshake of an HTTP/1.1 or HTTP/2 leg selected an ALPN
    /// protocol other than the configured leg's.
    UnsupportedProtocol,
    /// The proxy did not send `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`.
    ExtendedConnectUnavailable,
    /// The proxy did not enable HTTP/3 Datagrams in SETTINGS and QUIC
    /// transport parameters.
    DatagramUnavailable,
    /// The proxy's datagram limit cannot carry a full-size inner QUIC Initial.
    DatagramCapacity,
    /// The proxy answered with a final non-2xx status, or a final status
    /// other than 101 over HTTP/1.1.
    Rejected,
    /// The proxy's Basic challenge was malformed or unsupported, or it
    /// answered the one authenticated retry with 407.
    Authentication,
    /// The outer HTTP/3 exchange or tunnel failed.
    Protocol,
}

impl ConnectUdpErrorKind {
    pub(super) const fn trace_name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Configuration => "configuration",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Handshake => "handshake",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::ExtendedConnectUnavailable => "extended_connect_unavailable",
            Self::DatagramUnavailable => "datagram_unavailable",
            Self::DatagramCapacity => "datagram_capacity",
            Self::Rejected => "rejected",
            Self::Authentication => "authentication",
            Self::Protocol => "protocol",
        }
    }
}

/// Error returned while opening a CONNECT-UDP tunnel.
///
/// It is carried as the source of an
/// [`super::Http3ConnectorErrorKind::Proxy`] connector error.
#[derive(Debug)]
pub struct ConnectUdpError {
    kind: ConnectUdpErrorKind,
    status: Option<StatusCode>,
    message: &'static str,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl ConnectUdpError {
    pub(super) const fn new(kind: ConnectUdpErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            status: None,
            message,
            source: None,
        }
    }

    pub(super) fn with_source(
        kind: ConnectUdpErrorKind,
        message: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            status: None,
            message,
            source: Some(Box::new(source)),
        }
    }

    const fn rejected(status: StatusCode) -> Self {
        Self {
            kind: ConnectUdpErrorKind::Rejected,
            status: Some(status),
            message: "CONNECT-UDP proxy rejected the request",
            source: None,
        }
    }

    /// The authenticated retry was answered with 407.
    pub(super) const fn authentication_rejected() -> Self {
        Self {
            kind: ConnectUdpErrorKind::Authentication,
            status: Some(StatusCode::PROXY_AUTHENTICATION_REQUIRED),
            message: "CONNECT-UDP proxy rejected HTTP Basic authentication",
            source: None,
        }
    }

    /// Maps an unusable Basic challenge on a 407 response.
    fn challenge(error: HttpConnectError) -> Self {
        Self::with_source(
            ConnectUdpErrorKind::Authentication,
            "CONNECT-UDP proxy sent an unusable authentication challenge",
            error,
        )
    }

    /// Maps a failure while opening an HTTP/1.1 or HTTP/2 proxy leg.
    pub(super) fn proxy_leg(error: HttpConnectError) -> Self {
        let (kind, message) = match &error {
            HttpConnectError::Rejected { status } => match StatusCode::from_u16(*status) {
                Ok(status) => return Self::rejected(status),
                Err(_) => (
                    ConnectUdpErrorKind::Protocol,
                    "CONNECT-UDP proxy returned an invalid status",
                ),
            },
            HttpConnectError::AuthenticationRejected => return Self::authentication_rejected(),
            HttpConnectError::ProxyHttp2(inner)
                if matches!(
                    inner.as_ref(),
                    Http2TlsError::Http2(Http2Error::ExtendedConnectProtocolDisabled)
                ) =>
            {
                (
                    ConnectUdpErrorKind::ExtendedConnectUnavailable,
                    "CONNECT-UDP proxy did not enable extended CONNECT",
                )
            }
            _ => match error.kind() {
                HttpConnectErrorKind::InvalidConfiguration => (
                    ConnectUdpErrorKind::Configuration,
                    "CONNECT-UDP proxy connection is misconfigured",
                ),
                HttpConnectErrorKind::InvalidRequest => (
                    ConnectUdpErrorKind::InvalidRequest,
                    "CONNECT-UDP request is invalid",
                ),
                HttpConnectErrorKind::Authentication => (
                    ConnectUdpErrorKind::Authentication,
                    "CONNECT-UDP proxy sent an unusable authentication challenge",
                ),
                HttpConnectErrorKind::RuntimeUnavailable => (
                    ConnectUdpErrorKind::RuntimeUnavailable,
                    "CONNECT-UDP requires a Tokio runtime with network I/O enabled",
                ),
                HttpConnectErrorKind::Connect => (
                    ConnectUdpErrorKind::Connect,
                    "CONNECT-UDP proxy connection failed",
                ),
                HttpConnectErrorKind::Tls => (
                    ConnectUdpErrorKind::Handshake,
                    "CONNECT-UDP proxy handshake failed",
                ),
                HttpConnectErrorKind::UnsupportedProtocol => (
                    ConnectUdpErrorKind::UnsupportedProtocol,
                    "CONNECT-UDP proxy selected a different application protocol",
                ),
                _ => (
                    ConnectUdpErrorKind::Protocol,
                    "CONNECT-UDP proxy exchange failed",
                ),
            },
        };
        Self::with_source(kind, message, error)
    }

    /// Maps an invalid HTTP/1.1 or HTTP/2 leg request found before I/O.
    pub(super) fn proxy_leg_request(error: HttpConnectError) -> Self {
        Self::with_source(
            ConnectUdpErrorKind::InvalidRequest,
            "CONNECT-UDP request is invalid",
            error,
        )
    }

    /// Maps a leg configuration that cannot speak the selected protocol,
    /// found before I/O.
    pub(super) fn proxy_leg_configuration(error: HttpConnectError) -> Self {
        Self::with_source(
            ConnectUdpErrorKind::Configuration,
            "CONNECT-UDP proxy connection is misconfigured",
            error,
        )
    }

    /// Maps a failure to establish or use the outer HTTP/3 connection.
    pub(super) fn outer(error: Http3Error) -> Self {
        let (kind, message) = match error.kind() {
            Http3ErrorKind::Endpoint | Http3ErrorKind::Connect | Http3ErrorKind::Connection => (
                ConnectUdpErrorKind::Connect,
                "CONNECT-UDP proxy connection failed",
            ),
            Http3ErrorKind::Handshake => (
                ConnectUdpErrorKind::Handshake,
                "CONNECT-UDP proxy handshake failed",
            ),
            Http3ErrorKind::Configuration => (
                ConnectUdpErrorKind::Configuration,
                "CONNECT-UDP proxy connection is misconfigured",
            ),
            Http3ErrorKind::Request => (
                ConnectUdpErrorKind::InvalidRequest,
                "CONNECT-UDP request is invalid",
            ),
            Http3ErrorKind::RuntimeUnavailable => (
                ConnectUdpErrorKind::RuntimeUnavailable,
                "CONNECT-UDP requires a Tokio runtime with network I/O enabled",
            ),
            Http3ErrorKind::ExtendedConnectUnavailable => (
                ConnectUdpErrorKind::ExtendedConnectUnavailable,
                "CONNECT-UDP proxy did not enable extended CONNECT",
            ),
            _ => (
                ConnectUdpErrorKind::Protocol,
                "CONNECT-UDP proxy exchange failed",
            ),
        };
        Self::with_source(kind, message, error)
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> ConnectUdpErrorKind {
        self.kind
    }

    /// Returns the proxy's final status for [`ConnectUdpErrorKind::Rejected`].
    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        self.status
    }
}

impl fmt::Display for ConnectUdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)?;
        if let Some(status) = self.status {
            write!(formatter, " with status {}", status.as_u16())?;
        }
        Ok(())
    }
}

impl StdError for ConnectUdpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

/// Outer-profile capability needed before any CONNECT-UDP I/O.
pub(super) struct OuterProfile {
    pub(super) receives_http_datagrams: bool,
    pub(super) max_datagram_frame_size: Option<u64>,
    pub(super) max_udp_payload_size: u64,
}

/// Rejects an outer profile that cannot carry a full inner Initial in one
/// HTTP Datagram in either direction. Capsule fallback is never used.
pub(super) fn validate_outer_profile(profile: &OuterProfile) -> Result<(), ConnectUdpError> {
    if !profile.receives_http_datagrams {
        return Err(ConnectUdpError::new(
            ConnectUdpErrorKind::Configuration,
            "CONNECT-UDP requires an outer HTTP/3 profile that sends SETTINGS_H3_DATAGRAM = 1",
        ));
    }
    if profile
        .max_datagram_frame_size
        .is_none_or(|size| size < MIN_OUTER_DATAGRAM_FRAME_SIZE)
    {
        return Err(ConnectUdpError::new(
            ConnectUdpErrorKind::Configuration,
            "CONNECT-UDP requires an outer max_datagram_frame_size of at least 1205 bytes",
        ));
    }
    if profile.max_udp_payload_size < u64::from(OUTER_PATH_MTU) {
        return Err(ConnectUdpError::new(
            ConnectUdpErrorKind::Configuration,
            "CONNECT-UDP requires an outer max_udp_payload_size of at least 1252 bytes",
        ));
    }
    Ok(())
}

/// Creates the `proxy.connect_udp` span; it stays open for the tunnel's
/// lifetime so drop counters are recorded when the tunnel ends.
pub(super) fn span(proxy_leg: &'static str) -> Span {
    debug_span!(
        "proxy.connect_udp",
        proxy_protocol = "connect-udp",
        proxy_leg,
        status = field::Empty,
        authentication_retry = field::Empty,
        proxy_attempts = field::Empty,
        outcome = field::Empty,
        error_kind = field::Empty,
        dropped_unknown_context = field::Empty,
        dropped_overflow = field::Empty,
        dropped_early = field::Empty,
        dropped_malformed = field::Empty,
        dropped_oversized = field::Empty,
        dropped_send = field::Empty,
    )
}

pub(super) fn record_setup_outcome(span: &Span, result: &Result<(), &ConnectUdpError>) {
    match result {
        Ok(()) => {
            span.record("outcome", "accepted");
        }
        Err(error) => {
            span.record(
                "outcome",
                if matches!(
                    error.kind,
                    ConnectUdpErrorKind::Rejected | ConnectUdpErrorKind::Authentication
                ) {
                    "rejected"
                } else {
                    "error"
                },
            );
            span.record("error_kind", error.kind.trace_name());
        }
    }
}

/// Records whether the one challenge-driven authenticated retry happened.
pub(super) fn record_attempts(span: &Span, retried: bool) {
    span.record("authentication_retry", retried);
    span.record("proxy_attempts", if retried { 2_u64 } else { 1_u64 });
}

/// Result of one CONNECT-UDP request on a fresh proxy connection.
pub(super) enum OpenOutcome {
    /// The tunnel is open; the socket presents one fixed logical peer.
    Tunnel(Arc<dyn AsyncUdpSocket>, SocketAddr),
    /// The proxy sent 407 with a valid Basic challenge; retry once with
    /// credentials on another fresh proxy connection.
    Retry,
}

/// Opens the CONNECT-UDP stream on an established outer connection.
///
/// Peer SETTINGS must enable extended CONNECT and HTTP/3 Datagrams, and the
/// QUIC peer must accept DATAGRAM frames, before a request stream opens. No
/// datagram is sent before the 2xx response (optimistic sending, permitted by
/// RFC 9298 section 5, is not used). With `inspect_challenge`, a 407 carrying
/// a valid Basic challenge yields [`OpenOutcome::Retry`].
pub(super) async fn open(
    outer: Http3Connection,
    request: Request<()>,
    span: Span,
    inspect_challenge: bool,
) -> Result<OpenOutcome, ConnectUdpError> {
    let extensions = outer
        .peer_extensions()
        .await
        .map_err(ConnectUdpError::outer)?;
    if !extensions.extended_connect {
        return Err(ConnectUdpError::new(
            ConnectUdpErrorKind::ExtendedConnectUnavailable,
            "CONNECT-UDP proxy did not enable extended CONNECT",
        ));
    }
    // RFC 9297 section 2.1.1: DATAGRAM frames require the setting in both
    // directions; RFC 9221 section 3 requires the transport parameter.
    if !extensions.datagram || outer.max_datagram_size().is_none() {
        return Err(ConnectUdpError::new(
            ConnectUdpErrorKind::DatagramUnavailable,
            "CONNECT-UDP proxy did not enable HTTP/3 Datagrams",
        ));
    }
    let exchange = outer
        .send_connect_udp(request)
        .await
        .map_err(ConnectUdpError::outer)?;
    let (status, send, recv, flow) = match exchange {
        ConnectUdpExchange::Accepted {
            status,
            send,
            recv,
            flow,
        } => (status, send, recv, flow),
        ConnectUdpExchange::Rejected { status, headers } => {
            span.record("status", status.as_u16());
            if inspect_challenge && status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                validate_basic_proxy_challenge(&headers).map_err(ConnectUdpError::challenge)?;
                return Ok(OpenOutcome::Retry);
            }
            return Err(ConnectUdpError::rejected(status));
        }
    };
    span.record("status", status.as_u16());
    let stream = TunnelStream {
        send,
        recv,
        capsules: CapsuleDecoder::new(),
        ended: None,
    };
    let mut datagram_prefix = Vec::with_capacity(9);
    varint::encode(flow.stream_id() / 4, &mut datagram_prefix);
    datagram_prefix.push(0);
    let capacity = outer.max_datagram_size().unwrap_or(0);
    if capacity < datagram_prefix.len() + INNER_INITIAL_LEN {
        drop(stream);
        return Err(ConnectUdpError::new(
            ConnectUdpErrorKind::DatagramCapacity,
            "CONNECT-UDP proxy datagram limit cannot carry a 1200-byte QUIC Initial",
        ));
    }
    let socket = ConnectUdpSocket::new(
        Transport::Datagram(DatagramTransport {
            quinn: outer.quinn().clone(),
            datagram_prefix,
            flow,
            stream: Mutex::new(stream),
            _outer: outer,
        }),
        span,
    );
    let logical_peer = socket.logical_peer;
    Ok(OpenOutcome::Tunnel(Arc::new(socket), logical_peer))
}

/// Wraps an accepted HTTP/1.1 or HTTP/2 CONNECT-UDP byte stream.
///
/// Both directions carry DATAGRAM capsules (RFC 9297 section 3.5). A driver
/// task owns the stream; dropping the socket stops the task and closes the
/// stream, which closes the tunnel (RFC 9298 section 3.1). Capsules impose no
/// datagram size limit beyond the 65 527-byte Context ID zero bound.
pub(super) fn open_stream<S>(
    stream: S,
    span: Span,
) -> Result<(Arc<dyn AsyncUdpSocket>, SocketAddr), ConnectUdpError>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let runtime = Handle::try_current().map_err(|_| {
        ConnectUdpError::new(
            ConnectUdpErrorKind::RuntimeUnavailable,
            "CONNECT-UDP requires a Tokio runtime with network I/O enabled",
        )
    })?;
    let flow = Arc::new(FlowShared::default());
    let end = Arc::new(Mutex::new(None));
    let (outbound, outbound_rx) = mpsc::channel(MAX_QUEUED_CAPSULES);
    let dispatch = dispatcher::get_default(Clone::clone);
    let task = runtime.spawn(
        drive_capsule_stream(stream, outbound_rx, Arc::clone(&flow), Arc::clone(&end))
            .instrument(debug_span!("proxy.connect_udp.capsules"))
            .with_subscriber(dispatch),
    );
    let socket = ConnectUdpSocket::new(
        Transport::Stream(StreamTransport {
            flow,
            outbound,
            end,
            task,
        }),
        span,
    );
    let logical_peer = socket.logical_peer;
    Ok((Arc::new(socket), logical_peer))
}

/// Relays capsules until either direction ends, then records why.
async fn drive_capsule_stream<S>(
    stream: S,
    mut outbound: mpsc::Receiver<Bytes>,
    flow: Arc<FlowShared>,
    end: Arc<Mutex<Option<TunnelEnd>>>,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let read = async {
        let mut decoder = CapsuleDecoder::new();
        let mut buffer = vec![0; STREAM_READ_CHUNK];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    return match decoder.finish() {
                        Ok(()) => TunnelEnd::Finished,
                        Err(error) => TunnelEnd::Malformed(error),
                    };
                }
                Ok(count) => {
                    if let Err(error) = decoder.feed(&buffer[..count], |value| flow.deliver(value))
                    {
                        return TunnelEnd::Malformed(error);
                    }
                    // RFC 9298 section 5: an oversized Context ID zero payload
                    // aborts the stream.
                    if flow.received_oversized_payload() {
                        return TunnelEnd::OversizedDatagram;
                    }
                }
                Err(_) => return TunnelEnd::Reset,
            }
        }
    };
    let write = async {
        while let Some(capsule) = outbound.recv().await {
            if writer.write_all(&capsule).await.is_err() || writer.flush().await.is_err() {
                return Some(TunnelEnd::Reset);
            }
        }
        // The socket was dropped; closing the stream closes the tunnel.
        None
    };
    let reason = tokio::select! {
        reason = read => Some(reason),
        reason = write => reason,
    };
    if let Some(reason) = reason {
        lock(&end).get_or_insert(reason);
    }
    flow.end(FlowEnd::ConnectionClosed);
}

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The CONNECT-UDP request stream, whose lifetime bounds the tunnel
/// (RFC 9298 section 3.1).
struct TunnelStream {
    send: Box<RequestSendStream>,
    recv: Box<RequestRecvStream>,
    capsules: CapsuleDecoder,
    ended: Option<TunnelEnd>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelEnd {
    Finished,
    Reset,
    Malformed(CapsuleError),
    OversizedDatagram,
}

impl TunnelStream {
    /// Reads DATA into the capsule decoder, delivering DATAGRAM capsules to
    /// `flow`. Returns `Ready(true)` after progress and `Ready(false)` once
    /// the stream has ended.
    fn poll_capsules(&mut self, context: &mut Context<'_>, flow: &DatagramFlow) -> Poll<bool> {
        if self.ended.is_some() {
            return Poll::Ready(false);
        }
        for _ in 0..MAX_STREAM_READS_PER_POLL {
            match self.recv.poll_recv_data(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Some(mut data))) => {
                    let chunk = data.copy_to_bytes(data.remaining());
                    if let Err(error) = self
                        .capsules
                        .feed(&chunk, |payload| flow.deliver_capsule(payload))
                    {
                        self.abort(TunnelEnd::Malformed(error));
                        return Poll::Ready(false);
                    }
                }
                Poll::Ready(Ok(None)) => {
                    let end = match self.capsules.finish() {
                        Ok(()) => TunnelEnd::Finished,
                        Err(error) => TunnelEnd::Malformed(error),
                    };
                    self.abort(end);
                    return Poll::Ready(false);
                }
                Poll::Ready(Err(_)) => {
                    self.abort(TunnelEnd::Reset);
                    return Poll::Ready(false);
                }
            }
        }
        context.waker().wake_by_ref();
        Poll::Ready(true)
    }

    fn abort(&mut self, end: TunnelEnd) {
        if self.ended.is_some() {
            return;
        }
        let code = match end {
            // RFC 9297 section 3.3 treats Capsule Protocol errors as a
            // malformed message (RFC 9114 section 4.1.2).
            TunnelEnd::Malformed(_) => Code::H3_MESSAGE_ERROR,
            TunnelEnd::OversizedDatagram => Code::H3_DATAGRAM_ERROR,
            TunnelEnd::Finished | TunnelEnd::Reset => Code::H3_NO_ERROR,
        };
        self.recv.stop_sending(code);
        self.send.stop_stream(code);
        self.ended = Some(end);
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        // Closing the request stream closes the tunnel (RFC 9298 section 3.1).
        if self.ended.is_none() {
            self.recv.stop_sending(Code::H3_NO_ERROR);
            self.send.stop_stream(Code::H3_NO_ERROR);
        }
    }
}

/// Quinn socket that carries one inner QUIC connection over CONNECT-UDP.
///
/// The inner connection sends to and receives from one fixed logical peer.
/// Every payload leaves with Context ID zero, as an HTTP Datagram on an
/// HTTP/3 leg or as a DATAGRAM capsule on an HTTP/2 or HTTP/1.1 leg. Like
/// `quinn-udp`, only `WouldBlock` would reach Quinn from a send; undeliverable
/// or oversized datagrams are dropped and counted, and QUIC recovers the loss.
pub(super) struct ConnectUdpSocket {
    transport: Transport,
    logical_peer: SocketAddr,
    logical_local: SocketAddr,
    dropped_oversized: AtomicU64,
    dropped_send: AtomicU64,
    span: Span,
}

enum Transport {
    Datagram(DatagramTransport),
    Stream(StreamTransport),
}

/// HTTP/3 leg: QUIC DATAGRAM frames plus capsules on the request stream.
struct DatagramTransport {
    quinn: quinn::Connection,
    datagram_prefix: Vec<u8>,
    flow: DatagramFlow,
    stream: Mutex<TunnelStream>,
    // Declared last: the outer connection lease outlives the stream and flow.
    _outer: Http3Connection,
}

/// HTTP/2 or HTTP/1.1 leg: DATAGRAM capsules on one byte stream.
struct StreamTransport {
    flow: Arc<FlowShared>,
    outbound: mpsc::Sender<Bytes>,
    end: Arc<Mutex<Option<TunnelEnd>>>,
    task: JoinHandle<()>,
}

impl Drop for StreamTransport {
    fn drop(&mut self) {
        // Stopping the driver drops the proxy stream and closes the tunnel.
        self.task.abort();
    }
}

impl DatagramTransport {
    fn lock_stream(&self) -> MutexGuard<'_, TunnelStream> {
        lock(&self.stream)
    }

    fn encode_datagram(&self, payload: &[u8]) -> Bytes {
        let mut datagram = BytesMut::with_capacity(self.datagram_prefix.len() + payload.len());
        datagram.extend_from_slice(&self.datagram_prefix);
        datagram.extend_from_slice(payload);
        datagram.freeze()
    }
}

impl ConnectUdpSocket {
    fn new(transport: Transport, span: Span) -> Self {
        Self {
            transport,
            logical_peer: SocketAddr::new(IpAddr::V4(LOGICAL_PEER_IP), 443),
            logical_local: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            dropped_oversized: AtomicU64::new(0),
            dropped_send: AtomicU64::new(0),
            span,
        }
    }

    fn send_datagram(&self, transport: &DatagramTransport, payload: &[u8]) {
        match transport
            .quinn
            .send_datagram(transport.encode_datagram(payload))
        {
            Ok(()) => {}
            Err(SendDatagramError::TooLarge) => {
                self.dropped_oversized.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.dropped_send.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn send_capsule(&self, transport: &StreamTransport, payload: &[u8]) {
        let mut value = Vec::with_capacity(1 + payload.len());
        value.push(0);
        value.extend_from_slice(payload);
        let capsule = Bytes::from(capsule::encode(capsule::DATAGRAM, &value));
        if transport.outbound.try_send(capsule).is_err() {
            self.dropped_send.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Copies one payload into Quinn's buffer; `None` drops an oversized one.
    fn deliver(
        &self,
        payload: &[u8],
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Option<()> {
        // Quinn ends its endpoint driver on any receive error other than
        // `ConnectionReset`, so a payload that does not fit is dropped like
        // any datagram QUIC cannot accept.
        if payload.len() > bufs[0].len() {
            self.dropped_oversized.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        bufs[0][..payload.len()].copy_from_slice(payload);
        meta[0] = udp::RecvMeta {
            addr: self.logical_peer,
            len: payload.len(),
            stride: payload.len(),
            ecn: None,
            dst_ip: None,
        };
        Some(())
    }

    fn poll_recv_datagram(
        &self,
        transport: &DatagramTransport,
        context: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        for _ in 0..MAX_PACKETS_PER_POLL {
            match transport.flow.poll_recv(context) {
                Poll::Ready(Ok(payload)) => {
                    if self.deliver(&payload, bufs, meta).is_some() {
                        return Poll::Ready(Ok(1));
                    }
                    continue;
                }
                Poll::Ready(Err(end)) => {
                    if end == FlowEnd::OversizedPayload {
                        // RFC 9298 section 5: such a datagram aborts the stream.
                        transport.lock_stream().abort(TunnelEnd::OversizedDatagram);
                    }
                    return Poll::Ready(Err(tunnel_closed(end.into())));
                }
                Poll::Pending => {}
            }
            let mut stream = transport.lock_stream();
            match stream.poll_capsules(context, &transport.flow) {
                Poll::Ready(true) => {}
                Poll::Ready(false) => {
                    let end = stream.ended.unwrap_or(TunnelEnd::Reset);
                    return Poll::Ready(Err(tunnel_closed(end.into())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_recv_stream(
        &self,
        transport: &StreamTransport,
        context: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        for _ in 0..MAX_PACKETS_PER_POLL {
            match transport.flow.poll_recv(context) {
                Poll::Ready(Ok(payload)) => {
                    if self.deliver(&payload, bufs, meta).is_some() {
                        return Poll::Ready(Ok(1));
                    }
                }
                Poll::Ready(Err(FlowEnd::OversizedPayload)) => {
                    return Poll::Ready(Err(tunnel_closed(TunnelEnd::OversizedDatagram.into())));
                }
                Poll::Ready(Err(_)) => {
                    let end = lock(&transport.end).unwrap_or(TunnelEnd::Reset);
                    return Poll::Ready(Err(tunnel_closed(end.into())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }
}

impl fmt::Debug for ConnectUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectUdpSocket")
            .field("logical_peer", &self.logical_peer)
            .field(
                "transport",
                &match self.transport {
                    Transport::Datagram(_) => "http_datagram",
                    Transport::Stream(_) => "datagram_capsule",
                },
            )
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for ConnectUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ConnectUdpPoller)
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.logical_peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CONNECT-UDP tunnel received a different logical target",
            ));
        }
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CONNECT-UDP tunnel does not support segmented sends",
            ));
        }
        // RFC 9298 section 5: Context ID zero never carries more than 65 527
        // bytes, on either transport.
        if transmit.contents.len() > MAX_UDP_PAYLOAD_LEN {
            self.dropped_oversized.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        match &self.transport {
            Transport::Datagram(transport) => self.send_datagram(transport, transmit.contents),
            Transport::Stream(transport) => self.send_capsule(transport, transmit.contents),
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match &self.transport {
            Transport::Datagram(transport) => {
                self.poll_recv_datagram(transport, context, bufs, meta)
            }
            Transport::Stream(transport) => self.poll_recv_stream(transport, context, bufs, meta),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.logical_local)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

impl Drop for ConnectUdpSocket {
    fn drop(&mut self) {
        let FlowCounters {
            dropped_unknown_context,
            dropped_overflow,
            dropped_early,
            dropped_malformed,
            ..
        } = match &self.transport {
            Transport::Datagram(transport) => transport.flow.counters(),
            Transport::Stream(transport) => transport.flow.counters(),
        };
        self.span
            .record("dropped_unknown_context", dropped_unknown_context);
        self.span.record("dropped_overflow", dropped_overflow);
        self.span.record("dropped_early", dropped_early);
        self.span.record("dropped_malformed", dropped_malformed);
        self.span.record(
            "dropped_oversized",
            self.dropped_oversized.load(Ordering::Relaxed),
        );
        self.span
            .record("dropped_send", self.dropped_send.load(Ordering::Relaxed));
    }
}

/// Sending never blocks: Quinn queues HTTP Datagrams and drops the oldest when
/// its bounded send buffer is full.
#[derive(Debug)]
struct ConnectUdpPoller;

impl UdpPoller for ConnectUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Why the tunnel stopped carrying datagrams.
#[derive(Debug)]
enum TunnelClosed {
    Flow(FlowEnd),
    Stream(TunnelEnd),
}

impl From<FlowEnd> for TunnelClosed {
    fn from(end: FlowEnd) -> Self {
        Self::Flow(end)
    }
}

impl From<TunnelEnd> for TunnelClosed {
    fn from(end: TunnelEnd) -> Self {
        Self::Stream(end)
    }
}

impl fmt::Display for TunnelClosed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Flow(FlowEnd::ConnectionClosed) => "CONNECT-UDP outer connection closed",
            Self::Flow(FlowEnd::RouterFailed) => "CONNECT-UDP outer datagram routing failed",
            Self::Flow(FlowEnd::OversizedPayload) => {
                "CONNECT-UDP proxy sent a UDP payload longer than 65527 bytes"
            }
            Self::Stream(TunnelEnd::Finished) => "CONNECT-UDP proxy closed the request stream",
            Self::Stream(TunnelEnd::Reset) => "CONNECT-UDP request stream failed",
            Self::Stream(TunnelEnd::Malformed(error)) => error.message(),
            Self::Stream(TunnelEnd::OversizedDatagram) => {
                "CONNECT-UDP proxy sent a UDP payload longer than 65527 bytes"
            }
        })
    }
}

impl StdError for TunnelClosed {}

/// Ends the inner endpoint: Quinn stops its driver on any receive error other
/// than `ConnectionReset`, so the inner connection is never reused.
fn tunnel_closed(reason: TunnelClosed) -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, reason)
}

#[cfg(test)]
mod tests;
