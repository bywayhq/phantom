//! Loopback origin recording each connection's ALPN offer and openings.
//!
//! Every accepted connection records the client's ALPN offer. HTTP/2
//! connections record each client HEADERS frame's priority, pseudo-field
//! HPACK representations, and ordered ordinary fields; HTTP/1.1 connections
//! record the opening request line and fields.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::{AlpnError, select_next_proto};
use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use http::{Method, Response};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::timeout,
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, connection_peer::FixtureFailures},
};

use super::{
    TestResult,
    fixture::Representation,
    tls_support::{H2_ALPN, TestIdentity, accept_tls_stream, read_head},
    websocket_support::append_server_frame,
};

const ALPN_PREFERENCE: &[u8] = b"\x02h2\x08http/1.1";
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// HPACK Huffman encoding of `:protocol`, the only literal pseudo-field name.
const PROTOCOL_HUFFMAN: &[u8] = &[0xb9, 0x5d, 0x87, 0x49, 0xc8, 0x7a, 0x3f];
// Fixture guardrails, comfortably above the scripts' two connections and six
// requests. They bound a defective client without changing the expected wire.
const MAX_CONNECTIONS: usize = 64;
const MAX_ACTIVE_CONNECTIONS: usize = 16;
const MAX_RECORDS: usize = 128;
const MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reply {
    Accept,
    Reject,
    RefuseStream,
    /// Refuses the first extended CONNECT stream and accepts the rest, as the
    /// retained `refused-stream` captures' server does.
    RefuseFirstStream,
    /// Resets the extended CONNECT stream with `INTERNAL_ERROR`, a peer reset
    /// that is not `REFUSED_STREAM`, leaving the session usable.
    ResetStream,
    /// Answers the extended CONNECT with a connection-level GOAWAY instead of
    /// a stream reset, so the stream fails without `REFUSED_STREAM`.
    GoAway,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Behavior {
    /// Whether HTTP/2 SETTINGS enable extended CONNECT.
    pub(crate) connect_protocol: bool,
    pub(crate) connect: Reply,
    pub(crate) upgrade: Reply,
    /// Whether an accepted extended CONNECT selects `permessage-deflate`.
    pub(crate) deflate: bool,
}

impl Behavior {
    pub(crate) const ACCEPT: Self = Self {
        connect_protocol: true,
        connect: Reply::Accept,
        upgrade: Reply::Accept,
        deflate: false,
    };
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectionLog {
    pub(crate) alpn_offer: Vec<String>,
    pub(crate) protocol: Option<String>,
    pub(crate) h2: Vec<H2Headers>,
    pub(crate) h1: Vec<H1Request>,
    /// Client WebSocket data frames, in arrival order.
    pub(crate) client_frames: Vec<ClientDataFrame>,
    /// Client `RST_STREAM` frames as (stream, error code), filled when the
    /// log is read so it always reflects every byte received so far.
    pub(crate) resets: Vec<(u32, u32)>,
    /// Every byte the client sent, for the reset scan.
    client_wire: Arc<Mutex<Vec<u8>>>,
}

/// One WebSocket data frame the client sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClientDataFrame {
    pub(crate) rsv1: bool,
    pub(crate) opcode: u8,
    /// Payload length on the wire, after any compression.
    pub(crate) payload_len: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct H2Headers {
    pub(crate) stream_id: u32,
    pub(crate) method: String,
    pub(crate) priority: Option<Priority>,
    pub(crate) pseudo: PseudoFields,
    pub(crate) fields: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub(crate) struct H1Request {
    pub(crate) request_line: String,
    pub(crate) fields: Vec<(String, String)>,
}

type Log = Arc<Mutex<Vec<ConnectionLog>>>;
type ServingFailure = Arc<Mutex<Option<Box<dyn std::error::Error + Send + Sync>>>>;
/// RFC 7540 HEADERS priority as (exclusive, dependency, weight).
pub(crate) type Priority = (bool, u32, u16);
/// Pseudo-field names with their HPACK representation, in wire order.
pub(crate) type PseudoFields = Vec<(String, Representation)>;

#[derive(Debug)]
pub(crate) struct TestServer {
    pub(crate) address: SocketAddr,
    log: Log,
    task: Option<ConnectionPeer<TestResult<()>>>,
    stop: watch::Sender<bool>,
    failure: Option<Box<dyn std::error::Error + Send + Sync>>,
    serving_failure: ServingFailure,
    incomplete_shutdown: bool,
}

impl TestServer {
    pub(crate) async fn start(identity: Arc<TestIdentity>, behavior: Behavior) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let log = Log::default();
        Ok(Self::listening(listener, address, log, Some(identity), behavior))
    }

    /// Starts a plaintext HTTP/1.1 origin for `ws://` openings.
    pub(crate) async fn start_plaintext(behavior: Behavior) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let log = Log::default();
        Ok(Self::listening(listener, address, log, None, behavior))
    }

    fn listening(
        listener: TcpListener,
        address: SocketAddr,
        log: Log,
        identity: Option<Arc<TestIdentity>>,
        behavior: Behavior,
    ) -> Self {
        let (stop, stopped) = watch::channel(false);
        let serving_failure = ServingFailure::default();
        let task = ConnectionPeer::spawn(serve_listener(
            listener, Arc::clone(&log), identity, behavior, stop.clone(), stopped,
            Arc::clone(&serving_failure),
        ));
        Self { address, log, task: Some(task), stop, failure: None, serving_failure, incomplete_shutdown: false }
    }

    pub(crate) fn connections(&self) -> TestResult<Vec<ConnectionLog>> {
        self.log.lock().map_err(|_| "server log lock was poisoned")?
            .iter().map(|connection| {
                let mut connection = connection.clone();
                connection.resets = client_resets(&connection.client_wire.lock()
                    .map_err(|_| "recorded wire lock was poisoned")?);
                Ok(connection)
            }).collect()
    }

    /// Stop admission, then observe every accepted connection before returning
    /// the caller's result. The worker remains owned if this await is dropped.
    pub(crate) async fn finish<T>(&mut self, caller: TestResult<T>) -> TestResult<T> {
        let value = match caller {
            Ok(value) => Some(value),
            Err(error) => { retain_failure(&mut self.failure, error); None }
        };
        self.stop.send_replace(true);
        let Some(task) = self.task.as_mut() else {
            if let Some(error) = self.failure.take() { return Err(error); }
            if self.incomplete_shutdown { return Err("an earlier profile shutdown returned before collection completed".into()); }
            return value.ok_or_else(|| "profile server caller completed without a value".into());
        };
        let joined = match timeout(CLEANUP_TIMEOUT, &mut *task).await {
            Ok(joined) => Some(joined),
            Err(elapsed) => {
                retain_failure(&mut self.failure, FixtureDeadline::new(
                    "profile server cleanup exceeded its deadline", elapsed,
                ).into());
                task.abort();
                match timeout(CLEANUP_TIMEOUT, &mut *task).await {
                    Ok(joined) => Some(joined),
                    Err(elapsed) => {
                        retain_failure(&mut self.failure, FixtureDeadline::new(
                            "profile server abort exceeded its deadline", elapsed,
                        ).into());
                        self.incomplete_shutdown = true;
                        None
                    }
                }
            }
        };
        if let Some(joined) = joined {
            self.task.take();
            match self.serving_failure.lock() {
                Ok(mut serving) => {
                    if let Some(error) = serving.take() { retain_failure(&mut self.failure, error); }
                }
                Err(_) => retain_failure(&mut self.failure, "profile serving outcome lock was poisoned".into()),
            }
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => retain_failure(&mut self.failure, error),
                Err(error) => retain_failure(&mut self.failure, error.into()),
            }
        }
        if let Some(error) = self.failure.take() { return Err(error); }
        if self.incomplete_shutdown { return Err("an earlier profile shutdown returned before collection completed".into()); }
        value.ok_or_else(|| "profile server caller completed without a value".into())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        // External destruction cannot asynchronously join. The retained worker
        // owns its JoinSet, whose Drop aborts remaining accepted connections.
        if let Some(task) = &self.task { task.abort(); }
    }
}

pub(super) fn retain_failure(
    failure: &mut Option<Box<dyn std::error::Error + Send + Sync>>,
    error: Box<dyn std::error::Error + Send + Sync>,
) {
    *failure = Some(match failure.take() {
        Some(primary) => Box::new(FixtureFailures { primary, cleanup: error }),
        None => error,
    });
}

async fn stop_requested(stopped: &mut watch::Receiver<bool>) -> TestResult<()> {
    if !*stopped.borrow() { stopped.changed().await?; }
    Ok(())
}

async fn serve_listener(
    listener: TcpListener,
    log: Log,
    identity: Option<Arc<TestIdentity>>,
    behavior: Behavior,
    stop: watch::Sender<bool>,
    mut stopped: watch::Receiver<bool>,
    failure: ServingFailure,
) -> TestResult<()> {
    let mut children = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            result = stop_requested(&mut stopped) => {
                if let Err(error) = result { retain_serving_failure(&failure, error)?; }
                break;
            }
            joined = children.join_next(), if !children.is_empty() => {
                match joined.ok_or("accepted peer outcome disappeared")? {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => { retain_serving_failure(&failure, error)?; break; }
                    Err(error) => { retain_serving_failure(&failure, error.into())?; break; }
                }
            }
            accepted = listener.accept() => {
                let (tcp, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => { retain_serving_failure(&failure, error.into())?; break; }
                };
                let index = match log.lock() {
                    Ok(mut log) if log.len() < MAX_CONNECTIONS && children.len() < MAX_ACTIVE_CONNECTIONS => {
                        log.push(ConnectionLog::default()); log.len() - 1
                    }
                    Ok(_) => { retain_serving_failure(&failure, "profile connection bound exceeded".into())?; break; }
                    Err(_) => { retain_serving_failure(&failure, "server log lock was poisoned".into())?; break; }
                };
                let log = Arc::clone(&log);
                let stopped = stopped.clone();
                if let Some(identity) = &identity {
                    let identity = Arc::clone(identity);
                    children.spawn(async move { serve(tcp, &identity, index, &log, behavior, stopped).await });
                } else {
                    children.spawn(async move { serve_h1(tcp, index, &log, behavior, stopped).await });
                }
            }
        }
    }
    drop(listener);
    stop.send_replace(true);
    while let Some(joined) = children.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => retain_serving_failure(&failure, error)?,
            Err(error) => retain_serving_failure(&failure, error.into())?,
        }
    }
    Ok(())
}

fn retain_serving_failure(
    failure: &ServingFailure,
    error: Box<dyn std::error::Error + Send + Sync>,
) -> TestResult<()> {
    let mut failure = failure.lock().map_err(|_| "profile serving outcome lock was poisoned")?;
    retain_failure(&mut failure, error);
    Ok(())
}

async fn serve(
    tcp: TcpStream,
    identity: &TestIdentity,
    index: usize,
    log: &Log,
    behavior: Behavior,
    mut stopped: watch::Receiver<bool>,
) -> TestResult<()> {
    let offer = Arc::new(Mutex::new(Vec::new()));
    let mut builder = identity.acceptor_builder(H2_ALPN)?;
    let recorded_offer = Arc::clone(&offer);
    builder.set_alpn_select_callback(move |_, offered| {
        if let Ok(mut offer) = recorded_offer.lock() {
            offer.extend_from_slice(offered);
        }
        select_next_proto(ALPN_PREFERENCE, offered).ok_or(AlpnError::NOACK)
    });
    let stream = tokio::select! {
        biased;
        result = accept_tls_stream(tcp, builder.build()) => result?,
        result = stop_requested(&mut stopped) => return result,
    };
    let protocol = stream
        .ssl()
        .selected_alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
    let alpn_offer = decode_alpn(&offer.lock().map_err(|_| "ALPN offer lock was poisoned")?);
    update(log, index, |connection| {
        connection.alpn_offer = alpn_offer;
        connection.protocol.clone_from(&protocol);
    })?;
    match protocol.as_deref() {
        Some("h2") => serve_h2(stream, index, log, behavior, stopped).await,
        _ => serve_h1(stream, index, log, behavior, stopped).await,
    }
}

async fn serve_h2<T>(stream: T, index: usize, log: &Log, behavior: Behavior, mut stopped: watch::Receiver<bool>) -> TestResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let io = RecordingIo {
        inner: stream,
        read: Arc::clone(&recorded),
    };
    let mut builder = ::http2::server::Builder::new();
    if behavior.connect_protocol {
        builder.enable_connect_protocol();
    }
    update(log, index, |connection| {
        connection.client_wire = Arc::clone(&recorded);
    })?;
    let mut connection = tokio::select! {
        biased;
        result = builder.handshake::<_, Bytes>(io) => result?,
        result = stop_requested(&mut stopped) => return result,
    };
    let mut wire = WireDecoder::default();
    let mut refused_any = false;
    let mut echoes = FuturesUnordered::new();
    let (echo_stop, echo_stopped) = watch::channel(false);
    let result: TestResult<()> = async {
    loop {
        let accepted = tokio::select! {
            biased;
            result = echoes.next(), if !echoes.is_empty() => {
                result.ok_or("echo outcome disappeared")??;
                continue;
            }
            accepted = connection.accept() => match accepted {
                Some(Ok(accepted)) => accepted,
                Some(Err(error)) if error.get_io().is_some_and(super::tls_support::is_peer_gone) => break,
                Some(Err(error)) => return Err(error.into()),
                None => break,
            },
            result = stop_requested(&mut stopped) => { result?; break; }
        };
        let (request, mut respond) = accepted;
        let stream_id = u32::from(respond.stream_id());
        let (priority, pseudo) = {
            let bytes = recorded.lock().map_err(|_| "wire lock was poisoned")?;
            wire.headers_for(&bytes, stream_id)?
        };
        let fields = request
            .extensions()
            .get::<::http2::ext::OrderedHeaders>()
            .map(|ordered| {
                ordered
                    .as_slice()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_owned(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        )
                    })
                    .collect()
            })
            .ok_or("HTTP/2 request omitted ordered fields")?;
        let method = request.method().clone();
        if log.lock().map_err(|_| "server log lock was poisoned")?
            .get(index).ok_or("missing connection log")?.h2.len() >= MAX_RECORDS {
            return Err("profile request bound exceeded".into());
        }
        update(log, index, |connection| {
            connection.h2.push(H2Headers {
                stream_id,
                method: method.to_string(),
                priority,
                pseudo,
                fields,
            });
        })?;
        if method == Method::CONNECT {
            match behavior.connect {
                Reply::Accept => {
                    echoes.push(accept_connect(request, respond, behavior, log, index, echo_stopped.clone())?);
                }
                Reply::ResetStream => respond.send_reset(::http2::Reason::INTERNAL_ERROR),
                Reply::GoAway => connection.abrupt_shutdown(::http2::Reason::NO_ERROR),
                Reply::Reject => {
                    let response = Response::builder().status(403).body(())?;
                    respond.send_response(response, true)?;
                }
                Reply::RefuseStream => respond.send_reset(::http2::Reason::REFUSED_STREAM),
                Reply::RefuseFirstStream if !refused_any => {
                    refused_any = true;
                    respond.send_reset(::http2::Reason::REFUSED_STREAM);
                }
                Reply::RefuseFirstStream => {
                    echoes.push(accept_connect(request, respond, behavior, log, index, echo_stopped.clone())?);
                }
            }
        } else {
            let mut send = respond.send_response(Response::new(()), false)?;
            send.send_data(Bytes::from_static(b"ok"), true)?;
        }
    }
    Ok(())
    }.await;
    echo_stop.send_replace(true);
    let mut failure = result.err();
    while let Some(result) = echoes.next().await {
        if let Err(error) = result { retain_failure(&mut failure, error); }
    }
    match failure { Some(error) => Err(error), None => Ok(()) }
}

/// Accepts one extended CONNECT, selecting compression when asked, and starts
/// the echo that records the client's frames.
fn accept_connect(
    request: http::Request<::http2::RecvStream>,
    mut respond: ::http2::server::SendResponse<Bytes>,
    behavior: Behavior,
    log: &Log,
    index: usize,
    stopped: watch::Receiver<bool>,
) -> TestResult<impl std::future::Future<Output = TestResult<()>> + Send + 'static + use<>> {
    let response = if behavior.deflate {
        Response::builder()
            .header("sec-websocket-extensions", "permessage-deflate")
            .body(())?
    } else {
        Response::new(())
    };
    let send = respond.send_response(response, false)?;
    Ok(echo_h2(
        request.into_body(),
        send,
        Arc::clone(log),
        index,
        behavior.deflate,
        stopped,
    ))
}

/// Returns the client's `RST_STREAM` frames as (stream, error code).
pub(crate) fn client_resets(wire: &[u8]) -> Vec<(u32, u32)> {
    let mut resets = Vec::new();
    if !wire.starts_with(PREFACE) {
        return resets;
    }
    let mut offset = PREFACE.len();
    while let Some(head) = wire.get(offset..offset + 9) {
        let length =
            (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let Some(payload) = wire.get(offset + 9..offset + 9 + length) else {
            break;
        };
        if head[3] == 3 && payload.len() == 4 {
            let id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            resets.push((id, code));
        }
        offset += 9 + length;
    }
    resets
}

/// Echoes each client WebSocket frame and ends the stream after the client.
async fn echo_h2(
    mut body: ::http2::RecvStream,
    mut send: ::http2::SendStream<Bytes>,
    log: Log,
    index: usize,
    deflate: bool,
    mut stopped: watch::Receiver<bool>,
) -> TestResult<()> {
    let operation = async {
    let mut wire = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) if expected_stream_end(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        body.flow_control().release_capacity(chunk.len())?;
        if wire.len().checked_add(chunk.len()).is_none_or(|length| length > MAX_WIRE_BYTES) {
            return Err("profile WebSocket buffered-input bound exceeded".into());
        }
        wire.extend_from_slice(&chunk);
        while let Some((rsv1, opcode, payload, consumed)) = client_frame(&wire)? {
            // Recorded before the echo, so a client that has read the echo
            // has already had its own frame logged.
            if log.lock().map_err(|_| "server log lock was poisoned")?
                .get(index).ok_or("missing connection log")?.client_frames.len() >= MAX_RECORDS {
                return Err("profile WebSocket record bound exceeded".into());
            }
            update(&log, index, |connection| {
                connection.client_frames.push(ClientDataFrame {
                    rsv1,
                    opcode,
                    payload_len: payload.len(),
                });
            })?;
            let mut echo = Vec::new();
            // With compression selected the client's payload is deflated, so
            // it is echoed as uncompressed binary rather than replayed as
            // text the client would UTF-8 validate.
            let echo_opcode = if deflate && opcode < 0x8 { 0x2 } else { opcode };
            append_server_frame(&mut echo, true, echo_opcode, &payload);
            if let Err(error) = send.send_data(Bytes::from(echo), false) {
                if expected_stream_end(&error) {
                    return Ok(());
                }
                return Err(error.into());
            }
            wire.drain(..consumed);
        }
    }
    if !wire.is_empty() { return Err("client ended with a partial WebSocket frame".into()); }
    // The client ended its side after the close handshake; end ours too.
    if let Err(error) = send.send_data(Bytes::new(), true) {
        if !expected_stream_end(&error) { return Err(error.into()); }
    }
    Ok(())
    };
    tokio::select! {
        biased;
        result = operation => result,
        result = stop_requested(&mut stopped) => result,
    }
}

async fn serve_h1<T>(mut stream: T, index: usize, log: &Log, behavior: Behavior, mut stopped: watch::Receiver<bool>) -> TestResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let operation = async {
    let head = String::from_utf8(read_head(&mut stream).await?)?;
    let mut lines = head.trim_end().split("\r\n");
    let request_line = lines.next().ok_or("empty H1 request")?.to_owned();
    let fields = lines
        .map(|line| {
            line.split_once(": ")
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .ok_or("H1 field has no `: `")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let key = fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
        .map(|(_, value)| value.clone());
    update(log, index, |connection| {
        connection.h1.push(H1Request {
            request_line,
            fields,
        });
    })?;
    let Some(key) = key else {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .await?;
        return Ok(());
    };
    if behavior.upgrade != Reply::Accept {
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    let mut input = key.into_bytes();
    input.extend_from_slice(ACCEPT_GUID);
    let accept = btls::base64::encode_block(&btls::sha::sha1(&input));
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let (opcode, payload) = read_profile_frame(&mut stream).await?;
    let mut echo = Vec::new();
    append_server_frame(&mut echo, true, opcode, &payload);
    stream.write_all(&echo).await?;
    let mut rest = [0_u8; 1024];
    let mut received = 0_usize;
    loop {
        match stream.read(&mut rest).await {
            Ok(0) => break,
            Ok(length) => {
                received += length;
                if received > MAX_FRAME_BYTES { return Err("profile post-echo input bound exceeded".into()); }
            }
            Err(error) if super::tls_support::is_peer_gone(&error) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
    };
    tokio::select! {
        biased;
        result = operation => result,
        result = stop_requested(&mut stopped) => result,
    }
}

fn expected_stream_end(error: &::http2::Error) -> bool {
    // The scripts deliberately drop accepted WebSockets as well as closing
    // them gracefully. Local protocol/I/O errors remain failures.
    error.get_io().is_some_and(super::tls_support::is_peer_gone)
        || (error.is_remote() && error.is_reset() && error.reason() == Some(::http2::Reason::CANCEL))
}

async fn read_profile_frame(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<(u8, Vec<u8>)> {
    let mut head = [0_u8; 2];
    stream.read_exact(&mut head).await?;
    let extended = match head[1] & 0x7f { 126 => 2, 127 => 8, _ => 0 };
    let mut wire = head.to_vec();
    wire.resize(2 + extended, 0);
    stream.read_exact(&mut wire[2..]).await?;
    let length = match extended {
        2 => usize::from(u16::from_be_bytes([wire[2], wire[3]])),
        8 => usize::try_from(u64::from_be_bytes(wire[2..10].try_into()?))?,
        _ => usize::from(head[1] & 0x7f),
    };
    if head[1] & 0x80 == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            "profile client frame was unmasked or exceeded its bound").into());
    }
    let prefix = wire.len();
    wire.resize(prefix + 4 + length, 0);
    stream.read_exact(&mut wire[prefix..]).await?;
    let (_, opcode, payload, _) = client_frame(&wire)?.ok_or("complete profile frame was truncated")?;
    Ok((opcode, payload))
}

fn update(log: &Log, index: usize, change: impl FnOnce(&mut ConnectionLog)) -> TestResult<()> {
    let mut log = log.lock().map_err(|_| "server log lock was poisoned")?;
    change(log.get_mut(index).ok_or("missing connection log")?);
    Ok(())
}

fn decode_alpn(mut wire: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();
    while let Some((&length, rest)) = wire.split_first() {
        let length = usize::from(length).min(rest.len());
        protocols.push(String::from_utf8_lossy(&rest[..length]).into_owned());
        wire = &rest[length..];
    }
    protocols
}

/// Unmasks one complete client frame, or returns `None` until it is complete.
fn client_frame(wire: &[u8]) -> TestResult<Option<(bool, u8, Vec<u8>, usize)>> {
    let Some(&first) = wire.first() else { return Ok(None); };
    let (rsv1, opcode) = (first & 0x40 != 0, first & 0x0f);
    let Some((&second, mut rest)) = wire.get(1..).and_then(|tail| tail.split_first()) else { return Ok(None); };
    if second & 0x80 == 0 { return Err("client WebSocket frame was not masked".into()); }
    let length = match second & 0x7f {
        126 => {
            let Some((bytes, tail)) = rest.split_at_checked(2) else { return Ok(None); };
            rest = tail;
            usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
        }
        127 => {
            let Some((bytes, tail)) = rest.split_at_checked(8) else { return Ok(None); };
            rest = tail;
            usize::try_from(u64::from_be_bytes(bytes.try_into()?))?
        }
        length => usize::from(length),
    };
    if length > MAX_FRAME_BYTES { return Err("profile WebSocket frame bound exceeded".into()); }
    let Some((mask, tail)) = rest.split_at_checked(4) else { return Ok(None); };
    let Some(payload) = tail.get(..length) else { return Ok(None); };
    Ok(Some((
        rsv1,
        opcode,
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4])
            .collect(),
        wire.len() - tail.len() + length,
    )))
}

/// Incremental parser for the client's side of an HTTP/2 connection.
#[derive(Default)]
struct WireDecoder {
    offset: usize,
    /// Dynamic-table names, newest first; `None` for a Huffman literal name.
    table: Vec<Option<String>>,
    headers: Vec<(u32, Option<Priority>, PseudoFields)>,
}

impl WireDecoder {
    fn headers_for(
        &mut self,
        wire: &[u8],
        stream_id: u32,
    ) -> TestResult<(Option<Priority>, PseudoFields)> {
        if self.offset == 0 {
            if !wire.starts_with(PREFACE) {
                return Err("client omitted the HTTP/2 preface".into());
            }
            self.offset = PREFACE.len();
        }
        while let Some(head) = wire.get(self.offset..self.offset + 9) {
            let length =
                (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
            let Some(payload) = wire.get(self.offset + 9..self.offset + 9 + length) else {
                break;
            };
            let (kind, flags) = (head[3], head[4]);
            let id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            self.offset += 9 + length;
            if kind != 1 {
                continue;
            }
            if flags & 0x08 != 0 || flags & 0x04 == 0 {
                return Err("test decoder supports only unpadded single-frame HEADERS".into());
            }
            let (priority, block) = if flags & 0x20 != 0 {
                let priority = payload.get(..5).ok_or_else(||
                    io::Error::new(io::ErrorKind::InvalidData, "HEADERS priority was truncated"))?;
                let dependency =
                    u32::from_be_bytes([priority[0], priority[1], priority[2], priority[3]]);
                (
                    Some((
                        dependency & 0x8000_0000 != 0,
                        dependency & 0x7fff_ffff,
                        u16::from(priority[4]) + 1,
                    )),
                    &payload[5..],
                )
            } else {
                (None, payload)
            };
            let pseudo = self.decode_block(block)?;
            if self.headers.len() >= MAX_RECORDS { return Err("profile decoded-header bound exceeded".into()); }
            self.headers.push((id, priority, pseudo));
        }
        self.headers
            .iter()
            .find(|(id, _, _)| *id == stream_id)
            .map(|(_, priority, pseudo)| (*priority, pseudo.clone()))
            .ok_or_else(|| format!("no HEADERS recorded for stream {stream_id}").into())
    }

    /// Returns pseudo-field names with their representation, in wire order.
    fn decode_block(&mut self, block: &[u8]) -> TestResult<PseudoFields> {
        let mut cursor = 0;
        let mut pseudo = Vec::new();
        while let Some(&first) = block.get(cursor) {
            let (kind, prefix) = if first & 0x80 != 0 {
                ("indexed", 7)
            } else if first & 0xc0 == 0x40 {
                ("incremental", 6)
            } else if first & 0xe0 == 0x20 {
                read_integer(block, &mut cursor, 5)?;
                continue;
            } else if first & 0x10 != 0 {
                ("never-indexed", 4)
            } else {
                ("without-indexing", 4)
            };
            let index = read_integer(block, &mut cursor, prefix)?;
            let mut name_huffman = None;
            let mut value_huffman = None;
            let name = if kind == "indexed" {
                self.name(index)?
            } else {
                let name = if index == 0 {
                    let (name, huffman) = read_literal_name(block, &mut cursor)?;
                    name_huffman = Some(huffman);
                    name
                } else {
                    self.name(index)?
                };
                value_huffman = Some(skip_string(block, &mut cursor)?);
                if kind == "incremental" {
                    self.table.insert(0, name.clone());
                }
                name
            };
            if let Some(name) = name.filter(|name| name.starts_with(':')) {
                pseudo.push((
                    name,
                    Representation {
                        kind: kind.to_owned(),
                        index,
                        name_huffman,
                        value_huffman,
                    },
                ));
            }
        }
        Ok(pseudo)
    }

    fn name(&self, index: usize) -> TestResult<Option<String>> {
        Ok(match index {
            0 => return Err("HPACK index 0 is invalid".into()),
            1 => Some(":authority".to_owned()),
            2 | 3 => Some(":method".to_owned()),
            4 | 5 => Some(":path".to_owned()),
            6 | 7 => Some(":scheme".to_owned()),
            8..=14 => Some(":status".to_owned()),
            15..=61 => None,
            dynamic => self
                .table
                .get(dynamic - 62)
                .ok_or("HPACK dynamic index is out of range")?
                .clone(),
        })
    }
}

fn read_integer(block: &[u8], cursor: &mut usize, prefix_bits: u8) -> TestResult<usize> {
    let mask = (1_u8 << prefix_bits) - 1;
    let first = *block.get(*cursor).ok_or("HPACK integer is truncated")?;
    *cursor += 1;
    let mut value = usize::from(first & mask);
    if value < usize::from(mask) {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        let byte = *block.get(*cursor).ok_or("HPACK integer is truncated")?;
        *cursor += 1;
        value += usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Returns a literal field name and whether it was Huffman-coded.
fn read_literal_name(block: &[u8], cursor: &mut usize) -> TestResult<(Option<String>, bool)> {
    let huffman = block.get(*cursor).ok_or("HPACK string is truncated")? & 0x80 != 0;
    let length = read_integer(block, cursor, 7)?;
    let bytes = block
        .get(*cursor..*cursor + length)
        .ok_or("HPACK string is truncated")?;
    *cursor += length;
    let name = match (huffman, bytes) {
        (true, PROTOCOL_HUFFMAN) => Some(":protocol".to_owned()),
        (true, _) => None,
        (false, raw) => Some(String::from_utf8_lossy(raw).into_owned()),
    };
    Ok((name, huffman))
}

/// Skips a literal string and returns whether it was Huffman-coded.
fn skip_string(block: &[u8], cursor: &mut usize) -> TestResult<bool> {
    let huffman = block.get(*cursor).ok_or("HPACK string is truncated")? & 0x80 != 0;
    let length = read_integer(block, cursor, 7)?;
    if block.len() < *cursor + length {
        return Err("HPACK string is truncated".into());
    }
    *cursor += length;
    Ok(huffman)
}

struct RecordingIo<T> {
    inner: T,
    read: Arc<Mutex<Vec<u8>>>,
}

impl<T> AsyncRead for RecordingIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = result {
            let mut recorded = this.read.lock().map_err(|_| io::Error::other("recorded wire lock was poisoned"))?;
            let bytes = &buffer.filled()[before..];
            if recorded.len().checked_add(bytes.len()).is_none_or(|length| length > MAX_WIRE_BYTES) {
                return Poll::Ready(Err(io::Error::other("profile recorded-wire bound exceeded")));
            }
            recorded.extend_from_slice(bytes);
        }
        result
    }
}

impl<T> AsyncWrite for RecordingIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests;
