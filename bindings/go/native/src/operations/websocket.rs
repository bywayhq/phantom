//! WebSocket custody and exclusive, independently cancellable message halves.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use phantom::{
    Bytes, HttpProtocol, WebSocket, WebSocketCloseFrame, WebSocketHeader, WebSocketLimits,
    WebSocketMessage, WebSocketRetryPolicy,
};
use tokio::sync::Notify;

use super::{Completed, CompletedHead, Execution, Outcome, Target, global};
use crate::{client::Header, error::Failure};

pub(crate) const MAX_MESSAGE: usize = 64 * 1024 * 1024;

pub(crate) struct Opening {
    pub(crate) client: u64,
    pub(crate) url: String,
    pub(crate) protocol: u64,
    pub(crate) headers: Vec<Header>,
    pub(crate) template: Option<Vec<WebSocketHeader>>,
    pub(crate) limits: WebSocketLimits,
    pub(crate) timeout: Option<Option<Duration>>,
    pub(crate) retries: usize,
    pub(crate) retry_delay: Duration,
    pub(crate) deflate: Option<phantom::PerMessageDeflate>,
}

type Reader = SplitStream<WebSocket>;
type Writer = SplitSink<WebSocket, WebSocketMessage>;

pub(super) struct Socket {
    pub(super) client: u64,
    reader: Mutex<Option<Reader>>,
    writer: Mutex<Option<Writer>>,
    closed: AtomicBool,
    changed: Notify,
    maximum: usize,
}

impl Socket {
    pub(super) fn abort(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
        // In-flight halves are owned by their leases and observe changed.
        self.reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn check(&self) -> Result<(), Failure> {
        if self.closed.load(Ordering::SeqCst) {
            Err(Failure::new("websocket_closed"))
        } else {
            Ok(())
        }
    }
}

pub(crate) struct ResultData {
    pub(crate) kind: u64,
    pub(crate) code: u64,
    pub(crate) bytes: Bytes,
    pub(crate) compression: [u64; 3],
    // Retained results and admitted sends share a bounded process allowance.
    _permit: Option<super::UploadPermit>,
}

pub(super) enum Finished {
    Open {
        socket: Arc<Socket>,
        head: CompletedHead,
        selected: Bytes,
        compression: [u64; 3],
    },
    Rejected(super::response::Head),
    Message(ResultData),
}

pub(super) fn finish(
    state: &mut super::State,
    id: u64,
    reserved: Option<u64>,
    finished: Finished,
) -> Result<Completed, Failure> {
    match finished {
        Finished::Open {
            socket,
            mut head,
            selected,
            compression,
        } => {
            let handle = reserved.ok_or_else(|| Failure::new("internal"))?;
            head.body = handle;
            state.sockets.insert(handle, socket);
            if let Some(operation) = state.operations.get_mut(&id) {
                operation.socket = Some(handle);
                operation.websocket = Some(Arc::new(ResultData {
                    kind: 1,
                    code: 0,
                    bytes: selected,
                    compression,
                    _permit: None,
                }));
            }
            Ok(Completed::Head(head))
        }
        Finished::Rejected(head) => {
            let handle = reserved.ok_or_else(|| Failure::new("internal"))?;
            state.bodies.insert(handle, head.body);
            if let Some(operation) = state.operations.get_mut(&id) {
                operation.response = Some(handle);
                operation.websocket = Some(Arc::new(ResultData {
                    kind: 7,
                    code: 0,
                    bytes: Bytes::new(),
                    compression: [0; 3],
                    _permit: None,
                }));
            }
            Ok(Completed::Head(CompletedHead {
                body: handle,
                status: head.status,
                protocol: head.protocol,
                headers: head.headers,
                effective_url: head.effective_url,
                redirects_followed: 0,
                connection_setup_retries: 0,
                decoded_content_codings: Vec::new(),
                redirect_history: None,
            }))
        }
        Finished::Message(message) => {
            if let Some(operation) = state.operations.get_mut(&id) {
                operation.websocket = Some(Arc::new(message));
            }
            Ok(Completed::Complete)
        }
    }
}

pub(crate) fn result(id: u64) -> Result<Arc<ResultData>, Failure> {
    let state = global()?.lock();
    state
        .operations
        .get(&id)
        .filter(|operation| !operation.abandoned && operation.delivered)
        .and_then(|operation| operation.websocket.clone())
        .ok_or_else(|| Failure::new("websocket_result_unavailable"))
}

pub(crate) fn open(opening: Opening) -> Result<Execution, Failure> {
    let global = global()?;
    let mut state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let client = state
        .clients
        .get(&opening.client)
        .ok_or_else(|| Failure::new("client_closed"))?;
    if client.closing {
        return Err(Failure::new("client_closed"));
    }
    let native = client.client.clone();
    let mut request = match opening.protocol {
        0 => native.websocket_with_profile_policy(&opening.url),
        1 => native.websocket_with_protocol(HttpProtocol::Http1, &opening.url),
        2 => native.websocket_with_protocol(HttpProtocol::Http2, &opening.url),
        3 => native.websocket_with_protocol(HttpProtocol::Http3, &opening.url),
        _ => return Err(Failure::new("invalid_websocket_protocol")),
    }
    .map_err(failure)?;
    if let Some(template) = opening.template {
        request = request.headers(template);
    }
    for header in opening.headers {
        request = request.header(header.into_request());
    }
    request = request.limits(opening.limits);
    if let Some(deflate) = opening.deflate {
        request = request.permessage_deflate(deflate);
    }
    if let Some(timeout) = opening.timeout {
        request = request.handshake_timeout(timeout);
    }
    if let Some(maximum) = NonZeroUsize::new(opening.retries) {
        request = request.retry_policy(WebSocketRetryPolicy::connection_failures(
            maximum,
            opening.retry_delay,
        ));
    }
    let (id, cancel) = state.reserve(Target::WebSocketOpen(opening.client))?;
    drop(state);
    global.spawn(id, cancel, async move {
        match request.connect().await {
            Ok(socket) => {
                let handshake = socket.handshake_response();
                let headers = response_headers(handshake)?;
                let head = CompletedHead {
                    body: 0,
                    status: handshake.status().as_u16(),
                    protocol: protocol(handshake.version()),
                    headers,
                    effective_url: opening.url,
                    redirects_followed: 0,
                    connection_setup_retries: 0,
                    decoded_content_codings: Vec::new(),
                    redirect_history: None,
                };
                let selected = Bytes::copy_from_slice(
                    socket.selected_protocol().unwrap_or_default().as_bytes(),
                );
                let compression = socket
                    .negotiated_permessage_deflate()
                    .map_or([0; 3], |value| {
                        [
                            1 | (u64::from(value.server_no_context_takeover()) << 1)
                                | (u64::from(value.client_no_context_takeover()) << 2),
                            u64::from(value.server_max_window_bits()),
                            u64::from(value.client_max_window_bits()),
                        ]
                    });
                let maximum = socket.limits().max_message_size().get();
                let (writer, reader) = socket.split();
                let socket = Arc::new(Socket {
                    client: opening.client,
                    reader: Mutex::new(Some(reader)),
                    writer: Mutex::new(Some(writer)),
                    closed: AtomicBool::new(false),
                    changed: Notify::new(),
                    maximum,
                });
                Ok(Outcome::WebSocket(Finished::Open {
                    socket,
                    head,
                    selected,
                    compression,
                }))
            }
            Err(error) => {
                let cause = failure_ref(&error);
                match error.into_response() {
                    Some(response) => Ok(Outcome::WebSocket(Finished::Rejected(rejected(
                        response,
                        opening.client,
                        opening.url,
                    )?))),
                    None => Err(cause),
                }
            }
        }
    });
    Ok(Execution::Operation(id))
}

pub(crate) fn abort(handle: u64) -> Result<Execution, Failure> {
    let mut state = global()?.lock();
    state.close_socket(handle);
    Ok(Execution::Complete)
}

pub(crate) fn read(handle: u64) -> Result<Execution, Failure> {
    let global = global()?;
    let mut state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let socket = state
        .sockets
        .get(&handle)
        .cloned()
        .ok_or_else(|| Failure::new("websocket_closed"))?;
    socket.check()?;
    let (id, cancel) = state.reserve(Target::WebSocketRead(handle))?;
    drop(state);
    global.spawn(id, cancel, async move {
        let mut lease = ReadLease::take(socket)?;
        let changed = lease.owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        lease.owner.check()?;
        let reader = lease
            .reader
            .as_mut()
            .ok_or_else(|| Failure::new("internal"))?;
        let message = tokio::select! {
            biased;
            () = &mut changed => return Err(Failure::new("websocket_closed")),
            message = reader.next() => message,
        };
        let message = message
            .ok_or_else(|| Failure::new("websocket_closed"))?
            .map_err(failure)?;
        let (kind, code, bytes) = match message {
            WebSocketMessage::Text(text) => (2, 0, Bytes::from(text)),
            WebSocketMessage::Binary(bytes) => (3, 0, bytes),
            WebSocketMessage::Ping(bytes) => (4, 0, bytes),
            WebSocketMessage::Pong(bytes) => (5, 0, bytes),
            WebSocketMessage::Close(frame) => {
                lease.owner.abort();
                match frame {
                    Some(frame) => (
                        6,
                        u64::from(frame.code()),
                        Bytes::copy_from_slice(frame.reason().as_bytes()),
                    ),
                    None => (6, 0, Bytes::new()),
                }
            }
            _ => return Err(Failure::new("websocket_protocol")),
        };
        let permit = global.websocket_bytes(bytes.len())?;
        lease.completed = true;
        Ok(Outcome::WebSocket(Finished::Message(ResultData {
            kind,
            code,
            bytes,
            compression: [0; 3],
            _permit: Some(permit),
        })))
    });
    Ok(Execution::Operation(id))
}

pub(crate) fn write(handle: u64, kind: u64, code: u16, bytes: &[u8]) -> Result<Execution, Failure> {
    let global = global()?;
    let mut state = global.lock();
    if state.failed {
        return Err(Failure::new("internal"));
    }
    let socket = state
        .sockets
        .get(&handle)
        .cloned()
        .ok_or_else(|| Failure::new("websocket_closed"))?;
    socket.check()?;
    if state
        .operations
        .values()
        .any(|operation| matches!(operation.target, Target::WebSocketWrite(id) if id == handle))
    {
        return Err(Failure::new("websocket_write_pending"));
    }
    if ((kind == 2 || kind == 3) && bytes.len() > socket.maximum)
        || ((kind == 4 || kind == 5) && bytes.len() > 125)
    {
        return Err(Failure::new("websocket_capacity"));
    }
    let permit = global.websocket_bytes(bytes.len())?;
    let message = match kind {
        2 if code == 0 => WebSocketMessage::Text(
            std::str::from_utf8(bytes)
                .map_err(|_| Failure::new("websocket_invalid_utf8"))?
                .to_owned(),
        ),
        3 if code == 0 => WebSocketMessage::Binary(Bytes::copy_from_slice(bytes)),
        4 if code == 0 => WebSocketMessage::Ping(Bytes::copy_from_slice(bytes)),
        5 if code == 0 => WebSocketMessage::Pong(Bytes::copy_from_slice(bytes)),
        6 => WebSocketMessage::Close(if code == 0 {
            if !bytes.is_empty() {
                return Err(Failure::new("invalid_websocket_close"));
            }
            None
        } else {
            Some(
                WebSocketCloseFrame::new(
                    code,
                    std::str::from_utf8(bytes)
                        .map_err(|_| Failure::new("websocket_invalid_utf8"))?,
                )
                .map_err(failure)?,
            )
        }),
        _ => return Err(Failure::new("invalid_websocket_message")),
    };
    let (id, cancel) = state.reserve(Target::WebSocketWrite(handle))?;
    drop(state);
    global.spawn(id, cancel, async move {
        let _permit = permit;
        let mut lease = WriteLease::take(socket)?;
        let changed = lease.owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        lease.owner.check()?;
        let writer = lease
            .writer
            .as_mut()
            .ok_or_else(|| Failure::new("internal"))?;
        tokio::select! {
            biased;
            () = &mut changed => return Err(Failure::new("websocket_closed")),
            result = writer.send(message) => result.map_err(failure)?,
        };
        lease.completed = true;
        Ok(Outcome::Complete)
    });
    Ok(Execution::Operation(id))
}

struct ReadLease {
    owner: Arc<Socket>,
    reader: Option<Reader>,
    completed: bool,
}
impl ReadLease {
    fn take(owner: Arc<Socket>) -> Result<Self, Failure> {
        let reader = owner
            .reader
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .take()
            .ok_or_else(|| Failure::new("websocket_read_pending"))?;
        Ok(Self {
            owner,
            reader: Some(reader),
            completed: false,
        })
    }
}
impl Drop for ReadLease {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.abort();
        }
        let mut slot = self
            .owner
            .reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.owner.closed.load(Ordering::SeqCst) {
            *slot = self.reader.take();
        }
    }
}
struct WriteLease {
    owner: Arc<Socket>,
    writer: Option<Writer>,
    completed: bool,
}
impl WriteLease {
    fn take(owner: Arc<Socket>) -> Result<Self, Failure> {
        let writer = owner
            .writer
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .take()
            .ok_or_else(|| Failure::new("websocket_write_pending"))?;
        Ok(Self {
            owner,
            writer: Some(writer),
            completed: false,
        })
    }
}
impl Drop for WriteLease {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.abort();
        }
        let mut slot = self
            .owner
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.owner.closed.load(Ordering::SeqCst) {
            *slot = self.writer.take();
        }
    }
}

fn response_headers<B>(response: &http::Response<B>) -> Result<Vec<Header>, Failure> {
    let fields = response
        .extensions()
        .get::<phantom::OrderedResponseHeaders>()
        .ok_or_else(|| Failure::new("ordered_headers_unavailable"))?;
    let mut size = 0usize;
    fields
        .iter()
        .map(|field| {
            size = size
                .saturating_add(field.name().len())
                .saturating_add(field.value().len());
            if size > 32 * 1024 {
                return Err(Failure::new("response_headers_limit"));
            }
            Ok(Header {
                name: field.name().to_owned(),
                value: field.value().to_vec(),
                sensitive: field.is_sensitive(),
            })
        })
        .take(257)
        .collect::<Result<Vec<_>, _>>()
        .and_then(|headers| {
            if headers.len() > 256 {
                Err(Failure::new("response_headers_limit"))
            } else {
                Ok(headers)
            }
        })
}

fn rejected(
    response: http::Response<phantom::ResponseBody>,
    client: u64,
    url: String,
) -> Result<super::response::Head, Failure> {
    use super::response::{BodyOwner, Head, Stream};
    let headers = response_headers(&response)?;
    let status = response.status().as_u16();
    let protocol = protocol(response.version());
    Ok(Head {
        status,
        protocol,
        effective_url: url,
        redirects_followed: 0,
        connection_setup_retries: 0,
        decoded_content_codings: Vec::new(),
        redirect_history: None,
        headers,
        body: Arc::new(BodyOwner {
            client,
            stream: Mutex::new(Some(Stream::Body {
                body: Box::new(response.into_body()),
                pending: Bytes::new(),
            })),
            closed: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            changed: Notify::new(),
            _upload: None,
            stream_upload: None,
        }),
    })
}

fn protocol(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_11 => "h1",
        http::Version::HTTP_2 => "h2",
        http::Version::HTTP_3 => "h3",
        _ => "unknown",
    }
}

pub(crate) fn limits(frame: u64, message: u64, fragments: u64) -> Result<WebSocketLimits, Failure> {
    let frame = usize::try_from(frame)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| Failure::new("invalid_websocket_limits"))?;
    let message = usize::try_from(message)
        .ok()
        .filter(|size| *size <= MAX_MESSAGE)
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| Failure::new("invalid_websocket_limits"))?;
    let fragments = usize::try_from(fragments)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| Failure::new("invalid_websocket_limits"))?;
    WebSocketLimits::new(frame, message)
        .map(|limits| limits.with_max_message_fragments(fragments))
        .map_err(failure)
}

fn failure(error: phantom::WebSocketError) -> Failure {
    failure_ref(&error)
}
fn failure_ref(error: &phantom::WebSocketError) -> Failure {
    use phantom::WebSocketErrorKind as Kind;
    let mut failure = Failure::new(match error.kind() {
        Kind::ServerPinPolicy => "server_pin_policy",
        Kind::SessionTickets => "session_tickets",
        Kind::InvalidUri => "invalid_uri",
        Kind::UnsupportedScheme => "unsupported_scheme",
        Kind::InvalidAuthority => "invalid_authority",
        Kind::InvalidRequest => "invalid_websocket_request",
        Kind::ProtocolUnavailable => "protocol_unavailable",
        Kind::UnsupportedRoute => "unsupported_route",
        Kind::RuntimeUnavailable => "runtime_unavailable",
        Kind::Connect => "connect",
        Kind::Proxy => "proxy",
        Kind::Tls => "tls",
        Kind::Http1 => "http1",
        Kind::Http2 => "http2",
        Kind::Http3 => "http3",
        Kind::Random => "random",
        Kind::Timeout => "timeout",
        Kind::HandshakeRejected => "websocket_handshake_rejected",
        Kind::InvalidHandshake => "websocket_invalid_handshake",
        Kind::Capacity => "websocket_capacity",
        Kind::ClientClosed => "client_closed",
        Kind::AttemptBudgetExhausted => "attempt_budget_exhausted",
        Kind::Protocol => "websocket_protocol",
        Kind::InvalidUtf8 => "websocket_invalid_utf8",
        Kind::Io => "websocket_io",
        Kind::AbnormalClosure => "websocket_abnormal_closure",
        Kind::Closed => "websocket_closed",
        Kind::DestinationDenied => "destination_denied",
        _ => "websocket_unknown",
    });
    failure.timeout_phase = error.timeout_phase().map(|phase| match phase {
        phantom::TimeoutPhase::Connect => "connect",
        phantom::TimeoutPhase::PoolAdmission => "pool_admission",
        phantom::TimeoutPhase::ResponseHead => "response_head",
        phantom::TimeoutPhase::ReadIdle => "read_idle",
        phantom::TimeoutPhase::Total => "total",
        phantom::TimeoutPhase::WebSocketHandshake => "websocket_handshake",
        _ => "unknown",
    });
    failure
}
