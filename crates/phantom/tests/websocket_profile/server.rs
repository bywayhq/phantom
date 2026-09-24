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
};

use btls::ssl::{AlpnError, select_next_proto};
use bytes::Bytes;
use http::{Method, Response};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use super::{
    TestResult,
    fixture::Representation,
    tls_support::{H2_ALPN, TestIdentity, accept_tls_stream, read_head},
    websocket_support::{append_server_frame, read_client_frame},
};

const ALPN_PREFERENCE: &[u8] = b"\x02h2\x08http/1.1";
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// HPACK Huffman encoding of `:protocol`, the only literal pseudo-field name.
const PROTOCOL_HUFFMAN: &[u8] = &[0xb9, 0x5d, 0x87, 0x49, 0xc8, 0x7a, 0x3f];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reply {
    Accept,
    Reject,
    RefuseStream,
    /// Refuses the first extended CONNECT stream and accepts the rest, as the
    /// retained `refused-stream` captures' server does.
    RefuseFirstStream,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Behavior {
    /// Whether HTTP/2 SETTINGS enable extended CONNECT.
    pub(crate) connect_protocol: bool,
    pub(crate) connect: Reply,
    pub(crate) upgrade: Reply,
}

impl Behavior {
    pub(crate) const ACCEPT: Self = Self {
        connect_protocol: true,
        connect: Reply::Accept,
        upgrade: Reply::Accept,
    };
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectionLog {
    pub(crate) alpn_offer: Vec<String>,
    pub(crate) protocol: Option<String>,
    pub(crate) h2: Vec<H2Headers>,
    pub(crate) h1: Vec<H1Request>,
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
/// RFC 7540 HEADERS priority as (exclusive, dependency, weight).
pub(crate) type Priority = (bool, u32, u16);
/// Pseudo-field names with their HPACK representation, in wire order.
pub(crate) type PseudoFields = Vec<(String, Representation)>;

pub(crate) struct TestServer {
    pub(crate) address: SocketAddr,
    log: Log,
    task: JoinHandle<()>,
}

impl TestServer {
    pub(crate) async fn start(identity: Arc<TestIdentity>, behavior: Behavior) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let log = Log::default();
        let task_log = Arc::clone(&log);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let index = match task_log.lock() {
                    Ok(mut log) => {
                        log.push(ConnectionLog::default());
                        log.len() - 1
                    }
                    Err(_) => return,
                };
                let log = Arc::clone(&task_log);
                let identity = Arc::clone(&identity);
                tokio::spawn(async move {
                    // Connection failures are the client's observable
                    // behavior; the log keeps what arrived before them.
                    let _ = serve(tcp, &identity, index, &log, behavior).await;
                });
            }
        });
        Ok(Self { address, log, task })
    }

    /// Starts a plaintext HTTP/1.1 origin for `ws://` openings.
    pub(crate) async fn start_plaintext(behavior: Behavior) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let log = Log::default();
        let task_log = Arc::clone(&log);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let index = match task_log.lock() {
                    Ok(mut log) => {
                        log.push(ConnectionLog::default());
                        log.len() - 1
                    }
                    Err(_) => return,
                };
                let log = Arc::clone(&task_log);
                tokio::spawn(async move {
                    let _ = serve_h1(tcp, index, &log, behavior).await;
                });
            }
        });
        Ok(Self { address, log, task })
    }

    pub(crate) fn connections(&self) -> TestResult<Vec<ConnectionLog>> {
        Ok(self
            .log
            .lock()
            .map_err(|_| "server log lock was poisoned")?
            .clone())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    tcp: TcpStream,
    identity: &TestIdentity,
    index: usize,
    log: &Log,
    behavior: Behavior,
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
    let stream = accept_tls_stream(tcp, builder.build()).await?;
    let protocol = stream
        .ssl()
        .selected_alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
    update(log, index, |connection| {
        connection.alpn_offer = offer
            .lock()
            .map(|offer| decode_alpn(&offer))
            .unwrap_or_default();
        connection.protocol.clone_from(&protocol);
    })?;
    match protocol.as_deref() {
        Some("h2") => serve_h2(stream, index, log, behavior).await,
        _ => serve_h1(stream, index, log, behavior).await,
    }
}

async fn serve_h2<T>(stream: T, index: usize, log: &Log, behavior: Behavior) -> TestResult<()>
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
    let mut connection = builder.handshake::<_, Bytes>(io).await?;
    let mut wire = WireDecoder::default();
    let mut refused_any = false;
    while let Some(accepted) = connection.accept().await {
        let (request, mut respond) = accepted?;
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
            .unwrap_or_default();
        let method = request.method().clone();
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
                    let send = respond.send_response(Response::new(()), false)?;
                    tokio::spawn(echo_h2(request.into_body(), send));
                }
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
                    let send = respond.send_response(Response::new(()), false)?;
                    tokio::spawn(echo_h2(request.into_body(), send));
                }
            }
        } else {
            let mut send = respond.send_response(Response::new(()), false)?;
            send.send_data(Bytes::from_static(b"ok"), true)?;
        }
    }
    Ok(())
}

/// Echoes each client WebSocket frame and ends the stream after the client.
async fn echo_h2(mut body: ::http2::RecvStream, mut send: ::http2::SendStream<Bytes>) {
    let mut wire = Vec::new();
    while let Some(Ok(chunk)) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk.len());
        wire.extend_from_slice(&chunk);
        if let Some((opcode, payload)) = client_frame(&wire) {
            let mut echo = Vec::new();
            append_server_frame(&mut echo, true, opcode, &payload);
            if send.send_data(Bytes::from(echo), false).is_err() {
                return;
            }
            wire.clear();
        }
    }
    // The client ended its side after the close handshake; end ours too.
    let _ = send.send_data(Bytes::new(), true);
}

async fn serve_h1<T>(mut stream: T, index: usize, log: &Log, behavior: Behavior) -> TestResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
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
    let frame = read_client_frame(&mut stream).await?;
    let mut echo = Vec::new();
    append_server_frame(&mut echo, true, frame.opcode, &frame.payload);
    stream.write_all(&echo).await?;
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest).await;
    Ok(())
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
fn client_frame(wire: &[u8]) -> Option<(u8, Vec<u8>)> {
    let opcode = wire.first()? & 0x0f;
    let (&second, mut rest) = wire.get(1..)?.split_first()?;
    let length = match second & 0x7f {
        126 => {
            let (bytes, tail) = rest.split_at_checked(2)?;
            rest = tail;
            usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
        }
        127 => return None,
        length => usize::from(length),
    };
    let (mask, tail) = rest.split_at_checked(4)?;
    let payload = tail.get(..length)?;
    Some((
        opcode,
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4])
            .collect(),
    ))
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
                let dependency =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                (
                    Some((
                        dependency & 0x8000_0000 != 0,
                        dependency & 0x7fff_ffff,
                        u16::from(payload[4]) + 1,
                    )),
                    &payload[5..],
                )
            } else {
                (None, payload)
            };
            let pseudo = self.decode_block(block)?;
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
            let name = if kind == "indexed" {
                self.name(index)?
            } else {
                let name = if index == 0 {
                    read_literal_name(block, &mut cursor)?
                } else {
                    self.name(index)?
                };
                skip_string(block, &mut cursor)?;
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

fn read_literal_name(block: &[u8], cursor: &mut usize) -> TestResult<Option<String>> {
    let huffman = block.get(*cursor).ok_or("HPACK string is truncated")? & 0x80 != 0;
    let length = read_integer(block, cursor, 7)?;
    let bytes = block
        .get(*cursor..*cursor + length)
        .ok_or("HPACK string is truncated")?;
    *cursor += length;
    Ok(match (huffman, bytes) {
        (true, PROTOCOL_HUFFMAN) => Some(":protocol".to_owned()),
        (true, _) => None,
        (false, raw) => Some(String::from_utf8_lossy(raw).into_owned()),
    })
}

fn skip_string(block: &[u8], cursor: &mut usize) -> TestResult<()> {
    let length = read_integer(block, cursor, 7)?;
    if block.len() < *cursor + length {
        return Err("HPACK string is truncated".into());
    }
    *cursor += length;
    Ok(())
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
            this.read
                .lock()
                .map_err(|_| io::Error::other("recorded wire lock was poisoned"))?
                .extend_from_slice(&buffer.filled()[before..]);
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
