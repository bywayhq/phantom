//! A raw HTTP/3 origin for the WebSocket tests, on a loopback QUIC endpoint.
//!
//! It sends its own SETTINGS and decodes each request's field section with
//! `h3::qpack::decode_stateless`. It announces no QPACK dynamic table, so
//! every field section decodes alone.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    sync::oneshot,
    task::JoinHandle,
};

use crate::support::h3::server_endpoint;
use crate::support::tls::{TestIdentity, TestResult};
use crate::support::websocket::{
    self as websocket_support, ClientFrame, append_server_frame, append_server_frame_with_rsv1,
};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const DATA_FRAME: u64 = 0x00;
const HEADERS_FRAME: u64 = 0x01;
const SETTINGS_FRAME: u64 = 0x04;
/// RFC 9220, section 3.
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// "hello" compressed with a raw DEFLATE block, as RFC 7692 section 7.2.3.1
/// shows it.
const COMPRESSED_HELLO: &[u8] = &[0xca, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

/// How the origin's request stream ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Ending {
    Finished,
    Reset(u64),
    Failed(String),
}

/// How the origin's send side of a WebSocket stream ended after it sent FIN.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SendEnding {
    /// The client acknowledged every byte and the FIN.
    Acknowledged,
    /// The client sent STOP_SENDING with this code.
    Stopped(u64),
    Failed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Answer {
    /// Accept with 200 and echo text and binary messages; echo the Close
    /// frame and then end the send side with FIN.
    Echo,
    /// Answer 403 with a body.
    Reject,
    /// Accept with a `permessage-deflate` selection, send one compressed
    /// message, and record the client's frames.
    Deflate,
    /// Never answer the CONNECT; record how the client ends the stream.
    Withhold,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Behavior {
    /// Whether SETTINGS carry `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`.
    pub(crate) extended_connect: bool,
    pub(crate) answer: Answer,
}

impl Behavior {
    pub(crate) const ECHO: Self = Self {
        extended_connect: true,
        answer: Answer::Echo,
    };

    pub(crate) const fn answering(answer: Answer) -> Self {
        Self {
            extended_connect: true,
            answer,
        }
    }
}

#[derive(Default)]
struct Log {
    /// Connection attempts, refused ones included.
    attempts: usize,
    connections: usize,
    open: Vec<quinn::Connection>,
    requests: Vec<Vec<(String, Vec<u8>)>>,
    endings: Vec<Ending>,
    send_endings: Vec<SendEnding>,
    frames: Vec<ClientFrame>,
}

/// A raw HTTP/3 origin on a loopback QUIC endpoint; aborted on drop.
pub(crate) struct Origin {
    pub(crate) address: SocketAddr,
    endpoint: quinn::Endpoint,
    log: Arc<Mutex<Log>>,
    task: JoinHandle<()>,
}

impl Origin {
    pub(crate) fn spawn(identity: &TestIdentity, behavior: Behavior) -> TestResult<Self> {
        Ok(Self::serve(server_endpoint(identity)?, behavior, 0))
    }

    /// Serves on `endpoint`, refusing its first `refusals` connection
    /// attempts with QUIC `CONNECTION_REFUSED`.
    pub(crate) fn serve(
        (address, endpoint): (SocketAddr, quinn::Endpoint),
        behavior: Behavior,
        refusals: usize,
    ) -> Self {
        let log = Arc::new(Mutex::new(Log::default()));
        let task_log = Arc::clone(&log);
        let accepting = endpoint.clone();
        let task = tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                let attempt = {
                    let mut log = lock(&task_log);
                    log.attempts += 1;
                    log.attempts
                };
                if attempt <= refusals {
                    incoming.refuse();
                    continue;
                }
                let log = Arc::clone(&task_log);
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    {
                        let mut log = lock(&log);
                        log.connections += 1;
                        log.open.push(connection.clone());
                    }
                    let _ = serve_connection(connection, behavior, log).await;
                });
            }
        });
        Self {
            address,
            endpoint,
            log,
            task,
        }
    }

    pub(crate) fn uri(&self, path_and_query: &str) -> String {
        format!("wss://{}{path_and_query}", self.address)
    }

    pub(crate) fn connections(&self) -> usize {
        lock(&self.log).connections
    }

    pub(crate) fn requests(&self) -> Vec<Vec<(String, Vec<u8>)>> {
        lock(&self.log).requests.clone()
    }

    pub(crate) fn methods(&self) -> Vec<String> {
        self.requests()
            .iter()
            .filter_map(|fields| {
                fields
                    .iter()
                    .find(|(name, _)| name == ":method")
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
            })
            .collect()
    }

    pub(crate) async fn next_ending(&self) -> TestResult<Ending> {
        loop {
            if let Some(ending) = lock(&self.log).endings.first().cloned() {
                return Ok(ending);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    #[cfg(feature = "websocket-deflate")]
    pub(crate) async fn next_frame(&self) -> TestResult<ClientFrame> {
        loop {
            {
                let mut log = lock(&self.log);
                if !log.frames.is_empty() {
                    return Ok(log.frames.remove(0));
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    pub(crate) fn attempts(&self) -> usize {
        lock(&self.log).attempts
    }

    pub(crate) async fn next_send_ending(&self) -> TestResult<SendEnding> {
        loop {
            if let Some(ending) = lock(&self.log).send_endings.first().cloned() {
                return Ok(ending);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Closes every connection and waits until each has drained, so the
    /// client has seen the close and opens a new connection next.
    pub(crate) async fn close_connections(&self) {
        let open = std::mem::take(&mut lock(&self.log).open);
        for connection in open {
            connection.close(0u32.into(), b"closed by the test");
        }
        self.endpoint.wait_idle().await;
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn lock(log: &Mutex<Log>) -> MutexGuard<'_, Log> {
    log.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn serve_connection(
    connection: quinn::Connection,
    behavior: Behavior,
    log: Arc<Mutex<Log>>,
) -> TestResult<()> {
    let mut settings = Vec::new();
    if behavior.extended_connect {
        put_varint(&mut settings, SETTINGS_ENABLE_CONNECT_PROTOCOL);
        put_varint(&mut settings, 1);
    }
    // Stream type 0x00 is the control stream (RFC 9114, section 6.2.1); it
    // must stay open for the connection's lifetime.
    let mut control = connection.open_uni().await?;
    let mut opening = vec![0x00];
    put_frame(&mut opening, SETTINGS_FRAME, &settings);
    control.write_all(&opening).await?;
    loop {
        let (send, recv) = connection.accept_bi().await?;
        let log = Arc::clone(&log);
        tokio::spawn(async move {
            let _ = serve_stream(send, recv, behavior.answer, log).await;
        });
    }
}

async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    answer: Answer,
    log: Arc<Mutex<Log>>,
) -> TestResult<()> {
    let mut section = loop {
        match next_frame(&mut recv).await {
            Ok(Some((HEADERS_FRAME, payload))) => break Bytes::from(payload),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return Err("request stream ended before HEADERS".into()),
        }
    };
    let fields = h3::qpack::decode_stateless(&mut section, u64::MAX)?
        .fields
        .into_iter()
        .map(|field| {
            (
                String::from_utf8_lossy(&field.name).into_owned(),
                field.value.into_owned(),
            )
        })
        .collect::<Vec<_>>();
    let value = |name: &str| {
        fields
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
    };
    let method = value(":method");
    let protocol = value("sec-websocket-protocol");
    lock(&log).requests.push(fields.clone());

    if method.as_deref() != Some("CONNECT") {
        write_headers(&mut send, &[(":status", "200")]).await?;
        write_frame(&mut send, DATA_FRAME, b"ordinary").await?;
        send.finish()?;
        return Ok(());
    }
    match answer {
        Answer::Reject => {
            write_headers(&mut send, &[(":status", "403")]).await?;
            write_frame(&mut send, DATA_FRAME, b"forbidden").await?;
            send.finish()?;
            return Ok(());
        }
        Answer::Echo => {
            let selected = protocol
                .as_deref()
                .and_then(|offer| offer.split(',').next())
                .map(str::trim)
                .map(str::to_owned);
            let mut head = vec![(":status", "200")];
            if let Some(selected) = selected.as_deref() {
                head.push(("sec-websocket-protocol", selected));
            }
            write_headers(&mut send, &head).await?;
        }
        Answer::Withhold => {}
        Answer::Deflate => {
            write_headers(
                &mut send,
                &[
                    (":status", "200"),
                    (
                        "sec-websocket-extensions",
                        "permessage-deflate; server_no_context_takeover; client_max_window_bits=8",
                    ),
                ],
            )
            .await?;
            let mut frame = Vec::new();
            append_server_frame_with_rsv1(&mut frame, true, true, 0x1, COMPRESSED_HELLO);
            write_frame(&mut send, DATA_FRAME, &frame).await?;
        }
    }

    let (mut reader, writer) = tokio::io::duplex(64 * 1024);
    let (ended, ending) = oneshot::channel();
    tokio::spawn(async move {
        let _ = ended.send(pump_data(recv, writer).await);
    });
    while let Ok(frame) = websocket_support::read_client_frame(&mut reader).await {
        let opcode = frame.opcode;
        if answer == Answer::Deflate {
            lock(&log).frames.push(frame);
            continue;
        }
        let mut reply = Vec::new();
        append_server_frame(&mut reply, true, opcode, &frame.payload);
        write_frame(&mut send, DATA_FRAME, &reply).await?;
        if opcode == 0x8 {
            send.finish()?;
            break;
        }
    }
    let ending = ending
        .await
        .unwrap_or_else(|_| Ending::Failed("DATA pump stopped".into()));
    lock(&log).endings.push(ending);
    let send_ending = match send.stopped().await {
        Ok(None) => SendEnding::Acknowledged,
        Ok(Some(code)) => SendEnding::Stopped(code.into_inner()),
        Err(error) => SendEnding::Failed(error.to_string()),
    };
    lock(&log).send_endings.push(send_ending);
    Ok(())
}

/// Copies the payload of each DATA frame into `writer` until the stream
/// ends, and reports how it ended.
async fn pump_data(mut recv: quinn::RecvStream, mut writer: DuplexStream) -> Ending {
    loop {
        match next_frame(&mut recv).await {
            Ok(Some((DATA_FRAME, payload))) => {
                if writer.write_all(&payload).await.is_err() {
                    // The reader stopped; keep draining to see the ending.
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => return Ending::Finished,
            Err(ending) => return ending,
        }
    }
}

/// Reads one HTTP/3 frame, or `None` at a FIN between frames.
async fn next_frame(recv: &mut quinn::RecvStream) -> Result<Option<(u64, Vec<u8>)>, Ending> {
    let mut first = [0];
    match recv.read(&mut first).await {
        Ok(Some(1)) => {}
        Ok(Some(_)) => return Err(Ending::Failed("empty read".into())),
        Ok(None) => return Ok(None),
        Err(error) => return Err(read_ending(error)),
    }
    let frame_type = read_varint_after(recv, first[0]).await?;
    let mut length = [0];
    read_exact(recv, &mut length).await?;
    let length = read_varint_after(recv, length[0]).await?;
    let mut payload =
        vec![0; usize::try_from(length).map_err(|_| Ending::Failed("frame too long".into()))?];
    read_exact(recv, &mut payload).await?;
    Ok(Some((frame_type, payload)))
}

async fn read_varint_after(recv: &mut quinn::RecvStream, first: u8) -> Result<u64, Ending> {
    let width = 1_usize << (first >> 6);
    let mut encoded = [0; 8];
    encoded[0] = first & 0x3f;
    read_exact(recv, &mut encoded[1..width]).await?;
    Ok(encoded[..width]
        .iter()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte)))
}

async fn read_exact(recv: &mut quinn::RecvStream, buffer: &mut [u8]) -> Result<(), Ending> {
    recv.read_exact(buffer).await.map_err(|error| match error {
        quinn::ReadExactError::FinishedEarly(_) => Ending::Failed("frame cut short".into()),
        quinn::ReadExactError::ReadError(error) => read_ending(error),
    })
}

fn read_ending(error: quinn::ReadError) -> Ending {
    match error {
        quinn::ReadError::Reset(code) => Ending::Reset(code.into_inner()),
        error => Ending::Failed(error.to_string()),
    }
}

async fn write_headers(send: &mut quinn::SendStream, fields: &[(&str, &str)]) -> TestResult<()> {
    let fields = fields
        .iter()
        .map(|(name, value)| h3::qpack::HeaderField::new(*name, *value))
        .collect::<Vec<_>>();
    let mut block = BytesMut::new();
    h3::qpack::encode_stateless(&mut block, &fields)?;
    write_frame(send, HEADERS_FRAME, &block).await
}

async fn write_frame(
    send: &mut quinn::SendStream,
    frame_type: u64,
    payload: &[u8],
) -> TestResult<()> {
    let mut frame = Vec::with_capacity(payload.len() + 16);
    put_frame(&mut frame, frame_type, payload);
    send.write_all(&frame).await?;
    Ok(())
}

fn put_frame(output: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    put_varint(output, frame_type);
    put_varint(output, payload.len() as u64);
    output.extend_from_slice(payload);
}

/// Appends `value` as a QUIC variable-length integer (RFC 9000, section 16).
fn put_varint(output: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        output.push(value as u8);
    } else if value < 1 << 14 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}
