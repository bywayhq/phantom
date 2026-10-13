//! A raw HTTP/3 origin for the WebSocket tests, on a loopback QUIC endpoint.
//!
//! It sends its own SETTINGS and decodes each request's field section with
//! `h3::qpack::decode_stateless`. It announces no QPACK dynamic table, so
//! every field section decodes alone.

use std::{
    error::Error,
    fmt, io,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::watch,
    task::JoinSet,
    time::timeout,
};

use crate::support::deadline::FixtureDeadline;
use crate::support::h3::server_endpoint;
use crate::support::tls::{TestIdentity, TestResult};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};
use crate::support::websocket::{ClientFrame, append_server_frame, append_server_frame_with_rsv1};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const DATA_FRAME: u64 = 0x00;
const HEADERS_FRAME: u64 = 0x01;
const SETTINGS_FRAME: u64 = 0x04;
/// RFC 9220, section 3.
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// "hello" compressed with a raw DEFLATE block, as RFC 7692 section 7.2.3.1
/// shows it.
const COMPRESSED_HELLO: &[u8] = &[0xca, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
const MAX_STREAMS: usize = 128;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// How the origin's request stream ended.
#[derive(Clone, Debug)]
pub(crate) enum Ending {
    Finished,
    Reset(u64),
    Failed(Arc<StreamFailure>),
}

/// Retains the original boxed cause while its logged ending is cloned.
#[derive(Debug)]
pub(crate) struct StreamFailure {
    error: Box<dyn Error + Send + Sync>,
}

impl Ending {
    fn failed(error: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::Failed(Arc::new(StreamFailure {
            error: error.into(),
        }))
    }
}

impl PartialEq for Ending {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Finished, Self::Finished) => true,
            (Self::Reset(left), Self::Reset(right)) => left == right,
            (Self::Failed(left), Self::Failed(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for Ending {}

impl fmt::Display for Ending {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finished => formatter.write_str("request stream finished"),
            Self::Reset(code) => write!(formatter, "request stream reset with {code}"),
            Self::Failed(error) => fmt::Display::fmt(&error.error, formatter),
        }
    }
}

impl Error for Ending {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Failed(error) => Some(error.error.as_ref()),
            _ => None,
        }
    }
}

/// How the origin's send side of a WebSocket stream ended after it sent FIN.
#[derive(Clone, Debug)]
pub(crate) enum SendEnding {
    /// The client acknowledged every byte and the FIN.
    Acknowledged,
    /// The client sent STOP_SENDING with this code.
    Stopped(u64),
    Failed(Arc<StreamFailure>),
}

impl PartialEq for SendEnding {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Acknowledged, Self::Acknowledged) => true,
            (Self::Stopped(left), Self::Stopped(right)) => left == right,
            (Self::Failed(left), Self::Failed(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for SendEnding {}

impl fmt::Display for SendEnding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acknowledged => formatter.write_str("request send side acknowledged"),
            Self::Stopped(code) => write!(formatter, "request send side stopped with {code}"),
            Self::Failed(error) => fmt::Display::fmt(&error.error, formatter),
        }
    }
}

impl Error for SendEnding {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Failed(error) => Some(error.error.as_ref()),
            _ => None,
        }
    }
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
    streams: usize,
}

/// A raw HTTP/3 origin on a loopback QUIC endpoint; aborted on drop.
pub(crate) struct Origin {
    pub(crate) address: SocketAddr,
    endpoint: Option<quinn::Endpoint>,
    log: Arc<Mutex<Log>>,
    task: Option<ConnectionPeer<TestResult<()>>>,
    stop: watch::Sender<bool>,
    failure: Option<Box<dyn Error + Send + Sync>>,
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
        let (stop, stopped) = watch::channel(false);
        let serving = watch::Sender::clone(&stop);
        let task = ConnectionPeer::spawn(async move {
            let mut peers = JoinSet::new();
            let mut stopped = stopped;
            let result: TestResult<()> =
                async {
                    loop {
                        let incoming = tokio::select! {
                            biased;
                            joined = peers.join_next(), if !peers.is_empty() => {
                                joined.ok_or("origin connection outcome disappeared")???;
                                continue;
                            }
                            result = stopping(&mut stopped) => { result?; break; }
                            incoming = accepting.accept() => match incoming {
                                Some(incoming) => incoming,
                                None => break,
                            },
                        };
                        let attempt = {
                            let mut log = lock(&task_log);
                            if log.attempts >= MAX_CONNECTIONS {
                                return Err("HTTP/3 origin connection bound exceeded".into());
                            }
                            log.attempts += 1;
                            log.attempts
                        };
                        if attempt <= refusals {
                            incoming.refuse();
                            continue;
                        }
                        let log = Arc::clone(&task_log);
                        let mut stopped = stopped.clone();
                        peers.spawn(async move {
                        let connection = tokio::select! {
                            biased;
                            connected = incoming => match connected {
                                Ok(connection) => connection,
                                Err(error) if expected_connection_close(&error) => return Ok(()),
                                Err(error) => return Err(error.into()),
                            },
                            result = stopping(&mut stopped) => return result,
                        };
                        {
                            let mut log = lock(&log);
                            log.connections += 1;
                            log.open.push(connection.clone());
                        }
                        let result = serve_connection(connection, behavior, log, stopped).await;
                        match result {
                            Err(error)
                                if error.downcast_ref::<quinn::ConnectionError>()
                                    .is_some_and(expected_connection_close)
                                    || error.downcast_ref::<quinn::WriteError>()
                                        .is_some_and(expected_write_close) => Ok(()),
                            result => result,
                        }
                    });
                    }
                    Ok(())
                }
                .await;
            serving.send_replace(true);
            accepting.close(0_u32.into(), b"HTTP/3 origin cleanup");
            let mut result = result;
            while let Some(joined) = peers.join_next().await {
                result = finish_with_cleanup(
                    result,
                    joined.map_err(Into::into).and_then(|result| result),
                );
            }
            result
        });
        Self {
            address,
            endpoint: Some(endpoint),
            log,
            task: Some(task),
            stop,
            failure: None,
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
        if let Some(endpoint) = &self.endpoint {
            endpoint.wait_idle().await;
        }
    }

    pub(crate) async fn finish(&mut self, caller: TestResult<()>) -> TestResult<()> {
        if let Err(error) = caller {
            retain_failure(&mut self.failure, error);
        }
        self.stop.send_replace(true);
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0_u32.into(), b"HTTP/3 origin cleanup");
        }

        if let Some(task) = self.task.as_mut() {
            match timeout(CLEANUP_TIMEOUT, task.join()).await {
                Ok(joined) => {
                    drop(self.task.take());
                    lock(&self.log).open.clear();
                    drop(self.endpoint.take());
                    if let Err(error) = joined.map_err(Into::into).and_then(|result| result) {
                        retain_failure(&mut self.failure, error);
                    }
                }
                Err(elapsed) => retain_failure(
                    &mut self.failure,
                    FixtureDeadline::new("HTTP/3 origin cleanup exceeded its deadline", elapsed)
                        .into(),
                ),
            }
        }
        match self.failure.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0_u32.into(), b"HTTP/3 origin owner dropped");
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn lock(log: &Mutex<Log>) -> MutexGuard<'_, Log> {
    log.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn stopping(stopped: &mut watch::Receiver<bool>) -> TestResult<()> {
    stopped.wait_for(|value| *value).await?;
    Ok(())
}

fn retain_failure(
    failure: &mut Option<Box<dyn Error + Send + Sync>>,
    error: Box<dyn Error + Send + Sync>,
) {
    *failure = finish_with_cleanup::<()>(failure.take().map_or(Ok(()), Err), Err(error)).err();
}

fn expected_connection_close(error: &quinn::ConnectionError) -> bool {
    matches!(error, quinn::ConnectionError::LocallyClosed)
        || matches!(error, quinn::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == 0 || close.error_code.into_inner() == 0x100)
}

async fn serve_connection(
    connection: quinn::Connection,
    behavior: Behavior,
    log: Arc<Mutex<Log>>,
    mut stopped: watch::Receiver<bool>,
) -> TestResult<()> {
    let mut streams = JoinSet::new();
    let (stream_stop, stream_stopped) = watch::channel(false);
    let result: TestResult<()> = async {
        let mut settings = Vec::new();
        if behavior.extended_connect {
            put_varint(&mut settings, SETTINGS_ENABLE_CONNECT_PROTOCOL);
            put_varint(&mut settings, 1);
        }
        // The control stream stays open for this connection's lifetime.
        let setup = async {
            let mut control = connection.open_uni().await?;
            let mut opening = vec![0x00];
            put_frame(&mut opening, SETTINGS_FRAME, &settings);
            control.write_all(&opening).await?;
            TestResult::Ok(control)
        };
        let _control = tokio::select! {
            biased;
            result = setup => result?,
            result = stopping(&mut stopped) => { result?; return Ok(()); }
        };
        let mut count = 0;
        loop {
            let (send, recv) = tokio::select! {
                biased;
                joined = streams.join_next(), if !streams.is_empty() => {
                    joined.ok_or("origin request outcome disappeared")???;
                    continue;
                }
                result = stopping(&mut stopped) => { result?; break; }
                accepted = connection.accept_bi() => match accepted {
                    Ok(stream) => stream,
                    Err(error) if expected_connection_close(&error) => break,
                    Err(error) => return Err(error.into()),
                },
            };
            if count >= MAX_STREAMS {
                return Err("HTTP/3 origin stream bound exceeded".into());
            }
            count += 1;
            lock(&log).streams += 1;
            let log = Arc::clone(&log);
            let mut stopped = stream_stopped.clone();
            streams.spawn(async move {
                let result = tokio::select! {
                    biased;
                    result = serve_stream(send, recv, behavior.answer, log) => result,
                    result = stopping(&mut stopped) => result,
                };
                match result {
                    Err(error)
                        if error
                            .downcast_ref::<quinn::WriteError>()
                            .is_some_and(expected_write_close) =>
                    {
                        Ok(())
                    }
                    result => result,
                }
            });
        }
        Ok(())
    }
    .await;
    stream_stop.send_replace(true);
    let mut result = result;
    while let Some(joined) = streams.join_next().await {
        result = finish_with_cleanup(result, joined.map_err(Into::into).and_then(|result| result));
    }
    result
}

fn expected_write_close(error: &quinn::WriteError) -> bool {
    match error {
        quinn::WriteError::Stopped(code) => code.into_inner() == super::H3_REQUEST_CANCELLED,
        quinn::WriteError::ConnectionLost(error) => expected_connection_close(error),
        _ => false,
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
            Ok(None) => return Err("request stream ended before HEADERS".into()),
            Err(Ending::Finished | Ending::Reset(super::H3_REQUEST_CANCELLED)) => return Ok(()),
            Err(ending) => return Err(ending.into()),
        }
    };
    let fields = h3::qpack::decode_stateless(&mut section, MAX_FRAME_BYTES as u64)?
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
    let pump = pump_data(recv, writer);
    tokio::pin!(pump);
    let ending = {
        let frames = async {
            while let Some(frame) = read_client_frame(&mut reader).await? {
                let opcode = frame.opcode;
                if answer == Answer::Deflate {
                    let mut log = lock(&log);
                    if log.frames.len() >= MAX_STREAMS {
                        return Err("HTTP/3 origin frame-record bound exceeded".into());
                    }
                    log.frames.push(frame);
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
            TestResult::Ok(())
        };
        tokio::pin!(frames);
        tokio::select! {
            biased;
            result = &mut frames => {
                match result {
                    Ok(()) => pump.await,
                    Err(error) => {
                        // Retain a pump error already observed in this poll. A
                        // pending inline pump owns no detached worker to join.
                        let cleanup = match futures_util::poll!(&mut pump) {
                            std::task::Poll::Ready(ending) => {
                                lock(&log).endings.push(ending.clone());
                                match ending {
                                    Ending::Finished | Ending::Reset(super::H3_REQUEST_CANCELLED) => Ok(()),
                                    ending => Err(ending.into()),
                                }
                            }
                            std::task::Poll::Pending => Ok(()),
                        };
                        return finish_with_cleanup(Err(error), cleanup);
                    }
                }
            }
            ending = &mut pump => {
                let result = frames.await;
                let cleanup = match ending.clone() {
                    Ending::Finished | Ending::Reset(super::H3_REQUEST_CANCELLED) => Ok(()),
                    ending => Err(ending.into()),
                };
                if result.is_err() || cleanup.is_err() {
                    lock(&log).endings.push(ending.clone());
                }
                finish_with_cleanup(result, cleanup)?;
                ending
            }
        }
    };
    lock(&log).endings.push(ending.clone());
    match ending {
        Ending::Finished | Ending::Reset(super::H3_REQUEST_CANCELLED) => {}
        ending => return Err(ending.into()),
    }
    let send_ending = match send.stopped().await {
        Ok(None) => SendEnding::Acknowledged,
        Ok(Some(code)) => SendEnding::Stopped(code.into_inner()),
        Err(quinn::StoppedError::ConnectionLost(error)) if expected_connection_close(&error) => {
            return Ok(());
        }
        Err(error) => {
            let error = Arc::new(StreamFailure {
                error: error.into(),
            });
            lock(&log)
                .send_endings
                .push(SendEnding::Failed(Arc::clone(&error)));
            return Err(Ending::Failed(error).into());
        }
    };
    lock(&log).send_endings.push(send_ending.clone());
    match send_ending {
        SendEnding::Acknowledged | SendEnding::Stopped(super::H3_REQUEST_CANCELLED) => Ok(()),
        ending => Err(ending.into()),
    }
}

/// Copies the payload of each DATA frame into `writer` until the stream
/// ends, and reports how it ended.
async fn pump_data(mut recv: quinn::RecvStream, mut writer: DuplexStream) -> Ending {
    loop {
        match next_frame(&mut recv).await {
            Ok(Some((DATA_FRAME, payload))) => {
                if let Err(error) = writer.write_all(&payload).await {
                    // A completed Close stops the reader; keep draining QUIC to
                    // observe FIN/RESET. Unrelated pipe errors remain failures.
                    if error.kind() != io::ErrorKind::BrokenPipe {
                        return Ending::failed(error);
                    }
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
        Ok(Some(_)) => return Err(frame_failure("empty read")),
        Ok(None) => return Ok(None),
        Err(error) => return Err(read_ending(error)),
    }
    let frame_type = read_varint_after(recv, first[0]).await?;
    let mut length = [0];
    read_exact(recv, &mut length).await?;
    let length = read_varint_after(recv, length[0]).await?;
    if length > MAX_FRAME_BYTES as u64 {
        return Err(frame_failure("HTTP/3 origin frame bound exceeded"));
    }
    let length = usize::try_from(length).map_err(|_| frame_failure("frame too long"))?;
    let mut payload = vec![0; length];
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
        error @ quinn::ReadExactError::FinishedEarly(_) => Ending::failed(error),
        quinn::ReadExactError::ReadError(error) => read_ending(error),
    })
}

fn read_ending(error: quinn::ReadError) -> Ending {
    match error {
        quinn::ReadError::Reset(code) => Ending::Reset(code.into_inner()),
        quinn::ReadError::ConnectionLost(error) if expected_connection_close(&error) => {
            Ending::Finished
        }
        error => Ending::failed(error),
    }
}

fn frame_failure(message: &'static str) -> Ending {
    Ending::failed(io::Error::new(io::ErrorKind::InvalidData, message))
}

async fn read_client_frame(
    stream: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<ClientFrame>> {
    let mut head = [0_u8; 2];
    if stream.read(&mut head[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut head[1..]).await?;
    if head[1] & 0x80 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client frame was not masked",
        ));
    }
    let length = match head[1] & 0x7f {
        126 => {
            let mut encoded = [0; 2];
            stream.read_exact(&mut encoded).await?;
            u64::from(u16::from_be_bytes(encoded))
        }
        127 => {
            let mut encoded = [0; 8];
            stream.read_exact(&mut encoded).await?;
            u64::from_be_bytes(encoded)
        }
        length => u64::from(length),
    };
    if length > MAX_FRAME_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/3 client WebSocket frame bound exceeded",
        ));
    }
    let mut mask = [0; 4];
    stream.read_exact(&mut mask).await?;
    let mut payload = vec![0; length as usize];
    stream.read_exact(&mut payload).await?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Ok(Some(ClientFrame {
        rsv1: head[0] & 0x40 != 0,
        opcode: head[0] & 0x0f,
        payload,
    }))
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

#[cfg(test)]
mod tests;
