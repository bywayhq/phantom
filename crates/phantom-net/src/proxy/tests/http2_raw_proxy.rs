//! A frame-level HTTP/2 proxy for tests that need exact frame order.
//!
//! It answers each client SETTINGS frame with an acknowledgement and
//! otherwise writes only what a test tells it to, so a test controls which
//! frames the client sees and in what order.

use std::{pin::Pin, time::Duration};

use btls::ssl::{Ssl, SslAcceptor};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream;

use crate::tls::test_support::TestResult;

pub(super) const DATA: u8 = 0x0;
pub(super) const HEADERS: u8 = 0x1;
pub(super) const RST_STREAM: u8 = 0x3;
pub(super) const SETTINGS: u8 = 0x4;
pub(super) const GOAWAY: u8 = 0x7;
pub(super) const WINDOW_UPDATE: u8 = 0x8;
pub(super) const END_STREAM: u8 = 0x1;
pub(super) const END_HEADERS: u8 = 0x4;
const ACK: u8 = 0x1;
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAME: usize = 16_384;

/// One frame the client sent.
#[derive(Clone, Debug)]
pub(super) struct Frame {
    pub(super) kind: u8,
    pub(super) flags: u8,
    pub(super) stream: u32,
    pub(super) payload: Vec<u8>,
}

impl Frame {
    /// Returns the frame's type name, flags, and payload length.
    pub(super) fn shape(&self) -> (&'static str, u8, usize) {
        let name = match self.kind {
            DATA => "DATA",
            HEADERS => "HEADERS",
            RST_STREAM => "RST_STREAM",
            SETTINGS => "SETTINGS",
            GOAWAY => "GOAWAY",
            WINDOW_UPDATE => "WINDOW_UPDATE",
            _ => "OTHER",
        };
        (name, self.flags, self.payload.len())
    }
}

/// One accepted proxy connection.
pub(super) struct RawConnection {
    stream: SslStream<TcpStream>,
    buffer: Vec<u8>,
    /// Every frame the client has sent so far, in order.
    pub(super) frames: Vec<Frame>,
}

impl RawConnection {
    /// Accepts a TLS connection, reads the client preface, and sends a
    /// SETTINGS frame with `settings` as (identifier, value) pairs.
    pub(super) async fn accept(
        listener: &TcpListener,
        acceptor: &SslAcceptor,
        settings: &[(u16, u32)],
    ) -> TestResult<Self> {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
        Pin::new(&mut stream).accept().await?;
        let mut connection = Self {
            stream,
            buffer: Vec::new(),
            frames: Vec::new(),
        };
        let mut preface = [0_u8; 24];
        connection.stream.read_exact(&mut preface).await?;
        if preface != PREFACE {
            return Err("client omitted the HTTP/2 preface".into());
        }
        let payload: Vec<u8> = settings
            .iter()
            .flat_map(|(identifier, value)| {
                identifier
                    .to_be_bytes()
                    .into_iter()
                    .chain(value.to_be_bytes())
            })
            .collect();
        connection.write(&[frame(SETTINGS, 0, 0, &payload)]).await?;
        Ok(connection)
    }

    /// Writes `frames` in one write.
    pub(super) async fn write(&mut self, frames: &[Vec<u8>]) -> TestResult<()> {
        self.stream.write_all(&frames.concat()).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads the next client frame, or `None` at the end of the connection.
    pub(super) async fn read_frame(&mut self) -> TestResult<Option<Frame>> {
        loop {
            if self.buffer.len() >= 9 {
                let length = (usize::from(self.buffer[0]) << 16)
                    | (usize::from(self.buffer[1]) << 8)
                    | usize::from(self.buffer[2]);
                if self.buffer.len() >= 9 + length {
                    let head: Vec<u8> = self.buffer.drain(..9).collect();
                    let payload: Vec<u8> = self.buffer.drain(..length).collect();
                    let frame = Frame {
                        kind: head[3],
                        flags: head[4],
                        stream: u32::from_be_bytes([head[5], head[6], head[7], head[8]])
                            & 0x7fff_ffff,
                        payload,
                    };
                    if frame.kind == SETTINGS && frame.flags & ACK == 0 {
                        self.write(&[self::frame(SETTINGS, ACK, 0, &[])]).await?;
                    }
                    self.frames.push(frame.clone());
                    return Ok(Some(frame));
                }
            }
            let mut chunk = [0_u8; 16 * 1024];
            let read = match self.stream.read(&mut chunk).await {
                Ok(read) => read,
                Err(error) if is_disconnect(&error) => 0,
                Err(error) => return Err(error.into()),
            };
            if read == 0 {
                return Ok(None);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Reads frames until one matches `wanted`.
    pub(super) async fn read_until(
        &mut self,
        wanted: impl Fn(&Frame) -> bool,
    ) -> TestResult<Frame> {
        loop {
            let frame = self
                .read_frame()
                .await?
                .ok_or("client closed the proxy connection")?;
            if wanted(&frame) {
                return Ok(frame);
            }
        }
    }

    /// Reads frames until the client closes the connection, for at most
    /// `limit`.
    pub(super) async fn read_to_end(&mut self, limit: Duration) -> TestResult<()> {
        timeout(limit, async {
            while self.read_frame().await?.is_some() {}
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await
        .map_err(|_| "client kept the proxy connection open")?
    }

    /// Answers the tunnel on `stream` by echoing its next DATA payload.
    pub(super) async fn echo(&mut self, stream: u32) -> TestResult<()> {
        let data = self
            .read_until(|frame| frame.kind == DATA && frame.stream == stream)
            .await?;
        self.write(&[frame(DATA, 0, stream, &data.payload)]).await
    }

    /// Returns the client frames on `stream` that came before the first
    /// HEADERS frame of `later`.
    pub(super) fn frames_before(&self, stream: u32, later: u32) -> Vec<&Frame> {
        self.frames
            .iter()
            .take_while(|frame| !(frame.kind == HEADERS && frame.stream == later))
            .filter(|frame| frame.stream == stream && frame.kind != HEADERS)
            .collect()
    }
}

/// Encodes one frame.
pub(super) fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    let mut bytes = vec![length[1], length[2], length[3], kind, flags];
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// Encodes a response HEADERS frame; a `407` carries a Basic challenge.
pub(super) fn response(stream: u32, status: u16, end_stream: bool) -> Vec<u8> {
    let mut block = Vec::new();
    if status == 200 {
        // HPACK static entry 8, `:status: 200`.
        block.push(0x88);
    } else {
        // Literal without indexing, name from static entry 8 (`:status`).
        block.push(0x08);
        let digits = status.to_string();
        block.push(u8::try_from(digits.len()).unwrap_or(3));
        block.extend_from_slice(digits.as_bytes());
    }
    if status == 407 {
        // Literal without indexing, name from static entry 48
        // (`proxy-authenticate`): 15 in the prefix, then 33.
        let value = b"Basic realm=\"proxy\"";
        block.extend_from_slice(&[0x0f, 0x21, u8::try_from(value.len()).unwrap_or(0)]);
        block.extend_from_slice(value);
    }
    let flags = END_HEADERS | if end_stream { END_STREAM } else { 0 };
    frame(HEADERS, flags, stream, &block)
}

/// Encodes `length` bytes of response body on `stream` in frames of at most
/// 16,384 bytes, without END_STREAM.
pub(super) fn body(stream: u32, length: usize) -> Vec<Vec<u8>> {
    let payload = vec![b'x'; length];
    payload
        .chunks(MAX_FRAME)
        .map(|chunk| frame(DATA, 0, stream, chunk))
        .collect()
}

/// Encodes a GOAWAY frame with NO_ERROR.
pub(super) fn goaway(last_stream: u32) -> Vec<u8> {
    let mut payload = last_stream.to_be_bytes().to_vec();
    payload.extend_from_slice(&0_u32.to_be_bytes());
    frame(GOAWAY, 0, 0, &payload)
}

fn is_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}
