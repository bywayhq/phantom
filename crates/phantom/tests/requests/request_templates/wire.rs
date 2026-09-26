//! Records the client's HTTP/2 bytes so a test can read HEADERS priority.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::request_templates::TestResult;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HEADERS: u8 = 0x1;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// RFC 9113 section 6.2 HEADERS priority as (exclusive, dependency, weight).
pub(crate) type Priority = (bool, u32, u16);

/// Byte stream that keeps a copy of everything the client wrote.
pub(crate) struct RecordingIo<T> {
    pub(crate) inner: T,
    pub(crate) read: Arc<Mutex<Vec<u8>>>,
}

impl<T: AsyncRead + Unpin> AsyncRead for RecordingIo<T> {
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

impl<T: AsyncWrite + Unpin> AsyncWrite for RecordingIo<T> {
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

/// Returns the priority fields of the client's HEADERS frame on `stream_id`,
/// or `None` when that frame has no PRIORITY flag.
pub(crate) fn headers_priority(wire: &[u8], stream_id: u32) -> TestResult<Option<Priority>> {
    let mut rest = wire
        .strip_prefix(PREFACE)
        .ok_or("client omitted the HTTP/2 preface")?;
    while let Some(head) = rest.get(..9) {
        let length = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        let payload = rest.get(9..9 + length).ok_or("truncated HTTP/2 frame")?;
        let (kind, flags) = (head[3], head[4]);
        let id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        rest = &rest[9 + length..];
        if kind != HEADERS || id != stream_id {
            continue;
        }
        if flags & PRIORITY == 0 {
            return Ok(None);
        }
        let fields = if flags & PADDED != 0 {
            payload.get(1..6)
        } else {
            payload.get(..5)
        }
        .ok_or("HEADERS frame too short for priority fields")?;
        let dependency = u32::from_be_bytes([fields[0], fields[1], fields[2], fields[3]]);
        return Ok(Some((
            dependency & 0x8000_0000 != 0,
            dependency & 0x7fff_ffff,
            u16::from(fields[4]) + 1,
        )));
    }
    Err(format!("no HEADERS frame on stream {stream_id}").into())
}
