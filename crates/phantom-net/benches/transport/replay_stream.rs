use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct ReplayStream {
    response: Bytes,
    read_offset: usize,
    request_started: bool,
}

impl ReplayStream {
    pub(super) fn new(response: Bytes) -> Self {
        Self {
            response,
            read_offset: 0,
            request_started: false,
        }
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.request_started {
            return Poll::Pending;
        }
        let remaining = &self.response[self.read_offset..];
        let length = remaining.len().min(buffer.remaining());
        buffer.put_slice(&remaining[..length]);
        self.read_offset += length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.request_started = true;
        context.waker().wake_by_ref();
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.request_started = true;
        context.waker().wake_by_ref();
        Poll::Ready(Ok(buffers.iter().map(|buffer| buffer.len()).sum()))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
