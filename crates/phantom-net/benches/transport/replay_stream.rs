use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};

pub(super) struct ReplayTransportDropped(oneshot::Receiver<()>);

impl ReplayTransportDropped {
    pub(super) async fn wait(self) {
        if self.0.await.is_err() {
            panic!("replay transport dropped without signaling completion");
        }
    }
}

pub(super) struct ReplayStream {
    response: Bytes,
    read_offset: usize,
    written_bytes: usize,
    response_after_written_bytes: usize,
    completion: Option<oneshot::Sender<()>>,
}

impl ReplayStream {
    pub(super) fn new(response: Bytes) -> Self {
        Self {
            response,
            read_offset: 0,
            written_bytes: 0,
            response_after_written_bytes: 1,
            completion: None,
        }
    }

    pub(super) fn with_completion_after_written_bytes(
        response: Bytes,
        response_after_written_bytes: usize,
    ) -> (Self, ReplayTransportDropped) {
        let (completion, receiver) = oneshot::channel();
        (
            Self {
                response,
                read_offset: 0,
                written_bytes: 0,
                response_after_written_bytes,
                completion: Some(completion),
            },
            ReplayTransportDropped(receiver),
        )
    }
}

impl Drop for ReplayStream {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(());
        }
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.written_bytes < self.response_after_written_bytes {
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
        self.written_bytes = self.written_bytes.saturating_add(buffer.len());
        context.waker().wake_by_ref();
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let length = buffers.iter().map(|buffer| buffer.len()).sum();
        self.written_bytes = self.written_bytes.saturating_add(length);
        context.waker().wake_by_ref();
        Poll::Ready(Ok(length))
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
