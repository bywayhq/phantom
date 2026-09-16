use std::{fmt, pin::Pin, task::Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A proxy tunnel that preserves bytes read beyond the CONNECT response head.
pub struct TunnelStream<S> {
    inner: S,
    prefix: Bytes,
}

impl<S> TunnelStream<S> {
    pub(super) fn new(inner: S, prefix: Bytes) -> Self {
        Self { inner, prefix }
    }
}

impl<S> fmt::Debug for TunnelStream<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelStream")
            .field("buffered_bytes", &self.prefix.len())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TunnelStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !this.prefix.is_empty() {
            let length = this.prefix.len().min(buffer.remaining());
            buffer.put_slice(&this.prefix.split_to(length));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TunnelStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, bytes)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
