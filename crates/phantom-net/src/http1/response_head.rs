use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{OrderedResponseHeaders, ResponseHeader};

const MAX_RESPONSE_HEADERS: usize = 100;

pub(super) struct ResponseHeadObserver {
    headers: Arc<Mutex<Option<OrderedResponseHeaders>>>,
}

impl ResponseHeadObserver {
    pub(super) fn wrap<T>(stream: T) -> (ObservedStream<T>, Self) {
        let headers = Arc::new(Mutex::new(None));
        (
            ObservedStream {
                stream,
                parser: ResponseHeadParser {
                    buffered: Vec::new(),
                    headers: Arc::clone(&headers),
                    complete: false,
                },
            },
            Self { headers },
        )
    }

    pub(super) fn take(&self) -> Option<OrderedResponseHeaders> {
        self.headers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

pub(super) struct ObservedStream<T> {
    stream: T,
    parser: ResponseHeadParser,
}

struct ResponseHeadParser {
    buffered: Vec<u8>,
    headers: Arc<Mutex<Option<OrderedResponseHeaders>>>,
    complete: bool,
}

impl ResponseHeadParser {
    fn observe(&mut self, bytes: &[u8]) {
        if self.complete {
            return;
        }
        self.buffered.extend_from_slice(bytes);

        loop {
            let mut slots = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
            let mut response = httparse::Response::new(&mut slots);
            let head_length = match response.parse(&self.buffered) {
                Ok(httparse::Status::Partial) => return,
                Ok(httparse::Status::Complete(length)) => length,
                Err(_) => {
                    // The protocol parser reports the actual request error.
                    self.buffered.clear();
                    self.complete = true;
                    return;
                }
            };
            let status = response.code.unwrap_or_default();
            let headers = response
                .headers
                .iter()
                .map(|header| ResponseHeader::from_parts(header.name, header.value, false))
                .collect();

            if (100..200).contains(&status) && status != 101 {
                self.buffered.drain(..head_length);
                if self.buffered.is_empty() {
                    return;
                }
                continue;
            }

            *self
                .headers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(OrderedResponseHeaders::new(headers));
            self.buffered.clear();
            self.complete = true;
            return;
        }
    }
}

impl<T> AsyncRead for ObservedStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let previous_length = buffer.filled().len();
        match Pin::new(&mut self.stream).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                self.parser.observe(&buffer.filled()[previous_length..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T> AsyncWrite for ObservedStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write_vectored(context, buffers)
    }
}
