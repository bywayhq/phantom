use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{OrderedResponseHeaders, ResponseHeader};

use super::{
    Http1Error,
    limits::{MAX_INFORMATIONAL_RESPONSES, MAX_RESPONSE_HEAD_BYTES, MAX_RESPONSE_HEADERS},
};

pub(super) struct ResponseHeadObserver {
    state: Arc<Mutex<ResponseHeadState>>,
}

impl ResponseHeadObserver {
    pub(super) fn wrap<T>(stream: T) -> (ObservedStream<T>, Self) {
        let state = Arc::new(Mutex::new(ResponseHeadState::default()));
        (
            ObservedStream {
                stream,
                state: Arc::clone(&state),
            },
            Self { state },
        )
    }

    pub(super) fn begin(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.buffered.clear();
        state.headers = None;
        state.limit_error = None;
        state.informational_responses = 0;
        state.received_bytes = false;
        state.armed = true;
    }

    /// Returns whether any byte arrived since the current transaction began.
    pub(super) fn received_bytes(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .received_bytes
    }

    pub(super) fn take(&self) -> Option<OrderedResponseHeaders> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .headers
            .take()
    }

    pub(super) fn take_limit_error(&self) -> Option<Http1Error> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .limit_error
            .take()
            .map(ResponseHeadLimitError::into_http1_error)
    }
}

pub(super) struct ObservedStream<T> {
    stream: T,
    state: Arc<Mutex<ResponseHeadState>>,
}

#[derive(Default)]
struct ResponseHeadState {
    buffered: Vec<u8>,
    headers: Option<OrderedResponseHeaders>,
    limit_error: Option<ResponseHeadLimitError>,
    informational_responses: usize,
    /// Any byte read after `begin`, including bytes the head parser rejects.
    received_bytes: bool,
    armed: bool,
}

#[derive(Clone, Copy)]
enum ResponseHeadLimitError {
    HeaderCount,
    HeadBytes,
    InformationalResponses,
}

impl ResponseHeadLimitError {
    /// The HTTP backend accepts any number of interim responses, so this limit
    /// must end the read stream itself for the pending response to fail.
    const fn ends_stream(self) -> bool {
        matches!(self, Self::InformationalResponses)
    }
}

impl ResponseHeadLimitError {
    fn into_http1_error(self) -> Http1Error {
        match self {
            Self::HeaderCount => Http1Error::TooManyResponseHeaders {
                maximum: MAX_RESPONSE_HEADERS,
            },
            Self::HeadBytes => Http1Error::ResponseHeadTooLarge {
                maximum: MAX_RESPONSE_HEAD_BYTES,
            },
            Self::InformationalResponses => Http1Error::TooManyInformationalResponses {
                maximum: MAX_INFORMATIONAL_RESPONSES,
            },
        }
    }
}

impl ResponseHeadState {
    fn observe(&mut self, bytes: &[u8]) {
        if !self.armed {
            return;
        }
        let mut remaining = bytes;
        loop {
            let mut slots = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
            let mut response = httparse::Response::new(&mut slots);
            let head_length = match response.parse(&self.buffered) {
                Ok(httparse::Status::Partial) => {
                    if self.buffered.len() == MAX_RESPONSE_HEAD_BYTES {
                        self.fail(ResponseHeadLimitError::HeadBytes);
                        return;
                    }
                    if remaining.is_empty() {
                        return;
                    }
                    let available = MAX_RESPONSE_HEAD_BYTES - self.buffered.len();
                    let observed = available.min(remaining.len());
                    self.buffered.extend_from_slice(&remaining[..observed]);
                    remaining = &remaining[observed..];
                    continue;
                }
                Ok(httparse::Status::Complete(length)) => length,
                Err(httparse::Error::TooManyHeaders) => {
                    self.fail(ResponseHeadLimitError::HeaderCount);
                    return;
                }
                Err(_) => {
                    // The protocol parser reports the actual request error.
                    self.buffered.clear();
                    self.armed = false;
                    return;
                }
            };
            if head_length > MAX_RESPONSE_HEAD_BYTES {
                self.fail(ResponseHeadLimitError::HeadBytes);
                return;
            }
            let status = response.code.unwrap_or_default();
            let headers = response
                .headers
                .iter()
                .map(|header| ResponseHeader::from_parts(header.name, header.value, false))
                .collect();

            if (100..200).contains(&status) && status != 101 {
                self.informational_responses += 1;
                if self.informational_responses > MAX_INFORMATIONAL_RESPONSES {
                    self.fail(ResponseHeadLimitError::InformationalResponses);
                    return;
                }
                self.buffered.drain(..head_length);
                if self.buffered.is_empty() && remaining.is_empty() {
                    return;
                }
                continue;
            }

            self.headers = Some(OrderedResponseHeaders::new(headers));
            self.buffered.clear();
            self.armed = false;
            return;
        }
    }

    fn fail(&mut self, error: ResponseHeadLimitError) {
        self.buffered.clear();
        self.limit_error = Some(error);
        self.armed = false;
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
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let received = &buffer.filled()[previous_length..];
                if !received.is_empty() {
                    state.received_bytes = true;
                }
                state.observe(received);
                if state
                    .limit_error
                    .is_some_and(ResponseHeadLimitError::ends_stream)
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP/1 response exceeded its informational response limit",
                    )));
                }
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
