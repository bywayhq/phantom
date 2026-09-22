//! Production HTTP/1.1 response parsing driven over an in-memory origin.
//!
//! The harness drives `phantom_net::http1::Http1Connection::connect` and
//! `Http1Connection::send_get`, so fuzzed bytes reach the production response
//! path a hostile origin server actually reaches: the ordered response-head
//! observer in `crates/phantom-net/src/http1/response_head.rs`, the protocol
//! engine's own status-line, field, and body framing parsers, and the
//! streaming `Http1Body`. It is not a test-kit decoder.
//!
//! The read-chunk size and the transaction count come from a fixed control
//! prefix that is removed before the response payload begins, so they vary
//! independently of the response bytes and of the seed-perturbation offset.
//! Every read boundary is therefore reachable for any response.
//!
//! [`ScriptedOrigin`] scripts one response per transaction and releases each
//! only after the client has written the matching request, so a second
//! transaction reaches a second response head rather than end of stream. That
//! is the path that resets the ordered-header observer between transactions.

#[cfg(test)]
mod tests;

use std::{
    future::poll_fn,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use http_body::Body;
use phantom_net::http1::{Http1Connection, Http1Error, OriginForm, RequestHeader};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::Runtime,
};

use crate::seed;

/// Complete responses whose framing the parser must keep accepting.
pub const VALID_RESPONSES: [&[u8]; 4] = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"HTTP/1.1 103 Early Hints\r\nLink: </hint>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nServer: fixture\r\nServer: fixture\r\n\r\n",
];

/// Largest number of transactions one input drives on one connection.
const MAX_REQUESTS: usize = 2;

/// Leading bytes that carry the read-chunk size and the transaction count.
///
/// They are consumed before the response payload, so no control value shares a
/// byte with the payload or with the perturbation offset [`seed::perturb`]
/// reads.
const CONTROL_BYTES: usize = 2;

/// Start of every request line this harness sends. A write beginning with it
/// is a new request, which is how the origin releases the next response.
const REQUEST_LINE_PREFIX: &[u8] = b"GET /";

/// Rounds the origin may withhold a response before its request is written.
/// Bounded so the harness cannot stall, and large enough for the dispatcher's
/// ready, send, and flush rounds.
const REQUEST_WAIT_ROUNDS: u8 = 64;

thread_local! {
    /// One runtime per thread. Building one per transaction cost more than the
    /// parsing under test. A finished transaction's driver task is cancelled
    /// when its connection drops and owns only that transaction's origin, so
    /// reuse carries no state between inputs.
    static RUNTIME: Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a current-thread runtime");
}

/// An in-memory origin server holding one scripted response per transaction.
///
/// Requests are discarded. Reads return the response for the current
/// transaction in chunks of at most `chunk` bytes, and a zero-length read
/// reports end of stream once every response is delivered.
///
/// A response is withheld until its request has been written, because a client
/// that reads a response into an idle connection closes it before dispatching.
/// The wait is bounded and self-waking, so the harness never parks: once the
/// budget is spent the response is delivered regardless.
struct ScriptedOrigin {
    responses: Vec<Vec<u8>>,
    delivered: usize,
    offset: usize,
    chunk: usize,
    requests_seen: usize,
    wait_rounds: u8,
}

impl ScriptedOrigin {
    fn new(responses: &[&[u8]], chunk: usize) -> Self {
        Self {
            responses: responses.iter().map(|response| response.to_vec()).collect(),
            delivered: 0,
            offset: 0,
            chunk,
            requests_seen: 0,
            wait_rounds: REQUEST_WAIT_ROUNDS,
        }
    }
}

impl AsyncRead for ScriptedOrigin {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while self
            .responses
            .get(self.delivered)
            .is_some_and(|response| self.offset >= response.len())
        {
            self.delivered += 1;
            self.offset = 0;
            self.wait_rounds = REQUEST_WAIT_ROUNDS;
        }
        let Some(remaining) = self
            .responses
            .get(self.delivered)
            .map(|response| response.len() - self.offset)
        else {
            return Poll::Ready(Ok(()));
        };
        if self.requests_seen <= self.delivered && self.wait_rounds > 0 {
            self.wait_rounds -= 1;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        let length = remaining.min(self.chunk).min(buffer.remaining());
        let (delivered, start) = (self.delivered, self.offset);
        buffer.put_slice(&self.responses[delivered][start..start + length]);
        self.offset += length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedOrigin {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.starts_with(REQUEST_LINE_PREFIX) {
            self.requests_seen += 1;
        }
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Runs one transaction per scripted response on a single connection.
///
/// Returns the first failure. Connect, response-head, and body failures all
/// surface as [`Http1Error`], so the error is carried without formatting it on
/// the hot path.
///
/// # Errors
///
/// Returns [`Http1Error`] when the connection, a response head, or a response
/// body is rejected.
pub fn drive(responses: &[&[u8]], chunk: usize) -> Result<(), Http1Error> {
    let origin = ScriptedOrigin::new(responses, chunk);
    let transactions = responses.len();
    RUNTIME.with(|runtime| {
        runtime.block_on(async move {
            let connection = Http1Connection::connect(origin).await?;
            for _ in 0..transactions {
                let target = OriginForm::parse("/").expect("an origin-form request target");
                let headers = vec![RequestHeader::new("Host", "origin.example")];
                let response = connection.send_get(target, headers).await?;
                let (parts, mut body) = response.into_parts();
                let _ = std::hint::black_box(parts.extensions);
                while let Some(frame) =
                    poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
                {
                    let _ = std::hint::black_box(frame?);
                }
            }
            Ok(())
        })
    })
}

/// Drives the raw input and every perturbed structural seed.
pub fn exercise(input: &[u8]) {
    let (control, payload) = input.split_at(input.len().min(CONTROL_BYTES));
    let chunk = control
        .first()
        .map_or(usize::MAX, |&byte| usize::from(byte) + 1);
    let requests = control
        .get(1)
        .map_or(1, |&byte| usize::from(byte) % MAX_REQUESTS + 1);

    let _ = std::hint::black_box(drive(&vec![payload; requests], chunk));

    for seed in VALID_RESPONSES {
        let perturbed = seed::perturb(seed, payload);
        let _ = std::hint::black_box(drive(&vec![perturbed.as_slice(); requests], chunk));
    }
}
