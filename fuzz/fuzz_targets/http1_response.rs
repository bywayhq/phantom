//! Production HTTP/1.1 response parsing driven over an in-memory origin.
//!
//! The target drives `phantom_net::http1::Http1Connection::connect` and
//! `Http1Connection::send_get`, so fuzzed bytes reach the production response
//! path a hostile origin server actually reaches: the ordered response-head
//! observer in `crates/phantom-net/src/http1/response_head.rs`, the protocol
//! engine's own status-line, field, and body framing parsers, and the
//! streaming `Http1Body`. It is not a test-kit decoder.
//!
//! The scripted origin hands the response back in input-chosen chunks, so head
//! reassembly, interim `1xx` handling, and chunked-body framing are exercised
//! across read boundaries rather than on one whole buffer. A second request on
//! the same connection exercises keep-alive reuse and the observer's per-
//! transaction reset.
#![no_main]

use std::{
    future::poll_fn,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use http_body::Body;
use libfuzzer_sys::fuzz_target;
use phantom_net::http1::{Http1Connection, OriginForm, RequestHeader};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Complete responses whose framing the parser must keep accepting.
const VALID_RESPONSES: [&[u8]; 4] = [
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"HTTP/1.1 103 Early Hints\r\nLink: </hint>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 204 No Content\r\nServer: fixture\r\nServer: fixture\r\n\r\n",
];

/// Largest number of transactions one input drives on one connection.
const MAX_REQUESTS: usize = 2;

/// An in-memory origin server. Requests are discarded and reads return the
/// scripted response in chunks of at most `chunk` bytes; a zero-length read
/// reports end of stream. It never returns `Poll::Pending`, so every
/// transaction terminates without a timer or a second task.
struct ScriptedOrigin {
    response: Vec<u8>,
    offset: usize,
    chunk: usize,
}

impl AsyncRead for ScriptedOrigin {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = self.offset;
        let available = self.response.len() - start;
        let length = available.min(self.chunk).min(buffer.remaining());
        buffer.put_slice(&self.response[start..start + length]);
        self.offset += length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedOrigin {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Runs up to `requests` transactions against the scripted response and
/// reports whether the first one produced a response head and a complete body.
fn drive(response: &[u8], chunk: usize, requests: usize) -> bool {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("current-thread runtime");
    let origin = ScriptedOrigin {
        response: response.to_vec(),
        offset: 0,
        chunk,
    };
    runtime.block_on(async move {
        let Ok(connection) = Http1Connection::connect(origin).await else {
            return false;
        };
        let mut first_completed = false;
        for index in 0..requests {
            let target = OriginForm::parse("/").expect("origin-form request target");
            let headers = vec![RequestHeader::new("Host", "origin.example")];
            let Ok(response) = connection.send_get(target, headers).await else {
                break;
            };
            let (parts, mut body) = response.into_parts();
            let _ = std::hint::black_box(parts.extensions);
            let mut body_complete = true;
            loop {
                match poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await {
                    Some(Ok(frame)) => {
                        let _ = std::hint::black_box(frame);
                    }
                    Some(Err(error)) => {
                        let _ = std::hint::black_box(error);
                        body_complete = false;
                        break;
                    }
                    None => break,
                }
            }
            if index == 0 {
                first_completed = body_complete;
            }
            if !body_complete {
                break;
            }
        }
        first_completed
    })
}

fn perturb(seed: &[u8], input: &[u8]) -> Vec<u8> {
    let mut structured = seed.to_vec();
    let Some((&selector, mutation)) = input.split_first() else {
        return structured;
    };
    let offset = usize::from(selector) % structured.len();
    let replaced = mutation.len().min(structured.len() - offset);
    structured[offset..offset + replaced].copy_from_slice(&mutation[..replaced]);
    structured
}

fuzz_target!(|input: &[u8]| {
    let chunk = input
        .first()
        .map_or(usize::MAX, |&byte| usize::from(byte) + 1);
    let requests = input
        .get(1)
        .map_or(1, |&byte| usize::from(byte) % MAX_REQUESTS + 1);
    let _ = drive(input, chunk, requests);

    for seed in VALID_RESPONSES {
        let completed = drive(&perturb(seed, input), chunk, requests);
        if input.is_empty() {
            assert!(completed, "structural seeds must remain complete responses");
        }
    }
});
