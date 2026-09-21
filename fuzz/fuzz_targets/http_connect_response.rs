#![no_main]

use std::{
    future::Future,
    io,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};

use libfuzzer_sys::fuzz_target;
use phantom_net::proxy::{HttpConnectHeader, connect_http_tunnel};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const VALID_RESPONSES: [&[u8]; 2] = [
    b"HTTP/1.1 200 Connection established\r\n\r\n",
    b"HTTP/1.1 103 Early Hints\r\nLink: </hint>\r\n\r\nHTTP/1.1 204 No Content\r\nProxy-Agent: fixture\r\n\r\nprefix",
];

// A never-pending in-memory proxy: writes are discarded and reads return the
// response in chunks of at most `chunk` bytes, so head reassembly across reads
// is exercised.
struct ScriptedProxy<'a> {
    response: &'a [u8],
    chunk: usize,
}

impl AsyncRead for ScriptedProxy<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let length = self.response.len().min(self.chunk).min(buf.remaining());
        let (read, rest) = self.response.split_at(length);
        buf.put_slice(read);
        self.response = rest;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedProxy<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn establish(response: &[u8], chunk: usize) -> bool {
    let headers = [HttpConnectHeader::authority("host")];
    let proxy = ScriptedProxy { response, chunk };
    let mut connect = pin!(connect_http_tunnel(proxy, "origin.example:443", &headers));
    let mut context = Context::from_waker(Waker::noop());
    match connect.as_mut().poll(&mut context) {
        Poll::Ready(result) => std::hint::black_box(result).is_ok(),
        Poll::Pending => panic!("CONNECT stalled on a never-pending stream"),
    }
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
    let _ = establish(input, chunk);

    for seed in VALID_RESPONSES {
        let accepted = establish(&perturb(seed, input), chunk);
        if input.is_empty() {
            assert!(
                accepted,
                "structural seeds must remain successful responses"
            );
        }
    }
});
