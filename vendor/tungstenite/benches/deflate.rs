use std::io::{self, Read, Write};

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput};
use tungstenite::{
    Message, WebSocket,
    protocol::{Role, WebSocketConfig},
};

struct Discard;

impl Read for Discard {
    fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for Discard {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn socket(no_context_takeover: bool) -> WebSocket<Discard> {
    let config = WebSocketConfig::default()
        .write_buffer_size(0)
        .enable_deflate()
        .deflate_no_context_takeover(Role::Server, no_context_takeover);
    WebSocket::from_raw_socket(Discard, Role::Server, Some(config))
}

fn incompressible(size: usize) -> Bytes {
    let mut state = 0x9e37_79b9_u32;
    let bytes = (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect::<Vec<_>>();
    bytes.into()
}

fn benchmark(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("websocket_deflate/compress");
    for size in [1024, 64 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        for (payload_name, payload) in [
            ("repetitive", Bytes::from(vec![b'a'; size])),
            ("pseudorandom", incompressible(size)),
        ] {
            for (context_name, no_context_takeover) in
                [("warm_takeover", false), ("reset_each_message", true)]
            {
                let mut socket = socket(no_context_takeover);
                group.bench_with_input(
                    BenchmarkId::new(format!("{context_name}/{payload_name}"), size),
                    &payload,
                    |bencher, payload| {
                        bencher.iter(|| {
                            socket.write(Message::Binary(payload.clone())).unwrap();
                            socket.flush().unwrap();
                        });
                    },
                );
            }
        }
    }
    group.finish();
}

criterion::criterion_group!(deflate_benches, benchmark);
criterion::criterion_main!(deflate_benches);
