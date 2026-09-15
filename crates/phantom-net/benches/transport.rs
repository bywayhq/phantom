//! Deterministic public-path transport benchmarks.

#![allow(
    missing_docs,
    reason = "Criterion generates a public harness entry point"
)]

use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::Builder;

#[path = "transport/http1.rs"]
mod http1;
#[path = "transport/http2.rs"]
mod http2;
#[path = "transport/http2_supervisor.rs"]
mod http2_supervisor;
#[path = "transport/replay_stream.rs"]
mod replay_stream;

const BODY_BYTES: usize = 64 * 1024;

fn transport_benchmarks(criterion: &mut Criterion) {
    http1::register(criterion);
    http2::register(criterion);
}

fn runtime() -> tokio::runtime::Runtime {
    match Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(error) => panic!("failed to build benchmark runtime: {error}"),
    }
}

criterion_group!(benches, transport_benchmarks);
criterion_main!(benches);
