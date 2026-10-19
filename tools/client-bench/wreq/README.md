# Run the wreq adapter

Build this separate executable with Rust 1.98 or later. It pins `wreq=0.16.1`
and `wreq-util=0.2.0`. Its native dependencies remain separate from Phantom.
Use `scripts/dev/with-cargo-lock.sh` for Cargo commands in this repository.

Supply the executable in a pinned descriptor to the
[comparison controller](../README.md#use-another-client-executable).
Keep the resolved lockfile, compiler identity, source revision, complete build
command and native build settings with the binary. Diagnostic builds do not
qualify as optimized timing builds.

The adapter supports HTTPS GETs and bounded in-memory POST uploads over
exact HTTP/1.1 or HTTP/2.
HTTP/3 and unsupported routes or workload settings fail before warmup.
Cold and shared clients, stream and collect consumption, multiple loopback
origins, and planned arrivals use the existing controller contract.
Worker count selects Tokio runtime workers. Peer workers remain independent.

## Settings and timing

- Recipe: wreq-util's Chrome149 for Windows, with automatic headers disabled.
- Trust: only the peer's supplied root, with hostname and certificate checks.
- Routing: IPv4 loopback, direct or HTTP CONNECT with optional Basic auth.
- Limits: 5-second connect and 15-second application deadline through body EOF.
- Replay: protocol-NACK retries disabled; up to three configured redirects.
- Pools: library defaults. Equivalent per-origin limits are not established.

Response-head timing ends when `send()` returns. First-byte timing ends at the
first nonempty stream chunk delivered to the application. Collection reports
no first-byte timing. Completion includes EOF and full payload verification.
Failures before a response head report a null head timing and an error. Those
samples remain in the results and prevent the trial from being accepted.
Cold samples include client construction. Destruction is outside successful
request completion and inside phase elapsed time and CPU.

Observation storage records vector capacities for sample records and group
headers. It excludes allocator slack and task storage. The measured process
also includes the runtime, TLS backend, pools and observation overhead.
This is not a browser-fingerprint equivalence claim. Recipe versions differ
between adapters. Redirects cover same-origin GETs in collection mode.
CONNECT covers optional Basic authentication. Streaming uploads remain open.
The shared HTTP/1.1 and HTTP/2 cancellation workload checks early body drops
and completion of healthy requests. HTTP/3 remains unsupported.

## Next

- [Interpret measurements](../README.md#interpret-the-measurements).
