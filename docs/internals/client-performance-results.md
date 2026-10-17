# First public-client measurements

Use this run to choose the next investigation. It measures the public client
on Windows, with separate local peers and unchanged browser defaults.

This is an exploratory baseline. Host CPU use had an 80% median during the
measured phases, including the benchmark. Sampling targeted 10 ms but had a
41 ms median interval and an 8.21 s worst gap. Memory figures below are
sampled lower bounds, not exact peaks. Small speed comparisons need a quieter
host and longer paired runs. Allocation counts provide a separate view.

## Run and source

- Date: 2026-10-16, Windows 11, AMD Ryzen 9 9950X3D2, 16 cores / 32 threads.
- Base revision: `2dcd335029440a071994182d6d840f06c6ee3ab7`.
- Compiler: Rust 1.99.0, `x86_64-pc-windows-msvc`, release with symbols.
- Runtime: two workers in each client and peer process.
- Profiles: Chrome 154 Windows and Firefox 157 Windows.
- Timing binary SHA-256:
  `c66562242c5ee3240015dac0a792b85f772ea617f6d455926fd342ab7d53d353`.
- Native TLS: 282 effective C/C++ compiler commands checked for `/O2`,
  without `/Od`; symbols and native input hashes retained.

The optimized matrix ran 31 cases in three seeded repetition blocks.
86 of 93 trials passed all controls, covering 795,184 measured operations.
Seven failed trials remain excluded and visible. Six smaller allocation
profiles also passed their controls. A construction operation builds and
drops a client; other operations complete and verify a response body.

See the complete [CSV](client-performance-evidence/2026-10-16/summary.csv),
[trial ranges](client-performance-evidence/2026-10-16/summary.json),
[failed trials](client-performance-evidence/2026-10-16/failed-trials.json),
[host observations](client-performance-evidence/2026-10-16/host.json) and
[packet identities](client-performance-evidence/2026-10-16/packets.json).
The adjacent build receipts and matrices identify both executables.

## Time and throughput

Values are medians of accepted trial results. The response payload is 1 KiB
unless stated otherwise. Percentiles are computed within each trial.

| Case | Accepted trials | Requests/s, observed range | p50 / p99 ms |
| --- | --- | --- | --- |
| Warm H1, 1 worker | 3/3 | 8,920; 7,891–10,103 | 0.116 / 0.190 |
| Warm H1, 32 workers | 2/3 | 31,945; 31,876–32,013 | 0.992 / 1.436 |
| Warm H2, 1 worker | 3/3 | 8,200; 7,292–10,153 | 0.127 / 0.215 |
| Warm H2, 32 workers | 3/3 | 43,705; 39,757–54,122 | 0.680 / 1.476 |
| Warm H3, 1 worker | 3/3 | 4,266; 4,078–6,291 | 0.239 / 0.384 |
| Warm H3, 32 workers | 3/3 | 22,706; 19,851–23,792 | 1.374 / 2.496 |

Repeated Chrome client construction had a 9.56 ms median operation latency.
Firefox construction had an 11.80 ms median. Cold requests had median
latencies around 9–10 ms. These are fresh clients within an existing process,
not process-start measurements. The results support reusing clients, but do
not identify the constructor's CPU hotspot. Rust allocation profiles omit
native trust-store and TLS allocations.

The overloaded scheduled case offered 2,000 operations/s to four workers
with a minimum 20 ms peer delay. It completed about 135 requests/s.
Request-duration p99 was 35 ms, while intended-arrival-to-completion p99 was
2.75 s. The latter includes waiting for a worker. This finite schedule does
not allocate an application queue for that backlog.

Proxy cases measure reused CONNECT and SOCKS5 tunnels. They do not measure
cold tunnel setup. These loopback results include the peer, runtime,
application byte verification and host contention. They do not establish an
Internet throughput limit or a general ranking of protocols.

## Body memory and allocation

The timing cases use 16 workers and 1 MiB responses. RSS is process memory,
including native allocations, code and runtime state.

| H2 consumption | Accepted trials | MiB/s | CPU ms/response | Sampled peak RSS MiB |
| --- | --- | --- | --- | --- |
| Stream | 3/3 | 839 | 1.13 | 16.8 |
| Collect | 3/3 | 271 | 1.43 | 31.4 |

Separate DHAT runs used four workers and 32 responses per case. Streaming
allocated 51,307,771 Rust bytes in total, or 1.60 MB per response. Collection
allocated 117,880,381 bytes, or 3.68 MB per response. These are cumulative
allocation bytes, including reallocations, not simultaneously live memory.
The peaks of newly tracked live allocations were 0.67 MiB and 3.95 MiB.

Both profiles attribute about 50.3 MB to `BytesMut::reserve_inner` under the
HTTP/2 length-delimited decoder. Collection adds about 66.6 MB across its
largest buffer-growth points. The collector creates one `BytesMut` per
response and appends each frame to it. This is a concrete candidate for a
bounded experiment, not proof that preallocation or a decoder change will
improve the full client.

Small-response profiles also show large allocations below the driver's
`execute().await` path and, for H3, the public dispatch path. Their ownership
needs isolation before attributing them entirely to the library. The
[allocation stacks](client-performance-evidence/2026-10-16/allocations.json)
retain those unresolved points. Counts include driver, control and runtime
allocations. Construction profiles include lazy stdin initialization.
Existing warmup allocations and native TLS memory are outside DHAT's count.

Gzip uses a repeated-byte payload and is highly compressible. Its results
describe that case, not typical web-content compression. No instrumented
timing or process footprint was mixed into the timing baseline.

## Failures and priorities

1. Concurrent TLS setup returned `SessionTransferError::Busy` during two
   32-origin H2 warmups, two 64-origin H2 warmups and one single-origin H1
   warmup. Inspect native session-policy locking and its ordinary connection
   setup path first. Exceeding the pool limit cannot explain all these cases.
2. The other 64-origin trial completed all 512 measured requests but recorded
   21 peer connection aborts. It remains rejected. Its 639 total connections
   for 640 warmup-plus-measured requests also demonstrate connection churn.
3. One H3 collection trial had three body-completion timeouts after response
   heads arrived. It completed 509 of 512 requests. Earlier diagnostic runs
   also retained H3 warmup and body timeouts. Their causes remain unresolved.
4. After the correctness issues, isolate body growth, H2 decoder allocation
   and large async-path allocations. Test one mechanism at a time, with a
   held-out payload and unchanged wire behavior and resource limits.

The initial diagnostic matrix used unoptimized native TLS despite Cargo's
release label. It is retained separately as `baseline-v1`; its numbers are
excluded here. A benchmark-only MSVC configuration fixed the fresh profiling
build. This is not a measured library optimization or a production-build
regression claim. The native dependency helper and stale cache behavior
should be considered when reproducing a profiling build.

Raw packets, stderr, profiles, source hashes, executables and symbols are
retained locally under `target/client-profiling/`. The optimized packet is
`baseline-v2`, allocation packet `heap-v1`, and readable full table
`report-v3/summary.md`. ETW CPU sampling failed because the session lacks
administrator privileges; the failed probe is retained. No CPU stack profile
or native allocation attribution was obtained. No runtime library change
has been adopted from this run.

## Next

- [Measurement method](client-performance.md): controls and adoption rules.
- [Workload tool](../../tools/client-bench/README.md): repeat the matrix.
- [Performance roadmap](../roadmap.md#phase-4-profiling-and-optimization): remaining scope.
