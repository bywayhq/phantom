# Profile client time and memory

Measure completed work and its resource cost before changing the client.
Keep the workload, binary, raw observations and correctness controls together.

## First baseline

The first pass uses the public `Client` against separate loopback peers.
It changes no runtime library behavior. The isolated
[workload tool](../../tools/client-bench/README.md) owns instrumentation and
its dependency lock. The library and vendored sources remain unchanged.

| Question | Controlled workload | Measurements |
| --- | --- | --- |
| Cost of a new client | Chrome and Firefox construction | Build time, CPU, allocations |
| Cost of setup and reuse | Cold clients and warm H1/H2/H3 | Head and complete latency, connections |
| Scaling with concurrency | 1, 8 and 32 concurrent requests | Completed requests/s, CPU/request, tails |
| Body memory cost | Stream and collect the same 1 MiB payload | RSS, private bytes, allocations, MiB/s |
| Decoding cost | Gzip with the same decoded payload | CPU, allocations, decoded throughput |
| Proxy overhead | Direct, HTTP CONNECT and SOCKS5 | Latency, CPU, connection counts |
| Pool pressure | 32 and 64 origins | Connections, latency, retained memory |
| Waiting and backlog | Delayed heads and scheduled arrivals | Arrival lateness and scheduled completion |
| Slow bodies | Paced body chunks | Complete latency and memory |
| Request preparation | Minimal fields and navigation template | Throughput, CPU, allocations |

Profiles keep their limits and ordering. Tuning them changes the experiment
and needs its own labelled result. A synthetic loopback peer is useful for
repeatable comparisons; it does not reproduce a browser or an Internet path.
The known payload repeats one byte. Gzip cases therefore measure a highly
compressible body, not a representative distribution of web content.

## Measurement rules

1. Build optimized Rust and native code with symbols. Retain source, lock,
   binary and native-input identities. Record features, runtime worker count,
   compiler, operating system, CPU and available memory.
2. Validate the harness with small runs before a baseline. Check exact
   protocol, status, every payload byte, request totals and proxy use. Keep
   failures; never omit them from an accepted result.
3. Start fresh client and peer processes for each repetition. Keep warmup
   outside measurement. Randomize case order within seeded repetition blocks.
   Retain individual results rather than pooling samples into one flattering
   percentile. Confirm small differences with longer, quieter paired runs.
4. Measure wall time, completed requests/s, decoded MiB/s, CPU time/request,
   latency distributions, RSS and private bytes together. Count errors and
   connections. Report CPU and memory for the peer separately.
5. Keep profiler runs separate. Allocation and stack recording change costs.
   Record sampling intervals and profiler limits. RSS includes allocator
   retention and native memory; it is not the same as live Rust heap bytes.
6. Record contention and system load. A busy shared host can guide diagnosis,
   but cannot establish small gains or a production capacity promise.

Process CPU counters have finite resolution. Short phases can make CPU per
request coarse even when wall-clock timestamps are precise. Lengthen the
workload before using a small CPU difference to justify a change.

The approach follows resource utilization, saturation and error analysis in
the [USE method](https://www.brendangregg.com/usemethod.html), optimized builds
and profiling guidance in the
[Rust Performance Book](https://nnethercote.github.io/perf-book/profiling.html),
and separate diagnostic profiling in
[Criterion](https://bheisler.github.io/criterion.rs/book/user_guide/profiling.html).

Closed-loop throughput sweeps do not describe externally offered overload.
The scheduled cases retain intended-arrival latency, following the
[wrk2 measurement principle](https://github.com/giltene/wrk2#wrk2). Their
finite, fixed-worker schedule is explicit. No synthetic correction replaces
the retained timestamps, and a low sample count cannot establish deep tails.

## Scaling beyond the first baseline

The longer `scalability.json` sweep holds the browser recipe and payload fixed.
It varies concurrent requests and runtime workers separately, then offers
scheduled traffic below and above observed throughput. Record successful
requests/s together with CPU/request, request tails and scheduled completion.
Increasing workers applies to the peer too; it cannot isolate client scaling
without the separate process counters and profiles.

Keep an admission-limit probe separate from successful throughput. Count its
rejections and reconcile accepted work with the peer. Never remove a bound,
change a browser setting or retry failures to make that probe pass.

After a longer burst, sample the same idle client with its pools alive.
Account for the observation buffer, allocator retention and connection timers.
Retain process-private memory as well as RSS. Repeated bursts and a dedicated
load generator remain necessary before making a production capacity claim.

## Attribution and optimization

Use process counters to select a question, then a profiler to locate its
cost. Investigate the peer or configured admission limits when throughput
plateaus without client CPU saturation. Compare memory before warmup, during
work and after it before calling retained capacity a leak.

On Windows, sampling uses the installed ETW profiler when privileges permit.
Retain a failed probe if it cannot run. Do not label aggregate process CPU as
a stack profile. Rust allocation profiles use an optional DHAT build, whose
[documented overhead](https://docs.rs/dhat/0.3.3/dhat/) excludes it from speed
comparisons. Native allocations require a separate native-memory tool.

For each proposed change, record a hypothesis, the affected public workload,
the expected mechanism and its correctness constraints. Change one mechanism
at a time. Compare old and new binaries in interleaved runs. Include a
held-out workload and check wire ordering, cancellation and resource bounds.
Accept an improvement only when its measured benefit exceeds run variation
without an unacceptable regression elsewhere. Otherwise retain the result
and keep the default unchanged.

## Current optimization pass

Work from correctness failures to measured changes. Keep the first packet
and binaries unchanged. Each step retains its own results and failed trials.

- [x] Establish the public-client timing and allocation baseline.
- [x] Fix TLS policy contention with deterministic concurrency controls.
- [x] Fix the HTTP/3 body-demand race and repeat the failing workloads.
- [x] Compare body collection before and after one bounded buffer change.
- [x] Isolate decoder and async-driver allocations before deciding on changes.
- [x] Review changes, pass the full gate and record adoption decisions in the
  [results](client-performance-results.md#allocation-experiments-after-the-fixes).

This pass owns TLS policy synchronization, HTTP/3 body demand, response
collection, timeout-future storage and the profiling tool and evidence.
It does not alter browser
wire settings, route fallback or pool limits. Historical capture-timing
investigations remain separate unless a reproduction establishes a link.

## Scaling pass

Measure completed throughput and latency together as concurrency and runtime
workers increase. Use both a closed-loop sweep and planned arrivals below
and above the observed saturation point. Keep errors, application wait and
intended-arrival latency visible when the client falls behind.

- [x] Run the H2/H3 concurrency and worker sweep in `scalability.json`.
- [x] Compare offered and completed rates with queueing and latency tails.
- [x] Sample post-burst memory with the client and pools alive.
- [x] Obtain CPU stacks with separate client and peer reports.
- [x] Vary client and peer workers independently.
- [x] Capture worker busy time and park/unpark counters at slower settings.
- [ ] Attribute the client cost at the slower worker settings.
- [ ] Repeat burst and recovery cycles across more origins.
- [ ] Validate with a separate load generator and downstream traffic.
- [x] Compare a bounded change to request-future storage.

Record client and peer CPU separately. Set `peer_workers` to hold the peer
fixed while `workers` changes the client. Without that override, `workers`
changes both processes. A plateau can come from either process, the runtime
or the loopback stack. Inspect observation-buffer size and host load before
interpreting memory growth or a throughput ceiling. These local runs do not
establish production capacity under network delay and packet loss.

## Protocol work

Keep origin-visible browser settings intact when removing internal work.
Proxy-visible timing may change only when the caller enables it.

| Opportunity | Decision | Boundary |
| --- | --- | --- |
| H2 content-length formatting | Avoid unused strings | Same validation and fields |
| H3 request-map checks | Remove redundant allocation | Same order and sensitivity |
| H1 response-head copy | Reject prototype | Streamed-body regression |
| CONNECT plus ClientHello | Opt-in implementation | Compatible HTTP/1.1 proxy |
| QUIC transmit batching | Already present | Quinn segment batching |
| Larger flow-control windows | Profile policy | Origin-visible frames |
| Different QPACK or ACK policy | Profile policy | Origin-visible settings and traffic |
| More connections or coalescing | Explicit pool policy | Changes peer connections |
| TLS early application data | Separate existing policy | Replay semantics |

CONNECT overlap is distinct from TLS early application data. The origin
handshake still verifies its peer before sending application requests.
Basic credentials are preemptive, and proxy rejection closes the connection
without retry. Digest and outer HTTP/2 are unsupported in this first slice.
Quiet retained proxy openings remain quiet until claimed.

The peer example is httpcloak's
[pinned speculative transport](https://github.com/sardanioss/httpcloak/blob/3a426f92c44af452a249b388a16ae3720097e50a/transport/speculative_conn.go).
Its implementation motivates the experiment, not a performance prediction.
Classic CONNECT semantics are in
[RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).
The separate
[CONNECT-TCP draft](https://datatracker.ietf.org/doc/draft-ietf-httpbis-connect-tcp/)
has its own optimistic-data rules; do not apply those rules retroactively
to every classic CONNECT implementation.

Measure cold connections with the same binary, alternating strict and
opt-in configurations. Use bounded userspace delay only as a mechanism
check. Real network, proxy-vendor and cross-platform results remain separate.
Keep allocation profiles apart from timing and retain rejected prototypes.

## Request preparation follow-up

The rejected comparison reserved semantic header-map storage from the
validated input's distinct names. Counting followed the existing field and
byte checks and preceded cookie expansion. Repeated cookie values did not
reserve thousands of name buckets. Generated content-length and expect fields
were included. Wire settings and header order stayed intact.

This follows the pinned HTTP crate's
[fallible reservation API](https://docs.rs/http/1.5.0/http/header/struct.HeaderMap.html#method.try_reserve).
Reservation is best effort: duplicate values use separate storage and can
still cause growth. The matrix covered templates, minimal fields, Firefox,
higher worker counts, streaming and an unchanged H1 path. Allocation bytes
fell, but Firefox H3 was slower in all three timing pairs. Keep the current
implementation; the [results](client-performance-results.md#prepared-request-storage)
retain the tradeoff and shared-host limits.

Research leaves these candidates separate from that comparison:

| Candidate | Why investigate | Required control |
| --- | --- | --- |
| Preflight request preparation | Builds and discards a request before dispatch rebuilds it | Errors before I/O, hint restarts, retries, body ownership |
| Client-hint placement | Copies owned fields and builds temporary lists | Caller overrides, duplicate positions, hint restarts |
| H2 decoder reservation | Earlier profiles show buffer allocation churn | Fragmentation, held frames, EOF, backpressure |
| HPACK literal prefixes | Long coded literals are shifted to insert their length | Exact bytes, length boundaries, every Huffman policy |
| H3 worker coordination | Higher worker counts raise CPU and parking | Attribute a specific lock or wakeup path first |
| Single-frame collection | Could avoid one response copy | Retained backing memory while callers hold results |

Quinn's [chunk reads](https://docs.rs/quinn/0.11.12/quinn/struct.RecvStream.html#method.read_chunk)
already feed the H3 adapter. They avoid copying, but do not make retention
free. Hyper's
[buffered transport](https://github.com/hyperium/hyper/blob/master/src/proto/h1/io.rs)
also distinguishes queued and flattened writes. A vectored-write experiment
must use the actual TLS writer and check record boundaries.

Larger flow-control windows and different ACK, QPACK or connection policies
remain explicit profile or pool experiments. HTTP/2's
[flow-control rules](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2)
and HTTP/3's
[cookie compression rules](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.1)
constrain those changes. Peer implementations provide hypotheses, not a
speed estimate for Phantom.

The local HPACK encoder computes coded length under the conditional Huffman
policies, then shifts long literals to insert the length prefix. Test reusing
that known length before adding a cache. Preserve the profile's compression
choices and dynamic table updates. Follow the
[HPACK literal format](https://www.rfc-editor.org/rfc/rfc7541.html#section-5.2).
This is a source-level candidate; its runtime benefit remains unmeasured.

## Follow-up coverage

The [request diagnostics measurements](request-diagnostics-cost.md) compare
disabled and enabled collection against the preceding main branch. They
include separate allocation profiles and retain failed cold teardown controls.

The first matrix is a baseline, not completion of the full profiling phase.
Add uploads, cancellation, cookies, SSE, WebSockets and long idle/recovery
workloads next where the measurements or downstream demand justify them.
Use controlled RTT, bandwidth and packet-loss conditions on a separate
network test host for WAN conclusions. Compare peers only with matched TLS,
protocol, trust, limits, consumption and validation semantics.

CPU stacks, native allocation profiles and one-burst retention measurements
are recorded in the [results](client-performance-results.md). Controlled-host,
repeated-cycle and cross-platform confirmation remain open.
Build time, binary size and CI cost remain separate roadmap work.

## Next

- [First measurements](client-performance-results.md): results and priorities.
- [Workload tool](../../tools/client-bench/README.md): commands and fields.
- [Performance guide](../guides/performance.md): supported tuning controls.
