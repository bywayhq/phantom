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
| Scaling with concurrency | 1, 8 and 32 workers | Completed requests/s, CPU/request, tails |
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

## Follow-up coverage

The first matrix is a baseline, not completion of the full profiling phase.
Add uploads, cancellation, cookies, SSE, WebSockets and long idle/recovery
workloads next where the measurements or downstream demand justify them.
Use controlled RTT, bandwidth and packet-loss conditions on a separate
network test host for WAN conclusions. Compare peers only with matched TLS,
protocol, trust, limits, consumption and validation semantics.

CPU sampling, native allocation attribution, post-idle retention and isolated
cross-platform confirmation remain distinct from the first loopback matrix.
Build time, binary size and CI cost remain separate roadmap work.

## Next

- [First measurements](client-performance-results.md): results and priorities.
- [Workload tool](../../tools/client-bench/README.md): commands and fields.
- [Performance guide](../guides/performance.md): supported tuning controls.
