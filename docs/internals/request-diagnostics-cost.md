# Request diagnostics costs

Use these measurements to assess the cost of collecting a request timeline.
They cover one Windows host and local controlled peers.

## Method

The control is `becf77c3`; the final production source is `ec0bc2a8`.
The existing public-client harness compares three settings:

- Control: the main branch before request diagnostics.
- Off: the candidate with collection disabled.
- On: the same candidate binary with 128 event slots per request.

Enabled trials create a collector, consume the public body, copy a snapshot,
and check its admission and completion records. Timing includes snapshot
copying and validation, rather than collection alone.

Five blocks alternate control and candidate order. Each block shuffles cases
with a retained seed. Every trial starts fresh client and peer processes.
Both use two runtime workers. Warm trials use 128 warmup requests; cold trials
use eight. Ordinary timing runs have no profiler or concurrent local Cargo
work. Rust 1.99.0 targets x86-64 Windows 11, with 16 physical cores.
Native compiler logs verify `/O2`, with no `/Od`, for all 282 TLS commands.

| Workload | Requests per trial | Concurrent requests | Body |
| --- | --- | --- | --- |
| Warm H1 | 40,000 | 8 | 1 KiB |
| Warm H2 | 100,000 | 32 | 1 KiB |
| Warm H3 | 20,000 | 32 | 1 KiB |
| Cold H2 | 200 | 1 | 1 KiB |
| Stream H2 | 10,000 | 32 | 64 KiB |

Cold trials create and destroy clients as well as opening connections. Their
CPU and throughput include that work. These closed-loop trials have no planned
arrival queue. Samples distinguish response head and end-to-end completion.

## Timing results

The final matrix completed 2,553,000 requests without a request failure.
Of 75 trials, 74 passed all peer controls. One enabled cold trial completed
every body but reported a Windows connection abort during peer teardown.
It remains a failed trial and is excluded from accepted timing medians.
Cold enabled comparisons have four accepted pairs; others have five.

The table gives medians of trial throughput. The last column is the median
of within-block ratios, with its full range; it is not a confidence interval.

| Workload | Control requests/s | Off requests/s | On requests/s | On/off ratio (range) |
| --- | --- | --- | --- | --- |
| Warm H1 | 46,244 | 45,603 | 44,027 | 0.965 (0.901–1.000) |
| Warm H2 | 58,024 | 58,232 | 55,010 | 0.945 (0.843–1.077) |
| Warm H3 | 32,756 | 32,184 | 31,356 | 0.974 (0.948–0.986) |
| Cold H2 | 119 | 120 | 118 | 0.987 (0.967–1.024) |
| Stream H2 | 13,934 | 12,807 | 10,471 | 0.818 (0.641–0.963) |

| Workload | CPU off/on (µs/request) | Completion p99 off/on (ms) | Peak RSS off/on (MiB) |
| --- | --- | --- | --- |
| Warm H1 | 41.8 / 42.6 | 0.320 / 0.330 | 21.02 / 21.16 |
| Warm H2 | 28.9 / 30.8 | 1.066 / 1.132 | 27.80 / 27.95 |
| Warm H3 | 52.3 / 57.0 | 1.669 / 1.728 | 21.67 / 22.14 |
| Cold H2 | 8984 / 8906 | 7.901 / 8.020 | 22.04 / 22.07 |
| Stream H2 | 78.1 / 79.7 | 21.394 / 23.898 | 19.18 / 19.18 |

Collection has a measurable cost, especially in the streamed-body case.
Disabled/control throughput ratios change direction across blocks. Their
shared-host variation prevents a general claim of zero timing overhead.
These short local trials establish neither WAN performance nor production
capacity. Cold p99 has only two observations beyond it per trial.

## Allocation results

Separate DHAT builds run two trials per setting and protocol, with 2,000
measured requests per trial. The table shows median Rust allocation bytes per
completed request. It excludes native TLS allocation and allocations already
live when profiling starts. Instrumented timings are not speed results.

| Warm workload | Control bytes/request | Off bytes/request | On bytes/request |
| --- | --- | --- | --- |
| H1 | 37,829 | 38,179 | 39,579 |
| H2 | 23,352 | 23,729 | 25,133 |
| H3 | 46,036 | 46,501 | 47,942 |

Disabled collection adds about 350–465 allocated bytes per request, with
essentially unchanged allocation counts. Enabled collection plus snapshot
adds about 1,400 bytes and six or seven allocations in these warm cases.
Process RSS includes preallocated latency sample storage; it does not measure
collector memory alone.

The first candidate added about 3,800 bytes per H1/H2 request and 10,200 bytes
per H3 request even with collection disabled. Folding observation into the
existing timeout state machine removed most of that increase. The largest
checked all-feature future is now 15,264 bytes, below the unchanged 20,480-byte
limit. The initial candidate and its failed controls remain in the archive.

## Retained evidence

[Measurements](client-performance-evidence/2026-10-17-request-timeline/measurements.json)
retain medians, ranges, paired ratios and allocation trials.
[Timing rows](client-performance-evidence/2026-10-17-request-timeline/timing.csv)
also retain CPU, private memory, head/body percentiles and scheduled latency.
The [archive receipt](client-performance-evidence/2026-10-17-request-timeline/archive.json)
identifies raw trials, binaries, symbols, native build inputs and source hashes.
The archive is local to the measurement host.

An extra ten-trial cold control reproduced the same teardown abort on
unchanged main. It had one failed peer control while all requests completed.
That reproduction does not turn either candidate failure into a passing trial.

## Next

- [Measurement method](client-performance.md): controls and broader coverage.
- [Workload tool](../../tools/client-bench/README.md): reproduce the comparisons.
- [Request diagnostics reference](../reference/request-diagnostics.md): event boundaries.
