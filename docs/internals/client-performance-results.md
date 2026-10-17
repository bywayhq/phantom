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
| Warm H1, concurrency 1 | 3/3 | 8,920; 7,891–10,103 | 0.116 / 0.190 |
| Warm H1, concurrency 32 | 2/3 | 31,945; 31,876–32,013 | 0.992 / 1.436 |
| Warm H2, concurrency 1 | 3/3 | 8,200; 7,292–10,153 | 0.127 / 0.215 |
| Warm H2, concurrency 32 | 3/3 | 43,705; 39,757–54,122 | 0.680 / 1.476 |
| Warm H3, concurrency 1 | 3/3 | 4,266; 4,078–6,291 | 0.239 / 0.384 |
| Warm H3, concurrency 32 | 3/3 | 22,706; 19,851–23,792 | 1.374 / 2.496 |

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

The timing cases use 16 concurrent requests and 1 MiB responses. RSS includes
native allocations, code and runtime state.

| H2 consumption | Accepted trials | MiB/s | CPU ms/response | Sampled peak RSS MiB |
| --- | --- | --- | --- | --- |
| Stream | 3/3 | 839 | 1.13 | 16.8 |
| Collect | 3/3 | 271 | 1.43 | 31.4 |

Separate DHAT runs used four concurrent requests and 32 responses per case.
Streaming allocated 51,307,771 Rust bytes in total, or 1.60 MB per response. Collection
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

## Corrections after the first packet

Commit `05ea1001` fixes two races reproduced by the first measurements.
Ordinary TLS setup now shares a context guard. Policy mutation and session
transfer keep exclusive access. HTTP/3 now clears its outstanding-demand flag
when a body frame arrives during demand submission, allowing the next poll
to request another frame.

The new regression tests failed on the original code. With the fixes, all 18
native session-transfer tests and the deterministic HTTP/3 demand test pass.
A repeat of the same 20-trial correctness matrix produced these results:

| Result | Original | Corrected |
| --- | --- | --- |
| TLS contention trials | 3 | 0 |
| HTTP/3 timeout trials | 4 | 0 |
| Successful measured requests | 7,674 | 10,240 |
| Accepted trials | 10/20 | 15/20 |

Two original TLS failures occurred during warmup. The third trial had two
measured setup errors. The corrected run also completed every warmup.
The [comparison packet](client-performance-evidence/2026-10-16-remediation/correctness-comparison.json)
retains each trial's disposition.
The five remaining rejected trials use 64 origins. Every client response
completed, but the peer recorded transport aborts during connection churn.
Those failures remain rejected. An abort code alone does not establish
harmless retirement.

These reproductions establish the two races above. They do not establish a
connection to the separate historical browser-capture timing failures.

## Allocation experiments after the fixes

Two bounded experiments kept the browser settings, routes and pool limits
unchanged. Neither is enabled in the library.

Pinning the H2/H3 response-head operation locally reduced its async state.
Three allocation profiles per case confirmed the H3 request box changed from
16,600 to 10,408 bytes: 6,192 fewer bytes per request, with the same allocation
count. The outer 18,152-byte request box remained. Total measured Rust
allocation bytes fell about 11% for Chrome and 12% for Firefox in these small
streaming cases. H1 and small H2 allocation totals did not change.

The first timing comparison covered eight cases and three matched pairs.
Held-out H2 CONNECT throughput fell in all three pairs, by 17.8%, 9.5% and
18.9%. Shared-host variation prevents attributing that decline to the change.
The follow-up did not repeat CONNECT, so this adverse result remains open.
A six-pair follow-up used 50,000 requests per trial. All 36 follow-up trials
passed request, payload, protocol and peer-count controls. Its median paired
changes were:

| Workload | CPU/request | Requests/s | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| Chrome H3 | -1.9% | +3.1% | -2.6% | -7.9% |
| Firefox H3 | +0.7% | -3.6% | -1.4% | -4.7% |
| Unchanged H1 control | +8.9% | -7.2% | +7.0% | +0.6% |

Host busy time ranged from 29% to 98%. H3 trials lasted 1.86–2.98 seconds.
Chrome's experimental trials also had lower host load. Sampled H3 RSS rose
in every pair, by a median 0.6% for Chrome and 1.1% for Firefox. The allocation
saving is established, but lower process memory and throughput
non-regression are not. Adoption is on hold. The source patch, both binaries
and all packets are retained for a controlled-host follow-up.
The [paired results](client-performance-evidence/2026-10-16-remediation/focus-summary.json)
and [allocation records](client-performance-evidence/2026-10-16-remediation/allocation-experiments.json)
retain the per-trial values.

The collector experiment held data frames until EOF, then allocated one
contiguous result. Across three 32-request profiles of 1 MiB H2 bodies at
concurrency four, median cumulative Rust allocation bytes fell from
117,880,445 to 84,977,277. Median peak newly allocated live bytes rose from
4,054,078 to 4,492,689. Retaining all frames also retains their backing
buffers and adds per-frame metadata. The original collector was restored.
No uninstrumented speed conclusion was drawn for this candidate.

The H2 streaming profile separately attributes about 50.3 MB across 4,095
allocations to the length-delimited decoder's reservation after yielding a
frame. About 8 KiB remained at profile end. This is allocation churn, not
evidence of a leak. Changing that reservation needs separate fragmentation,
backpressure, EOF and multiplexing controls. No decoder change was adopted.

## CPU and native heap profiles

Windows CPU sampling required administrator privileges that were unavailable.
Separate Linux runs in WSL supplied CPU stacks and native heap traces.
They are diagnostic runs, not Windows speed comparisons.

Two CPU-profile trials completed 600,000 measured requests without request
or peer failures. Sampling recorded user-mode CPU at 199 Hz with DWARF
stacks and no lost samples. Reports filter client and peer PIDs separately,
within each measured request phase. Their percentages use each filtered
process as the denominator. Inline expansion failed in the symbol tool;
bounded reports retain function stacks without inline expansion. Some libc
addresses remain unresolved. Kernel CPU and off-CPU wait are outside these
samples.

The H2 client had 2,366 samples; `malloc` accounted for 6.2% of self samples.
The H2 peer had 990 samples; mutex contention accounted for 14.2%. The H3
client had 4,157 samples; `cfree` accounted for 4.2%. The H3 peer had 2,518
samples; `malloc` accounted for 9.7% and mutex contention for 6.8%. These
profiles do not establish the cause of the higher-worker Windows regression.
They show why peer work must remain separate from client attribution.
The [filtered summaries](client-performance-evidence/2026-10-16-remediation/linux-perf-summary.json)
record sample counts, top entries and profiling limits.

Two heaptrack trials completed all 64 measured requests and warmups. Whole
process lifetime includes trust-store setup, warmup and result export.
Native `OPENSSL_malloc` stacks reached about 3.44 MB of peak live memory
through certificate parsing during client construction. That is startup
cost, not a per-request allocation. Total traced heap peaks were 4.47 MB for
H2 streaming 1 MiB bodies and 7.05 MB for small H3 responses. About 33 KB
remained at exit in each run; exit-time retention alone does not prove a
library leak. These intervals differ from the request-only DHAT profiles.

## Longer scaling sweep

The corrected library completed 6.4 million measured 1 KiB requests across
32 accepted trials. Four early trials overlapped CPU-report processing.
Their timings were excluded and replaced once. The comparison retains two
trials per setting, covering 5.6 million requests. Every warmup, response and
peer count passed. This sweep uses Chrome 154 Windows, one origin and one
reused connection, with two runtime workers unless a row changes them.

| Setting | H2 requests/s | H3 requests/s | H2 / H3 CPU microseconds/request |
| --- | ---: | ---: | ---: |
| Concurrency 32 | 41,184 | 27,289 | 40.9 / 63.0 |
| Concurrency 128 | 59,427 | 27,549 | 29.5 / 62.5 |
| Concurrency 192 | 65,992 | 26,617 | 26.5 / 65.9 |
| Four runtime workers, concurrency 128 | 54,603 | 11,192 | 47.0 / 210.1 |
| Eight runtime workers, concurrency 128 | 42,013 | 10,176 | 90.3 / 254.6 |
| Planned 10,000/s, concurrency 128 | 9,999 | 9,999 | 34.1 / 64.6 |
| Planned 40,000/s, concurrency 128 | 39,984 | 27,264 | 36.8 / 63.0 |

From concurrency 32 to 192, H2 request p99 grew from 1.59 to 4.49 ms.
H3 p99 grew from 2.34 to 10.9 ms while throughput stayed roughly flat.
Concurrency, throughput and tail latency need to be assessed together.

Values are medians of trial results. At planned 40,000/s, H2's scheduled
completion p99 was 14.4 ms. H3's was 2.32 seconds, versus 7.85 ms within the
request itself. H3 falls behind the offered schedule. At planned 10,000/s,
scheduled p99 was 17.8 ms for H2 and 18.4 ms for H3. Windows timer bursts
contribute to scheduled waiting even when average throughput keeps up.

More workers increased client CPU/request and reduced throughput in both
protocols. That sweep changed the peer's worker count too. The independent
worker comparison below separates those changes.

Host busy time ranged from 54% to 98%. The median sampling gap was 57 ms and
the worst was 785 ms. Sampled client RSS medians ranged from 37 to 46 MiB,
including a fixed 19.8 MiB observation buffer. These shared-host loopback
results do not establish an Internet or production capacity ceiling.

A separate concurrency-256 probe used 20 ms peer delays. H2 returned 964
capacity errors and completed 3,132 requests. H3 returned 939 capacity errors
and completed 3,157. Peer totals exactly matched completions plus warmup,
with no peer failures. Both trials remain rejected throughput results. The
client kept its configured admission bounds and performed no hidden retries.
The [full scaling comparison](client-performance-evidence/2026-10-16-remediation/scaling-comparison.json)
retains individual trials, exclusions, ranges and process costs.

## Memory after a longer burst

H2 and H3 each completed 500,000 measured requests at planned 10,000/s, then
kept the same client alive for 180 seconds. Request and peer counts passed.
The following process figures include the fixed 49.59 MiB observation buffer.

| Protocol | Warm RSS / private MiB | After burst | After idle |
| --- | ---: | ---: | ---: |
| H2 | 66.31 / 57.55 | 69.54 / 60.05 | 69.54 / 60.05 |
| H3 | 67.41 / 57.46 | 71.32 / 61.86 | 71.40 / 61.88 |

The first H3 run completed every request but failed the idle peer check.
Its generic timeout remains a rejected result. A rebuilt peer recognizes
idle retirement only after the phase snapshot and exact completed count,
with both H3 and QUIC typed timeout reasons and successful response-task
completion. A repeat of the same H3 workload passed, recording one idle
retirement and zero failures. No library connection policy changed.

The [original recovery packet](client-performance-evidence/2026-10-16-remediation/recovery-v1-summary.json)
and [H3 replay](client-performance-evidence/2026-10-16-remediation/h3-recovery-v2-summary.json)
retain the observations and controls. Memory remained above the warm start.
One burst cannot distinguish retained capacity from long-term growth.
Repeated cycles and attribution of live allocations remain necessary.

## Independent client and peer workers

The tool now accepts `peer_workers`, leaving `workers` to select the client
runtime. The original coupled behavior remains the default. Three repeats
of nine settings completed all 2.7 million measured requests. Each used
100,000 1 KiB responses, concurrency 128 and one reused connection.

| Protocol | Client / peer workers | Requests/s | CPU microseconds/request | Request p99 ms |
| --- | ---: | ---: | ---: | ---: |
| H2 | 2 / 2 | 68,120 | 26.4 | 2.95 |
| H2 | 8 / 2 | 40,784 | 84.8 | 4.62 |
| H2 | 2 / 8 | 59,963 | 28.0 | 3.10 |
| H3 | 1 / 2 | 32,146 | 29.7 | 6.05 |
| H3 | 2 / 2 | 33,676 | 54.4 | 5.70 |
| H3 | 8 / 2 | 13,627 | 197.0 | 13.71 |
| H3 | 2 / 8 | 29,849 | 58.6 | 6.96 |

Values are medians. Raising client workers still reduces throughput and
raises CPU/request with the peer fixed. This locates part of the cost in
the client process; it does not distinguish scheduling, wakeups, locks or
transport work. The earlier two-worker Linux samples cannot establish the
cause of this Windows eight-worker result.

Median host busy time ranged from 44% to 50%. The fixed observation buffer
was 9.9 MiB, half the earlier sweep's buffer. Its lower absolute RSS is not
a library improvement. The
[worker comparison](client-performance-evidence/2026-10-16-timeout-storage/workers-summary.json)
retains all nine settings, individual trials, peer CPU and host load.

## Smaller timeout operation storage

The timeout wrapper now stores its operation directly in a pinned field.
This avoids storing the same large future in the argument and suspended
states of an async function. The first attempt only moved the pinning point
inside that async function; it produced no allocation benefit and was dropped.

Review caught delayed destruction in the first direct wrapper. A regression
failed while the completed wrapper retained owned work. The corrected version
clears the operation before returning completion, including timeout and
initial-validation errors. Its ten focused tests pass, covering deadline
priority, missing timers and cancellation as well.

Matched DHAT builds ran three profiles of 32 requests per case. Each passed
the response, protocol and peer controls. These are cumulative Rust allocation
bytes during measured requests, including the harness's request future.

| Workload | Before bytes | After bytes | Reduction |
| --- | ---: | ---: | ---: |
| H2, 1 KiB, concurrency 1 | 834,334 | 726,558 | 12.9% |
| H3, 1 KiB, concurrency 1 | 1,855,066 | 1,546,570 | 16.6% |
| H1, 1 KiB, concurrency 4 | 1,346,409 | 1,238,633 | 8.0% |
| Firefox H3, 1 KiB, concurrency 4 | 1,630,666 | 1,321,176 | 19.0% |

Values are medians. The harness's boxed outer request future shrank from
18,152 to 14,784 bytes. The inner H3 request allocation shrank from 16,600
to 10,320 bytes. The field layout is private and compiler-dependent.
Allocation counts stayed close; the benefit is fewer bytes per allocation.

Large H2 bodies reduced cumulative bytes by only 0.1% for collection and
0.2% for streaming. Their traced live peaks increased: collection medians
rose from 3.97 to 4.93 MB and streaming from 0.74 to 1.48 MB. At the streaming
peak, HTTP/2 frame buffers account for most of the difference. Instrumented
buffer overlap and whole-process memory need separate assessment; the
smaller future is not evidence that every workload uses less live memory.
The [allocation comparison](client-performance-evidence/2026-10-16-timeout-storage/heap-comparison.json)
retains the three profiles, live peaks and allocation stacks for every case.

Three fresh-process timing pairs then completed 3,603,072 measured requests
in 42 accepted trials. Client and peer each used two workers, except for the
held-out eight-client-worker case. Paired changes below use the median of
each pair's percentage change, not a ratio of pooled requests.

| Workload | Requests/s change | CPU/request change | Request p99 change |
| --- | ---: | ---: | ---: |
| H2, concurrency 128 | +6.8% | -7.0% | -9.3% |
| H3, concurrency 128 | +14.8% | -9.3% | -3.8% |
| Firefox H3, concurrency 128 | +17.8% | -15.0% | -15.6% |
| H1, concurrency 32 | +9.9% | -9.0% | -13.4% |
| H2 through CONNECT, concurrency 32 | -4.5% | +8.8% | +18.5% |
| H3, eight client workers | -5.6% | +7.7% | -3.6% |

Host load varied sharply. The last eight-worker candidate trial reached
97% busy time. No builds or report processing overlapped benchmark timing.
These numbers do not establish a general speedup. The
[timing comparison](client-performance-evidence/2026-10-16-timeout-storage/timing-comparison.json)
retains all trial values and host observations, including the lower results.

The three lower CONNECT results triggered a closer check: four alternating
pairs of 500,000 requests, totaling four million completed requests. The
candidate was faster in three pairs and slower in one. Paired throughput
changes ranged from -7.3% to +17.2%; CPU/request ranged from -12.5% to +8.4%.
That does not reproduce a consistent CONNECT regression. Host busy time
still ranged from 52% to nearly 100%. The
[proxy follow-up](client-performance-evidence/2026-10-16-timeout-storage/proxy-comparison.json)
retains both execution orders and every result.

Six ordinary H2 streaming trials completed another 3,072 requests with
1 MiB bodies. Candidate RSS medians were 16.61 versus 16.47 MiB; paired RSS
increases ranged from 0.5% to 2.3%. Throughput changes ranged from -7.5% to
+4.8%. Request p99 fell in all three pairs, while p95 rose by 9.8% to 16.2%
in every pair. With only 512 observations per trial, bulk-body tails remain
exploratory. The
[streaming follow-up](client-performance-evidence/2026-10-16-timeout-storage/stream-comparison.json)
keeps those observations separate from the allocation-instrumented runs.

Keep the storage change for its repeatable reduction in allocation bytes
and smaller request futures. Whole-process memory did not improve across
the small-response trials: paired RSS increased by roughly 0% to 5.4%.
The bulk-body live-heap tradeoff and noisy speed comparisons remain visible.
Further work must measure allocator retention and client worker overhead
separately. This pass does not establish a memory or throughput optimum.

## Worker contention follow-up

The slower eight-worker setting reproduced on Windows and in the Linux
diagnostic VM with the peer held at two workers. Each platform completed
four accepted trials of 300,000 requests, with concurrency 128 and 1 KiB
responses. These trials used the timeout-storage change already applied.

The Windows control adds stable Tokio counters at the phase boundaries.
Its library matches `118a48c`. Each row below is one diagnostic trial,
not a repeated speed comparison.

| Protocol | Client workers | Requests/s | CPU microseconds/request | Parks/request |
| --- | ---: | ---: | ---: | ---: |
| H2 | 2 | 76,912 | 23.3 | 0.054 |
| H2 | 8 | 41,080 | 81.1 | 2.024 |
| H3 | 2 | 34,365 | 51.6 | 0.041 |
| H3 | 8 | 14,855 | 189.1 | 6.017 |

Busy time and parks describe scheduler activity, not CPU time, OS context
switches or individual task wakeups. The snapshots are not atomic. Windows
host busy time ranged from 35% to 42%, using user and system time divided by user,
system and idle time. The fixed observation buffer was 29.8 MiB.

Linux sampling used user-space CPU events at 199 Hz, with 16 KiB DWARF
stacks and separate process/phase filters. No samples were lost. Contended
mutex locking took 8.08% of the H2 client's filtered self sample weight at
eight workers and 4.23% for H3. Allocation, scheduling and transport work
also remained visible. Inline expansion was disabled and some frames were
unresolved. These stacks do not identify one lock as the cause, or establish
the same cost distribution on Windows. Instrumented Linux timings are
excluded from speed comparisons.

The [diagnostic record](client-performance-evidence/2026-10-16-worker-contention/diagnostics.json)
retains process CPU, memory, peer controls and per-worker counter snapshots.

### Less shared-state work during H2 reuse

The H2 selector now skips peer stream-limit probes when its fixed connection
limit is one. It also reads each connection's limit once during placement
across several connections. The transport still waits for actual stream
credit. Connection limits, protocol selection and request ordering remain
unchanged.

Both Windows binaries use the same new counter snapshots. Their library
Rust sources differ only in the H2 selector. Native build receipts confirm
optimized TLS code for both. Snapshot work falls outside request elapsed
time but inside process CPU measurements. The
[build record](client-performance-evidence/2026-10-16-worker-contention/builds.json)
retains binary identities, source comparisons and the Linux diagnostic scope.

Three alternating pairs covered seven workloads: H2 at two and eight
workers, lower concurrency, body collection, Firefox, CONNECT and streaming
64 KiB bodies. All 42 trials passed, completing 7.32 million requests.
Results varied substantially. Firefox throughput ranged from -23.4% to
+17.7%; CONNECT ranged from -8.3% to +9.7%. One short bulk trial lost 41.3%
throughput and raised p99 by 298.1%. The
[complete comparison](client-performance-evidence/2026-10-16-worker-contention/timing.json)
keeps every trial, including those lower results.

A final confirmation placed each candidate trial immediately beside its
control, alternating their order. Three pairs covered each worker setting
and the bulk workload. Small bodies used 300,000 requests per trial; bulk
used 100,000, five times the earlier count. All 18 trials passed, completing
4.2 million requests. Ranges below are individual paired percentage changes,
not pooled percentiles or confidence intervals.

| H2 workload | Requests/s change | CPU/request change | Request p99 change | Peak RSS change |
| --- | ---: | ---: | ---: | ---: |
| 1 KiB, eight workers | +11.4% to +26.7% | -13.5% to -4.4% | -20.5% to -8.8% | -0.1% to +2.3% |
| 1 KiB, two workers | -1.0% to +21.3% | -15.9% to 0.0% | -14.9% to -4.0% | +0.4% to +1.3% |
| 64 KiB streaming, two workers | -4.0% to +19.7% | -11.3% to -6.4% | -38.7% to +9.8% | +1.1% to +1.8% |

Keep this small change for the repeated reduction in CPU/request at eight
workers and with bulk bodies. It does not establish a uniform throughput,
tail-latency or memory improvement. Bulk p95 changes were +31.3%, +0.5% and
-18.9%. Bulk peak private memory rose by 0.34 to 0.75 MiB, or 1.8% to 4.1%.
Those costs remain part of the adoption decision. The
[confirmation record](client-performance-evidence/2026-10-16-worker-contention/confirmation.json)
retains host load, absolute measurements, execution order and counters.

Across diagnostics and comparisons, 68 accepted trials completed 13.92
million measured requests without request failures. These local, reused
single-connection workloads do not establish production capacity. H3's
worker scaling remains unresolved; no H3 optimization was made in this pass.

## HTTP/3 body coordination experiments

Neither experiment below was adopted. Both saved a small amount of Rust
allocation traffic, but neither established a useful overall improvement.
The final Rust sources match the previously gated `6559a70c` baseline.

The first experiment replaced the body's demand queue with a notification.
The second restored that queue and replaced its cancellation channel with
a one-time signal. Each changed only `http3/body/task.rs`. The worker still
owned stream cleanup, upload monitoring and retained cleanup guards.
Independent source review found no correctness blocker in either prototype.

Each experiment ran three adjacent control/candidate pairs for six ordinary
workloads, alternating their order. Case order used seed `20261026`.
Workloads covered Chrome H3 at concurrency 1 and 128, two and eight client
workers, Firefox H3, 64 KiB streaming and an unchanged H2 reference.
The peer kept two workers.
Allocation profiling used separate binaries and four smaller workloads.
All 120 trials passed their controls: 72 ordinary trials completed
9,540,000 requests, and 48 instrumented trials completed another 3,072.
Instrumented timings are excluded from speed comparisons.

Both experiments used the same control library and optimized native TLS.
The ordinary control receipt predates the baseline commit and records its
patch separately. Its then-untracked counter module is retained separately
with the earlier run-identity reconciliation. The
[build comparison](client-performance-evidence/2026-10-16-h3-coordination/builds.json)
records these limits, binary hashes and source differences. Request counts
differ between experiments; their speeds are not a head-to-head comparison.

### Notification for body demand

Cumulative allocation bytes fell by 1.02–1.03% for tiny Chrome responses and
1.22–1.24% for Firefox. Bulk savings ranged from 0.29% to 0.69%.
These are allocation bytes, not RSS reductions. Bulk CPU/request changed by
+14.5%, -4.4% and +6.0%; throughput changed by -12.0%, +4.2% and -6.4%.
Bulk p95 rose in two pairs. The unchanged H2 reference also varied widely:
CPU/request changed from -18.2% to +41.9% across pairs.

Set this prototype aside. The small allocation saving does not justify
adoption under mixed speed results. This does not prove that notifications
cause a slowdown. The [ordinary results](client-performance-evidence/2026-10-16-h3-coordination/notify-timing-summary.json)
and [allocation results](client-performance-evidence/2026-10-16-h3-coordination/notify-heap-summary.json)
retain every pair, including absolute values and memory measurements.

### One-time body cancellation

Cumulative allocation bytes fell by 0.58–0.59% for tiny Chrome responses and
0.68–0.69% for Firefox. Bulk allocation changes ranged from -0.64% to +0.29%.
The peak of newly tracked live allocations rose in all three Firefox pairs
by 0.7–2.2%. Bulk live-heap changes ranged from -22.0% to +18.9%.
H2 allocation totals and live peaks were identical in all pairs.

Ranges below describe individual paired percentage changes. They are not
confidence intervals or pooled percentiles.

| Workload | Requests/s change | CPU/request change | Request p99 change | Peak RSS change |
| --- | ---: | ---: | ---: | ---: |
| H3, concurrency 1 | -16.8% to +71.4% | -41.2% to +13.6% | -17.9% to -1.4% | -1.4% to +0.4% |
| H3, two workers | -26.0% to +53.0% | -18.6% to +12.8% | -66.7% to +150.8% | -1.0% to +1.5% |
| H3, eight workers | -10.1% to +11.2% | -7.8% to +7.8% | -7.5% to +4.7% | -0.6% to +0.6% |
| Firefox H3 | -15.8% to +44.1% | -10.3% to +19.4% | -90.9% to +19.8% | -2.6% to +0.6% |
| H3, 64 KiB streaming | -1.2% to +14.2% | -10.0% to +4.0% | -10.4% to +1.0% | -2.6% to -0.7% |
| Unchanged H2 reference | -7.5% to +8.1% | -17.1% to +3.2% | -21.9% to +20.2% | -3.6% to +2.5% |

Set this prototype aside too. The small allocation saving and mixed timings
do not establish a reliable overall benefit. Whole-process memory did not
improve consistently. Two-worker p95 changes were -48.7%, -75.8% and +57.9%.
The [ordinary results](client-performance-evidence/2026-10-16-h3-coordination/oneshot-timing-summary.json)
retain every measurement, including private memory and worker counters.
The [allocation results](client-performance-evidence/2026-10-16-h3-coordination/oneshot-heap-summary.json)
retain individual heap totals, allocation stacks and profile hashes.

The host remained shared. Observed busy fractions ranged from 34% to 100%
in the notification comparison and 45% to 100% in the cancellation comparison.
Neither comparison establishes a general speed ranking or production limit.
H3's scheduler overhead remains open; changing these channels alone did not
resolve it within this measurement scope.

## Verification and retained evidence

The earlier remediation gate passed all 22 steps, including 5,738 passing tests
and three skips. Touched vendor checks, benchmark Clippy and tests, controller
tests, ShellCheck and the documentation checker passed separately.
The [verification record](client-performance-evidence/2026-10-16-remediation/verification.json)
lists commands, results and log hashes. The
[archive receipt](client-performance-evidence/2026-10-16-remediation/archive.json)
identifies the local archive of raw trials, profiles, binaries and logs.
These are local checks; no remote CI or production-capacity claim follows.

After the timeout-storage change, the full gate passed all 22 steps in
428 seconds: 5,740 tests passed and three were skipped. Benchmark Clippy
and its five tests passed separately. Independent source and evidence review
found no remaining blocker after the cleanup regression and reporting fixes.
The [follow-up verification record](client-performance-evidence/2026-10-16-timeout-storage/verification.json)
retains exact commands and log hashes. Its
[archive receipt](client-performance-evidence/2026-10-16-timeout-storage/archive.json)
identifies the raw trials, rejected prototypes, binaries, symbols and native
build receipts. This follow-up has Windows local checks, without new Linux
or remote CI results.

The H2 selector follow-up passed all 22 gate steps in 404 seconds, including
5,740 passing Rust tests and three skips. Its 50 focused pool tests, five
benchmark Rust tests and nine controller tests passed. Independent source
and evidence review found no blocker to the bounded CPU adoption decision.
The [worker follow-up checks](client-performance-evidence/2026-10-16-worker-contention/verification.json)
retain commands, step results and log hashes. The
[worker archive receipt](client-performance-evidence/2026-10-16-worker-contention/archive.json)
identifies all raw trials, CPU samples, binaries, symbols and build receipts.
Candidate verification was local to Windows. Linux sampling used the
baseline library; no new remote CI result is claimed.

The rejected H3 notification prototype passed 633 focused tests; the rejected
cancellation prototype passed 263. Final source reconciliation confirms that
every tracked Rust file matches the control, with the counter-module
supplement described above. This docs-and-evidence delivery reuses the prior
baseline gate result and runs the docs checker and diff checks separately.
It does not claim a fresh full gate or cross-platform candidate verification.
The [coordination checks](client-performance-evidence/2026-10-16-h3-coordination/verification.json)
retain prototype test counts, source scope and log hashes. The
[coordination archive receipt](client-performance-evidence/2026-10-16-h3-coordination/archive.json)
identifies the checked local archive of raw trials, heap profiles, binaries,
symbols, prototypes and baseline gate logs.

## Remaining investigations

- Attribute the remaining H2 and H3 worker overhead to specific scheduling,
  wakeup and lock paths. The H2 selector change addresses only part of it.
- Repeat bursts and idle intervals across more origins. The earlier 64-origin
  peer aborts remain unresolved and rejected.
- Validate the earlier held response-head pinning experiment on a quieter
  host. Use a separate load generator and downstream traffic before claiming
  production capacity.

## Next

- [Measurement method](client-performance.md): controls and adoption rules.
- [Workload tool](../../tools/client-bench/README.md): repeat the matrix.
- [Performance roadmap](../roadmap.md#phase-4-profiling-and-optimization): remaining scope.
