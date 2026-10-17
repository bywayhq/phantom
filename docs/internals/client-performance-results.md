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
protocols. The peer changes worker count too. This establishes a repeated
workload regression, not its cause. Profile client and peer contention before
changing the runtime or connection pool.

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

## Verification and retained evidence

The full integration gate passed all 22 steps, including 5,738 passing tests
and three skips. Touched vendor checks, benchmark Clippy and tests, controller
tests, ShellCheck and the documentation checker passed separately.
The [verification record](client-performance-evidence/2026-10-16-remediation/verification.json)
lists commands, results and log hashes. The
[archive receipt](client-performance-evidence/2026-10-16-remediation/archive.json)
identifies the local archive of raw trials, profiles, binaries and logs.
These are local checks; no remote CI or production-capacity claim follows.

## Remaining investigations

- Separate client and peer worker counts, then profile the slower settings.
- Repeat bursts and idle intervals across more origins. The earlier 64-origin
  peer aborts remain unresolved and rejected.
- Validate the held allocation experiment on a quieter host. Use a separate
  load generator and downstream traffic before claiming production capacity.

## Next

- [Measurement method](client-performance.md): controls and adoption rules.
- [Workload tool](../../tools/client-bench/README.md): repeat the matrix.
- [Performance roadmap](../roadmap.md#phase-4-profiling-and-optimization): remaining scope.
