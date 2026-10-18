# Measure the public client

Build the isolated workload tool, then run a repeatable matrix against local
peers. Its dependencies and heap allocator do not affect the library build.

```sh
scripts/dev/with-cargo-lock.sh cargo build \
  --manifest-path tools/client-bench/Cargo.toml --release --locked
uv run --no-project --with psutil==7.2.2 python tools/client-bench/run.py \
  --binary tools/client-bench/target/release/phantom-client-bench \
  --matrix tools/client-bench/matrix.json --output target/client-baseline-01
```

On Windows the executable has an `.exe` suffix. If you set
`CARGO_TARGET_DIR`, use the executable from that directory instead. Build
native dependencies in release mode too. Record any overridden native inputs.

For an MSVC build, set `CMAKE_TOOLCHAIN_FILE` to the absolute path of
`tools/client-bench/msvc.cmake` before building. It keeps native TLS
optimization and symbols when cmake-rs replaces the MSVC configuration flags.
Inspect the effective compiler command for `/O2`, with no later `/Od`
override. A Cargo release label alone does not prove native optimization.
Use a fresh target directory after changing native flags, or confirm that the
native build actually reran before accepting its compiler log.

Runs default to `--measurement-kind diagnostic`. For a timing baseline,
pass `--measurement-kind timing --build-receipt PATH`. That JSON receipt
must record `native_optimization_verified: true`, effective build flags and
native input hashes, plus `binary_sha256` matching the executable. Use
`--measurement-kind profile` for instrumentation and add `--external-profiler`
when a separate sampler is attached. Keep the
receipt beside the retained binary and symbols.

The output directory must be new. Each repetition starts a separate peer and
client process. The seeded order changes within each repetition. A phase
handshake excludes startup, warmup and result serialization from the process
CPU measurements. The controller samples client and peer memory about every
10 ms and retains actual sample times. Outputs include raw per-operation
times, counters, process samples, stderr, source hashes and the binary hash.
RSS peaks are sampled lower bounds. Inspect actual sampling gaps on a loaded
host. Process counters bracket the phase handshake, so controller scheduling
and snapshot delay can widen their interval beyond the client's elapsed time.

The matrix covers TLS H1/H2/H3 reuse and cold clients, concurrency, Chrome and
Firefox profiles, request templates, TCP proxies, multiple origins, large
bodies, gzip decoding and server delays. The default matrix has three
repetitions. Increase repetitions and phase lengths for a decision about a
small difference. Short cold runs have few observations beyond p99.

## Use another client executable

`--binary` owns the independent peer. By default it also runs Phantom.
Pass `--client PATH` to run another adapter against that same peer. The
comparison set is Phantom, wreq, curl_cffi and httpcloak. The wreq and
httpcloak adapters remain separate work; this option alone does not establish
parity.

The descriptor has exactly four fields:

```json
{
  "name": "curl_cffi",
  "version": "0.16.3",
  "command": ["/absolute/python", "/absolute/adapter.py"],
  "artifacts": [
    {"path": "/absolute/python", "sha256": "<64 lowercase hex digits>"},
    {"path": "/absolute/adapter.py", "sha256": "<64 lowercase hex digits>"}
  ]
}
```

List every loaded client input, including shared libraries, wheel archives,
module locks and adapter source. The controller checks the listed files and
command files, then retains their hashes and the complete descriptor. It
cannot discover every dynamically loaded dependency. Use an isolated pinned
environment. The example above needs those additional artifact entries.
Descriptors accept up to 1,024 artifact files, including runtime sources.

The command is an argument array, executed directly without a shell. It must
run the measured client in that process; do not use a shell or child-process
launcher. Runtime and binding overhead remain part of the client result.
The controller appends `run CONFIG READY RESULT`, using absolute paths.
The adapter must follow the existing JSON and stdin/stdout contract:

1. Read the config and peer ready files, then finish unmeasured warmup.
2. Emit `{"event":"ready"}` and wait for `go` on stdin.
3. Finish the measured work, emit `{"event":"phase_end"}`, and wait for `save`.
4. Write the result JSON, emit `{"event":"saved"}`, then exit successfully.

Flush each event. Keep the client and its pool alive through `save`.
Reject unsupported configs before `ready`; never silently change protocols,
routes or workloads. Verify response bytes, protocol and operation counts.
Use the same sample fields and timestamp boundaries as `src/client.rs`.
Client-specific limits and effective settings must accompany each adapter.
Results with invalid numeric fields, changed configuration, duplicate operation
IDs or incorrect successful byte counts fail before measurement summaries.
If the public API cannot expose response-head arrival, set every `head_ns` to
`null` and include `unavailable_timings: {"head_ns": "reason"}` in the result.
The summary retains that reason and leaves head statistics unavailable. Never
substitute a first-body or fully buffered response timestamp for a missing head.

Timing runs need both the peer's existing `--build-receipt` and the adapter's
`--client-build-receipt`. The latter includes `native_optimization_verified`,
the command executable's `binary_sha256` and an `artifact_sha256` map of every
descriptor path to its hash. These are retained build attestations, not an
automatic audit of compiler flags or dependency completeness. Keep compiler
logs and native configuration with them. Diagnostic runs need no build receipt.

## Compare CONNECT overlap

For `route: "connect"`, set `speculative_tls: true` to overlap CONNECT and
origin TLS. The default is false. Set `proxy_delay_ms` to 0–250 to add a
userspace propagation delay in each direction of the client-to-proxy link.
The delay relay queues at most sixteen 16 KiB chunks per direction. Each
chunk receives its deadline when read, preserving order without serializing
a new delay after every previous chunk. It does not model bandwidth, loss,
congestion or a real network stack.

Compare strict and speculative settings with the same binary and delay.
Use `cold: true`, one origin and low concurrency to measure new connections.
Warm pooled requests do not repeat CONNECT. Keep instrumented allocations
separate from ordinary timing. Cold runs include client construction, TLS,
request processing and destruction in phase CPU and throughput.

## Measure request diagnostics

Set `diagnostic_events: 128` to create and snapshot a fresh bounded collector
for each request. Zero, the default, leaves collection disabled. Enabled runs
validate admission and body-completion records. Their timing includes snapshot
copying and verification. Compare both settings with the same binary, seeded
trial order and workload. Keep disabled runs against the previous revision
separate from this enabled/disabled comparison.

Set `diagnostic_snapshot: false` to collect events without copying or checking
a snapshot. The default is true. Compare off, collection only, and collection
plus snapshots to distinguish their costs. Payload, protocol and peer checks
remain enabled in every setting.

## Measure allocations separately

Keep a copy of the uninstrumented executable and its symbols before building
with `--features heap`. Use a small matrix for this slower build. DHAT writes
`client.dhat.json` beside each result. Instrumented timing is diagnostic and
must not be mixed with the uninstrumented baseline.

DHAT starts after client creation, warmup and observation-buffer allocation.
It stops before result serialization. It attributes Rust allocations that
originate in this interval. Existing live allocations and native TLS
allocations are outside that count. Process RSS and private bytes cover a
broader footprint. The fixed observation buffer is included in start RSS and
its size is recorded separately.

## Check scaling and recovery

Use `scalability.json` for a longer H2/H3 sweep: 32, 128 and 192 concurrent
requests, two to eight runtime workers, and planned rates of 10,000 and
40,000 requests/s. `workers` applies to both processes unless `peer_workers`
overrides the peer. Both settings accept 1–16. Use `worker-isolation.json`
to vary each process independently. Inspect their CPU separately before
attributing a throughput plateau to the client.

The raw result includes `runtime_start` and `runtime_end` snapshots. Subtract
each worker's cumulative busy time, parks and park/unpark transitions to inspect
activity during the phase. Busy time includes waits inside a task poll; it is
not process CPU time. Snapshots are sequential reads, not one atomic view.
Queue depth and alive tasks describe the boundaries, not peaks. These stable
[Tokio counters](https://docs.rs/tokio/1.53.1/tokio/runtime/struct.RuntimeMetrics.html)
do not count task polls, steals, OS context switches or lock contention.
Snapshot work is outside `elapsed_ns`, but its CPU and small worker-vector
allocations remain in process and heap measurements. Use the same harness
on both sides of a comparison.

These are exploratory settings, not capacity promises or acceptance targets.
The default per-origin bounds allow 100 active and 100 waiting requests.
Keep a probe beyond those bounds separate from a successful-throughput sweep.

The planned-rate cases retain application wait in scheduled-to-complete
latency. Inspect it alongside request latency and completed throughput. The
fixed worker set limits in-flight requests, so overdue arrivals wait in the
schedule rather than becoming an unbounded queue of tasks.

Pass `--recovery-seconds 180` with a small selected matrix to sample idle
memory after the measured requests. `recovery.json` keeps the client and
connection pool alive. That interval is outside request timing and CPU.
Compare private bytes and RSS with their warm start and phase-end values.
Account for the retained observation buffer and browser idle timers. One
burst and idle interval cannot establish long-term memory stability.
Recovery also checks a peer snapshot before client teardown. It rejects peer
failures and heap-instrumented builds, whose allocation interval would include
idle time. Rebuild the tool before using this option.

The H3 peer records idle retirement separately only after the phase snapshot,
with every expected request complete, both typed transport timeout reasons,
and successful response-task completion. An interrupted request or different
transport error remains a failure. The retirement counter and stderr message
stay in the packet.

## Interpret the measurements

- `head_ns`: request preparation through receipt of the response head.
- `complete_ns`: preparation through EOF and payload verification.
- `build_ns`: profile construction and client build in cold/constructor runs.
- `first_byte_ns`: first data frame for streaming, absent for collection.
- `application_wait_ns`: planned arrival to worker start, outside the client.
- `scheduled_to_complete_ns`: application wait plus complete operation time.

Cold request samples stop before the newly built client's destructor. Phase
throughput and process CPU include that destruction. Construction samples
also record destruction in `complete_ns`. Every byte is checked against the
peer's known payload; this application validation contributes CPU time.

Ordinary cases are closed-loop capacity tests: a worker starts another
request after the previous one completes. Planned-arrival cases assign fixed
time slots to a fixed set of workers. They retain lateness when workers fall
behind, without allocating a task for every queued arrival. Windows timers
can deliver slots in bursts. This is a finite scheduled workload, not a
guarantee of evenly spaced packets or an application queue memory benchmark.

The tool keeps browser defaults, exact protocols and certificate checks.
It never follows a protocol fallback. A run fails if requests fail, payloads
or protocols differ, peer request totals differ, or route controls fail.
Warmup and measured requests must reconcile with the peer before teardown.
Expected teardown behavior remains in the separate final peer log/counters.

Connection setup and internal pool admission are included in head latency.
This harness cannot split them with public timestamps. It does not claim
browser parity, Internet performance or a client-only throughput ceiling:
the peer, loopback stack, runtime and host can limit the workload too.

Summarize an uninstrumented matrix with independent trial medians and ranges:

```sh
python tools/client-bench/report.py target/client-baseline-01 \
  target/client-baseline-report-01
```

`--keep-going` on the controller retains failures and finishes the matrix,
then exits unsuccessfully if any trial failed. The report lists rejected
trials separately and refuses allocation-profiler timings.
An operation is a client build in construction cases and a completed request
in the other cases.

## Next

- [Run the curl_cffi adapter](curl-cffi.md).
- [Transport benchmarks](../../crates/phantom-net/benches/transport.rs).
