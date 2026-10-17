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

- [Method and decisions](../../docs/internals/client-performance.md).
- [Transport benchmarks](../../crates/phantom-net/benches/transport.rs).
