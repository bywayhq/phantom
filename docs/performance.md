# Performance work

Phantom benchmarks TLS connector construction and public HTTP/1.1 and HTTP/2
request paths over deterministic in-memory replay transports. They do not
expose private parser or TLS-backend functions solely to make microbenchmarks
easier, and they do not currently measure a TLS handshake or network
end-to-end request.

Run the deterministic local suite with the pinned development toolchain:

```sh
cargo +1.98.0 bench --locked -p phantom-net --bench transport -- --noplot
```

Run only the HTTP/2 response-head or streaming-body workload with Criterion's
name filter:

```sh
cargo +1.98.0 bench --locked -p phantom-net --bench transport -- 'http2/response_head' --noplot
cargo +1.98.0 bench --locked -p phantom-net --bench transport -- 'http2/streaming_body/65536' --noplot
```

The response-head benchmark includes validation, Chromium-profile translation,
ordered request-header encoding, HTTP/2 protocol setup (the connection preface
and startup frames over the replay transport), response HPACK decoding, and
one-shot connection shutdown. The body benchmark additionally streams four
16 KiB DATA frames through the public response body and reports throughput for
the 64 KiB payload. Each HTTP/2 iteration separately waits for the connection
driver to drop its dedicated replay transport and for the final driver span to
close with a `complete` outcome. The final span close follows the bounded
shutdown supervisor, so neither transport nor supervisor work can overlap the
next sample. Criterion's batched setup constructs the cloned inputs, replay
state, and completion observers outside the timed routine.
The timed HTTP/2 routine includes default-dispatch switching and the minimal
mutex-backed driver-span lifecycle observation used to prove clean supervisor
completion, so these are not tracing-disabled transport measurements.

All HTTP/1 and HTTP/2 response microbenchmarks use a deterministic in-memory
replay stream, so they include neither TCP nor TLS costs. HTTP/1 releases its
response after the first request write; HTTP/2 waits through the connection
preface and startup frames until the first request byte. The TLS connector
benchmark measures connector construction, not a TLS handshake.

Record the OS, CPU, Rust version, power mode, and commit with any result. Compare
only runs from the same quiet machine. Criterion stores local samples under
`target/criterion`; a local before-and-after comparison can use
`--save-baseline before` and then `--baseline before`.

The scheduled GitHub Actions run is report-only. Hosted-runner measurements are
retained for inspection but never enforce a regression threshold or compare
results across runner images.

## Runtime tracing

The library emits `debug` spans and events but never installs a subscriber.
TLS connector-build and handshake spans expose bounded outcomes and static
error classes; HTTP response-head spans expose bounded protocol outcomes. The
streaming body emits one terminal event with its DATA byte count and a
`complete`, `protocol_error`, or `dropped` outcome. Endpoint names, request
targets, headers, bodies, and certificates are not recorded.

## Profiling

First build the optimized benchmark with symbols:

```sh
cargo +1.98.0 bench --locked -p phantom-net --bench transport --no-run
```

Cargo prints the benchmark executable path. Assign that path to `bench_bin` in
the commands below. A benchmark executable invoked directly needs `--bench` to
select Criterion's benchmark mode. `--profile-time` then repeatedly exercises
one exact workload without performing statistical analysis.

Create the output directory once before capturing a profile:

```sh
mkdir -p target/profiles
```

On macOS, start the benchmark normally and attach Instruments by PID. Keeping
launch and recording separate avoids Instruments changing Criterion's launch
environment. Use a longer Criterion duration than the trace window so the
process remains alive while Instruments attaches:

```sh
bench_bin='target/release/deps/transport-<hash>'
profile_workload=http2/response_head/12_ordered_headers
"$bench_bin" --bench "$profile_workload" --exact --profile-time 30 --noplot &
profile_pid=$!
xcrun xctrace record --quiet --no-prompt --template 'Time Profiler' \
  --time-limit 10s --output target/profiles/http2-response-head.trace \
  --attach "$profile_pid"
wait "$profile_pid"
```

For an allocation trace, repeat the same start-and-attach sequence with the
`Allocations` template and a distinct output path. On Linux, capture CPU samples
with `perf` or allocations with Heaptrack:

```sh
perf record -g --call-graph dwarf -o target/profiles/http2-response-head.data \
  -- "$bench_bin" --bench "$profile_workload" --exact --profile-time 20 --noplot
perf report -i target/profiles/http2-response-head.data
heaptrack "$bench_bin" --bench "$profile_workload" --exact --profile-time 20 --noplot
heaptrack --analyze <heaptrack-output>
```

Optimize only a repeatable hotspot, then rerun the identical workload before
and after the change. TLS-handshake and network end-to-end benchmarks remain
deferred until they have controlled trust roots and a reproducible server and
network setup.

## Phase 3 local profile

The Phase 3 closing pass ran on 2026-09-15 at commit `0d2f733` on an Apple M4
running macOS 15.5 (24F74), Rust 1.98.0, AC power, and low-power mode disabled.
These numbers are local evidence, not portable thresholds.

The first response-head Time Profiler trace contained 9,993 samples, 99.9% of
which were under benchmark-only subscriber construction. Criterion excludes
batched setup from its timing, but an external sampler observes the whole
process. Reusing one subscriber while retaining a distinct completion signal
for every driver span removed that artifact. The corrected trace contained
8,017 samples and exposed request preparation, HTTP/2 framing and HPACK, and
connection teardown rather than callsite-cache rebuilding.

The corrected response-head baseline was 9.1728–9.2014 microseconds. Reusing
the validated origin-form path/query instead of formatting and reparsing it,
and retaining one ordered header vector instead of a redundant semantic copy,
reduced the identical workload to 8.9322–8.9582 microseconds, a 2.63% change at
the interval midpoints. Request preparation fell from 20.64% to 18.59% of
inclusive CPU samples in matched 8,017- and 8,014-sample traces.

The 64 KiB streaming workload remained unchanged within noise: 11.210–11.283
microseconds before and 11.152–11.205 microseconds after. In its 7,223-sample
CPU trace, `memmove` accounted for 48.27% of leaf samples and
`http_body_util::Collected::to_bytes` for 33.22% of inclusive samples. The
benchmark consumer combines four yielded chunks into one contiguous buffer;
that is not a Phantom body-copy path, so the pass made no transport change for
it.
