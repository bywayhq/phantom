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

Cargo prints the benchmark executable path. Substitute it for `<bench-bin>` in
the commands below. Criterion's profile mode repeatedly exercises one workload
without performing its statistical analysis.

Create the output directory once before capturing a profile:

```sh
mkdir -p target/profiles
```

On macOS, capture CPU time or allocations with Instruments:

```sh
xcrun xctrace record --template 'Time Profiler' --output target/profiles/http1.trace --launch -- <bench-bin> 'http1/content_length/65536' --profile-time 20 --noplot
xcrun xctrace record --template 'Allocations' --output target/profiles/http1-allocations.trace --launch -- <bench-bin> 'http1/content_length/65536' --profile-time 20 --noplot
```

On Linux, capture CPU samples with `perf` or allocations with Heaptrack:

```sh
perf record -g --call-graph dwarf -o target/profiles/http1.data -- <bench-bin> 'http1/content_length/65536' --profile-time 20 --noplot
perf report -i target/profiles/http1.data
heaptrack <bench-bin> 'http1/content_length/65536' --profile-time 20 --noplot
heaptrack --analyze <heaptrack-output>
```

Optimize only a repeatable hotspot, then rerun the identical workload before
and after the change. TLS-handshake and network end-to-end benchmarks remain
deferred until they have controlled trust roots and a reproducible server and
network setup.
