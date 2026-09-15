# Performance work

Phantom benchmarks complete public transport paths. They do not expose private
parser or TLS-backend functions solely to make microbenchmarks easier.

Run the deterministic local suite with the pinned development toolchain:

```sh
cargo +1.98.0 bench --locked -p phantom-net --bench transport -- --noplot
```

Record the OS, CPU, Rust version, power mode, and commit with any result. Compare
only runs from the same quiet machine. Criterion stores local samples under
`target/criterion`; a local before-and-after comparison can use
`--save-baseline before` and then `--baseline before`.

The scheduled GitHub Actions run is report-only. Hosted-runner measurements are
retained for inspection but never enforce a regression threshold or compare
results across runner images.

## Runtime tracing

The library emits `debug` spans and events but never installs a subscriber.
TLS handshake and HTTP response-head spans expose bounded protocol outcomes;
the streaming body emits one terminal event with its DATA byte count and a
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
and after the change. TLS handshake measurement is deferred until Phantom has a
production trust-policy seam suitable for a deterministic local server.
