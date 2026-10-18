# Run the httpcloak adapter

Build this separate Go executable with Go 1.26 or later. It pins
`github.com/sardanioss/httpcloak v1.7.3` and its resolved `go.sum`.
Build in the integration checkout when other lanes are active:

```sh
cd tools/client-bench/httpcloak
GOTOOLCHAIN=local go build -mod=readonly -trimpath -o /absolute/path/httpcloak-bench .
```

CI checks this adapter on Linux, macOS and Windows with Go 1.26.5 and
`CGO_ENABLED=0`. These checks cover construction, TLS trust, headers and
HTTP/1.1 and HTTP/2 exchanges. Controlled peer runs cover HTTP/3 separately.

Supply the binary in a pinned descriptor to the
[comparison controller](../README.md#use-another-client-executable).
Retain source, module files, `go version`, `go env`, `go version -m BINARY`,
the build command and binary hash. Do not use race or debug builds for timings.

The adapter supports direct HTTPS GETs and bounded in-memory POST uploads over
exact HTTP/1.1, HTTP/2 or HTTP/3.
Cold and shared clients, streaming and collection, multiple loopback origins,
and planned arrivals use the controller's existing workload contract.
`workers` sets `GOMAXPROCS`, not a fixed number of operating-system threads.
At most `concurrency` application goroutines issue requests at once.

## Settings and timing

- Recipe: httpcloak's `chrome-150-windows` through its public session API.
- Trust: only the peer root, with certificate and hostname checks.
- Routing: IPv4 loopback source and destination, with proxies disabled.
- Deadline: 15 seconds from request start through body consumption.
- Replay: caller-enabled retries and redirect following disabled.
- Pools and connect timeout: library defaults, within the total deadline.

The HTTP/1.1 streaming API opens a connection for each request and closes it
with the response. This applies to both consumption modes here. `cold: false`
reuses the Session, but does not establish warm HTTP/1.1 connection reuse.

`template: false` selects TLS-only mode and disables automatic client hints.
`template: true` keeps navigation headers. Cookies, conditional caching and
high-entropy client hints are disabled in both modes. Compression, other
profiles, proxy routes and Phantom diagnostics fail before warmup. An
uncompressed peer response requires no decompression work.

Head timing ends when `GetStream` returns. First-byte timing ends on the first
nonempty application read. Collection uses `io.ReadAll` and has no first-byte
timing. Both modes verify every byte and read through EOF. Completion includes
payload verification. Response and cold-client cleanup follow successful
completion, within phase elapsed time and CPU. Cleanup errors retain request
errors and reject the operation. Failures before a head retain a null timing.

The fixed sample buffer is allocated before measurement. Its reported storage
excludes allocator slack, goroutine state and later timestamp/error allocations.
Process memory includes the Go runtime, transports, pools and observation work.

Recipe versions, headers, scheduler behavior and default pool limits differ
between libraries. Functional acceptance does not establish equivalent
fingerprints, performance or connection limits. Streaming uploads, redirects, proxy
authentication and cancellation need additional workloads.

## Next

- [Interpret measurements](../README.md#interpret-the-measurements).
