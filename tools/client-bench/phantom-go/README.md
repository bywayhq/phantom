# Run the public Go binding adapter

Build with Go 1.26 and the matching native `phantom-go` library. Use the binding's
[loader instructions](../../../bindings/go/README.md#build-and-limits). From this
directory, build the executable with `go build -mod=readonly -trimpath` and give
it to the [existing controller](../README.md#use-another-client-executable).
The descriptor must retain the executable, native library, module and binding
sources with their hashes. Timing runs also require the controller's build
receipts and effective native compiler flags.

This adapter covers direct verified HTTPS GETs over exact H1, H2 and H3, warm
or cold clients, collection or 64 KiB reads, multiple origins and planned
arrivals. It uses Chrome 154 Windows settings with raw headers, no cookies,
a five-second connect limit and a fifteen-second core total deadline.
The native runtime has two workers; Go `GOMAXPROCS` is also two. These are
separate schedulers, not a two-thread process limit.

The adapter verifies status, actual protocol and response metadata, length and
every `Z` byte. Head timing ends when `Do` returns. Streaming first-byte timing
ends on the first nonempty application read. Collection has no first-byte time.
Completion includes payload verification; body and cold-client cleanup
then remain inside phase elapsed time and CPU. The shared client stays alive
until `save`. Observation storage excludes allocator slack and later objects.

The binding's current process-wide capacity remains in effect, including 64
clients, response handles and ordinary operations. Capacity errors remain
errors, with no adapter retry or admission queue. Cold operations also create
and close their own client. Known-length POST uploads use a reusable source
chunk of at most 64 KiB. GET body-prefix cancellation closes the public body.
Upload-stage cancellation, proxies, templates, redirects, compression and
diagnostics are rejected before warmup. Runtime and
protocol acceptance must be established with the retained native build; source
compilation alone does not establish successful peer runs or performance.

## Next

- [Interpret measurements](../README.md#interpret-the-measurements).
