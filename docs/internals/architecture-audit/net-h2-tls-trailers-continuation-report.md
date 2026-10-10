# HTTP/2 TLS and trailer tests

Baseline df2ae9b7d87567907a2f273068220349dcd4750b, read-only. Three complete files, 1,163 lines, leave 34 paths not completed in this agent's additive inventory. The JSON distinguishes exact Git blob and working bytes. No runtime checks were executed and no new supported production defect was established.

## Requested TLS key update

`http2/tls/tests/key_update.rs` lines 1–301: a real TLS 1.3 BTLS server sends exactly one requested KeyUpdate while the first response body remains open. A literal H2 PING requires client processing before the remaining response bytes are sent. The server callback counts exact written requested and read non-requested handshake messages, as well as total type-24 messages; all four counters must be one. Client receives the exact concatenated body and reuses stream 3 for the follow-up. This checks TLS processing and composed H2 survival, not a browser differential.

The peer validates preface, SETTINGS shape, continuation stream identity and literal PING ACK. A frame is capped at 64 KiB and most probe loops at 128 frames; the continuation loop has no independent frame-count ceiling. Loopback TCP port zero avoids the UDP reserved-port issue. Each blocking socket read/write has TEST_TIMEOUT. The asynchronous test has an outer deadline, but spawn_blocking cannot be aborted by dropping its JoinHandle. Successful runs join it; early-error cleanup relies on socket timeout and runtime ownership. No explicit cancellation/join assertion establishes that failure path here.

## Fragmented encrypted records

`http2/tls/tests/record_shape.rs` lines 1–342: a rustls peer caps TLS fragments at 1,024 bytes. Actual bytes successfully written to the socket are recorded with a 256 KiB retention limit and an explicit overflow flag. The parser verifies complete five-byte headers and payload lengths and checks record boundaries before and after the first response. More than one type-23 record must be observed, every payload fits the configured 1,036-byte encrypted bound and at least one reaches it. The client receives the full deterministic body and exact follow-up body on streams 1 and 3.

This is server-record fragmentation compatibility, not evidence that Phantom emits a matching browser TLS record shape. Record parsing has checked length arithmetic. Frame parsing and outer loops have the same finite caps as the key-update helper, while continuation reads rely on per-operation socket timeout. The server task is joined on success but has no uniform early-failure abort/join guard. Capture overflow cannot silently pass because the final test explicitly rejects it.

## Trailer validation and stream-local failures

`http2/tests/request_trailers.rs` lines 1–520: static trailer-only, owned and streaming requests deliver exact body data, expected generated content-length and duplicate trailer values. Dynamic body trailers follow data and require a declared plan. Undeclared or mismatched dynamic trailers yield their distinct typed request-body error; the peer observes CANCEL reset and successfully accepts a later request on the same connection. Invalid declaration names and conflicting static/dynamic plans fail before opening a request; the only peer-accepted request is the subsequent valid follow-up. Metadata without a trailer plan is rejected by the validation seam.

The peer polls both body and connection, so payload/trailer progress does not depend on a detached hidden driver. The whole exchange is bounded by bounded_peer_test. Spawned peer handles are joined on success; early errors leave per-test runtime cleanup as the task owner.

### Precise assertion gap

The test named `body_produced_trailers_follow_the_declared_order_and_sensitivity` supplies a sensitive x-middle field and declares x-repeat / x-middle / x-repeat. The peer assertions at lines 385–398 check only the two x-repeat values in their same-name order and x-middle's content. They assert neither global interleaving nor sensitivity/never-indexed encoding. The static trailer peer makes the same narrower value observations. This is a test-claim/coverage gap, not proof that production encoding is wrong. A meaningful stronger control would inspect the raw trailing HEADERS/CONTINUATION HPACK block, prove literal global field order and never-indexed representation, and retain the semantic body/reuse assertions. Alternatively, the test name can describe only what it asserts. Other wire tests may cover part of that contract and must be checked before adding redundant controls.

No earlier supported defect or platform deferral is disposed by these reads.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
