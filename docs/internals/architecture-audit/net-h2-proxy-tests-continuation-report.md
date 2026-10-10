# HTTP/2 proxy test continuation

Baseline: df2ae9b7d87567907a2f273068220349dcd4750b. This is a read-only source review, with no test execution. The matching JSON records exact Git blob and working-file byte hashes separately. Three complete files, 1,557 lines, leave 43 paths not completed in this agent's additive reports. No new supported production defect was found in this pass.

## Pool ownership and independent observations

`proxy/tests/http2_pool.rs` lines 1–740: literal TLS/H2 peer frames verify Chrome stream IDs 1/3/5 and Firefox IDs 3/5/7, multiplexing across origins, a single TLS setup for concurrent calls, admission after RST, configured connection limits, and the public ceiling clamp. A rejected tunnel releases admission without a new TCP dial. Route eviction preserves an active duplex tunnel while reopening the evicted route requires another accepted connection. Separate credentials and H2 settings result in separate connections. GOAWAY preserves an accepted older tunnel while subsequent work obtains a new connection. A shared-session 407 retry leaves the first tunnel usable.

Tests poll a queued opening once, prove it remains pending, drop an earlier tunnel, then observe RST before the next HEADERS. Pool backpressure therefore has a peer-observed transition rather than merely checking internal counters. The concurrent failed TLS setup test checks shared typed failure and a finite 300 ms period without another accepted connection. It does not schedule a distinct later failed attempt before polling an old waiter; the already supported overwritten-failure finding remains separate.

At lines 482–488, the route-eviction peer drops spawned connection-task handles. Aborting the listener at line 515 does not join those children. Per-test runtime teardown owns their ultimate cleanup. This is a limitation of test failure-path ownership proof, not evidence of a production detached-task defect. Quiet accept windows establish finite observation only.

## Raw peer responsibilities

`proxy/tests/http2_raw_proxy.rs` lines 1–248: independently constructs SETTINGS, status and Basic challenge HPACK blocks, DATA, RST and GOAWAY. It compares the connection preface, parses the nine-byte frame header and 24-bit payload length, masks the reserved stream bit and acknowledges SETTINGS. Disconnect handling accepts Windows ConnectionAborted alongside reset/broken-pipe and EOF. `read_to_end` is explicitly timed; predicate-based reads inherit caller deadlines.

The helper retains frames and does not enforce a general total frame/buffer bound. It consumes the implementation's outgoing traffic in trusted tests; this is not a public malformed-peer parser. Partial EOF is treated as connection closure. The review does not claim complete adversarial decoder coverage from this helper.

## CONNECT validation, cancellation and backpressure

`proxy/tests/http2_connect.rs` lines 1–569: peers verify that missing or HTTP/1 ALPN yields UnsupportedProtocol without an H2 preface. Invalid H2 settings, forwarding protocol and connection-specific headers fail before an observed accept. The ordinary CONNECT request has only method and authority pseudo-fields, the ordered regular fields, and no END_STREAM; literal HPACK representation indexes and frame bytes are examined.

A peer with a 1,024-byte receive window withholds capacity while the client writes 16 KiB. The write times out with no more than the window accepted, then a controlled capacity release allows the exact remaining payload. Dropping one tunnel yields peer CANCEL while another tunnel still exchanges data on the same driver. Typed 403 and repeated 407 paths distinguish authentication failure and preserve the expected one-connection retry.

The HPACK helper checks representation order, not a complete independent decoder. Its arithmetic assumes client-generated blocks and may panic on arbitrary malformed helper input; that is not a production recoverable-input contract. Driver abort/join is not guarded uniformly on early test failure. At line 340, timing out while awaiting a driver drops its handle rather than aborting it, leaving runtime teardown responsible. No emitted-packet, memory-allocation or live proxy compatibility claim follows from these source assertions.

## Remaining scope

The inventory still includes 43 paths, mostly request, TLS, early-data and malformed-input tests. Previously deferred platform limitations and already supported defects retain their prior status. Production H2 ownership paths were read in earlier passes and are not counted again here.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
