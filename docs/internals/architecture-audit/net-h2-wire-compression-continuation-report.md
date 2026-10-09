# HTTP/2 wire and compression continuation

Read-only baseline df2ae9b7d87567907a2f273068220349dcd4750b. Three complete files, 1,257 lines, leave 31 paths not completed in this agent's additive inventory. The matching JSON records Git blob and working bytes separately. No test execution or new supported production defect in this pass.

## Peer table-size transitions

`http2/tests/hpack_transitions.rs` lines 1–314: literal SETTINGS cover zero, duplicate zero then 4,096, 65,536 and maximum u32 table sizes. A peer SETTINGS ACK and exact opaque PING ACK form a control-processing barrier before the client sends its first request. The first HPACK block must begin with the independently literal table-size update bytes, including minimum then final size after duplicate settings. A second nonempty block and two complete 204 responses establish continued connection usability. A finish barrier retains the peer until client reuse is checked.

The raw peer has a connection-wide 32-frame ceiling, a 64 KiB frame ceiling and a 64 KiB assembled header-block bound. HEADERS padding and priority offsets are checked and continuation stream/type must match. The second block is not independently decoded or checked for the absence of a repeated size update. Advertising the maximum table size does not assert that this much memory was allocated; source behavior and actual growth bounds remain separate.

## Legal representation and fragmentation matrix

`http2/tests/continuation_matrix.rs` lines 1–431: raw literal, Huffman, incremental indexing and subsequent dynamic index encode informational 103 sections with distinct legal splits, including empty fragments. The final 200 section and body are exact, no informational fields survive in the final header map, and stream 3 successfully returns 204 before peer release. A separate 65,460-byte value uses an independently assembled repeated 28-bit Huffman symbol. Its encoded section spans exactly fourteen 16 KiB frames; every decoded byte and decoded length are asserted under a 65,536-byte decoded budget, followed by reuse.

The peer requires both initial SETTINGS directions and ACK, complete request headers and exact stream IDs. Incoming client frames have a 32-frame, 64 KiB per-frame and 256 KiB total byte bound; checked arithmetic precedes buffering. Continuation type and stream identity are enforced. These are inclusive legal-input controls; malformed sequence rejection is covered in other files. They do not measure decoder allocation or compare fresh browser behavior.

## Exact request wire and typed failures

`http2/tests/request_wire.rs` lines 1–512: public error wrappers expose stable protocol kind, reason and nested backend sources. Actual peer reset and literal GOAWAY preserve stream-reset versus connection-error classification. Response tracing reports one protocol_error. Tests capture literal settings order and Chrome connection-window increment with finite capture frame/byte/deadline limits. Literal request HPACK bytes assert Chrome pseudo-header order, dependency/exclusive bit/weight, interleaved ordinary fields, equal-length raw strings and exact zero content-length in supplied order. A separately decoded semantic URI preserves bracketed IPv6 authority and port.

The raw frame helper in this file allocates up to the 24-bit wire length and has no aggregate frame bound. It reads this implementation's controlled outgoing frames inside a whole-test deadline; the production inbound parser is not this helper. Raw tests intentionally close the peer and require the in-flight transaction to fail after capture. Most peer tasks join on success, while early errors retain runtime teardown ownership. Exact initial HEADERS bytes here do not independently cover the trailing HEADERS sensitivity/order assertion gap recorded in the previous pass.

No prior platform deferral or supported finding is marked complete by these reads.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
