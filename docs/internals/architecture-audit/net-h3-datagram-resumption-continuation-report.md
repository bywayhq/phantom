# HTTP/3 lifecycle and resumption tests

Read-only baseline df2ae9b7d87567907a2f273068220349dcd4750b. Two newly complete files plus completion of the parent tests file: 1,457 newly read lines. The completed files total 1,568 lines; parent lines 614–724 were already reviewed. The inventory now has 21 paths not completed in this agent's reports. Exact Git blob and working bytes are separate in JSON. No tests were executed or production defect newly confirmed.

## Parent controls and helpers

`http3/tests.rs` newly read lines 1–613, prior read 614–724: a runtime without I/O returns RuntimeUnavailable. Invalid scheme/extension requests return the Request category, though the chosen unused destination alone does not independently observe zero network work; the production validation path was traced earlier. Actual peers establish certificate trust/name failure, streaming two gated DATA chunks then trailers then EOF, a profiled completed request, and body abandonment with peer-observed H3_REQUEST_CANCELLED. Each main network phase/body frame/join uses TEST_TIMEOUT. Server handles are joined or aborted on success; early errors lack a universal explicit task abort guard.

Qlog controls require nonempty output within the chosen byte limit, completion after endpoint/request ownership ends, safe reuse refusal with typed AlreadyAttached source and absence of a chosen request-header secret. The helper assert_complete_json_seq at lines 575–592 checks record separators, newlines and enclosing braces, not full JSON syntax. This is a syntax-oracle coverage limit, not evidence of malformed production output. The loopback bind-address test is literal for v4/v6 and public destinations. The IPv6 request test skips on any failed probe bind, so environmental availability is conditional rather than universal coverage.

## Datagram violation ownership

`http3/tests/datagram.rs` lines 1–314: a real QUIC/H3 peer accepts two named request streams, emits an unexpected datagram only for one and completes the sibling; a later request on the same connection succeeds. The affected body yields a Protocol error. A second test registers a pending body-frame waker, cancels that receive future, waits until exact data is queued, then releases the bad datagram. Peer observes H3_DATAGRAM_ERROR while consumer retains the already queued DATA and then receives the typed error. A pre-response datagram yields a request error and the same peer cancellation code.

The queued-data control uses explicit Notify/oneshot barriers rather than sleep to assume delivery; only the final shutdown-grace observation adds a delay. The first isolation test has no explicit overall timeout for setup, head barrier, body reads or later request, though final server join is bounded. The two other tests bound principal phases. Peer tasks join on success and otherwise rely on runtime teardown. These controls isolate an unexpected datagram on an ordinary GET; they do not validate all CONNECT-UDP context or queue limits.

## Session resumption and wire comparisons

`http3/tests/resumption.rs` lines 1–530: a first connection is fresh and a second using its learned origin/cache resumes. Separately isolated clones do not share tickets with each other or the base connector, while transport compatibility allows the base to reuse a connection from an isolated clone. This proves the cache isolation seam; actual route-entry selection belongs to facade tests. Ticket wait and connect are timed. The minimal server emits SETTINGS before tickets are considered usable and holds QUIC connections. Its listener task is aborted without joining the separately spawned child connection tasks; runtime teardown retains those children.

Fresh-record comparison generates a resumed ClientHello and requires PSK last while non-early tickets omit early_data. A second test learns early-data-capable tickets and compares the generated handshake with at least three resumed frozen captures per Chromium-family recipe. Stable vectors, ALPN, ALPS/PSK-mode/early-data payloads and transport parameter shapes are exact. Trust anchors compare as sets, while random GREASE/version ordering/connection IDs and measured RTT use explicit shape normalization. RTT must be positive and minimally encoded. Parameter parsing checks vector bounds and full consumption; version helper silently ignores a non-four-byte suffix, appropriate only to known generated/captured input here and not a general malformed-peer parser.

The generated-session comparison calls the real provider start_session seam but is not itself a completed resumed network request or live browser acceptance experiment. Isolated clone reuse and direct connection controls compose the narrower contracts. Existing startup error/CID and cache work-bound remedies remain separately tracked and are not revalidated by reading these tests.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
