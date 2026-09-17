# Adversarial differential testing

Passive wire parity is necessary but incomplete. A peer can distinguish client
stacks by sending valid but unusual protocol sequences and observing the
client's ordered reactions. Server-driven TLS fingerprinting has been
demonstrated experimentally; Phantom therefore tests both what it sends first
and how its state machines react.

This is not a license to copy unsafe behavior. The suite has two lanes:

- **Valid but unusual traffic** is a browser-parity differential. A claim about
  Chrome, Firefox, Safari, or another stack requires a retained run from that
  exact client, version, and platform.
- **Malformed traffic** is a bounded robustness and error-taxonomy test. It is
  not a parity requirement unless a safe, externally observable browser quirk
  is separately captured.

## Observable outcome

Each concrete peer fixture records only the behavior needed for comparison:

- request and body bytes received by the peer;
- response, event, or typed error delivered to the caller;
- protocol alerts and control frames sent by the client;
- whether a stream or connection remains reusable;
- whether a retry or new connection occurs; and
- bounded byte, task, connection, and deadline counters.

Ordered actions are compared; wall-clock nanoseconds are not. Payloads,
credentials, key material, and proxy secrets never enter ordinary logs or
fixtures.

## Ranked transport corpus

| Priority | Protocol | Peer stimulus | Required proof |
| --- | --- | --- | --- |
| P0 | TLS 1.3 | `KeyUpdate(update_requested)` between application records | Body continuity, receive-key update, bounded outbound response; exact batching only after a browser capture |
| P0 | TLS 1.3 | Several `NewSessionTicket` messages around fragmented response records | HTTP bytes remain isolated from post-handshake messages; a bounded second connection observes resumption policy |
| P0 | H1 | Chained `100`, `103`, and unknown 1xx responses under one-byte reads | Only the final response reaches the transaction result; no header leakage or duplicate body write |
| P0 | H1 | Chunk extensions, trailers, ambiguous framing, truncation, and surplus bytes | Correct streaming/trailers for valid input; typed failure and no reuse for ambiguous input |
| P0 | H2 | Interleaved `PING`, SETTINGS update, unknown frame, duplicate setting, and response DATA | Required ACKs for valid input; `PROTOCOL_ERROR` without retry churn for duplicates; continued body progress without parser desynchronization |
| P0 | H2 | Slow consumer across several flow-control windows | Credit tracks consumed bytes, memory stays bounded, and the response completes |
| P0 | H2 | Trailers plus `RST_STREAM(NO_ERROR)`, GOAWAY, and reset races | Trailers and accepted data survive; new work is not placed on a draining connection |
| P1 | QUIC | Retry, duplicate or late Retry, and Version Negotiation variants | At most one valid Retry is processed; spoofed or invalid negotiation cannot loop or downgrade |
| P1 | H3 | Missing or duplicate SETTINGS, forbidden frame placement, and unknown frames/streams | Correct H3 close code for violations; bounded draining and continuation for valid extensions |
| P1 | H3/ALPS | Absent, empty, malformed, forbidden, repeated, or conflicting application settings | Preserve negotiation state; fail invalid payloads before H3 streams; accept compatible first wire SETTINGS and reject late, reduced, or conflicting values |
| P1 | H3/QPACK | Blocked field section followed by insertion, cancellation, or critical-stream failure | Flow control remains accounted, cancellation is stream-scoped, and critical-stream errors close deterministically |
| P1 | H3 | Descending/increasing GOAWAY and response `103`/trailers/reset races | Draining semantics, `H3_ID_ERROR` for an increase, and response continuity match retained client behavior |
| P1 | H3 | Reuse before and after the peer idle timeout, including a silently expired path | Stale connections are evicted, one bounded replacement attempt succeeds when eligible, and forced H3 never falls back to TCP |

The current deterministic baseline includes HTTP CONNECT fragmentation,
informational-response bounds, arbitrary final 2xx, non-2xx rejection,
coalesced tunnel-byte preservation, oversized-head rejection, cancellation,
and proof that proxy failure does not open a direct socket. SOCKS5 coverage
includes exact remote-DNS `DOMAIN` and local-DNS `IPV4`/`IPV6` targets,
ordered address fallback, fragmented IPv4/IPv6/domain replies, malformed and
rejected replies, cancellation, missing-runtime behavior,
route-aware H2 tunnel reuse, WSS routing, and the same no-direct-fallback
proof. It also includes
H1 `100 Continue`, chained `103`/`100`, legal chunk extensions fragmented at
syntax boundaries, declared-length surplus isolation, H2 `RST_STREAM`, H2
`GOAWAY`, and a Reaper-derived valid H2 sequence combining an unknown setting,
unknown frame, exact PING acknowledgement, fragmented HPACK with an empty
`CONTINUATION`, response DATA, and a same-connection follow-up. A separate H2
sequence covers repeated `103`, `102`, final headers, DATA, trailers, and
same-connection reuse without leaking interim fields. It also covers
Reaper's current legal HPACK equivalence matrix: four `103` blocks using raw,
Huffman, incremental, and dynamic-indexed representations, followed by final
`200` headers, with exact empty and non-empty `CONTINUATION` splits and stream
3 reuse. Coverage also includes H3 missing or duplicate SETTINGS, forbidden
control-stream frames,
reserved streams and frames, increasing GOAWAY rejection with `H3_ID_ERROR`,
blocked inbound QPACK release and decoder acknowledgement, peer encoder-stream
closure with `H3_CLOSED_CRITICAL_STREAM`, one valid QUIC Retry, chained
informational responses through final DATA and trailers, rejection of HTTP/3
`101`, and peer-observed request-stream cancellation. H3 ALPS coverage retains
the authenticated absent/empty/nonempty states, rejects malformed or forbidden
payloads before stream startup, applies peer QPACK limits before a request, and
accepts a compatible first wire SETTINGS while rejecting late frames,
reductions, and conflicts. The remaining H3 cases
extend that focused loopback peer rather than introducing a speculative
universal peer framework.

Reaper is a reference corpus, not a runtime dependency. Its production lane is
mirrored as bounded Phantom-owned fixtures only when the stimulus is valid and
the client reaction is directly observed. Its malformed lane uses a fresh
connection per case and asserts protocol error codes without treating malformed
behavior as a browser-parity target. Reaper's current H3 Retry, reserved
extension, QPACK block/unblock, informational response, and trailer probes
overlap existing Phantom fixtures. Its isolated malformed H2 matrix is also
retained with exact `PROTOCOL_ERROR`, `FRAME_SIZE_ERROR`, and
`COMPRESSION_ERROR` reactions. A TLS 1.3 P-384 peer authenticates
HelloRetryRequest and retains both ClientHellos to check the permitted session,
cipher, extension-order, and key-share delta. Requested `KeyUpdate` and the
client's exact non-requested response are authenticated through BoringSSL's
message callback while an open response body crosses the key change and stream
3 proves same-connection reuse. Reaper's TLS 1.3 record-shaping recipe is
retained with its 1024-byte rustls fragment bound: the fixture checks the
derived 1036-byte ciphertext-payload ceiling, reconstructs the exact 8 KiB
response, and proves stream 3 reuse. Reaper's zero-only and ordered `0 → 4096`
header-table recipes are also retained as bounded raw peers. They require the
SETTINGS and exact PING acknowledgements, reassemble HEADERS/CONTINUATION, prove
streams 1 and 3 share a connection, and assert the required HPACK prefixes.
Its current request-flow-control recipe is retained against Phantom's real H2
request path: a 70,000-byte POST exhausts the initial stream and connection
windows independently, advances only after the corresponding credits, retains
the observed DATA-frame sequence, and then proves same-connection reuse. Upload
cancellation is separately stream-scoped and leaves a sibling stream usable.
An early final response with no remaining upload credit is raced against the
upload, surfaced immediately, and followed by a request on the same connection.

The retained 2026-09-16 Reaper snapshot has 21 active, non-passive probes.
Phantom has production-path regressions for the raw-client transport behavior
exercised by all 21. This is stimulus and reaction coverage, not a claim that
every fixture is byte-identical or that Phantom implements browser renderer
side effects. The
[machine-checked mapping](../fixtures/adversarial/reaper/2026-09-16/coverage.json)
records the source-manifest digest and exact Rust test names. CI validates that
local inventory with:

```console
python scripts/capture/reaper_coverage.py check \
  fixtures/adversarial/reaper/2026-09-16/coverage.json
```

When the matching Reaper source tree is available, audit its manifest directly:

```console
python scripts/capture/reaper_coverage.py check \
  fixtures/adversarial/reaper/2026-09-16/coverage.json \
  --source-manifest ../reaper/harness/manifest.json
```

The direct audit checks the byte-exact digest and reports added, removed, or
reordered active probes after a deliberate digest refresh. A changed manifest
requires a source review and new Phantom regressions before updating the
snapshot; it is never accepted by changing the digest alone.

The repository-only CI gate detects missing or renamed Phantom regressions; it
does not discover changes to an upstream probe recipe without a source manifest.
Refreshing the snapshot therefore requires a deliberate Reaper source and
retained-browser audit. Reaper and browser executables are not CI dependencies.
In addition to the cases above, those regressions cover:

- a six-write H1 response split across the status line, fields, header/body
  boundary, and body, followed by `Connection: close` replacement;
- two already-dispatched H2 requests straddling a GOAWAY processed boundary,
  with the lower stream preserved and the displaced bodyless GET retried once
  on a replacement connection;
- authenticated QUIC Retry with original-destination connection-ID continuity;
- ALPS `HEADER_TABLE_SIZE` final-value behavior carried through TLS, H2 state,
  and the first HPACK block without a synthetic wire acknowledgement;
- Reaper's current three-profile ALPS sequence ending in
  `MAX_CONCURRENT_STREAMS=0`, which emits no request HEADERS until a wire
  SETTINGS update releases capacity, followed by connection reuse; and
- TLS 1.3 resumption after a complete H2 response and graceful H2 shutdown on
  the replacement connection at
  `/.well-known/reaper/resume`, absence of an early-data offer, and a full
  handshake from a separate Phantom session.

Reaper's redirect pair is retained through the public H2 session path. Its 302
case rewrites POST to a bodyless GET, while its 307 case preserves the POST and
owned body. Both resolve an encoded dot segment to the canonical final path
and complete the request stream. The fixture also closes the first H2
generation before the second transaction, exercising pool replacement without
claiming that connection identity is part of Reaper's observation.

Reaper's current secondary-authority probe records `not_coalesced` for its
Chrome and Firefox controls; Safari did not establish the dual-authority test
precondition. Phantom retains that observed connection choice with two
authorities covered by one trusted certificate and routed to the same peer.
The secondary authority receives a dedicated H2 connection, matching Reaper's
current no-challenge outcome. A separate regression proves that a 421 received
on a dedicated connection is returned without hidden replay. Phantom does not
claim the unobserved recovery branch: future opt-in coalescing must carry
certificate, DNS, route, and peer-address proof plus one bounded 421 replay
regression.

## Later client and streaming corpus

- Redirect coverage includes H1 replacement after an incomplete adversarial
  response, H3 body-preserving replay, and cookie transitions across origins;
  future work should add broader retained browser matrices.
- Cookie tests preserve repeated `Set-Cookie`, host-only and domain scope,
  same-name paths, IP/IDNA hosts, and deterministic outbound ordering.
- Compression tests fragment gzip, deflate, Brotli, and zstd input while a slow
  consumer verifies incremental output, ratio limits, and one timeout budget.
- Proxy peers still need browser-differential 407 challenge/retry behavior,
  half-close coverage, HTTPS proxying, SOCKS5 authentication, and UDP
  route variants.
- SSE covers BOM and line-ending variants, split UTF-8, comments, `id`, and
  `retry`. A deterministic H1 session regression also covers one bounded
  reconnect, `Last-Event-ID`, cookie carry-over, cancellation-safe delay, and
  204 termination. Broader retained browser and H2/H3 reconnect matrices remain
  future work.
- WebSocket covers fragmented UTF-8 with interleaved Ping/Pong, simultaneous
  Close, RSV misuse, and invalid control frames. The current handshake rejects
  extensions; `permessage-deflate` and compression context-takeover coverage
  remain future work.

Renderer behavior is out of scope for the raw transport client. For example,
preloading a `Link` from a 103 response and synthesizing `Sec-Fetch-*` require
an explicit browsing-context policy; the transport should preserve the
protocol event without pretending to be a renderer.

## Fixture shape

Start with concrete `tls_peer`, `http1_peer`, `http2_peer`, `http3_peer`,
`proxy_peer`, `sse_peer`, and `websocket_peer` fixtures sharing only bounded
loopback I/O and transcript recording. Do not introduce a universal hostile-
peer DSL until repeated implementations prove a useful common grammar.

For a parity-sensitive case:

1. Run the pinned clients against the same bounded loopback peer.
2. Retain the raw server transcript and any required packet/qlog evidence.
3. Normalize entropy only.
4. Run Phantom with the corresponding profile.
5. Diff ordered protocol actions and resource outcomes.
6. If clients diverge, represent the behavior as typed profile data rather
   than a family-name branch in a transport.

Minimized failures stay in ordinary CI. Coverage-guided fuzzing, native
sanitizers, packet-loss scripts, and long slow-reader soaks reuse the same
bounded decoders on scheduled jobs.

## Evidence

- [NIST: browser fingerprinting using server message sequences](https://www.nist.gov/publications/browser-fingerprinting-using-combinatorial-sequence-testing)
- Reaper's versioned local probe corpus and raw-reaction methodology
- [Two-step TLS browser fingerprinting study](https://doi.org/10.1016/j.cose.2021.102575)
- [TLS 1.3 post-handshake messages](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6)
- [HTTP/1.1 message parsing](https://www.rfc-editor.org/rfc/rfc9112.html)
- [HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html), [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html), and [QPACK](https://www.rfc-editor.org/rfc/rfc9204.html)
- [Chromium HTTP/2 session tests](https://github.com/chromium/chromium/blob/main/net/spdy/spdy_session_unittest.cc)
- [Firefox Neqo Retry tests](https://github.com/mozilla/neqo/blob/main/neqo-transport/tests/retry.rs) and [Version Negotiation tests](https://github.com/mozilla/neqo/blob/main/neqo-transport/src/connection/tests/vn.rs)
- [WHATWG SSE processing model](https://html.spec.whatwg.org/multipage/server-sent-events.html)
- [WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html) and [per-message compression](https://www.rfc-editor.org/rfc/rfc7692.html)
