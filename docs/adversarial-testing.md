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
| P0 | H2 | Interleaved `PING`, SETTINGS update, unknown frame, and response DATA | Required ACKs, identical PING payload, continued body progress, no parser desynchronization |
| P0 | H2 | Slow consumer across several flow-control windows | Credit tracks consumed bytes, memory stays bounded, and the response completes |
| P0 | H2 | Trailers plus `RST_STREAM(NO_ERROR)`, GOAWAY, and reset races | Trailers and accepted data survive; new work is not placed on a draining connection |
| P1 | QUIC | Retry, duplicate or late Retry, and Version Negotiation variants | At most one valid Retry is processed; spoofed or invalid negotiation cannot loop or downgrade |
| P1 | H3 | Missing or duplicate SETTINGS, forbidden frame placement, and unknown frames/streams | Correct H3 close code for violations; bounded draining and continuation for valid extensions |
| P1 | H3/QPACK | Blocked field section followed by insertion, cancellation, or critical-stream failure | Flow control remains accounted, cancellation is stream-scoped, and critical-stream errors close deterministically |
| P1 | H3 | Descending/increasing GOAWAY and response `103`/trailers/reset races | Draining semantics, `H3_ID_ERROR` for an increase, and response continuity match retained client behavior |

The current deterministic baseline includes H1 `100 Continue`, chained
`103`/`100`, declared-length surplus isolation, H2 `RST_STREAM`, and H2
`GOAWAY`. The H3 cases become executable alongside the forced-H3 vertical
slice rather than through a speculative universal peer framework.

## Later client and streaming corpus

- Redirects cover 301/302/303/307/308 method and replayable-body behavior,
  cross-origin credential removal, URL resolution, and a finite hop budget.
- Cookie tests preserve repeated `Set-Cookie`, host-only and domain scope,
  same-name paths, IP/IDNA hosts, and deterministic outbound ordering.
- Compression tests fragment gzip, deflate, Brotli, and zstd input while a slow
  consumer verifies incremental output, ratio limits, and one timeout budget.
- Proxy peers fragment CONNECT, coalesce tunneled TLS bytes with the 2xx head,
  issue bounded 407 challenges, and prove that no direct socket escaped.
- SSE covers BOM and line-ending variants, split UTF-8, comments, `id`,
  `retry`, reconnect, `Last-Event-ID`, and 204 termination.
- WebSocket covers fragmented UTF-8 with interleaved Ping/Pong, simultaneous
  Close, compression context takeover, RSV misuse, and invalid control frames.

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
- [Two-step TLS browser fingerprinting study](https://doi.org/10.1016/j.cose.2021.102575)
- [TLS 1.3 post-handshake messages](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6)
- [HTTP/1.1 message parsing](https://www.rfc-editor.org/rfc/rfc9112.html)
- [HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html), [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html), and [QPACK](https://www.rfc-editor.org/rfc/rfc9204.html)
- [Chromium HTTP/2 session tests](https://github.com/chromium/chromium/blob/main/net/spdy/spdy_session_unittest.cc)
- [Firefox Neqo Retry tests](https://github.com/mozilla/neqo/blob/main/neqo-transport/tests/retry.rs) and [Version Negotiation tests](https://github.com/mozilla/neqo/blob/main/neqo-transport/src/connection/tests/vn.rs)
- [WHATWG SSE processing model](https://html.spec.whatwg.org/multipage/server-sent-events.html)
- [WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html) and [per-message compression](https://www.rfc-editor.org/rfc/rfc7692.html)
