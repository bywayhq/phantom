# Roadmap

Each phase ends when its observable acceptance criteria pass. Later work does not expand the active phase.

## Phase 0: foundation — complete

Acceptance:

- The Rust 2024 workspace builds on the pinned development toolchain and declared MSRV.
- Formatting, linting, tests, and documentation are enforced in CI.
- Browser-neutral profile identity supports Chromium, Firefox, Safari, and custom families.
- Agent ownership and integration rules are documented.

Non-goals:

- Network requests
- TLS configuration
- Complete profile serialization
- Protocol backend traits
- Performance tuning

## Phase 1: local wire testkit — complete

The testkit captures one TLS ClientHello from any asynchronous reader. It preserves exact record boundaries, legacy versions, and the reassembled handshake while bounding time, memory, record size, and record count. Its strict semantic decoder preserves the ordered cipher suites, extensions, supported groups, point formats, signature algorithms, ALPN protocols, supported versions, and key-share groups needed by current differential tests. Fragmented records, malformed nested lengths, duplicate extensions, and a real ephemeral loopback connection are covered by deterministic tests.

Fixture serialization, pcap ingestion, and broader normalization remain deferred until a transport test requires them.

## Phase 2: TLS and streaming HTTP/1.1

Send a streaming request with one pinned Chromium profile and verify its observable TLS and HTTP behavior.

Acceptance:

- Browser-neutral TLS settings produce an asserted ClientHello through the private BoringSSL adapter.
- A completed, certificate-verified TLS handshake composes with the streaming HTTP/1.1 transaction.
- Negotiated ALPN is routed explicitly; unsupported protocols never silently downgrade to HTTP/1.1.
- Ordered HTTP/1.1 request fields and response streaming are proven over the completed TLS connection.

## Phase 3: HTTP/2

Add explicit settings ordering, pseudo-header ordering, flow control, and frame-level fixtures.

## Phase 4: browser-family checks

Exercise the profile and transport seams with Firefox and Safari captures before they become expensive to change.

## Phase 5: forced HTTP/3

Establish one explicit QUIC and HTTP/3 path, with qlog and packet differentials, before adding negotiation or fallback.

## Later phases

Session state, protocol routing, SSE, WebSocket, proxies, automated profile freshness, and performance hardening follow only after their transport prerequisites are verified.
