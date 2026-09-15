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

## Phase 2: TLS and streaming HTTP/1.1 — complete

The public `chromium::v152_macos_tls()` recipe reproduces the stable,
observable fields retained from Chrome 152.0.7977.83 on macOS 15.5 and returns
the same owned `TlsSettings` type used for customization. The private BoringSSL
adapter performs certificate and hostname verification during the handshake
and composes the resulting stream with an ordered, streaming HTTP/1.1 request.
ALPN routing rejects incompatible negotiation before HTTP/1 bytes are written.

The differential compares exact ordered semantic vectors, SNI, ALPN, requested
trust-anchor IDs, extension membership, every stable extension payload length,
and TLS record count. Only the measured random ECH GREASE payload length and
GREASE codepoint values are normalized.

Acceptance:

- Browser-neutral TLS settings produce an asserted ClientHello through the private BoringSSL adapter.
- A completed TLS handshake with certificate and hostname verification composes with the streaming HTTP/1.1 transaction.
- Negotiated ALPN is routed explicitly; unsupported protocols never silently downgrade to HTTP/1.1.
- Ordered HTTP/1.1 request fields and response streaming are proven over the completed TLS connection.

## Phase 3: HTTP/2 — complete

Phase 3 adds a one-shot HTTP/2 request path without introducing a general client
or session abstraction. The Chrome 152 macOS profile controls initial SETTINGS,
connection flow control, pseudo-header order, and HEADERS priority; the request
API preserves caller-declared ordinary-header order. The TLS path requires
exact `h2` ALPN and decodes negotiated peer application settings before any
HTTP/2 bytes are written.

Acceptance:

- Bounded capture preserves the exact client connection preface and ordered
  startup frames, including SETTINGS and connection WINDOW_UPDATE.
- A direct differential requires a fresh public HTTP/2 request to reproduce the
  retained Chrome 152 macOS startup bytes.
- Request validation, pseudo-headers, ordinary headers, SETTINGS, and priority
  are emitted in declared order; invalid input fails before transport I/O.
- Response DATA and trailers stream with flow-control capacity returned as they
  are consumed. Dropping an incomplete body sends `CANCEL`, flushes the reset,
  and bounds shutdown of a stalled driver.
- The HTTP/2 TLS connector starts the protocol only after exact `h2`
  negotiation. ALPS distinguishes absent, negotiated-empty, and nonempty
  values; valid peer SETTINGS seed the connection without a wire ACK, while
  malformed input is rejected before the HTTP/2 preface.
- Vendored BoringSSL-wrapper and HTTP/2 changes have exact provenance,
  reproducible canonical patches, focused tests, and disposable candidate
  probes in the scheduled upstream-freshness workflow.
- Deterministic public-path HTTP/1.1 and HTTP/2 replay benchmarks run locally
  and in a report-only scheduled workflow. Runtime tracing and platform
  profiling procedures are documented without claiming TLS-handshake or
  network end-to-end measurements.

## Phase 4: browser-family checks — in progress

Retained captures now support a Safari 18.5 macOS TLS recipe and a Firefox 154
macOS HTTP/2 recipe through the existing typed settings. The Safari recipe
retains the observed TLS vector; the Firefox recipe takes startup SETTINGS and
connection flow control from local raw frames, while its request pseudo-header
order and priority are explicitly supplemental observations. Firefox TLS and
Safari HTTP/2 recipes remain deferred until their currently unsupported or
uncaptured wire behavior can be proved without fallback. This phase does not
add HTTP/3, sessions, SSE, or WebSocket.

## Phase 5: forced HTTP/3 — planned

Establish one explicitly selected QUIC and HTTP/3 path with bounded qlog and
packet differentials. Unsupported H3 behavior must fail explicitly; protocol
negotiation, fallback, session reuse, SSE, and WebSocket remain outside this
phase.

## Later phases

A public client facade, reusable sessions, protocol routing, SSE, WebSocket,
proxies, and workload-driven performance optimization follow only after their
transport prerequisites exist.
