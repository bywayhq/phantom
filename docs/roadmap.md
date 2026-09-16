# Roadmap

Each phase ends when its observable acceptance criteria pass. Later work does not expand the active phase.

## Phase 0: foundation — complete

Acceptance:

- The Rust 2024 workspace builds on the pinned development toolchain and declared MSRV.
- Formatting, linting, tests, and documentation are enforced in CI.
- Client-neutral profile identity supports Chromium, Firefox, Safari, and
  arbitrary custom client families without transport branches.
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

## Phase 4: browser-family checks — complete

Retained captures now support Safari 18.5 and Firefox 154 macOS TLS recipes and
a Firefox 154 macOS HTTP/2 recipe through the existing typed settings. The
Firefox TLS differential retains its fixed extension layout, exact delegated-
credential advertisement, record-size limit, certificate compression vector,
and ECH GREASE length while excluding only fresh cryptographic entropy. Its
HTTP/2 recipe takes startup SETTINGS and connection flow control from local raw
frames, while request pseudo-header order and priority are explicitly
supplemental observations. Safari HTTP/2 remains deferred until its uncaptured
wire behavior can be proved without fallback. This phase does not add HTTP/3,
sessions, SSE, or WebSocket.

## Phase 5: forced HTTP/3 — in progress

Establish one explicitly selected QUIC and HTTP/3 path using Quinn, hyperium
`h3`, and an isolated `btls` crypto adapter. Carry narrow, default-preserving
forks only where retained captures or a production-safety contract prove that
an upstream seam is insufficient. Current evidence requires an H3 SETTINGS
patch for observable ordering and a Quinn provider-contract patch so key-update
derivation failures close the connection instead of reaching an internal
`expect` panic.
Start with one Chromium desktop profile; Firefox and Safari follow from their
own captures rather than assumptions about shared engine behavior.

The current vertical slice completes a direct empty-body request, streams the
response and trailers, and proves peer-visible cancellation without any TCP or
protocol fallback. A capture-backed Chrome recipe now configures Quinn's live
transport limits and reproduces the retained transport-parameter extension
under deterministic entropy; production connections randomize its permitted
order and GREASE. It intentionally advertises static QPACK `0/0`. This is
working HTTP/3 transport substrate, not Chrome H3 parity; request ordering,
dynamic QPACK, and packet differentials remain acceptance work.

Acceptance:

- A forced H3 request and streaming response complete without automatic TCP or
  protocol fallback.
- A seeded transport-parameter serializer reproduces the retained ordered
  fixture exactly, while multi-seed tests preserve Chrome's semantic set,
  varint encodings, one GREASE element, and non-constant order.
- The first H3 control stream reproduces the captured fixed SETTINGS prefix;
  seeded tests reproduce GREASE exactly and policy tests cover its measured
  variability without sorting or removing it.
- Nonzero QPACK table capacity and blocked-stream limits are enabled only with
  encoder-stream processing, bounded blocked-section accounting, decoder
  acknowledgements and cancellations, and adversarial resource-limit tests.
  Until that complete path exists, static-only H3 advertises QPACK `0/0` and
  is not treated as Chrome parity.
- Bounded qlog plus key-log-assisted packet decryption make failures
  diagnosable without logging application payloads or credentials.
- The dedicated crypto-adapter crate documents every unsafe invariant and does
  not expose BoringSSL, Quinn, or `h3` types through Phantom's public API.
- Initial installation and every later 1-RTT key update propagate local
  derivation failure as a transport error without changing key phase, emitting
  a packet under partial keys, or panicking.
- Unsupported profile controls fail validation instead of silently using an
  upstream default.

Protocol negotiation, fallback, session reuse, SSE, and WebSocket remain
outside this phase.

## Cross-cutting adversarial validation

Every transport phase gains a scripted hostile-peer suite after its happy path
works. Tests cover fragmented, delayed, duplicated, malformed, and abruptly
closed traffic; flow-control exhaustion; cancellation at every lifecycle
boundary; and proof that proxy failures do not leak into direct retries.
Observable reactions are compared with a retained real-client run when
emulation matters. Minimized deterministic cases gate pull requests, while
coverage-guided fuzzing, native sanitizers, and long-running soak tests run on a
schedule.

## Phase 6: client, sessions, routing, and proxies — planned

Build the small public `Client` facade and connection pool around explicit
protocol and route policies. Support direct, HTTP forwarding and CONNECT,
HTTPS-proxy CONNECT, SOCKS5 local DNS, and SOCKS5 remote DNS. Route identity,
auth identity, DNS ownership, origin, profile, protocol, and local binding are
all pool-key inputs. Per-request rotation is an owned route override, not a
global mutable callback.

Tokio is the initial explicit runtime. Core bodies remain backpressured
`http_body::Body` values; optional Cargo features add capabilities and adapters
without changing enabled behavior. The feature matrix and cancellation
contract are defined in [async and feature policy](async-and-features.md).
Mutable cookies, redirects, retries, tickets, and learned client hints belong
to session policy rather than immutable wire profiles.

Acceptance:

- Forced H1, H2, and H3 never silently negotiate or retry another protocol.
- Proxy failures never fall back direct; local fixtures observe every egress
  leg and assert the selected proxy was used.
- Ordered CONNECT headers, authentication challenges, IPv4, bracketed IPv6,
  IDNA, local/remote DNS, half-close, cancellation, and rotation are covered.
- H3 over SOCKS5 UDP ASSOCIATE is packet-tested before exposure; CONNECT-UDP
  and MASQUE follow as separate proven capabilities.
- Pooling never crosses a route, profile, origin/SNI, protocol, or session-state
  boundary, and client shutdown drains with a deadline.
- HTTP/1.1 reuse remains single-exchange and non-pipelined; HTTP/2 and HTTP/3
  admission respects both peer and local stream limits, bounds waiters, and
  keeps cancellation and GOAWAY draining stream-scoped.
- `Accept-CH` state is secure-origin scoped and session owned; redirects do not
  leak hints cross-origin, and `Critical-CH` can retry at most once only for a
  replayable request. Transport-delivered ACCEPT_CH data feeds the same state.
- Each public option is covered by validation and an observable integration
  test; no option is a pass-through placeholder for future work.

## Phase 7: SSE and WebSocket — planned

SSE remains a zero-buffering parser/reconnect policy over the ordinary response
body. WebSocket starts with H1 Upgrade and shares route, TLS, ordered headers,
pool ownership, cancellation, and tracing with normal requests. RFC 8441 and H3
WebSocket support follow only with retained wire evidence.

## Phase 8: production hardening and profiling — planned

Run cross-platform debug/release CI, dependency-update isolation, native patch
replay, sanitizers, fuzzing, long soaks, and workload benchmarks. Profile
allocations, CPU, contention, and syscall behavior across direct and proxy
routes, cold/warm pools, multiplexed concurrency, large slow bodies, SSE, and
WebSocket. Optimize measured bottlenecks without changing packet fixtures.
Close with the repository's [Rust production-quality review](rust-quality.md),
including the explicit AI-smell, feature-combination, documentation, async
lifecycle, unsafe-boundary, and cross-platform audits.

## Later profile work

Evidence-backed non-browser client stacks reuse the same typed settings,
routing, and differential harness. New recipes remain data plus fixtures; they
do not introduce family-name branches in transports.
