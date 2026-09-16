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

## Phase 5: forced HTTP/3 — complete

Phase 5 establishes one explicitly selected QUIC and HTTP/3 path using Quinn,
hyperium `h3`, and an isolated `btls` crypto adapter. Carry narrow,
default-preserving
forks only where retained captures or a production-safety contract prove that
an upstream seam is insufficient. Current evidence requires an H3 SETTINGS
patch for observable ordering and a Quinn provider-contract patch so key-update
derivation failures close the connection instead of reaching an internal
`expect` panic.
Start with one Chromium desktop profile; Firefox and Safari follow from their
own captures rather than assumptions about shared engine behavior.

The completed vertical slice sends a direct empty-body request, streams the
response and trailers, and proves peer-visible cancellation without any TCP or
protocol fallback. A capture-backed Chrome recipe now configures Quinn's live
transport limits and reproduces the retained transport-parameter extension
under deterministic entropy; production connections randomize its permitted
order and GREASE. The H3 driver now opens and actively drives both QPACK
critical streams, bounds fragmented instruction state and decoder feedback,
and maps malformed instructions and closed streams to their protocol-specific
connection errors. Response headers and trailers share a stateful decoder with
bounded parked sections, acknowledgements, cancellations, reset wakeups, and
receive-future persistence. A typed Chrome H3 profile now emits the captured
nonzero QPACK limits, maximum field-section size, H3 DATAGRAM setting,
ascending setting order, and randomized GREASE. A live raw control-stream
differential checks the resulting SETTINGS frame. Captured pseudo-header and
ordinary-field order now pass through the request encoder; outbound dynamic
QPACK bytes match the retained first request both in isolation and through the
live connection-owned encoder stream. Dynamic requests use bounded admission,
wait for peer settings before opening a request stream, and cannot publish
dependent HEADERS before their instructions are accepted by QUIC.
Diagnostics are default-off: a single forced connection can retain a bounded,
complete-record qlog, while a separately enabled BoringSSL builder callback
publishes NSS TLS 1.3 secrets through a bounded nonblocking queue. A payload-free
aioquic analyzer now proves authenticated Initial, Handshake, and 1-RTT packet
normalization with deterministic encrypted vectors. Fresh controlled Chrome
and Phantom runs now authenticate all three spaces through the first request
and retain only payload-free summaries. They match the request and encoder
markers. The first comparison exposed Phantom's eager one-byte QPACK decoder
prefix; the Chrome profile now defers that stream type until feedback exists,
and a fresh controlled rerun produced the captured empty decoder prefix. The
engine default remains eager for profiles that do not request this behavior.
A logical-flight comparator now gates authenticated packet spaces and complete
symbolic request markers without depending on fragmentation, ACK, padding, or
retransmission placement. Exact packet placement remains telemetry until
repeated captures establish which shape fields are stable. Its first run
exposed an engine-generated reserved frame after Phantom's request HEADERS.
Disabling engine GREASE in favor of the profile-owned SETTINGS entry produced
a fresh Chrome/Phantom match for every logical marker, packet space, FIN
boundary, retransmission indicator, and terminal-frame check.

The focused hostile-peer suite now exercises missing and duplicate SETTINGS,
forbidden and reserved control-stream behavior, increasing GOAWAY, chained
informational responses, invalid `101`, delayed inbound QPACK, decoder
acknowledgement, critical-stream closure, request cancellation, and a live
Retry through the BoringSSL provider. Engine-level regressions retain the
fragmentation, reset, resource-ceiling, duplicate/late Retry, and version-
negotiation cases that do not require a Phantom policy seam. Reuse after idle
expiry and descending-GOAWAY admission remain Phase 6 work because the Phase 5
transport intentionally owns one connection for one request.

Acceptance:

- A forced H3 request and streaming response complete without automatic TCP or
  protocol fallback.
- A seeded transport-parameter serializer reproduces the retained ordered
  fixture exactly, while multi-seed tests preserve Chrome's semantic set,
  varint encodings, one GREASE element, and non-constant order.
- The first H3 control stream reproduces the captured fixed SETTINGS prefix;
  seeded tests reproduce GREASE exactly and policy tests cover its measured
  variability without sorting or removing it.
- The first request preserves the captured pseudo-header sequence and exact
  caller-supplied ordinary-field order, including cross-name interleaving and
  duplicates, through its encoded QPACK field section.
- Nonzero QPACK table capacity and blocked-stream limits are enabled in a
  browser profile only after its raw control-stream differential passes. The
  engine path covers encoder-stream processing, bounded section accounting,
  decoder acknowledgements and cancellations, dropped futures, reset races,
  and resource ceilings; custom static-only profiles remain valid at QPACK
  `0/0`.
- Bounded qlog plus key-log-assisted packet decryption make failures
  diagnosable without logging application payloads or credentials.
- The dedicated crypto-adapter crate documents every unsafe invariant and does
  not expose BoringSSL, Quinn, or `h3` types through Phantom's public API.
- Initial installation and every later 1-RTT key update propagate local
  derivation failure as a transport error without changing key phase, emitting
  a packet under partial keys, or panicking.
- Unsupported profile controls fail validation instead of silently using an
  upstream default.

Protocol negotiation, fallback, session reuse, SSE, and WebSocket are separate
client-layer phases rather than part of the HTTP/3 transport acceptance gate.

## Cross-cutting adversarial validation

Every transport phase gains a scripted hostile-peer suite after its happy path
works. Tests cover fragmented, delayed, duplicated, malformed, and abruptly
closed traffic; flow-control exhaustion; cancellation at every lifecycle
boundary; and proof that proxy failures do not leak into direct retries.
Observable reactions are compared with a retained real-client run when
emulation matters. Minimized deterministic cases gate pull requests, while
coverage-guided fuzzing, native sanitizers, and long-running soak tests run on a
schedule.

## Phase 6: client, sessions, routing, and proxies — in progress

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

The first landed slice is deliberately smaller than the complete phase. It
adds an immutable `Client` built from TLS and optional H2 profile components,
exact per-request H1/H2 selection, additive DER trust roots, URI-owned
authority fields, and one streaming response body. Loopback TLS tests cover H1
and H2 streaming, H2 trailers, ordered fields, and pre-I/O
rejection of unavailable protocols and invalid fields.

The next landed slice adds a closed `Route` vocabulary for direct connections
and plaintext HTTP CONNECT, with a client default and owned per-request
override. CONNECT authority is a typed placeholder in an ordered field
sequence. Negotiation is bounded, accepts any final 2xx after a bounded number
of informational responses, preserves bytes read beyond the response head,
and reports rejection without exposing peer fields. Loopback tests prove H1
and H2 origin TLS through the proxy, H2 trailers, pre-I/O validation,
cancellation, response bounds, and that rejection never opens a direct origin
socket. It does not introduce an empty `Session` or pool. HTTPS proxies,
forwarding, SOCKS5, authentication challenge negotiation, IDNA normalization,
and UDP-capable proxy routes remain later Phase 6 slices.

The third landed slice brings the existing direct H3 path into the public
facade. `HttpProtocol::Http3` selects it exactly, `ClientProfile` owns one
atomic H3 bundle with distinct QUIC TLS, transport, connection, and request
settings, and the shared response body streams H3 data and trailers. Profile
and request validation precede DNS and UDP. The TCP-only HTTP CONNECT route is
rejected before proxy or origin I/O and never escapes to a direct attempt.
Loopback tests cover certificate and IP-literal verification, ordered duplicate
fields, streaming trailers, cancellation, missing-runtime errors, and route
anti-leak behavior. A built-in Chrome H3 TLS recipe remains pending a retained
H3 ClientHello; the captured Chrome QUIC and H3 components are not presented as
proof of those TLS bytes.

The fourth landed slice separates HTTP/2 connection ownership from individual
requests. A cloneable lower-level connection can open sequential or concurrent
streams over supplied, direct-TLS, or HTTP-CONNECT transports. Cancelling or
dropping one response resets only that stream; the final connection/body lease
starts bounded driver shutdown. The public client does not pool these
connections yet, and GOAWAY admission, waiter limits, retries, coalescing, and
pool keys remain Phase 6 work.

The fifth landed slice exposes that seam through an isolated, cloneable public
`Session`. Requests own cheap client/session handles, so builders are `Send +
'static` rather than borrowing the facade. Each session retains compatible H2
connections by canonical origin and complete route identity, shares concurrent
same-key connection setup, bounds retained entries, keeps independent sessions
isolated, and performs no hidden replay. Direct and plaintext-CONNECT tests
prove sequential/concurrent reuse, tunnel reuse, pre-I/O validation, and
stream-scoped cancellation.

The sixth landed route slice adds no-auth remote-DNS SOCKS5 through an exact
`socks5h://` configuration. H1, one-shot H2, session-owned H2 reuse, and H1 WSS
share the same route; domain targets reach the proxy as SOCKS `DOMAIN`
addresses. Invalid requests and unsupported H3 pairings fail before proxy I/O,
and proxy rejection never opens a direct origin socket. Typed redacted errors,
payload-free tracing, cancellation, fragmented-reply tests, and missing-runtime
tests cover the lower seam. Local origin DNS, credentials, UDP ASSOCIATE, and
H3 proxying remain separate future capabilities.

With the optional `cookies` feature, a session builder can explicitly activate
a bounded in-memory jar or accept a caller-created one. Phantom delegates
cookie syntax/domain/path/expiry mechanics to `cookie_store` while owning PSL,
prefix, partitioning, quota, redacted-diagnostic, and RFC request-order policy.
Invalid response fields are ignored independently; a caller-supplied Cookie
field suppresses automatic injection for that request. SameSite navigation
context, CHIPS, persistence, redirects, and browser-specific eviction remain
future session slices rather than implicit claims.

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

## Phase 7: SSE and WebSocket — in progress

The feature-gated SSE slice is a bounded pull parser over the ordinary response
body, with WHATWG field semantics and cancellation-safe incremental reads.
Reconnect, idle-timeout, and `Last-Event-ID` request policy remain session work.

The first feature-gated WebSocket slice is also landed. It performs WSS over
an exact ordered H1 Upgrade on direct or plaintext-CONNECT routes, retains the
ordinary response when the server rejects the Upgrade, strictly validates the
`101`, preserves coalesced post-head bytes, and exposes bounded Phantom-owned
message types through both methods and standard `Stream`/`Sink` traits.
Sessions contribute cookies without retaining the exclusive upgraded socket.
The framing engine is `tokio-tungstenite` with its HTTP/TLS handshake disabled.
Compression/extensions, reconnect policy, RFC 8441, H3 extended CONNECT, and
named browser WebSocket recipes wait for retained wire evidence.

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
