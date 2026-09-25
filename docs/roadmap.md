# Roadmap

What Phantom does today, what Phase 1 still has to deliver, and the phases
after it. It states intent, not commitments or dates; for exact current
support, see [Coverage](reference/coverage.md).

> For builders planning around Phantom and contributors choosing work.

Each phase names its main delivery focus. Idiomatic Rust, clear ownership,
accurate documentation, and green validation gates are required in every
phase, and the [standing rules](#standing-rules) apply to all of them.

## Phase 1: Functionality (current)

### Complete

- One-line git or path dependency with no `[patch]` table
  ([Adding Phantom to a project](guides/downstream.md)).
- Chrome 154, Edge 153, and Firefox 156 recipes from retained captures and
  browser source, with request templates and client hints
  ([Browser profiles](guides/profiles.md),
  [Request templates and client hints](guides/request-templates.md)).
- Exact and negotiated HTTP/1.1 and HTTP/2, ordered fields, streaming bodies,
  and ordered static or body-produced trailers ([Using the client](guides/client.md)).
- Bounded response collection and opt-in decompression
  ([Responses and errors](guides/responses.md),
  [Content decoding](guides/content-decoding.md)).
- Exact HTTP/3 with QUIC session resumption and early data in the Chrome and
  Edge recipes ([HTTP/3 and Alt-Svc](guides/http3.md)).
- Alt-Svc upgrade, H2 ALTSVC frames, racing with broken-alternative backoff,
  HTTPS-record discovery, and Alt-Svc snapshots
  ([HTTP/3 discovery](guides/http3-discovery.md)).
- Encrypted Client Hello from an HTTPS record on direct TCP connections,
  negotiated or exact, and on `wss://` openings, with the Chrome 154 recipe
  ([Real ECH evidence](explanation/validation.md#real-ech-evidence)).
- HTTP proxies with CONNECT and forwarding over HTTP/1.1 or HTTP/2, and
  remembered Basic proxy credentials ([Routes and proxies](guides/routes-and-proxies.md)).
  A `407` on an HTTP/1.1 proxy connection is replayed on that connection
  when the proxy keeps it open, as the captured browsers do.
- SOCKS5 tunnels and UDP ASSOCIATE, and exact HTTP/3 through CONNECT-UDP over
  HTTP/3, HTTP/2, or HTTP/1.1 proxy legs
  ([SOCKS5 and CONNECT-UDP proxies](guides/socks-and-connect-udp.md)).
- Parallel HTTP/1.1 connections per origin, bounded pools, and the address
  cache ([Connections and client state](guides/connections-and-state.md)).
- Redirects, the cookie jar, and cookie snapshots
  ([Redirects](guides/redirects.md), [Cookies](guides/cookies.md)).
- Connection-setup retries, reused-connection replay, unprocessed-request
  replay, and status retries ([Retries and replays](guides/retries.md)).
- Throughput options, each off by default
  ([Tune throughput and latency](guides/performance.md)).
- Server-sent events with Chrome and Firefox reconnects
  ([Server-sent events](guides/sse.md)).
- WebSocket over HTTP/1.1 on direct, HTTP proxy, and SOCKS5 routes, and over
  HTTP/2 extended CONNECT with named Chrome, Edge, and Firefox recipes
  ([WebSocket](guides/websocket.md)).

### Remaining

Each entry names what exists as evidence and what blocks the work, if
anything does.

#### Browser recipes

- Firefox HTTP/3 recipe. Evidence: only the resumption captures, where a
  resumed Firefox 156 connection chooses QUIC v2 (`0x6b3343cf`) in
  `version_information` and starts in v2 packets
  ([QUIC resumption evidence](explanation/validation.md#quic-resumption-and-0-rtt-evidence)).
  Blocker: a fresh-connection capture, and QUIC v2 support; Phantom speaks
  only QUIC v1.
- Chrome on macOS. Evidence: none; Chromium's macOS idle-only keepalive is
  known from source. Blocker: a matched Chrome build on an Apple Silicon
  capture host. Retain each difference from the Windows recipe rather than
  assuming the platforms match.
- Chrome for Android. Evidence: none. Blocker: Android emulator captures.
- Brave and Opera. Evidence: none; the development host carries Brave
  153.1.95.104 and Opera 135.0.5973.92. Blocker: captures in all seven areas.
  A Chromium fork cannot borrow the Chrome recipe: the Edge captures
  disproved that every Chromium browser shares one fingerprint.
- Firefox keepalive schedule and address selection. Evidence: not yet
  gathered. Today every TCP path applies Chromium's keepalive and Happy Eyeballs v2, so
  a Firefox profile connects with Chromium's transport behavior.

#### Wire fidelity

- QPACK stream order. Chromium opens its decoder stream before its encoder
  stream (client stream 10) and writes a stream's type byte with its first
  instruction; Phantom's encoder is stream 6 and sends its type byte at
  connection start. Status: in progress. Needs a vendored `h3` seam and a
  capture that records stream types.
- Resend on the same connection after a server rejects early data. Evidence:
  the Chrome 154, Edge 153, and Firefox 156 captures resend every request in
  1-RTT on that connection; Phantom opens a new one. Status: in progress.
- Cookie crumbling: one `cookie` field per cookie on HTTP/2 and HTTP/3.
  Evidence: browser source (quiche `HpackEncoder::CookieToCrumbs`, Firefox
  `Http2Compressor`). Blocker: a vendored encoder patch and a two-cookie
  capture.
- TLS resumption over TCP. Evidence: none; the QUIC side is proved.
  Blocker: a capture of a resumed TCP ClientHello.
- Per-profile HPACK indexing for WebSocket openings and ordinary requests.
  Evidence: the [WebSocket captures](explanation/validation.md#websocket-browser-evidence).
  Blocker: the vendored `http2` encoder chooses every representation itself
  and keeps one dynamic table per connection.
- HPACK indexing of `proxy-authorization`. Evidence: the
  [proxy authentication captures](explanation/validation.md#proxy-authentication-evidence)
  show an incrementally indexed literal, then an indexed field; Phantom
  sends a never-indexed literal. Blocker: a profile setting and a
  `RequestHeader` marker that hides a value from `Debug` without choosing
  the never-indexed form.
- Chromium's preface `PING` on a pooled connection idle past its
  at-risk-of-loss time. Evidence: not yet gathered; comparable clients
  reproduce it. Blocker: none recorded.
- Trust-anchor identifier order: per process, as the retained 60-process
  capture shows, or per connection. Blocker: a capture of many connections
  from one process.
- Revalidation with `If-None-Match` or `If-Modified-Since` and `304`
  handling. Evidence: none. Blocker: a capture of what Chrome and Firefox
  send on a second fetch, before any cache is written.
- `Expect: 100-continue`. Evidence: none; whether a browser sends it, and on
  which uploads, is unknown.
- An origin that advertises more than one alternative. Phantom uses one.
  Blocker: a capture of such an origin, which decides whether Chrome races
  them, picks one by rule, or tries them in order.

#### Discovery, DNS, and ECH

- ECH over QUIC. Evidence: Chrome passes the record's list to QUIC
  (`net/quic/quic_chromium_client_session.cc`); the QUIC connector rejects
  the field. Blocker: a capture of Chrome's QUIC handshake with a record.
- Edge's ECH default. Evidence: unknown; `edge::v153_tls` keeps GREASE.
  Blocker: a capture on a host where Edge's DNS-over-HTTPS policy can be set,
  which needs elevation.
- Host-to-address overrides, a caller-supplied address resolver, and DNS
  over HTTPS where the captured browser uses it. Blocker: none recorded.

#### Routes and proxies

- Replay a challenged HTTP/2 CONNECT on the challenged proxy connection.
  Evidence: in the `https-proxy-auth-secure-hostname`
  [captures](explanation/validation.md#proxy-authentication-evidence),
  Chromium and Firefox open the replay as a new stream on the HTTP/2 proxy
  connection that carried the `407`. Phantom gives each HTTP/2 tunnel its own
  proxy connection and opens a new one for the replay. HTTP/1.1 CONNECT,
  HTTP/1.1 forwarding, and HTTP/2 forwarding already replay on the
  challenged connection. Blocker: none recorded.

#### Caller options, off by default

Each of these needs no capture, because no named recipe may reach it
([standing rules](#standing-rules)).

- WebSocket over HTTP/3 (RFC 9220) for custom profiles. The `phantom-net`
  extended CONNECT foundation exists; no shipping browser opens one, so no
  recipe will.
- More than one HTTP/3 connection per origin and route. Blocker: the H3
  pool's early-data and connect-turn state assume one connection, and
  spreading streams needs the peer's `initial_max_streams_bidi`.
- An opt-in retry of a failed exact HTTP/3 attempt over the profile's own
  HTTP/2 recipe, as a browser does once it marks an alternative broken.
- A WebSocket handshake timeout and an explicit handshake retry.
- A caller-pinned Alt-Svc alternative, which needs no TLS stream to learn
  from and so could work on CONNECT-UDP.
- Racing more than one alternative, bounded and chosen by the caller.
- `Expect: 100-continue` and caller-owned conditional-request validators.
- A buffered request body that a retry may replay.
- Keepalive and address-selection settings on a custom profile.
- WebSocket reuse of a pooled HTTP/2 session on a proxy route.
- A source address or interface binding, and client certificates.

#### Request pipeline

- Build each request once. A negotiated request assembles its HTTP/1.1 and
  HTTP/2 field lists, and an Alt-Svc attempt its HTTP/3 list as well, on
  every attempt, before one protocol is chosen.
- Refuse a template without an HTTP/3 list only when the route can carry
  QUIC. Today a negotiated request on a client with Alt-Svc enabled is
  refused on every route, including an HTTP proxy that can never upgrade.

#### Publication

- Publish to crates.io. Blocker: the `btls-sys` git dependency in the
  workspace manifest and in the vendored `btls` manifest, which crates.io
  rejects; the release script refuses to publish while either remains.
  Upstream already publishes `btls-sys` with the BoringSSL sources and every
  native patch at about 4.9 MiB, inside the 10 MiB limit.
  - Keep every native patch. Two have no upstream equivalent, and dropping
    any changes the wire.
  - Bundling BoringSSL makes Phantom a redistributor: carry the third-party
    licenses and declare a license expression that covers Apache-2.0.
  - Renaming the package does not let Phantom and a stock `boring` or `btls`
    share a dependency graph outside Linux, because symbol prefixing is
    skipped elsewhere and both ask for the same static archive names. Do not
    promise coexistence beyond Linux.

### Proposed after Phase 1

Each starts from a proposal with acceptance criteria and, where it touches
the wire, capture evidence.

- A feature-gated `danger_accept_invalid_certs` for debugging through an
  intercepting proxy; it skips chain verification and changes no wire field.
- Digest proxy authentication.
- SOCKS4 and SOCKS4a routes, which refuse HTTP/3 and the Alt-Svc upgrade
  before I/O.
- Import of externally described fingerprints, limited to fields Phantom
  reproduces byte for byte.

## Standing rules

- No lock is held across an `.await` on a shared path.
- Every per-client store has a bound
  ([Design](explanation/design.md#state-belongs-to-one-client-and-has-a-bound)).
- Discovery adds no serial round trip. The one exception is documented and
  opt-in: when a recipe turns on ECH from HTTPS records, a direct TLS
  handshake waits 5 to 50 ms for the record.
- Browser behavior is the default. A departure is an explicit caller option,
  off by default, with the tradeoff documented
  ([Tune throughput and latency](guides/performance.md)).
- A named recipe never emits a field, order, or protocol option that no
  capture or browser source backs. A caller option may exist ahead of any
  capture, but no named recipe may reach it
  ([Design](explanation/design.md#recorded-browser-behavior-is-the-specification)).
- Carry one version per browser, the current stable build on the capture
  host. When a browser updates, recapture it and replace the recipe. The
  matrix grows only from captures, and a scheduled capture workflow is the
  prerequisite for a large one.
- Extend the pre-dispatch retry policy only to a replay class with explicit
  ownership and bounded lifecycle rules.
- Tests bind loopback only.

## Phase 2: Ergonomics

- Composed per-browser profile constructors, such as `chromium::v154()`, so
  a caller cannot pair the HTTP/3 leg with the TCP ClientHello by mistake.
- Error triage over `kind()`, a public replay-safety accessor, and the
  response carried on errors that have one.
- Bounded `text()`, `bytes()`, and typed-JSON helpers that never set a
  request field.
- Re-exports of the types the public API names, such as `Bytes`.
- A tracing span and field contract, then one narrow request hook that may
  fill a declared slot but never add a field.
- A per-request timeout that layers onto the client's, and a retry budget.
- One naming convention across the ordered-field types and request builders;
  retire `Route::http_connect`.
- Query construction that never sorts, authorization value constructors, and
  `Link` parsing as data.
- JSON, form, and multipart bodies, after a POST capture shows where a
  browser places `Content-Type`; opt-in `HTTP_PROXY` and `NO_PROXY` routes.
- A default request template on the profile.
- An opt-in status-to-error conversion that keeps the response.
- A published wire-assertion harness, so downstream tests can check a request
  against a named recipe.
- Sessions: the hidden compatibility `SessionBuilder` lacks the newest
  builder options (request timeouts, `alt_svc_policy`, `http3_early_data`,
  `https_record_discovery`, `max_http2_connections_per_origin`,
  `negotiated_setup_wait_limit`). Expose it with every per-session option, or
  retire it in favor of separately built clients.

Non-goals: middleware that can add a field or change an order, fallback from
a proxy route to a direct connection, silent protocol fallback, automatic
`Link` following, base-URL joining, and a blocking API.

## Phase 3: Hardening

- Cross-platform debug and release gates, and `unwrap_used` and
  `expect_used` denied once every recoverable path has a typed error.
- Broader fuzzing, sanitizers, lifecycle regressions, and soak tests,
  including the QUIC session-resumption FFI in `phantom-quic-btls` on its
  failure paths and a fuzzing seam for HTTPS-record `h3` selection.
- Make `enable_session_resumption` refuse a context that already has a
  new-session callback.
- Audit the vendored `h3` engine against Hyperium and the
  [`0x676e67/http3`](https://github.com/0x676e67/http3) fork before its next
  refresh: port the QPACK absolute-Base fix and Hyperium's buffered-write fix,
  then review later fixes one commit at a time.
- Document the TCP/IP stack fingerprint as the host's, with reference JA4T
  and p0f signatures and a check that compares the host with the profile's
  platform.
- A bounded spike on [compio](https://github.com/compio-rs/compio) support
  behind a narrow runtime seam in `phantom-net`, adopted only with
  byte-identical wire evidence.

## Phase 4: Profiling and optimization

- Measure the cold cost of building a client for each supported profile.
- Profile cold and warm connections, proxy routes, multiplexing, streaming
  bodies, SSE, and WebSocket workloads.
- Optimize only measured bottlenecks, keeping the packet, frame, ordering,
  cancellation, and bounded-resource evidence.

## Phase 5: Architecture audit

- Audit the workspace for readable, idiomatic Rust once functionality and
  measured optimization have settled the real boundaries: naming, module
  ownership, seams, and file layout.
- Keep wire fixtures, public API contracts, diagnostics, cancellation
  behavior, and the full gates through every behavior-preserving refactor.
- Audit the tooling (capture and conformance scripts, CI and release scripts,
  development helpers, workflows, and agent configuration), remove what no
  gate uses, and keep documented commands in step with CI.

## Next

- [Coverage](reference/coverage.md): what is supported today, layer by layer.
- [Validation](explanation/validation.md): the evidence behind each complete
  item.
- [Contributing](../CONTRIBUTING.md): how to take on a remaining item.
