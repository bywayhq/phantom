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
- Chrome 154, Edge 154, Brave 154, Opera 136, and Firefox 157 recipes from
  retained captures and browser source, with request templates and client hints
  ([Browser profiles](guides/profiles.md),
  [Request templates and client hints](guides/request-templates.md)).
- Chrome 154, Edge 153, Brave 153, Opera 102, and Firefox 156 for Android
  recipes from Android emulator captures
  ([Chrome for Android 154 recipes](explanation/validation.md#chrome-for-android-154-recipes),
  [Edge for Android 153 recipes](explanation/validation.md#edge-for-android-153-recipes)).
- TCP options, the HTTP/1.1 connection bound, and the address cache of the
  Chromium recipes for Brave 154, from a `brave-core` source reading, and for
  Edge 154 and Opera 136, from Frida hook logs that match Chrome 154's
  ([Socket hook evidence](explanation/validation.md#socket-hook-evidence)).
- Exact and negotiated HTTP/1.1 and HTTP/2, ordered fields, streaming bodies,
  and ordered static or body-produced trailers ([Using the client](guides/client.md)).
- Bounded response collection and opt-in decompression
  ([Responses and errors](guides/responses.md),
  [Content decoding](guides/content-decoding.md)).
- Exact HTTP/3 with QUIC session resumption and early data in the Chrome,
  Edge, Brave, and Opera recipes ([HTTP/3 and Alt-Svc](guides/http3.md)).
- Chrome's QPACK stream order in the Chrome, Edge, Brave, and Opera HTTP/3
  recipes: the encoder stream is client stream 10, and its type is written
  with its first instructions
  ([QUIC resumption evidence](explanation/validation.md#quic-resumption-and-0-rtt-evidence)).
- Requests sent again on the same connection after a server rejects early
  data, as the Chrome 154 and Edge 154 captures show
  ([QUIC resumption evidence](explanation/validation.md#quic-resumption-and-0-rtt-evidence)).
- Alt-Svc upgrade, H2 ALTSVC frames, racing with broken-alternative backoff,
  HTTPS-record discovery, and Alt-Svc snapshots
  ([HTTP/3 discovery](guides/http3-discovery.md)).
- TLS 1.3 session resumption over TCP, with the per-origin ticket count and
  resumed ClientHello of each recipe's browser
  ([TLS resumption over TCP evidence](explanation/validation.md#tls-resumption-over-tcp-evidence)).
- Early data over TCP in the Firefox recipe: a resumed direct connection
  offers `early_data` where Firefox 157 does, sends replay-safe requests in
  it, sends them again on the same connection after a rejection, and restarts
  them without early data when the server then picks another ALPN protocol
  ([TLS resumption over TCP evidence](explanation/validation.md#tls-resumption-over-tcp-evidence)).
- Encrypted Client Hello from an HTTPS record on direct TCP connections,
  negotiated or exact, on `wss://` openings, and on QUIC connections to the
  origin, with the Chrome 154, Edge 154, and Brave 154 recipes
  ([Real ECH evidence](explanation/validation.md#real-ech-evidence),
  [over QUIC](explanation/validation.md#real-ech-over-quic-evidence)).
- HTTP proxies with CONNECT and forwarding over HTTP/1.1 or HTTP/2, and
  remembered Basic proxy credentials ([Routes and proxies](guides/routes-and-proxies.md)).
  A `407` on an HTTP/1.1 proxy connection is replayed on that connection
  when the proxy keeps it open, and a `407` on an HTTP/2 proxy connection
  on a new stream of it, as the captured browsers do.
  CONNECT tunnels share HTTP/2 proxy connections, and the Chromium and
  Firefox CONNECT recipes decide whether forwarded requests and WebSocket
  tunnels join them. `ClientBuilder::max_http2_proxy_connections_per_route`
  opts into more than one connection per proxy route, off by default.
- SOCKS5 tunnels and UDP ASSOCIATE, and exact HTTP/3 through CONNECT-UDP over
  HTTP/3, HTTP/2, or HTTP/1.1 proxy legs
  ([SOCKS5 and CONNECT-UDP proxies](guides/socks-and-connect-udp.md)).
- Parallel HTTP/1.1 connections per origin and bounded pools
  ([Connections and client state](guides/connections-and-state.md)).
- Chromium's HTTP/1.1 idle limit in the Chrome, Edge, Brave, and Opera
  recipes: a connection that has sat idle 300 s is closed when the next
  request comes, and that request opens another, as the Chrome 154, Edge
  154, and Opera 136 hook logs show
  ([HTTP/1.1 connection bound evidence](explanation/validation.md#http11-connection-bound-evidence)).
- The address cache, host-to-address overrides, and a caller-supplied
  address resolver ([Resolve host names](guides/name-resolution.md)).
- Redirects, the cookie jar, and cookie snapshots
  ([Redirects](guides/redirects.md), [Cookies](guides/cookies.md)).
- Connection-setup retries, reused-connection replay, unprocessed-request
  replay, and status retries ([Retries and replays](guides/retries.md)).
- Field lists built once: a negotiated request builds and checks its
  HTTP/1.1 and HTTP/2 lists, and a raced request its HTTP/3 list as well,
  once per redirect hop before any I/O. The race's winner and every replay
  that follows no response send them as built
  ([Fields of a repeated attempt](explanation/design.md#fields-of-a-repeated-attempt)).
- Client hints fixed per request on every protocol, as Chromium sets them
  before it chooses a connection. On HTTP/2 and HTTP/3, a connection whose
  ALPS `ACCEPT_CH` names a hint a navigation lacks restarts it with the hint
  before anything is sent, as Chromium 154 does; a `fetch` goes out as
  built
  ([Fields of a repeated attempt](explanation/design.md#fields-of-a-repeated-attempt)).
- Throughput options, each off by default
  ([Tune throughput and latency](guides/performance.md)).
- A local source address per address family and, on Linux and Android, an
  interface binding for every TCP and QUIC socket, and a client certificate
  sent over TCP and QUIC when a server requests one, each off by default
  ([Send connections from a chosen local address](guides/connections-and-state.md#send-connections-from-a-chosen-local-address),
  [Present a client certificate](guides/client.md#present-a-client-certificate)).
- More than one HTTP/3 connection per origin and route with
  `ClientBuilder::max_http3_connections_per_origin`, off by default: streams
  spread by the server's `initial_max_streams_bidi`
  ([Tune throughput and latency](guides/performance.md#open-more-than-one-connection-per-origin)).
- Server-sent events with Chrome and Firefox reconnects
  ([Server-sent events](guides/sse.md)).
- WebSocket over HTTP/1.1 on direct, HTTP proxy, and SOCKS5 routes, and over
  HTTP/2 extended CONNECT with named Chrome, Edge, and Firefox recipes
  ([WebSocket](guides/websocket.md)).
- A WebSocket handshake timeout, which the Chromium and Firefox recipes set
  to their browsers' 240-second and 20-second timers, and an opt-in retry of
  an opening whose connection setup failed
  ([WebSocket](guides/websocket.md#bound-a-connect-with-a-timeout)).
- Per-browser HPACK encoding: every HEADERS block of the retained Chrome,
  Edge, Brave, Opera, and Firefox cookie and WebSocket sessions equals the
  recipe's byte for byte
  ([HPACK encoder evidence](explanation/validation.md#hpack-encoder-evidence)).
- Per-browser HTTP/2 stream numbering and the stream limit before SETTINGS:
  Firefox 157 starts each connection at stream 3 and Chromium at 1, and both
  open at most 100 streams until the peer states a limit
  ([HTTP/2 stream numbering evidence](explanation/validation.md#http2-stream-numbering-evidence)).
- Chrome 154's trust-anchor ID order: one ascending list in every browser
  process and on every connection of a process, over TCP and QUIC, as
  Chromium sorts it once when it builds the SSL configuration. The recipe
  carries the compiled-in set of 28 identifiers, not a set from
  component-updated PKI metadata
  ([Chrome 154 trust-anchor ID order](explanation/validation.md#chrome-154-trust-anchor-id-order)).

### Remaining

Each entry names what exists as evidence and what blocks the work, if
anything does.

#### Browser recipes

- Firefox HTTP/3 beyond the recipe. Delivered: `firefox::v157_http3_tls`,
  `v157_quic`, `v157_http3`, and `v157_http3_request` from Firefox 157.0
  captures, with QUIC v2 and compatible version negotiation
  ([Validation](explanation/validation.md#firefox-157-http3-recipe)).
  Remaining: the QUIC ClientHello's fixed tail of `quic_transport_parameters`
  and `encrypted_client_hello`, and its `record_size_limit`,
  `extended_master_secret`, and `renegotiation_info` extensions; the
  position of `Alt-Used`. Blocker: the first four need changes to the
  BoringSSL fork; `Alt-Used` needs a template slot for a field the client
  generates.
- macOS beyond client hints and request fields. Delivered: `macos` client
  hints for Chrome 154, Edge 154, and Opera 135 and `macos` request
  templates for Chrome 154 and Firefox 156, from macOS 15.5 captures on an
  Apple silicon Mac, with single runs of the TCP, QUIC, H2, and H3 layers
  replayed against the Windows recipes
  ([Validation](explanation/validation.md#macos-recipes)). Remaining: a
  literal Chromium-family `User-Agent`, which needs a headful capture; the
  idle-only TCP keepalive, known from Chromium source but not captured; Intel
  Macs and other macOS versions. Blocker: a headful launch on the capture
  host and an Intel Mac.
- macOS Firefox at 157.0. Evidence: the macOS Firefox fixtures and the
  `v156_macos_*` templates come from Firefox 156.0, while the Windows
  Firefox captures are from 157.0. Blocker: none; update the Mac's Firefox
  and capture the navigation, TLS, and WebSocket sets under
  `fixtures/*/firefox/156.0/macos-15.5-arm64` again.
- Firefox for Android beyond TLS. Evidence: `firefox_android::v156_tls` only.
  Blocker: trusting a test certificate on Android, such as a user CA with
  `security.enterprise_roots.enabled`.
- Chrome for Android on a phone. Evidence: Chrome 154.0.8037.57 captures on
  an Android 17 emulator that reports a Pixel 7 back
  `chrome_android::v154_*`, and Play served that build to the emulator; no
  record compares it with the stable version Google lists. Blocker: a
  physical device, to check the emulator's CPU and network against a phone.
  The emulator hides TCP, so the Android TCP layer also needs a phone.
- Windows TCP port randomization. Evidence: hook logs of Chrome 154, Edge
  154, and Opera 136 show `SO_RANDOMIZE_PORT` on every TCP socket, which
  Chromium 154 sets right before `connect` on Windows 11 22H2 and later
  (`net/socket/tcp_socket_win.cc:1048-1053`, `net/base/features.cc:308-314`)
  ([Socket hook evidence](explanation/validation.md#socket-hook-evidence)).
  Blocker: no safe Rust API sets the option. `socket2` 0.6.5, the newest
  release, exposes neither `SO_RANDOMIZE_PORT` nor a general `setsockopt`,
  and a `windows-sys` call would be unsafe code outside the one allowed FFI
  module ([Design](explanation/design.md#unsafe-code)). It needs a `socket2`
  method or a new documented and audited FFI boundary.
- Opera 136 and Edge 154.0.4258.48 on macOS. Evidence: the macOS captures
  are of Opera 135.0.5973.92 and Edge 154.0.4258.37, so
  `opera::v135_macos_client_hints` and `edge::v154_macos_client_hints` carry
  those builds. Blocker: none; update the Mac's browsers and take the macOS
  client hints and request captures again.
- Opera's ECH default. Evidence: unknown; Opera 135 sent no DNS-over-HTTPS
  query with the capture tool's preferences, and `opera::v136_tls` keeps
  GREASE. Blocker: a way to point Opera at a test DNS-over-HTTPS server.
- Firefox keepalive schedule and address selection. Evidence: not yet
  gathered. Today every TCP path applies Chromium's keepalive and Happy Eyeballs v2, so
  a Firefox profile connects with Chromium's transport behavior.

#### Wire fidelity

- Opera's trust-anchor ID order. Evidence: Opera 136 encodes its 32 IDs in
  Chromium 152's hash-set order, one order per process over TCP (16 orders
  in 29 processes) and a new one per connection over QUIC (19 orders in 20
  ClientHellos); the recipes send one fixed order each
  ([Brave 154 and Opera 136 recipes](explanation/validation.md#brave-154-and-opera-136-recipes)).
  Blocker: modelling it needs a `TlsSettings` option that draws an order,
  per client or per connection, from the observed orders.
- Chromium's built-in DNS client. Evidence: with their default resolver,
  Chrome 154, Edge 154, and Opera 136 sent one query for a name in 120 s of
  fetches, keeping the answer for the record's TTL
  ([Socket hook evidence](explanation/validation.md#socket-hook-evidence)).
  `chromium::v154_dns_cache` keeps every answer 60 s, the browsers' rule for
  the system resolver. Blocker: Phantom resolves through the operating
  system, which reports no TTL; a resolver that returns record TTLs, and a
  cache that honors them, are needed.
- The ECH GREASE payload of a resumed Firefox ClientHello. Evidence: the
  [TLS resumption captures](explanation/validation.md#tls-resumption-over-tcp-evidence),
  where every Firefox 156.0.1 and 157.0 resumption sends a 368-byte payload
  against 240 bytes on a fresh connection; the recipe sends 240 bytes on
  both. NSS sizes the GREASE payload from the ClientHello it has built,
  `pre_shared_key` included: `tls13_MaybeGreaseEch` (`security/nss/lib/ssl/tls13ech.c:2143`,
  called from `ssl3con.c:5889` at tag `FIREFOX_157_0_RELEASE`) encodes an
  inner ClientHello from the outer extensions and pads it with
  `tls13_PadChInner` to the `security.tls.ech.grease_size` name target
  (100) and a multiple of 32 bytes. Blocker: a fixed recipe length cannot
  follow a ticket's size; modelling that rule needs a ClientHello-dependent
  length in the TLS backend.
- Early data on Firefox-profile WebSocket openings and on connections that
  offer ECH from HTTPS records. Evidence: Firefox 157 disables TCP early data
  only on proxy connections and origins that failed before
  (`netwerk/protocol/http/TlsHandshaker.cpp:134-137`); no capture resumed a
  WebSocket opening. Phantom offers no early data on either.
- Closing a TLS connection without `close_notify`. Evidence: source only;
  Chromium's `SSLClientSocketImpl::Disconnect` never calls `SSL_shutdown`
  ([HTTP/2 preface PING evidence](explanation/validation.md#http2-preface-ping-evidence)),
  while Phantom's TLS stream sends `close_notify` from `poll_shutdown` on
  every close. Blocker: a TLS profile setting that `poll_shutdown` applies,
  and a capture of a Chrome close.
- Chromium's retry of a request whose session ended with
  `ERR_HTTP2_PING_FAILED`: up to twice on a new connection, whatever the
  method. Evidence: source only
  ([HTTP/2 preface PING evidence](explanation/validation.md#http2-preface-ping-evidence));
  Phantom closes the connection as Chromium does but fails the request.
  Blocker: a replay class for requests the client cannot show were
  unprocessed, which the unprocessed-replay policy does not cover.
- Firefox's read-timeout `PING`. Evidence: source only; `Http2Session`
  sends a `PING` after `network.http.http2.ping-threshold`, 58 seconds,
  without a read (`Http2Session.cpp:436-503` at `FIREFOX_157_0_RELEASE`).
  Blocker: a capture showing whether an idle pooled Firefox connection
  receives the timer tick.
- Revalidation with `If-None-Match` or `If-Modified-Since` and `304`
  handling. Evidence: none. Blocker: a capture of what Chrome and Firefox
  send on a second fetch, before any cache is written.
- `Expect: 100-continue`. Evidence: none; whether a browser sends it, and on
  which uploads, is unknown.
- An origin that advertises more than one alternative. Phantom uses one.
  Blocker: a capture of such an origin, which decides whether Chrome races
  them, picks one by rule, or tries them in order.
- Capture evidence for the ALPS `ACCEPT_CH` restart. Phantom fixes a
  request's client hints when it builds its lists and restarts a navigation
  when its connection's `ACCEPT_CH` names a hint it lacks, from Chromium
  source ([Design](explanation/design.md#fields-of-a-repeated-attempt)).
  Blocker: a capture of a Chrome navigation whose connection's `ACCEPT_CH`
  adds a hint, to confirm which fields the restarted request rebuilds and
  where the appended hint lands among the fields the network stack adds,
  such as `Cookie`.

#### Discovery, DNS, and ECH

- ECH on an Alt-Svc alternative at another host. Evidence: Chrome's
  alternative job resolves that host, HTTPS record included
  (`net/quic/quic_session_pool_direct_job.cc`); Phantom looks up only the
  origin's records. Blocker: a capture of Chrome reaching such an
  alternative whose own record carries `ech`.
- DNS over HTTPS where the captured browser uses it. Blocker: none
  recorded; a caller can already supply an `AddressResolver` that queries
  over HTTPS, but no recipe does.

#### Caller options, off by default

Each of these needs no capture, because no named recipe may reach it
([standing rules](#standing-rules)).

- WebSocket over HTTP/3 (RFC 9220) for custom profiles. The `phantom-net`
  extended CONNECT foundation exists; no shipping browser opens one, so no
  recipe will.
- An opt-in retry of a failed exact HTTP/3 attempt over the profile's own
  HTTP/2 recipe, as a browser does once it marks an alternative broken.
- A caller-pinned Alt-Svc alternative, which needs no TLS stream to learn
  from and so could work on CONNECT-UDP.
- Racing more than one alternative, bounded and chosen by the caller.
- `Expect: 100-continue` and caller-owned conditional-request validators.
- A buffered request body that a retry may replay.
- Keepalive and address-selection settings on a custom profile.
- WebSocket reuse of a pooled HTTP/2 session on a proxy route.
- Interface binding by name on macOS and Windows (`IP_BOUND_IF`,
  `IP_UNICAST_IF`), and a client certificate chosen per origin.

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
- One naming convention across the ordered-field types and request builders.
- Query construction that never sorts, authorization value constructors, and
  `Link` parsing as data.
- JSON, form, and multipart bodies, after a POST capture shows where a
  browser places `Content-Type`; opt-in `HTTP_PROXY` and `NO_PROXY` routes.
- A default request template on the profile.
- An opt-in status-to-error conversion that keeps the response.
- A published wire-assertion harness, so downstream tests can check a request
  against a named recipe.

Non-goals: middleware that can add a field or change an order, fallback from
a proxy route to a direct connection, silent protocol fallback, automatic
`Link` following, base-URL joining, and a blocking API.

## Release to crates.io

Publish once Phase 2 has settled the public API, so the first releases do
not carry its renames. Until then, depend on a pinned git revision
([Adding Phantom to a project](guides/downstream.md)).

- Publish `btls-sys` under a Phantom name. Crates.io rejects the git
  dependency in the workspace manifest and in the vendored `btls` manifest,
  and the release script refuses to publish while either remains. Upstream
  already publishes `btls-sys` with the BoringSSL sources and every native
  patch at about 4.9 MiB, inside the 10 MiB limit.
  - Keep every native patch. Two have no upstream equivalent, and dropping
    any changes the wire.
  - Bundling BoringSSL makes Phantom a redistributor: carry the third-party
    licenses and declare a license expression that covers Apache-2.0.
  - Renaming the package does not let Phantom and a stock `boring` or `btls`
    share a dependency graph outside Linux, because symbol prefixing is
    skipped elsewhere and both ask for the same static archive names. Do not
    promise coexistence beyond Linux.
- Decide how `phantom-testkit` appears in the published manifests.
  `crates/phantom`, `crates/phantom-net`, and `crates/phantom-quic-btls` name
  it by path alone, so `cargo publish` drops it, and a downstream
  `cargo deny check --all-features` reads it as a wildcard. An exact version
  removes the warning but means publishing `phantom-testkit` too, which the
  Phase 2 wire-assertion harness may need anyway.

## Phase 3: Hardening

- Cross-platform debug and release gates, and `unwrap_used` and
  `expect_used` denied once every recoverable path has a typed error.
- Broader fuzzing, sanitizers, lifecycle regressions, and soak tests,
  including a panic across a real BoringSSL callback in `phantom-quic-btls`
  and a fuzzing seam for HTTPS-record `h3` selection.
- Audit the vendored `h3` engine against Hyperium and the
  [`0x676e67/http3`](https://github.com/0x676e67/http3) fork before its next
  refresh: port the QPACK absolute-Base fix and Hyperium's buffered-write fix,
  then review later fixes one commit at a time.
- Find which vendored `h3` patch lets a server send a field section larger
  than the client's `SETTINGS_MAX_FIELD_SECTION_SIZE`, which fails the
  upstream tests `header_too_big_server_error` and
  `header_too_big_server_error_trailers`, and restore the check.
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
