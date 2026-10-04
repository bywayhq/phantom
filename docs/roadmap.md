# Roadmap

What Phantom does today, what Phase 1 still has to deliver, and the phases
after it. It states intent, not commitments or dates; for exact current
support, see [Coverage](reference/coverage.md).

> For builders planning around Phantom and contributors choosing work.

Each phase names its main delivery focus. Idiomatic Rust, clear ownership,
accurate documentation, and green validation gates are required in every
phase, and the [standing rules](#standing-rules) apply to all of them.
Counts in the later phases come from a read-only review of `main` at
438f8de6 (2026-10-02) and change as work lands.

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
- Firefox's ECH GREASE payload length, sized from each ClientHello as NSS
  does: 240 bytes fresh and 368 resumed with the capture servers' tickets,
  over TCP and QUIC, and padded by the host text of an IP literal
  ([Firefox ECH GREASE payload](explanation/validation.md#firefox-ech-grease-payload-evidence)).
- Chromium's resend of a request whose HTTP/2 session ended with
  `ERR_HTTP2_PING_FAILED`: at once on another connection, up to twice per
  redirect hop, whatever the method
  ([HTTP/2 preface PING evidence](explanation/validation.md#http2-preface-ping-evidence)).
- Early data over TCP in the Firefox recipe: a resumed direct connection
  offers `early_data` where Firefox 157 does, sends replay-safe requests in
  it, sends them again on the same connection after a rejection, and restarts
  them without early data when the server then picks another ALPN protocol
  ([TLS resumption over TCP evidence](explanation/validation.md#tls-resumption-over-tcp-evidence)).
- Ticket resumption on `Client` WebSocket openings: a `wss://` opening
  shares the TLS session tickets of its origin's request pool, as the
  Firefox 157 `websocket` and `websocket-http1` runs resumed the page's
  ticket, so a Firefox-profile opening sends early data as they did
  ([TLS resumption over TCP evidence](explanation/validation.md#tls-resumption-over-tcp-evidence)).
- Encrypted Client Hello from an HTTPS record on direct TCP connections,
  negotiated or exact, on `wss://` openings, and on QUIC connections to the
  origin, with the Chrome 154, Edge 154, Brave 154, and Opera 136 recipes
  ([Real ECH evidence](explanation/validation.md#real-ech-evidence),
  [over QUIC](explanation/validation.md#real-ech-over-quic-evidence)).
- A TLS shutdown without `close_notify` in the Chromium-family recipes and
  with it in the Firefox recipe, through `TlsSettings::close_notify`, as the
  Chrome 154 and Firefox 157 captures of aborted responses, failed PINGs,
  and browser exit show
  ([TLS close evidence](explanation/validation.md#tls-close-evidence)).
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
- Revalidation fields in template order: `chromium::v154_windows_fetch_template`,
  `chromium::v154_macos_fetch_template`, and the Firefox 157 equivalents take a
  caller's `If-None-Match` and `If-Modified-Since` where Chrome 154 and
  Firefox 157 send them, and the cookie placements put `Cookie` before them
  ([Revalidation evidence](explanation/validation.md#revalidation-and-upload-evidence)).
- Firefox's idle PING in `firefox::v157_http2`: a zero-payload PING after
  58 seconds without a read, whether or not requests are open, and a close
  with `GOAWAY(0, INTERNAL_ERROR)` when one goes 8 seconds with nothing
  read, as Firefox 157 sent the PING on an idle pooled connection
  ([HTTP/2 idle PING evidence](explanation/validation.md#http2-idle-ping-evidence)).
- Firefox's HTTP/1.1 idle limit: `firefox::v157_http1` closes a connection
  idle 115 s on one timer per client, as Firefox 157 closed one 115.5 s
  after its last response in the hook logs
  ([Firefox socket hook evidence](explanation/validation.md#firefox-socket-hook-evidence)).
- Firefox's address selection in `firefox::v157_tcp`: an IPv4 backup
  attempt 250 ms after a slow first attempt; the slower connection kept
  idle by the HTTP/1.1 and negotiated pools on the direct route, counted
  against the bound of the pool key of the runtime that opened it,
  finished with its TLS handshake, claimable by a request, and closed once
  the first connection selects HTTP/2; and the
  address family of an origin, which later connections try alone until a
  prune of the idle timer finds the origin without a connection, as five
  Firefox 157 runs show
  ([Firefox socket hook evidence](explanation/validation.md#firefox-socket-hook-evidence)).
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
  right after `Accept` before anything is sent, as a Chrome 154 capture
  shows; a `fetch` goes out as built
  ([Fields of a repeated attempt](explanation/design.md#fields-of-a-repeated-attempt),
  [ALPS `ACCEPT_CH` restart evidence](explanation/validation.md#alps-accept_ch-restart-evidence)).
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
- Opera 136's trust-anchor ID order: `TrustAnchorIds::PerClient` and
  `PerConnection` draw an order per client or per connection, and the Opera
  recipes draw from the 16 TCP orders of 29 processes, per client, and the
  19 QUIC orders of 20 ClientHellos, per connection, at their observed
  frequencies. A test fits every retained order to Chromium 152's hash-set
  layout
  ([Opera 136 trust-anchor ID order](explanation/validation.md#opera-136-trust-anchor-id-order)).
- Windows TCP port randomization: `chromium::v154_tcp`, and so the Brave,
  Edge, and Opera profiles, set `SO_RANDOMIZE_PORT` on every TCP socket from
  Windows 11 22H2 (build 22621), as the Chrome 154, Edge 154, and Opera 136
  hook logs show, through a new audited FFI module in `phantom-net`
  ([Socket hook evidence](explanation/validation.md#socket-hook-evidence),
  [Design](explanation/design.md#windows-port-randomization-audit)).
- Windows UDP port randomization: `chromium::v154_udp`, which Brave, Edge,
  and Opera profiles take through `ClientProfile::with_udp`, sets
  `SO_RANDOMIZE_PORT` before the QUIC socket binds, direct, to a
  CONNECT-UDP proxy, or for a SOCKS5 UDP association, on every Windows, as
  Chromium 154 sets it on every UDP socket it connects and the three
  browsers' hook logs show. It goes through the same FFI module, now at the
  crate root of `phantom-net`
  ([Socket hook evidence](explanation/validation.md#socket-hook-evidence)).
- Record TTLs in the address cache: `DnsCacheSettings::min_record_ttl`
  keeps an answer that carries a record TTL for that TTL or the minimum,
  60 s in `chromium::v154_dns_cache` and none in `firefox::v157_dns_cache`.
  With the `https-records` feature, `AddressResolver::system_nameservers`
  sends Phantom's own A and AAAA queries as Chromium's built-in DNS client
  does and reports each answer's TTL; it is opt-in
  ([Chromium's built-in DNS client](explanation/validation.md#chromiums-built-in-dns-client)).
- Phantom's own DNS query sockets, for HTTPS records and addresses, take
  the profile's `UdpSettings`: with `chromium::v154_udp` on Windows each
  sets `SO_RANDOMIZE_PORT` and binds port 0, through a hickory
  `RuntimeProvider` that binds as the QUIC sockets do
  ([UDP socket option evidence](explanation/validation.md#udp-socket-option-evidence)).

### Remaining

Each entry names what exists as evidence and what blocks the work, if
anything does.

#### Browser recipes

- Firefox HTTP/3 beyond the recipe. Delivered: `firefox::v157_http3_tls`,
  `v157_quic`, `v157_http3`, and `v157_http3_request` from Firefox 157.0
  captures, with QUIC v2 and compatible version negotiation, and the QUIC
  ClientHello's fixed tail of `quic_transport_parameters` and
  `encrypted_client_hello` and its `record_size_limit`,
  `extended_master_secret`, and `renegotiation_info` extensions
  ([Validation](explanation/validation.md#firefox-157-http3-recipe)).
  Remaining: the position of `Alt-Used`. Blocker: a template slot for a
  field the client generates.
- macOS beyond client hints and request fields. Delivered: `macos` client
  hints for Chrome 154, Edge 154, and Opera 136 and `macos` request
  templates for Chrome 154 and Firefox 157, from macOS 15.5 captures on an
  Apple silicon Mac, with single runs of the TCP, QUIC, H2, and H3 layers
  replayed against the Windows recipes
  ([Validation](explanation/validation.md#macos-recipes)). Remaining: a
  literal Chromium-family `User-Agent`, which needs a headful capture; the
  idle-only TCP keepalive, known from Chromium source but not captured; Intel
  Macs and other macOS versions. Blocker: a headful launch on the capture
  host and an Intel Mac.
- Firefox for Android beyond TLS. Evidence: `firefox_android::v156_tls` only.
  Blocker: trusting a test certificate on Android, such as a user CA with
  `security.enterprise_roots.enabled`.
- Chrome for Android on a phone. Evidence: Chrome 154.0.8037.57 captures on
  an Android 17 emulator that reports a Pixel 7 back
  `chrome_android::v154_*`, and Play served that build to the emulator; no
  record compares it with the stable version Google lists. Blocker: a
  physical device, to check the emulator's CPU and network against a phone.
  The emulator hides TCP, so the Android TCP layer also needs a phone.
- Firefox's address selection beyond direct HTTP/1.1 and negotiated
  requests. Evidence: Firefox keeps the slower backup connection and the
  address family on every connection entry, proxies, WebSocket, and HTTP/2
  included, and skips an address that failed to connect on the same cached
  DNS record (`netwerk/protocol/http/DnsAndConnectSocket.cpp:671-745`,
  `netwerk/base/nsSocketTransport2.cpp:1742-1745`); no hook log covers
  these routes, and Phantom closes the slower attempt there, learns no
  family, and tries a failed address again
  ([TCP socket option evidence](explanation/validation.md#tcp-socket-option-evidence)).
  Blocker: the proxy, WebSocket, exact HTTP/2, and ECH connectors return one
  connection and take no family, and the address cache records no connect
  failures.

#### Wire fidelity

- Opera's unobserved trust-anchor ID orders. Evidence: each Opera 136
  order is the iteration order of a hash-set copy, set by an 8-bit seed and
  the order of the set it copies; the recipes draw only the 35 retained
  orders, and draw a client's TCP and QUIC orders independently, where one
  Opera process derives them all from one source set
  ([Opera 136 trust-anchor ID order](explanation/validation.md#opera-136-trust-anchor-id-order)).
  Blocker: generating new orders needs the source set's order and the seed
  distribution, which no capture shows; the seed comes from a thread-local
  counter, and one seed served 5 of 29 processes.
- Chromium's built-in DNS client as the default resolver of the
  Chromium-family profiles. Evidence: with their default resolver, Chrome
  154, Edge 154, and Opera 136 sent their own HTTPS and A queries and kept
  the answer for the record's TTL
  ([Socket hook evidence](explanation/validation.md#socket-hook-evidence));
  `AddressResolver::system_nameservers` does the same when a caller passes
  it. Blocker: Chromium's per-platform reading of the DNS configuration,
  which takes the first adapter's servers on Windows and falls back to the
  system resolver for a VPN adapter, a name resolution policy, a DNS proxy,
  or different servers per adapter
  (`net/dns/dns_config_service_win.cc:411-502`), with its own rules on macOS
  and Linux; and the `https-records` feature, which the resolver needs and
  the default build lacks
  ([Chromium's built-in DNS client](explanation/validation.md#chromiums-built-in-dns-client)).
- Firefox's record TTL on Windows. Evidence: Firefox 157 reads the record
  TTL from the operating system's cache with `DnsQuery_A` after each lookup
  and kept a 1,757-second answer
  ([Firefox socket hook evidence](explanation/validation.md#firefox-socket-hook-evidence));
  `firefox::v157_dns_cache` honors a record TTL, but Phantom's system
  lookups report none. Blocker: `DnsQuery_A` needs a new audited FFI
  boundary; Phantom's own queries would leave from its process, not the
  operating system's resolver as Firefox's do.
- Firefox's choice of ticket for a request after a WebSocket. Evidence: in
  every Firefox 157 `websocket-http1` run, the `/done` request after the
  WebSocket resumed a ticket the page's connection was issued, not one the
  WebSocket's connection was issued
  ([TLS resumption over TCP evidence](explanation/validation.md#tls-resumption-over-tcp-evidence));
  Phantom presents the newest ticket of the request pool key, which the
  WebSocket's connection was issued. Blocker: NSS's token cache order for a
  peer, checked against `FIREFOX_157_0_RELEASE`, and whether Firefox stores
  the tickets of a WebSocket connection at all.
- Early data on connections that offer ECH from HTTPS records. Evidence:
  NSS offers `early_data` in both ClientHellos of a resumed ECH connection,
  and Firefox 157 disables TCP early data only on proxy connections and
  origins that failed before
  ([TLS resumption over TCP evidence](explanation/validation.md#tls-resumption-over-tcp-evidence)).
  Blocker: no Firefox recipe offers ECH from HTTPS records, since Firefox
  waits for the record only over DNS over HTTPS; with early data, Phantom's
  retry after an ECH rejection would also have to move from the handshake to
  the request.
- Firefox's close of an idle HTTP/2 connection. Evidence: Firefox 157
  stops reusing an HTTP/2 connection whose last HEADERS or DATA read is
  `network.http.http2.timeout`, 170 seconds, old
  (`netwerk/protocol/http/nsHttpConnection.cpp:414`, `:982`, `:1002-1017` at
  `FIREFOX_157_0_RELEASE`); `firefox::v157_http2` keeps it, answering its
  idle PING
  ([HTTP/2 idle PING evidence](explanation/validation.md#http2-idle-ping-evidence)).
  Blocker: no capture shows the close or what Firefox writes for it.
- Validator slots in the Edge, Brave, Opera, and Android templates.
  Evidence: Chrome 154 and Firefox 157 place `If-None-Match` and
  `If-Modified-Since` as their default-mode `fetch` templates do
  ([Revalidation evidence](explanation/validation.md#revalidation-and-upload-evidence)),
  and the other Chromium-family browsers share Chromium's network stack.
  Blocker: no revalidation capture of those browsers.
- The next Alt-Svc alternative after a broken one. Evidence: Chrome 154
  uses the first alternative a field lists, races no other, and moves to the
  next once the first is broken
  ([Alt-Svc racing evidence](explanation/validation.md#alt-svc-racing-evidence));
  Phantom stores only the first. Blocker: the Alt-Svc store and its
  snapshots must keep every listed alternative, with brokenness for each.

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
- `Expect: 100-continue`, which neither Chrome 154 nor Firefox 157 sends on
  any `fetch`, `FormData`, or form upload
  ([Upload evidence](explanation/validation.md#revalidation-and-upload-evidence)),
  and caller-owned conditional-request validators.
- A buffered request body that a retry may replay.
- WebSocket reuse of a pooled HTTP/2 session on a proxy route.
- Interface binding by name on macOS and Windows (`IP_BOUND_IF`,
  `IP_UNICAST_IF`), and a client certificate chosen per origin.

### Proposed after Phase 1

Each starts from a proposal with acceptance criteria and, where it touches
the wire, capture evidence.

- HTTP/3 with verification off. The `danger-disable-verification` feature's
  `ServerAuthentication::DangerDisabled` already skips chain and name
  verification over HTTP/1.1 and HTTP/2, for example to debug through an
  intercepting proxy, and changes no wire field.
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

Phase 2 settles the public API before the first release, so it starts with
the structural changes that would otherwise break published crates. They
wait for Phase 1, so they cover every route and setting it adds. A lint
baseline comes first, so the lints guide the refactor rather than follow it.

- A workspace lint baseline: `missing_debug_implementations`,
  `rust_2018_idioms`, a chosen subset of `clippy::pedantic` (such as
  `must_use_candidate`, `needless_pass_by_value`, `doc_markdown`, and the
  `cast_*` lints), and `clippy::cargo` for the release. Each lint is fixed
  across the workspace before it is turned on.
- Replace the route-specific public API of `phantom-net` (109 methods on
  five connectors and 14 free functions; 84 `pub fn` names spell out a
  route, such as `upgrade_get_plaintext_https_connect_with_basic_auth`) with
  one connect, send, and upgrade operation per protocol that takes a route
  value, and build the connection leg in one place. This removes most of
  the duplication between `http1/tls.rs` and `http2/tls.rs`, most of the 89
  `too_many_arguments` allowances in `phantom-net`, and the 9
  `match route` blocks in 6 pool and WebSocket files. It changes no wire
  field or order: every fixture replay stays byte-identical.
- Narrow what `phantom-net` and `phantom-quic-btls` publish. 104 of
  `phantom-net`'s 543 non-test `pub` items are named by no other crate,
  example, or test, 9 `pub` functions have no caller at all, and 12
  `#[doc(hidden)] pub` items carry plumbing between crates.
  `phantom-quic-btls` exports packet-protection primitives, such as
  `derive_initial_keys`, `HeaderProtectionKey`, and `retry_integrity_tag`,
  that only its own tests use. Make them `pub(crate)` and check the result
  with `cargo public-api`.
- `#[non_exhaustive]` on the 24 exhaustive public enums of `phantom-net`,
  among them its 6 error enums and 9 error-kind enums, so a new failure
  mode is not a breaking change. `phantom` already marks 18 of its 21 enums
  and `phantom-profile` 48 of 51.
- Keep vendored-fork types out of `phantom-net`'s public API: `Http1Error`
  wraps `wreq_proto::Error` and `Http3Error` has a public
  `From<h3::error::StreamError>`, so refreshing a fork is a semver break.
  Wrap foreign errors in opaque types reached through `source()`, and list
  each crate's intended public dependencies, such as the `btls` and
  `quinn-proto` types `phantom-quic-btls` names as a quinn crypto provider.
- Decide how the 26 public profile settings structs (135 `pub` fields)
  grow: `#[non_exhaustive]` with constructors, or an explicit versioning
  policy. Let the constructors make invalid combinations unrepresentable.
  `TlsSettings` pairs `session_tickets: bool` with a per-origin count and
  `ech_grease: bool` with a payload policy, and accepts a `min_version`
  above `max_version`; today only the 10 `validate()` methods, with about
  144 rejection sites, catch these when `ClientBuilder::build` runs.
- Group the 23 public `phantom-profile` modules: browser recipes under one
  module beside the protocol settings modules, with one naming rule for
  Chrome and Chromium (today `chromium` holds the Chrome desktop recipes and
  `chrome_android` the Android ones).
- Check every public type against the
  [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html):
  common traits derived where they make sense (no `phantom-profile` type
  derives `Hash`), `Send` and `Sync` asserted in tests (no error type is
  today), `as_`, `to_`, and `into_` naming, consistent builders, `# Errors`
  and `# Panics` sections, an example on each public item, and
  `#[must_use]` where dropping a value is a bug. Today 7 of `phantom`'s 282
  public functions have an example and the other library crates have none.
  `# Errors` is on every `phantom` function that returns `Result`, but on 88
  of 218 in `phantom-net`, 5 of 12 in `phantom-profile`, and 1 of 28 in
  `phantom-quic-btls`.
- `From` and `TryFrom` where a constructor is a conversion, such as
  `CipherSuite::from_iana_id`, `QuicVersion::from_wire`, and
  `RequestBody::from_bytes`; enums in place of value-selecting `bool`
  parameters, such as `RequestField::default_value(trustworthy)`; and a
  `Stream` impl on the SSE types, which offer only `next_event()` while
  `WebSocket` implements `Stream` and `Sink`.
- Public errors with a stable `kind()`, a `source()` chain, and lowercase
  messages without trailing punctuation; enums or newtypes in place of
  strings a caller would match on. The messages already meet the style
  rule. The gaps: 23 of the 47 library error types have no `kind()`, 14 of
  them classify by a `&'static str` field name, and 13 types print their
  cause in `Display` and also return it from `source()`, so a chain
  reporter prints each cause once per level above it.
- Named types in place of bare primitives and nested collections in public
  settings where the meaning is not obvious, such as the
  `Vec<Vec<Box<[u8]>>>` of trust-anchor orders.
- Composed per-browser profile constructors, such as `chromium::v154()`, so
  a caller cannot pair the HTTP/3 leg with the TCP ClientHello by mistake.
- Error triage over `kind()`, a public replay-safety accessor, the
  response carried on errors that have one, and the origin (scheme, host,
  and port, never the full URI) on `RequestError`.
- Bounded `text()`, `bytes()`, and typed-JSON helpers that never set a
  request field.
- Re-exports of the types the public API names, such as `Bytes`,
  `http::Response`, `StatusCode`, and `Uri`, and of the five profile types
  reachable only through public fields, such as `Http2StreamSettings`.
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
- Measure the public API with `cargo public-api`, and check each release
  against the previous one with `cargo semver-checks`.
- Check the vendored forks against security advisories before the first
  publish. RustSec and `cargo deny` match advisories by registry crate
  name, so none reaches the nine renamed `phantom-*` forks of h2, h3,
  quinn, quinn-proto, tungstenite, btls, and the others; the http2 fork's
  RUSTSEC-2026-0258 fix was found and backported by hand
  ([`vendor/http2/PHANTOM.md`](../vendor/http2/PHANTOM.md)). Look up each
  fork's upstream name and version in the weekly freshness job, fail on an
  unaddressed advisory, and record the handled ones in its `PHANTOM.md`.
- Turn the further-reading paths in the `phantom` crate docs into absolute
  repository links. They are code spans today, which a docs.rs reader
  cannot follow.

## Phase 3: Hardening

- Cross-platform debug and release gates. Non-test code already has no
  `unwrap`, `expect`, or panicking macro; turn the `unwrap_used` and
  `expect_used` lints from warn to deny, and allow them in tests through
  `clippy.toml` instead of the `unwrap_or_else(|_| panic!(..))` workaround.
- Coverage reports, `cargo hack` feature-powerset checks in place of the
  hand-written feature rows, and a minimal-versions check.
- Miri on the pure-Rust codecs (HPACK, frames, DNS and HTTPS records, ECH
  configurations, SOCKS5, Alt-Svc, cookie snapshots, HTTP/1.1 response
  parsing), `clippy::indexing_slicing` on the same parsers, and a loom or
  deterministic-scheduler test for pool admission and setup waiters.
- One SOCKS5 negotiation for TCP CONNECT and UDP ASSOCIATE; today TCP uses
  `tokio-socks` and UDP a separate implementation, so their greetings are not
  guaranteed to match.
- Broader fuzzing, sanitizers, lifecycle regressions, and soak tests,
  including a panic across a real BoringSSL callback in `phantom-quic-btls`
  and a fuzzing seam for HTTPS-record `h3` selection. Peer-facing parsers
  with no fuzz target: Alt-Svc fields, SSE, the content-coding pipeline and
  its gzip header parser, CONNECT-UDP capsules, SOCKS5 replies, ALPS
  `ACCEPT_CH`, `Retry-After`, the WebSocket handshake checks, QUIC header
  protection and the Retry tag, and the vendored HPACK and QPACK engines.
  Two of the 11 targets, `client_hello` and `http2_frame`, fuzz testkit
  parsers rather than the production ones.
- An async correctness audit: cancellation safety at every `select!` and
  dropped future, no lock held across an `.await`, no detached task that
  outlives its owner, no blocking call on a runtime thread, and `Send` bounds
  on public futures. Known sites: the HTTP/3 session sender, a Tokio mutex
  held across `send_request().await`, which waits on stream credit and flow
  control; the HTTP/3 connect turn, a mutex guard held across connection
  setup; pool state behind Tokio mutexes although no critical section
  awaits, with every stream end waking every setup waiter; and no `Send`
  assertion for the futures of `collect_with_limit` and of the WebSocket
  `send`, `receive`, and `close`.
- A resource lifecycle audit: each per-client store's bound, what drop and
  shutdown release, timers cancelled with their owner, and the threads and
  runtimes the library starts. Known gaps: in-flight HTTPS-record lookups
  have no count bound, where the address cache caps shared resolutions at
  its capacity, and a `from_fn` resolver has no time bound; an orphaned
  Alt-Svc setup holds a `Client` clone, so dropping the client does not
  release its pools until the setup ends; `Client` has no shutdown method;
  idle connections close only on checkout or eviction, unless the profile
  sets `Http1IdleTimeout::ClosedOnTimer`, as the Firefox recipes do, whose
  client-wide timer closes idle HTTP/1.1 connections at their limit on
  every runtime; pool entries opened on a runtime that was dropped keep
  their sockets until the pool evicts them, because nothing tells a pool
  that a runtime ended, though that timer removes their idle HTTP/1.1
  connections; evicting a pool
  entry with a setup in flight lets a second setup exceed the per-key
  bound for a while; qlog output writes files on runtime threads with no
  size bound; and the first use of the process-wide
  `phantom-shutdown-timer` thread blocks the calling runtime thread until
  that thread has built its runtime.
- A secrets audit: proxy credentials, cookies, and authorization values
  kept out of `Debug` output and tracing fields and zeroized on drop
  (`zeroize` covers only QUIC and TLS key material today), and parser
  limits against oversized headers and decompression bombs.
- Input limits that the per-field caps miss. The default cookie limits
  allow about 720 KiB of cookies per domain against a 32 KiB request-header
  cap, so one origin can make every later request to its domain fail
  locally. `br, br, br` holds about 48 MiB of decoder windows from a few
  bytes, which the decoded-bytes cap does not count. The HTTP/1.1 response
  head is parsed again from byte 0 on every read
  (`phantom-net/src/http1/response_head.rs`), quadratic in the bytes of a
  server that trickles them.
- Document that Phantom checks neither revocation nor Certificate
  Transparency: it requests OCSP staples and SCTs for the fingerprint only
  and trusts only the bundled `webpki-root-certs`. Decide whether a custom
  profile may keep the TLS 1.0 minimum that validation allows today, or
  needs an explicit opt-in below 1.2.
- Build `zstd` without its default features, whose `legacy` decoders for
  the v0.1 to v0.7 formats read peer bodies today, and run `cargo deny`
  over `fuzz/Cargo.lock` (240 packages), which the root check skips.
- Tighten the unsafe-code boundary. `fuzz/Cargo.toml` has no `[lints]`
  table, and `check-unsafe-boundaries.sh` fails a manifest that allows
  `unsafe_code` but not one that omits the lint; it also reads attributes
  line by line, so it misses a multi-line `allow(...)`. `phantom-net` and
  `phantom-quic-btls` copy the workspace lint table instead of inheriting
  it. In `phantom-quic-btls`, drop the redundant `unsafe impl Send` and
  `Sync` for `AesHeaderCipher`, and correct two SAFETY comments in
  `quic_callbacks.rs`: one omits the non-zero-size precondition of
  `alloc`, and one calls a built `SslContext` immutable, which
  `set_ech_keys(&self)` contradicts.
- Run tests at default features: every test runs with `--all-features`,
  so the off-state stubs are compiled but never run, and the Windows and
  macOS jobs build no reduced feature set. Compile the branches no job
  builds: Android interface binding, which Phase 1 and the `SourceBinding`
  rustdoc claim; the fallback for targets outside the 16-target list in
  `phantom-net/src/tcp.rs`, which is written out three times; and its
  OpenBSD, Haiku, and Vita exclusion. Otherwise narrow the claims to Linux.
- Tests that do not depend on wall-clock speed: 16 real-time upper-bound
  asserts (such as `http2/tests/preface_ping.rs`, which expects 5 to 7 s
  over real 4 and 2 s waits), two test servers that stop accepting after a
  300 or 500 ms quiet spell, and 110 real-time sleeps; only 11 files pause
  the clock. Assert ordering and lower bounds, and stop servers on an
  explicit signal. Paused time cannot reach code on `std::time`, such as
  Alt-Svc expiry and backoff and the DNS cache TTL: non-test code reads
  `std::time::Instant` 35 times and `tokio::time::Instant` 18 times, so
  give each crate one clock.
- Make skipped tests visible: 8 runtime skip paths print `skipped:` and
  pass, so a runner that lost a capability, such as port randomization or
  interface binding, looks green.
- Close the gaps between the gate and CI. From 2026-09-25 to 2026-10-02
  `main` failed on macOS for 67 runs and nothing reported it; alert when
  `main` fails twice in a row. The nightly recursion check, which guards
  `Send` on public futures, runs only in a local gate with that nightly
  installed, and the fuzz crate's lints and tests only in the advisory,
  path-filtered fuzz workflow. The full gate runs no ShellCheck,
  `cargo deny`, `check-downstream.sh`, script self-tests, or release-link
  test, all of which CI runs, and CI's ShellCheck covers 15 of the 20
  shell scripts.
- Check every copy of a toolchain version: `check-tool-pins.sh` checks
  none of the hard-coded copies of the 1.88.0 MSRV (in the Platform job,
  AGENTS.md, CONTRIBUTING.md, README.md, and others), the btls 1.85.0 MSRV,
  or the `rust:1.99.0` images of the conformance Dockerfiles.
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
  platform. JA4T is published under the FoxIO License 1.1, unlike JA3 and
  JA4; check its terms before Phantom tooling computes it.
- A bounded spike on [compio](https://github.com/compio-rs/compio) support
  behind a narrow runtime seam in `phantom-net`, adopted only with
  byte-identical wire evidence.

## Phase 4: Profiling and optimization

- Measure the cold cost of building a client for each supported profile.
- Profile cold and warm connections, proxy routes, multiplexing, streaming
  bodies, SSE, and WebSocket workloads.
- Optimize only measured bottlenecks, keeping the packet, frame, ordering,
  cancellation, and bounded-resource evidence.
- Build health: compile time, generic code that monomorphizes per profile or
  route, binary size of a minimal client, and dependencies that add build
  time for little use. Starting points: 48 `async fn`s in `phantom-net` are
  generic over the stream type, behind 55 connection-setup futures (the
  largest 9,248 bytes against a 12 KiB budget); 8 crates are locked at two
  versions, such as `syn` 2 and 3 and `thiserror` 1 through `tokio-socks`,
  which `deny.toml` allows; 11 dependencies, `tokio` among them, repeat
  across member manifests instead of `[workspace.dependencies]`; and no
  `[profile.release]` is set.
- CI cost. The fuzz workflow takes 71 runner-minutes for 15 s of fuzzing
  per target, because each of its 11 jobs rebuilds the ASan fuzz crate and
  9 build `cargo-fuzz` from source. The Downstream and Vendor jobs run
  without a Cargo cache. Real protocol timers set test time: 40 tests take
  over 1 s on Linux, the slowest 7.5 s, waiting on HTTP/2 `PING` and
  keepalive timers.

## Phase 5: Architecture audit

- Audit the workspace for readable, idiomatic Rust once functionality and
  measured optimization have settled the real boundaries: naming, module
  ownership, seams, and file layout. It changes no public API; the
  structural changes that do open [Phase 2](#phase-2-ergonomics).
- A readability pass by a human reviewer for code that passes the lints but
  reads as generated: over-parameterized helpers, deeply nested `match`
  blocks, defensive branches for states that cannot occur, and names that
  spell out a whole call path. 45 non-test functions exceed 100 lines and
  9 exceed 200, such as `connect_http1` in `phantom/src/websocket/http1.rs`
  (345 lines) and `ClientBuilder::build` (326); the deepest, the two proxy
  Basic authentication exchanges, nest 7 and 8 brace levels.
- Inline comments where the code needs them. Counted over non-test,
  non-blank lines with rustdoc excluded, Phantom's inline comments are
  1.23% of lines, against 3.44% in quinn 0.11.12, 3.58% in rustls 0.23.45,
  4.76% in hyper 1.11.1, 5.83% in quinn-proto 0.11.19, and 6.46% in h2
  0.4.19. The pools already carry 3.7 to 5.0 comments per 100 code lines;
  the gap is branchy functions with no invariant comment. Start with
  `send_prepared_request` in `phantom-net/src/http1/connection.rs`, which
  holds a Tokio mutex across `.await` as an exception to a standing rule,
  then the `biased` select in `http3/body/task.rs`, the nested `Option` in
  `http2/upload.rs`, and the phase changes in `tls/early_data.rs`.
- Test files split by behavior where they pass about 1,500 lines (3 today,
  the largest `phantom-profile/src/request_template/tests.rs` at 2,039),
  and table-driven tests where cases differ only by data (23 groups of 50
  structurally identical tests, most of them per-browser recipe tests).
- Decide retry, replay, and early-data handling from typed fields set where an
  error is created, instead of downcasting error chains to `phantom-net`
  types at 11 sites.
- Give the five connection pools one core for origin entries, admission,
  setup waiters, ECH choice, and lease guards: the four in
  `phantom/src/session` (5,342 lines, each with its own `PoolState`,
  `PoolKey`, `PoolEntry`, and `ConnectionLease`) and `Http2ProxyPool` in
  `phantom-net`, whose crate docs say it owns no pools. Pass one request
  context into the pools in place of the 15 to 17 inputs of each
  `send_request`, which keep the 25 `too_many_arguments` allowances in
  `phantom` that the Phase 2 route value leaves. Split functions longer
  than 100 lines, and add invariant comments to the most deeply nested
  state machines.
- One runtime seam. 20 `Handle::try_current` checks in 12 files and 15
  `RuntimeUnavailable` variants each check the runtime; probe it once when
  the client is built, and route spawn, sleep, and dial through one module,
  the seam the Phase 3 compio spike needs.
- Test hooks out of production types: production files carry 225
  `#[cfg(test)]` attributes outside `mod tests`, 67 of them on struct
  fields, most in `phantom-net/src/http3`. Give each owner one test-only
  hooks field.
- One copy of each private helper: the span-outcome drop guard (11 copies
  across `phantom` and `phantom-net`), `is_token_byte` (3 in
  `phantom-profile`), and the WebSocket handshake's nonce, base64, and
  SHA-1 calls, which reach `btls` directly and are the only reason the
  `websocket` feature pulls `btls` into `phantom-http`.
- Allowances that fail when stale: 23 `too_many_arguments` allowances sit
  on functions with 7 inputs, which the lint does not flag, and
  module-level `dead_code` allowances in `phantom-quic-btls` cover 1,884
  lines and hide an uncalled `into_packet_key`. Use `#[expect]` instead.
- Move test helpers copied across test files into `phantom-testkit` or
  `tests/support`. 90 helper names are defined in 3 or more files,
  `bounded` in 49 and `const TEST_TIMEOUT` in 58 with four values, and a
  blanket `allow(dead_code)` on `tests/support` hides the unused ones.
- Bring the file layout to the test-placement and module-file rules in
  [AGENTS.md](../AGENTS.md#code-and-documentation): fold back inline the 31
  of the 44 `tests.rs`-only directories whose tests are 300 lines or fewer,
  and the 6 in `fuzz/src`; move the 3 inline test modules over 300 lines
  (`retry.rs`, `client.rs`, `socks5_udp.rs`) to `tests.rs` files; drop the
  22 redundant `#[path]` attributes of the 39; replace the 7 `mod.rs` files
  (4 in `phantom-net`, 2 in `phantom-testkit`, and `tests/support/mod.rs`)
  and enforce the rule with Clippy's `mod_module_files`; move test-only
  code such as `tracing_test.rs` out of `src`; place the Windows FFI module
  with its owner; and split source files over about 1,500 lines (9 today),
  such as `client.rs`, along protocol lines. `http1/tls.rs` repeats 52% of
  its lines within itself and should fall below 1,000 lines through the
  Phase 2 route value rather than a split.
- Keep capture history in [Validation](explanation/validation.md) rather
  than in recipe rustdoc, which is 35.1% of `phantom-profile`'s lines
  against 13.7 to 22.3% in the peers above, and split Validation into one
  evidence page per browser.
- Give `phantom-profile` a crate page: one line covers its 23 public
  modules today. Explain the `<browser>::v<N>_<layer>` naming and which
  layers a `ClientProfile` takes, with one composed example.
- Re-read at the `154.0.8037.58` tag the 11 Chromium source citations still
  pinned to `153.0.8010.48` (cookies, Alt-Svc policy, address racing, and
  TCP settings), or make the re-read a step of each recipe refresh.
- Add the last-checked date that
  [Writing the documentation](internals/documentation.md#claims) requires
  to the [At a glance](reference/coverage.md#at-a-glance) table of Coverage
  and to the table in [Profile reference](reference/profiles.md).
- Keep wire fixtures, public API contracts, diagnostics, cancellation
  behavior, and the full gates through every behavior-preserving refactor.
- Audit the tooling (capture and conformance scripts, CI and release scripts,
  development helpers, workflows, and agent configuration), remove what no
  gate uses, and keep documented commands in step with CI. Start with
  `scripts/dev/consolidate_integration_tests.py`, a finished one-off
  migration whose tests still run in the gate and CI, and the copied script
  code: 11 groups of byte-identical Python helpers across the capture and
  conformance scripts, and shell functions copied between the
  upstream-freshness scripts.

## Next

- [Coverage](reference/coverage.md): what is supported today, layer by layer.
- [Validation](explanation/validation.md): the evidence behind each complete
  item.
- [Contributing](../CONTRIBUTING.md): how to take on a remaining item.
