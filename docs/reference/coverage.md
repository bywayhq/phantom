# Coverage

Phantom's support contract lists what works today and what is planned, layer
by layer. Anything it does not list as supported is unsupported.

> For evaluators deciding whether Phantom fits, and specialists checking a
> claim. Read [How servers recognize a client](../fingerprinting.md) first if
> fingerprinting is new to you.

## At a glance

Phantom reproduces what an HTTP client sends on the network. It does not
provide a DOM, JavaScript, rendering, canvas, fonts, WebRTC, or device
fingerprinting. Each layer is listed separately, so a TLS match is never
presented as a complete client match.

| Browser | TCP | TLS | H1 | H2 | QUIC | H3 | Client hints | Request templates | WebSocket opening |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Chrome 154 | Browser source | Captured | Captured | Captured | Captured | Captured | Captured | Captured | Captured |
| Edge 154 | Not covered | Captured | Captured | Captured | Captured | Captured | Captured | Captured | Captured |
| Brave 154 | Browser source | Captured | Captured | Captured | Captured | Captured | Captured | Captured | Captured |
| Opera 135 | Not covered | Captured | Captured | Captured | Captured | Captured | Captured | Captured | Captured |
| Firefox 156 | Browser source, partial | Captured | Captured | Captured | Not covered | Not covered | Not sent by Firefox | Captured | Captured |
| Firefox 156 for Android | Not covered | Captured | Not covered | Not covered | Not covered | Not covered | Not sent by Firefox | Not covered | Not covered |
| Opera 102 for Android | Not covered | Captured | Not covered | Not covered | Not covered | Not covered | Captured | Not covered | Not covered |
| Brave 153 for Android | Not covered | Captured | Captured | Captured | Captured | Captured | Captured | Captured | Captured |
| Chrome 154 for Android | Not covered | Captured | Captured | Captured | Captured | Captured | Captured | Captured | Captured |
| Edge 153 for Android | Not covered | Captured | Captured | Captured | Captured | Captured | Captured | Captured | Not covered |

- **Captured**: a [recipe](glossary.md#recipe) or
  [request template](glossary.md#request-template) is compared in tests with
  retained [captures](glossary.md#capture) of that browser build.
- **Browser source**: taken from the browser's source code at the release tag,
  because a capture cannot show it. Firefox's recipe sets `TCP_NODELAY` only.
- **Not covered**: no recipe exists, and none is claimed.

Read the matrix with these conditions:

- Every desktop capture comes from one Windows 11 build (10.0.26200), except
  the macOS 15.5 arm64 captures behind the `macos` recipes. Those cover
  client hints and request fields, with single runs of the other captured
  layers; no Linux capture exists, so platform independence is not claimed
  beyond them. The Android captures come from emulators, not from a phone,
  with Wi-Fi as the default network: an Android 17 emulator on the Windows
  host that reports a Pixel 7, an earlier Android 15 emulator for the Chrome
  153 cellular startup, some Brave layers, and Firefox, and an arm64
  Android 17 emulator on a Mac for Edge.
- H1's captured part is the request field order that request templates
  carry. The Chrome and Firefox recipes set a connection bound
  (`Http1Settings`) of 6 per origin and route, from browser source; without
  them the bound is 1. Brave uses the Chromium one, since it builds the same
  Chromium tag without changing the bound; Edge and Opera have no H1
  connection recipe.
- Edge's, Brave's, and Opera's H2, QUIC, H3, and WebSocket layers use the
  Chromium recipes, which equal their captures on every compared field.
  Opera 135 is built on Chromium 151 and is compared with the Chrome 154
  recipes, the only Chromium version Phantom carries. So do Chrome's,
  Edge's, and Brave's for Android, except that Edge for Android has no
  WebSocket recipe.
- The emulator's network hides the device's TCP connections, so the Android
  browsers have no TCP, HTTP/1.1 connection, or address-cache recipe.
- Firefox's H2 recipe rests on H2 session captures, not on raw startup bytes.
- Navigation templates cover H1, H2, and H3 for Chrome, Edge, Brave, Opera,
  and Brave for Android, and H1 and H2 for Firefox. For Chrome and Edge for
  Android, the H1 and H2 lists are compared with typed captures; their H3
  list is the Chromium one, compared with H3 captures opened by intent.
  Fetch templates cover H1 and H2 for all eight.
- Server-sent events (SSE) reconnects are captured for Chrome 154 and Firefox
  156 over plaintext H1 only.

[Validation](../explanation/validation.md) holds the evidence for every
"Captured" and "Browser source" cell.

## What "supported" means

A feature is supported only when its whole lifecycle works: configuration,
validation, what Phantom sends, response handling, cancellation, errors,
observability, and deterministic tests. Parsing an option or completing a
connection is not enough.

## Contents

- [Layer summary](#layer-summary)
- [TCP](#tcp)
- [TLS over TCP](#tls-over-tcp)
- [HTTP/1.1](#http11)
- [HTTP/2](#http2)
- [QUIC](#quic)
- [HTTP/3](#http3)
- [Public client](#public-client)
- [Cross-request state](#cross-request-state)
- [Server-sent events and WebSocket](#server-sent-events-and-websocket)
- [Routes](#routes)
- [Validation](#validation)
- [Browser profiles](#browser-profiles)
- [Claim boundary](#claim-boundary)

## Layer summary

| Layer | Summary | Main gaps |
| --- | --- | --- |
| TCP | Profile `TCP_NODELAY`, keepalive, and Chromium Happy Eyeballs from browser source, on every TCP path | Firefox keepalive and address selection |
| TLS over TCP | Typed ordered ClientHellos from retained captures | More versions and platforms |
| HTTP/1.1 | Ordered streaming requests and responses, keep-alive reuse, browser per-host connection bounds | Broader retry classes |
| HTTP/2 | Ordered SETTINGS, fields, priority, multiplexing, extended CONNECT, profile HPACK encoder identity and stream numbering | Firefox stream `WINDOW_UPDATE` |
| QUIC | BoringSSL-backed Quinn with captured transport parameters | Generic non-H3 connection API |
| HTTP/3 | Exact H3 over direct, SOCKS5, or CONNECT-UDP; opt-in Alt-Svc upgrade and racing over direct and SOCKS5 | Multiple-alternative racing |
| Routes | Direct, HTTP forward and CONNECT, SOCKS5, CONNECT-UDP | Other proxy authentication schemes |
| SSE and WebSocket | Feature-gated, bounded, with browser comparisons and Chrome/Firefox WebSocket recipes | H2/H3 SSE captures, proxy WebSocket captures |

The [route matrix](route-matrix.md) lists every combination of scheme,
protocol, and [route](glossary.md#route). H1, H2, and H3 mean HTTP/1.1,
HTTP/2, and HTTP/3; [exact](glossary.md#exact-protocol) and
[negotiated](glossary.md#negotiated-protocol) requests are defined in the
glossary.

## TCP

Supported:

- Profile TCP socket options (`ClientProfile::with_tcp`): `TCP_NODELAY`, and
  keepalive idle time and interval. Phantom applies them before connecting, on
  every TCP connection, including proxy connections and SOCKS5 UDP control
  connections. If the OS rejects an option, that connection attempt fails.
- Profile address racing (`TcpAddressRacing`): Chromium's Happy Eyeballs v2
  over the complete resolver result. At most two attempts run at once, the
  losing attempt is cancelled, and the most recent failure is returned.
- The recipes `chromium::v154_tcp` (Windows and Linux) and
  `firefox::v156_tcp` (`TCP_NODELAY` only, attempts in resolver order), both
  taken from browser source. See
  [TCP socket option evidence](../explanation/validation.md#tcp-socket-option-evidence).

Not modeled:

- Firefox's per-connection keepalive schedule and its address selection.
- Chromium's macOS idle-only keepalive as a named recipe.
- Chromium's resolver behavior before racing: its own address sorting, IPv6
  reachability probe, partial DNS results, and HTTPS records fetched with the
  address queries. Phantom races the system resolver's complete answer.
- Racing for HTTP/3. Chromium's QUIC job connects only to the first resolved
  address. Phantom's H3 connector tries the resolved addresses in order after
  a connection failure.
- An Edge or Opera TCP recipe. No capture shows their options, and their
  network source is not public. Brave uses `chromium::v154_tcp`: Brave
  1.96.59 builds Chromium tag `154.0.8037.58` and changes none of the values
  the recipe cites.
- The TCP SYN itself (window, MSS, options, TTL). The host OS decides it.

## TLS over TCP

Supported:

- Typed, ordered profiles.
- Recipes backed by retained captures: Chrome 154, Edge 154, Brave 154,
  Opera 135, and Firefox 156 from Windows captures, and Chrome 154, Edge
  153, Brave 153, Opera 102, and Firefox 156 for Android from Android
  emulator captures. Phantom carries one version per browser. For a desktop
  browser it is the current stable build on the capture host. For an Android
  browser it is the build the Play Store served to the emulator, which can
  trail stable. See
  [Browser profiles](#browser-profiles).
- Certificate and hostname verification.
- [ALPN](glossary.md#alpn) and [ALPS](glossary.md#alps).
- Bounded, client-owned TLS ticket caches for H1 and H2, partitioned by exact
  [origin](glossary.md#origin) and route, with no early data. Each keeps the
  recipe's `session_tickets_per_origin` (2 for the Chromium family, 8 for
  Firefox), presents the newest first, and uses each TLS 1.3 ticket once. A
  resumed Firefox-profile ClientHello omits `session_ticket`, as Firefox 156
  does
  ([evidence](../explanation/validation.md#tls-resumption-over-tcp-evidence)).

Planned:

- More versions and platform captures.
- A public ticket policy.
- Generic imported stacks.

## HTTP/1.1

Supported:

- Ordered request fields.
- Request trailers, either static or produced by a declared streaming body.
- Ordinary methods with owned-byte or pull-driven streaming bodies, and exact
  `Content-Length` validation.
- Response field order, interleaving of duplicate fields, and name spelling.
- Streaming responses with backpressure.
- Keep-alive reuse owned by the client, without pipelining. Each origin and
  route keeps up to the profile's `Http1Settings` bound of connections, idle
  ones included, and runs one request on each. A request reuses the most
  recently used idle connection before it opens another, and waits in
  arrival order, up to a bounded number of waiters, once the bound is
  reached. The Chrome 154 and Firefox 156 recipes set the browsers'
  per-host limit of 6, from browser source. A profile without
  `Http1Settings` keeps one connection. Negotiated requests that select H1
  use the same bound, each connection with its own TLS handshake; until a
  connection has selected H2, their handshakes run in parallel.
- Finite opt-in redirects for `http://` and `https://` requests.
- Opt-in typed connection-setup retries before dispatch.
- Opt-in replay of an idempotent request, once, on a fresh connection when a
  reused keep-alive connection closes before any response byte.
- Direct HTTPS and plaintext HTTP.
- Absolute-form forwarding of `http://` origins over plaintext or TLS proxies,
  including one replay after a strict, valid Basic challenge, on the
  challenged connection when the `407` leaves it open.
- HTTP and HTTPS CONNECT routes, and SOCKS5 routes with local or remote DNS.
- Upgrade handoff that preserves every byte.
- At most 8 informational (1xx) responses before the final response head.

Not modeled:

- Chromium's caps across groups: 256 sockets per pool and 128 per proxy
  chain.
- Firefox's limit of 32 for plaintext requests forwarded through an HTTP
  proxy, where its recipe keeps 6, and the 3 extra connections it allows
  urgent-start requests. Firefox also leaves idle connections out of its
  count; Phantom counts them.
- Chromium's 300 ms cap on holding a connection attempt to a server known
  to speak H2 while another attempt is in flight is not a recipe value.
  By default Phantom holds it until that attempt finishes, as Firefox does;
  `ClientBuilder::negotiated_setup_wait_limit` sets a cap. Phantom
  remembers that a server spoke H2 per origin and route, as Firefox does;
  Chromium remembers it per origin, across proxies, and saves it to disk.

Planned:

- Broader retry classes.
- Additional proxy modes.

## HTTP/2

Supported:

- Ordered [SETTINGS](glossary.md#settings), request and response fields,
  window update, pseudo-header order, and priority.
- Request trailers, either static or produced by a declared streaming body.
- ALPS peer settings and connection-scoped `ACCEPT_CH`.
- Flow-controlled request bodies, owned or pull-driven, and streaming
  responses.
- An early, incomplete response does not stop the request upload (RFC 9113
  §8.1). The upload continues as the caller reads the response body.
- Exact direct WebSocket [extended CONNECT](glossary.md#extended-connect): an
  explicit order for the five pseudo-header fields, gating on the peer's
  capability, duplex DATA flow control, and cancellation scoped to the stream.
- Per-request HEADERS overrides. An extended CONNECT stream on a pooled
  session carries the profile's pseudo-header order and priority, while
  ordinary streams keep theirs.
- A profile HPACK encoder identity: which pseudo-headers and ordinary fields
  stay out of the dynamic table, which entry names a literal, how large an
  indexed field may be, when a literal string is Huffman-coded, and when a
  dynamic-table size update is sent. An HPACK encoder holds these for the
  life of a connection, so they apply to every field block it sends,
  ordinary requests included, and not only to extended CONNECT. A profile
  that states none of them keeps the encoder's own behavior. Every HEADERS
  block of the retained Chrome, Edge, Brave, Opera, and Firefox cookie and
  WebSocket sessions equals the recipe's byte for byte
  ([HPACK encoder evidence](../explanation/validation.md#hpack-encoder-evidence)).
- Profile stream numbering and an assumed stream limit: the first request of
  each connection takes the profile's first stream (1 for Chromium, 3 for
  Firefox), and until the peer states `SETTINGS_MAX_CONCURRENT_STREAMS` the
  connection opens at most the profile's assumed number of streams (100 in
  both recipes). A stated limit above the profile's cap is lowered to it (256
  for Chromium, no cap for Firefox). A profile that states none of these
  starts at stream 1 with no limit before the peer's SETTINGS and no cap
  ([HTTP/2 stream numbering evidence](../explanation/validation.md#http2-stream-numbering-evidence)).
- A preface PING on a read-idle connection: when the profile sets an idle
  time (10 seconds for Chromium, none for Firefox), a connection that has
  read nothing for longer sends a PING right after the next request HEADERS
  or non-empty DATA frame, with a payload that counts up from 1. When the
  profile also sets a PING timeout (10 seconds for Chromium), a PING left
  unanswered with nothing read for that long closes the connection with
  `GOAWAY(PROTOCOL_ERROR)`; its requests fail with
  `Http2Error::PingTimeout` and are not replayed
  ([HTTP/2 preface PING evidence](../explanation/validation.md#http2-preface-ping-evidence)).
- Reuse owned by the client, keyed by exact origin and route, with bounded
  local active work and waiters, and enforcement of the peer's stream limit.
- Opt-in typed connection-setup retries before dispatch.
- One retry on a replacement connection for a bodyless GET rejected by
  `GOAWAY(NO_ERROR)`.
- Bounded response receive state: at most 8 informational responses before
  the final head, a response header-list ceiling that is not advertised, and
  limits on empty and small unread DATA frames. The values are in
  [Defaults and limits](limits.md#protocol-state).

Planned:

- Broader retry classes.
- Captured extended CONNECT behavior through proxies.

## QUIC

Supported:

- A BoringSSL-backed Quinn client: handshake, packet and header protection,
  key updates, live Retry, and endpoint HMAC.
- Typed transport settings taken from captures.
- An exact, seeded [transport-parameter](glossary.md#transport-parameters)
  serializer with randomized permitted order and [GREASE](glossary.md#grease).
- A reusable connection lifecycle owned by H3.
- TLS 1.3 session resumption when the H3 TLS settings enable
  `session_tickets`, as the Chrome 154 and Edge 154 recipes do. Each client
  pool entry (exact origin and route) keeps its own cache of at most four
  tickets, filled only by authenticated connections and presented only for the
  same verified server name. Tickets are single-use and expire at the server's
  lifetime; an expired ticket falls back to a full handshake. A handshake that
  presented a ticket and failed is repeated once with a full handshake on the
  same route.
- Early (0-RTT) data on resumed connections, offered by the Chrome 154 and
  Edge 154 recipes through `QuicTransportSettings::early_data`.
  `ClientBuilder::http3_early_data` overrides the profile either way. A
  request's first new connection offers early data when it presents a ticket
  that permits it, but only a request with a safe method, no body, and no
  trailers is sent before the handshake completes; any other request waits
  for it. If the server rejects the early data, HTTP/3 starts again on the
  same connection after the handshake, without the remembered SETTINGS, and
  the request is sent on it, as Chrome 154 and Edge 154 resend; a failed
  handshake or invalid handshake metadata fails the waiting requests.
  Concurrent requests to a resumed origin share one connection while its
  early data is unanswered.
- Server SETTINGS remembered with each session ticket, as Chromium keeps
  them, in the same cache and under the same isolation as the ticket. A
  connection that offers early data starts from them, so under the recipes'
  dynamic QPACK policy a replay-safe request leaves in 0-RTT packets, as in
  resumed Chrome 154 and Edge 154 connections. Server SETTINGS that change a
  remembered QPACK table capacity, or omit or lower another remembered value,
  close the connection with `H3_SETTINGS_ERROR` (RFC 9114, section 7.2.4.2).
- QUIC transport parameter `initial_rtt_us` (`0x3127`) on resumed
  connections, carrying the round-trip time last measured to the same server
  through the same pool entry, as a minimal-length varint.
- Tests replay the retained resumed Chrome 154 and Edge 154 connections
  against Phantom's resumed ClientHello and transport parameters, and check,
  with the recipes' dynamic QPACK policy, that a resumed connection sends
  `GET` as early data and holds `POST`
  ([QUIC resumption evidence](../explanation/validation.md#quic-resumption-and-0-rtt-evidence)).
- A bounded opt-in NSS key-log queue for TCP and QUIC TLS 1.3 handshakes,
  exposed as `ClientBuilder::key_log` behind the `diagnostics` feature.
- A QUIC v1 packet analyzer that retains no payloads, and a comparator of
  logical flights that does not depend on packetization.
- Controlled decrypted Chrome and Phantom captures through the first request.

Known gaps:

- After a server rejects early data, Chrome 154 and Edge 154 retransmit the
  same encoder-stream and request bytes, encoded from the remembered
  SETTINGS. Phantom's new session encodes from the server's SETTINGS, and
  keeps a connection open whose server lowered a remembered limit, which
  Chromium closes.
- No H3 recipe exists for Firefox, whose resumed connections switch to QUIC
  v2, which Phantom does not implement.

Planned:

- A generic non-H3 connection API.
- A repeated study of packet-shape stability.

## HTTP/3

Supported requests and routes:

- Forced exact requests over direct QUIC.
- SOCKS5 with local or remote DNS, using RFC 1928 UDP ASSOCIATE with optional
  authentication. The TCP control connection is retained and connections are
  reused per route. Remote-DNS DOMAIN targets need no local lookup of the
  origin and present a stable logical QUIC peer.
- RFC 9298 [CONNECT-UDP](glossary.md#connect-udp) proxies (see
  [Routes](#routes)).
- Opt-in, bounded [Alt-Svc](glossary.md#alt-svc) upgrade from negotiated HTTPS
  on a direct or SOCKS5 route. Phantom adds a canonical `Alt-Used` field with
  an explicit port and keeps the origin authority, SNI, and authentication
  identity. The alternative is dialed over the route that learned it.
- Opt-in H3 discovery from [HTTPS DNS records](glossary.md#https-record)
  (RFC 9460) on the direct route,
  for an origin with no stored Alt-Svc alternative. A ServiceMode record
  listing `h3` for the origin's own host and port, selected by Chrome
  154.0.8037.58's rules, sends the negotiated request over H3 to the origin,
  without `Alt-Used`. Phantom sends the query itself over UDP, with a TCP
  retry on truncation, to the host's or the caller's nameservers. The lookup
  runs beside the request and does not hold it back, except for the TLS
  handshake described below; results are cached per client
  for the record TTL (at most one day, 60 seconds without one) in at most the
  Alt-Svc store's number of origins. Records are parsed into typed fields
  (`alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ipv6hint`, `mandatory`,
  and `ech` kept as raw bytes), and a malformed record is a typed error.
  With the Chrome 154, Edge 154, or Brave 154 recipe, a direct HTTP/1.1 or
  HTTP/2 connection, negotiated or exact, and a `wss://` opening encrypt the
  ClientHello with the record's `ech`, waiting up to 50 ms after address
  resolution for the lookup, not at all when the address comes from the
  client's address cache, and retrying once after a rejection whose server
  authenticates as the public name, as Chrome 154, Edge 153, and Brave 154
  do
  ([Real ECH evidence](../explanation/validation.md#real-ech-evidence)).
  Their HTTP/3 recipes do the same on a QUIC connection to the origin, an
  HTTPS-record alternative or an exact HTTP/3 request, except that a
  rejected QUIC connection is not repeated
  ([Real ECH over QUIC evidence](../explanation/validation.md#real-ech-over-quic-evidence)).
  Requires the `https-records` feature. See
  [Find HTTP/3 through HTTPS DNS records](../guides/http3-discovery.md#find-http3-through-https-dns-records).

Supported wire behavior:

- Exact `h3` ALPN and the Chrome H3 ALPS offer.
- Authenticated peer application SETTINGS, and strict decoding and handoff of
  connection-scoped `ACCEPT_CH`.
- Typed, ordered SETTINGS and request and response fields.
- Chrome's nonzero inbound [QPACK](glossary.md#qpack), randomized GREASE, H3
  DATAGRAM, and deferred decoder-stream policy.
- Chrome's QPACK stream order: the decoder stream is client stream 6 and the
  encoder stream is client stream 10. The encoder stream's type is written
  with its first instructions, ahead of the first request's HEADERS, so a
  connection that sends no request writes only its control stream.
- Bounded dynamic decoding of responses and request encoding owned by the
  connection. Live QPACK stream and HEADERS bytes match the captures.
- A local 256 KiB ceiling on a decoded response field section, lower when the
  profile advertises less. It does not change the SETTINGS frame.

Supported lifecycle:

- Ordinary methods with flow-controlled request bodies, owned or pull-driven,
  and ordered trailers, either static or produced by a declared streaming
  body.
- Streaming data and trailers, and chained informational responses.
- Multiplexed reuse owned by the client, with bounded active work and waiters.
- Opt-in typed retries of DNS, endpoint, and QUIC setup before dispatch.
  Loopback recovery tests cover a refused direct handshake, a refused SOCKS5
  proxy connect, and a refused handshake retried through a fresh SOCKS5
  association.
- Tests for the exact close codes sent to hostile peers.
- Cancellation scoped to the stream, and bounded shutdown.
- One qlog file per QUIC connection, written to `ClientBuilder::qlog_dir`
  behind the `diagnostics` feature.
- Opt-in Alt-Svc racing (`AltSvcPolicy::race`):
  - QUIC setup to the alternative starts first. H1/H2 setup to the origin
    starts after a delay the caller sets, or at once if the alternative fails
    or a reusable pooled H2 connection exists.
  - The request is dispatched once, on the winner.
  - Alternative setup is limited to 4 seconds.
  - A losing alternative keeps connecting in the background and is then
    pooled or marked broken.
  - A raced setup offers early data when the client does, unless QUIC to the
    origin's own host and port failed a race and has not connected since,
    as in Chromium 154. A resumed alternative can then win before its
    handshake completes and carry a replay-safe request as early data. If
    that handshake fails, the request is raced again without early data, as
    Chromium restarts it.
  - Broken alternatives back off as in Chromium 153: 300 seconds, doubling,
    capped at two days.

  See [Racing](../guides/http3-discovery.md#race-the-alternative-against-the-origin).

Supported in `phantom-net` only (`phantom-http` does not expose it):

- RFC 9220 extended CONNECT for the WebSocket protocol. It is gated on peer
  SETTINGS from ALPS or the control stream and emits no local setting. It
  uses an explicit five-field pseudo-header order from a custom profile, a
  bounded duplex DATA stream with FIN, a stream-scoped `H3_REQUEST_CANCELLED`
  reset with datagram abort, and a readable rejection body.

Planned:

- A live H3 `ACCEPT_CH` request differential against a BoringSSL server.
- Nonempty local H3 application settings.
- Repeated packet differentials against fresh browsers.
- Datagram APIs for specific extensions.
- Alt-Svc racing across multiple alternatives, and a racing delay derived
  from RTT.
- Encrypted Client Hello from a record's `ech` value for Opera, and on an
  Alt-Svc alternative at another host.
- HTTPS-record queries sent with the address queries from one DNS client, as
  Chrome does; Phantom's address lookups go through the operating system.
- Multiplexing several CONNECT-UDP tunnels on one outer connection.
- MASQUE recipes captured from browsers.

## Public client

Supported:

- A pooled facade for exact H1, H2, and H3 that is cheap to clone.
- Pooled H1/H2 selection over a direct or SOCKS5 route, with optional later H3
  selection through Alt-Svc on the same route. H3 is tried sequentially by
  default, or raced against the origin under an opt-in policy. A negotiated
  `http://` request uses H1 on any route that carries exact H1 `http://`, and
  learns no Alt-Svc alternative.
- Owned request builders with explicit methods.
- Ordered [trailers](glossary.md#trailers), either static or produced by a
  declared streaming body, on exact H1/H2/H3 and negotiated requests.
- Streaming bodies, owned-byte or pull-driven.
- Default and per-request connection retry policies for exact H1/H2/H3 setup
  and for TCP setup of negotiated requests before ALPN.
- Opt-in status retry for idempotent requests on 408, 425, 429, and 5xx
  statuses that the caller lists, with an optional capped `Retry-After` and a
  budget for the whole request.
- Opt-in per-request browser field templates. A template holds:
  - the captured field order and values for each protocol;
  - slots for caller fields and client hints;
  - the captured H2 HEADERS priority for its request kind.

  Recipes cover address-bar navigations and same-origin no-store `fetch`
  GETs. See [Request templates](../guides/request-templates.md#apply-a-captured-request-template).
- One WHATWG/IDNA endpoint boundary, shared by the wire authority and state
  keys.
- Separate TLS settings for TCP and QUIC.
- Additional DER trust roots.
- Default and per-request routes.
- One streaming response body type, with bounded collection whose limit is
  inclusive.
- Opt-in streaming decoding of the `gzip`/`x-gzip`, `deflate`, `br`, and
  `zstd` codings the caller advertises. The decoded-byte cap is inclusive,
  chains fail closed, and response fields stay as received. See
  [Content decoding](../guides/content-decoding.md).
- Metadata for the selected protocol, ordered fields, redirect count, and
  setup-retry count.
- Typed errors.

Deliberately excluded:

- Replay of H3 requests on streams that were already open when `GOAWAY`
  arrived. Servers disagree on the boundary the `GOAWAY` identifier marks.

## Cross-request state

Supported:

- Bounded retained H1, H2, and H3 pools, with active and waiting admission per
  origin and route.
- One H2 connection per origin and route, as browsers keep; an opt-in
  `max_http2_connections_per_origin` opens more when every connection is at
  its stream limit. H3 keeps one connection per transport location; an
  opt-in `max_http3_connections_per_origin` opens more when every connection
  is at the server's `initial_max_streams_bidi`.
- Bounded admission per origin and route for negotiated requests before
  protocol selection, converted to H1 or H2 admission after ALPN.
- A bounded opt-in Alt-Svc store keyed by exact origin and route:
  - `Age`/`ma` handling, replacement, expiry, and `clear`;
  - eviction after a setup failure or a `421` response;
  - learning from H2 ALTSVC frames for the exact origin on negotiated
    requests;
  - H3 connection slots per location, so exact H3 and Alt-Svc H3 do not
    replace each other;
  - an automatic `Alt-Used` field, scoped to the request and sent only on
    managed H3 attempts; and
  - export and import of direct-route snapshots by the caller (canonical
    origin, location, and expiry in whole seconds; revalidated on import and
    never extended). A snapshot carries no route, so export omits proxy-route
    entries and import restores direct-route entries only.
- One bounded budget of setup retries before dispatch per request, shared by
  redirects and internal replacement attempts.
- A bounded retry after a graceful H2 `GOAWAY`, for exact and negotiated H2.
- Opt-in replay of unprocessed requests: H2 `REFUSED_STREAM` or `GOAWAY` above
  the stream, and H3 `H3_REQUEST_REJECTED` or `GOAWAY` before the stream
  opened. It applies to any method with no body or an owned body, and replays
  on a different connection with the same route and protocol.
- Bounded retention of TLS tickets for H1/H2 and of QUIC tickets for H3,
  partitioned by exact origin and route.
- Alt-Svc broken state per origin, route, and alternative, with capped
  doubling backoff. A successful connection to the alternative or
  `clear_alt_svc` clears it.
- A per-client address cache (`DnsCacheSettings`) for the names the client
  resolves itself: origin hosts on a direct route, proxy hosts, and local-DNS
  `socks5://` targets. It is bounded, keeps each answer for a fixed time and
  failures optionally, shares one lookup between concurrent connections, and
  keeps the resolver's address order. The recipes `chromium::v154_dns_cache`
  and `firefox::v156_dns_cache` come from browser source. Proxy-resolved
  targets never reach it. See
  [Address cache evidence](../explanation/validation.md#address-cache-evidence).
- Caller host-to-address overrides and a caller-supplied async address
  resolver for the same names, off by default. An override skips the
  resolver and the cache; the resolver's answers go through the cache when
  there is one. Proxy-resolved targets never use either. See
  [Resolve host names](../guides/name-resolution.md).
- With the `https-records` feature, an opt-in per-client cache of HTTPS DNS
  record results, one entry per origin, bounded by the Alt-Svc store's
  capacity and kept for the record TTL. It stores only whether the records
  advertise `h3`.
- An optional bounded cookie jar that the caller activates explicitly:
  - deterministic path and creation order;
  - Public Suffix List checks (including private and unlisted suffixes),
    `__Secure-` and `__Host-` prefix checks, and expiry;
  - Chromium-style least-recently-used eviction;
  - stores `SameSite` and `Partitioned` cookies and sends them as for a
    user-initiated top-level navigation;
  - rejects insecure `SameSite=None`, insecure `Partitioned`, and `Secure`
    cookies set by an origin that is not potentially trustworthy. A
    potentially trustworthy origin, as in Chromium, is an `https://`
    origin or an `http://` loopback, `localhost`, or `.localhost`
    origin;
  - places the `Cookie` field where the profile's `CookiePlacement` puts it,
    with Chrome 154 and Firefox 156 recipes; and
  - export and import of snapshots by the caller (every attribute, the
    partition key, the setting scheme, and expiry in whole seconds; session
    cookies included). Import revalidates each entry as the `Set-Cookie`
    field its scheme and domain would send, under the jar's own rules, so it
    stores only what a response could have stored. It never extends expiry,
    replaces a held cookie, or evicts one. The optional `serde` feature
    serializes snapshots.

  See [Cookies](../guides/cookies.md#keep-cookies-between-requests).
- [Client-hint](glossary.md#client-hints) fields defined by the profile, with
  bounded `Accept-CH` state per exact origin from responses,
  connection-scoped H2/H3 ALPS `ACCEPT_CH`, and one bounded `Critical-CH`
  retry for safe methods. A request template places the hints at its captured
  slots. Without one, they precede the caller's fields. See
  [Client hints](../guides/request-templates.md#send-client-hints).
- Opt-in finite redirects: WHATWG URL resolution, `http://` and `https://`
  targets, browser method and body transitions, and removal of credentials
  and client hints on cross-origin hops, including a change of scheme. Each
  hop is checked against the request's protocol and route before it is sent.

Not modeled:

- Chromium's `__Http-` and `__Host-Http-` cookie prefixes, which also require
  `HttpOnly` (`net/cookies/cookie_util.cc` lines 342-347 at tag
  `153.0.8010.48`). Chromium matches the longer prefix first, so the two names
  fail differently in Phantom: `__Host-Http-` is caught by the `__Host-` check
  and held to that weaker rule, and `__Http-` matches no check and is stored as
  an ordinary cookie.
- A `Domain` attribute on a `__Host-` cookie whose value equals an IP-literal
  request host. Chromium's `HasValidHostPrefixAttributes` admits it; Phantom
  rejects every `Domain` on a `__Host-` cookie. Only a request to an IP
  literal can reach the difference, which for `http://` means a loopback
  address.
- The browsers' address cache lifetimes from record TTLs (Chromium's built-in
  DNS client, Firefox on Windows), Firefox's 600-second grace period for
  expired answers, and the flush both browsers do when the network changes.
  Phantom's system lookups report no TTL, and an `AddressResolver` returns
  none.

Planned:

- Cookie contexts the caller selects (cross-site and embedded requests, and
  cross-site CHIPS partitions).
- Permissions and delegation context.
- DNS over HTTPS where a captured browser uses it.
- Persistence of Alt-Svc brokenness, reset on network change, and proxy-route
  snapshots.
- Broader policy and retry classes.

## Server-sent events and WebSocket

Supported SSE (`sse` feature):

- A bounded decoder over the ordinary streaming response body.
- Finite reconnects owned by the client, with:
  - a `Last-Event-ID` placeholder the caller can position;
  - the server's retry delay, with an optional minimum;
  - an optional idle timeout on DATA activity that is safe to cancel;
  - cookies; and
  - termination on a 204 response.
- Differential tests that replay retained Chrome 154 and Firefox 156 Windows
  HTTP/1.1 captures.

Supported WebSocket (`websocket` feature):

- WebSocket over H1 on its direct and proxy routes.
- Exact WebSocket over H2 extended CONNECT, for profiles that define an
  extended CONNECT pseudo-header order. Routes: direct, HTTP CONNECT
  (plaintext or TLS proxy, HTTP/1.1 or HTTP/2 proxy transport, one Basic
  replay, on the challenged HTTP/1.1 connection when the `407` leaves it
  open), and SOCKS5 with local or remote DNS.
  The peer capability gate applies, with no route or H1 fallback.
- `ws://` through an HTTP proxy as a CONNECT tunnel (HTTP/1.1 transport) or
  CONNECT stream (HTTP/2 transport) with the direct Upgrade inside, as Chrome
  154, Edge 154, and Firefox 156 send it.
- Ordered, customizable handshakes, and Basic authentication to an HTTP
  proxy when it sends a challenge to the CONNECT.
- Typed opt-in `permessage-deflate` (`websocket-deflate` feature), including
  the per-profile empty-message rule: Chrome 154 and Edge 154 compress a
  zero-length message and set RSV1, Firefox 156 sends it with RSV1 clear.
- Client cookies, bounded messages, `Stream`/`Sink`, and strict response
  validation for each protocol.
- A profile WebSocket connection policy with Chrome 154/Edge 154 and Firefox
  156 recipes. Depending on the recipe, it reuses a capable H2 session or
  opens either an `http/1.1`-only Upgrade connection or a new H2 connection.
  It uses the captured CONNECT pseudo-header order, priority, field templates,
  and deflate offers. A recipe also carries what its client does when the peer
  refuses the CONNECT stream: Chrome 154 and Edge 154 reopen once on the same
  session, Firefox 156 reopens nothing. See
  [Profile connection policy](websocket.md#profile-connection-policy).

Planned or not captured:

- Firefox-style transaction restarts on fresh connections. Chrome's single
  resend, after a reused H1 connection closes before a response, is already
  available as opt-in reused-connection replay.
- SSE over H2 and H3, on macOS, and in Safari is not yet captured.
- Other WebSocket extensions, named send policies beyond the empty-message
  rule, and automatic reconnect.
- A named browser recipe for WebSocket over HTTP/3. No shipping browser opens
  one by default;
  [Design](../explanation/design.md#recorded-browser-behavior-is-the-specification)
  explains why no recipe will emit one until a browser does.

The captures show that Chromium uses H2 WebSockets only on an existing session
that advertises the setting, while Firefox also opens fresh H2 connections,
and that pseudo-header order, priority, deflate offer, send policy, and HPACK
encoder identity differ by family. `Http2Settings::hpack` states the
encoder choices RFC 7541 leaves open, and with it every captured HEADERS
block on these sessions, CONNECT included, equals the recipe's byte for byte
([HPACK encoder evidence](../explanation/validation.md#hpack-encoder-evidence)).
The WebSocket recipes still differ from those captures in two ways:

| Gap | Why | What would close it |
| --- | --- | --- |
| Firefox's stream `WINDOW_UPDATE` | It appears on every Firefox stream, not only the CONNECT stream, so it belongs to the HTTP/2 request path. | Modeling it on the Firefox HTTP/2 request path |
| `wss://` WebSocket through a proxy | The proxy route captures record only `ws://` openings through a proxy. | A `wss://` capture through a proxy |

## Routes

Supported direct paths:

- Direct HTTPS over H1 or H2, plaintext HTTP over H1, exact direct H2
  WebSocket extended CONNECT, and H3 over QUIC.
- Direct negotiated HTTPS can upgrade through a learned Alt-Svc alternative
  without changing the direct route.

Supported HTTP proxies:

- HTTP/1.1 absolute-form forwarding for `http://` origins over plaintext or
  TLS-encrypted proxies. Basic authentication is challenge-driven: the first
  request to a proxy is anonymous, and exactly one replay follows over the
  same route, on the challenged connection when the `407` leaves it open and
  on a new connection otherwise. After the proxy accepts the credentials,
  later requests through it send them first. A caller's own
  `Proxy-Authorization` field is forwarded
  when the proxy has no configured credentials. A negotiated `http://` request
  is forwarded as H1. Forwarding never switches to CONNECT or another
  protocol.
- HTTP/1.1 CONNECT over plaintext proxies or TLS proxies verified with
  their own trust settings, including one bounded Basic retry after a challenge
  and credentials on the first CONNECT once the proxy has accepted them.
- CONNECT fields from the profile, on both proxy transports, in the order
  Chrome 154, Edge 154, and Firefox 156 send them, with the tunnelled
  request's `User-Agent`.
- HTTPS proxies reached over HTTP/2 when the route selects it explicitly
  (RFC 9113 §8.5 CONNECT). Tunnels to different origins are streams of one
  proxy connection per session, proxy, and set of credentials, as Chrome
  154, Edge 154, and Firefox 156 open them. A tunnel past the proxy's
  `SETTINGS_MAX_CONCURRENT_STREAMS` waits on that connection, as in the
  browsers; after the proxy's `GOAWAY` or close, the next tunnel opens a new
  one. `ClientBuilder::max_http2_proxy_connections_per_route` opts into
  more connections per route, a departure from the browsers. The profile's
  ALPN is offered unchanged, and a selection mismatch is a typed error with
  no fallback. A Basic `407` is answered with one replay on a new
  stream of the challenged connection, as Chrome 154, Edge 154, and Firefox
  156 do.
- `http://` requests forwarded over such an HTTP/2 proxy with `:scheme`
  `http`, in the profile's pseudo-header order, as Chrome 154, Edge 154, and
  Firefox 156 send them. Forwarded requests share one proxy connection; with
  the Chromium recipe, CONNECT and WebSocket tunnels share it too, and with
  the Firefox recipe each of the three has its own, as in the captures.
  Exact H2 and negotiated requests use it, and a Basic `407` is answered with
  one replay on it; exact H1 fails before I/O.
- Negotiated HTTPS through either CONNECT transport, with the same CONNECT
  request and Basic retry as exact requests. One origin TLS handshake runs in
  the tunnel and ALPN selects H1 or H2; a failed handshake is not retried with
  another offer. The route learns no Alt-Svc alternative, because the tunnel
  cannot carry QUIC.

Supported [SOCKS5](glossary.md#socks5):

- SOCKS5 with local or remote DNS and optional RFC 1929 credentials, for exact
  H1/H2 origin TLS, negotiated H1-or-H2 origin TLS, plaintext H1 `http://`
  (exact or negotiated), and H1 WS/WSS.
- Negotiated HTTPS over SOCKS5 can upgrade through a learned Alt-Svc
  alternative, dialing it over the same proxy with UDP ASSOCIATE. The
  advertisement is keyed to that route and is never reused directly or through
  another proxy.
- Exact H3 over local-DNS `socks5://` or remote-DNS `socks5h://` through
  RFC 1928 UDP ASSOCIATE. The TCP control connection is retained, the target
  is a fixed IP or canonical domain, connections are reused per route, and
  terminal proxy failures are typed.
- The SOCKS5 UDP adapter drops oversized or undeliverable datagrams, as UDP
  does, and ends the association when its TCP control connection closes.

Supported CONNECT-UDP:

- Exact H3 over RFC 9298 CONNECT-UDP proxies, with an `https` URI template, a
  percent-encoded target, and proxy trust and SNI set separately from the
  origin's.
- On the default HTTP/3 proxy leg: SETTINGS and QUIC DATAGRAM gating before
  any stream opens, Context ID 0 HTTP Datagrams with bounded queues per
  stream, and a 1,252-byte outer path MTU with capacity checks before I/O.
- An explicitly selected HTTP/2 extended CONNECT or HTTP/1.1 Upgrade leg that
  carries DATAGRAM capsules.
- Basic proxy authentication after a challenge on every leg, with one replay
  on a fresh proxy connection.
- One outer connection per inner connection. Resolve and connect retries
  apply to the outer connection only.

Across all routes:

- No route or protocol fallback.
- Proxy and origin hosts use their canonical Unicode form.
- Trust settings and ticket caches are kept separate for HTTPS proxies and
  origins.

Deliberately excluded:

- Negotiated HTTPS over a CONNECT-UDP proxy, which carries QUIC only and
  offers no TLS stream for ALPN. It is a typed refusal before any proxy I/O,
  never a fallback.
- The Alt-Svc upgrade over an HTTP proxy. A CONNECT tunnel is TCP and cannot
  reach an `h3` alternative, so the route stores no advertisement and its
  negotiated requests stay on H1 or H2. See
  [Upgrade to HTTP/3](../guides/http3.md#upgrade-to-http3-when-the-server-advertises-it).

Planned:

- Other proxy authentication schemes, and learned challenge state.
- Basic challenge retry for `http://` requests forwarded over H2.
- Custom SOCKS5 resolvers.
- CONNECT-UDP proxy authentication schemes other than Basic.

## Validation

[Validation](../explanation/validation.md) records how each claim on this page
is proved.

Supported:

- Local TLS, H2, and QUIC fixtures, and hostile H1/H2/H3 peers.
- Bounded qlog and key-log seams.
- Deterministic authenticated QUIC packet analysis, two fresh-profile Chrome
  H3 ClientHellos, and controlled Chrome and Phantom packet evidence.
- Parser fuzzing under AddressSanitizer: short runs on relevant changes and
  longer weekly runs. The targets are listed under
  [Fuzzing and sanitizers](../explanation/validation.md#fuzzing-and-sanitizers).

Not currently used:

- Third-party observers. No third-party observation is retained today, and no
  recipe rests on one. See
  [Recorded coverage losses](../explanation/validation.md#recorded-coverage-losses).

Planned:

- Restoring a supplemental observer for a current recipe, and a repeated
  packet-shape study and Prism comparison.
- Broader protocol fuzzing and sanitizers for native adapters.
- Long soak tests.

## Browser profiles

TLS, H2, and QUIC protocol settings are transport recipes. They do not select
behavior by host OS. Capture provenance stays platform-specific, because
browser builds, system integrations, launch conditions, and release channels
can change the bytes a browser sends.
[Profile reference](profiles.md#recipe-names-and-platforms) explains
the naming rules.

Each recipe records the platform its captures came from, and no recipe
shares component data with a capture from another platform:

- Chrome 154 (154.0.8037.58), Edge 154 (154.0.4258.37), Brave 154
  (154.1.96.59), Opera 135 (135.0.5973.92), and Firefox 156 (156.0) recipes
  come from Windows 11 captures. The `macos` client-hint and template
  recipes of Chrome, Edge, Opera, and Firefox, at the same builds, come from
  macOS 15.5 captures on Apple silicon. Single retained macOS runs of the TCP
  ClientHello and resumption and the H2 session for all four, and of the
  QUIC ClientHello and H3 startup for Chrome, Edge, and Opera, match the
  Windows recipes in the replay tests
  ([Validation](../explanation/validation.md#macos-recipes)). No Linux
  capture exists, and no other layer is claimed to be platform
  independent. The retired Chrome 152 and Firefox 154 captures, which did
  compare two platforms, are no longer in the tree.
- Chrome 154 for Android (154.0.8037.57) recipes come from captures on the
  Android 17 emulator described in
  [Validation](../explanation/validation.md#chrome-for-android-154-recipes),
  including QUIC resumption, WebSocket openings, and plaintext trust. Edge
  153 for Android (153.0.4234.49) recipes come from an arm64 Android 17
  emulator ([Validation](../explanation/validation.md#edge-for-android-153-recipes)).
- SSE browser captures are from Windows 11 (10.0.26200) only, and WebSocket
  browser captures from that host and the Android emulators. The macOS
  WebSocket captures back request fields only. Phantom does not assume macOS
  parity for SSE or WebSocket behavior.
- [Capture normalization](../explanation/validation.md#capture-normalization)
  records what a comparison normalizes.

How the recipes differ:

- `chromium::v154_*` is a complete Chromium set: TLS, TCP, H2, WebSocket,
  cookie placement, client hints, the navigation and fetch templates, and the
  H3, H3 TLS, H3 request, and QUIC recipes. Its
  [trust-anchor](glossary.md#trust-anchor-ids) list holds 28 identifiers in
  one ascending order, which every captured process emits; Chromium commit
  `942bda4298c1` sorts the list before encoding it. The `sec-ch-ua` brand
  list is `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`.
- Edge 154 matches the Chromium H2, QUIC, and H3 recipes and omits
  trust-anchor IDs. So `edge::` carries only `v154_tls`, `v154_http3_tls`,
  `v154_windows_client_hints`, `v154_macos_client_hints`, and its request
  templates.
- Brave 154 matches the Chromium H2, QUIC, H3, WebSocket, and proxy CONNECT
  recipes and omits trust-anchor IDs. `brave::` carries `v154_tls`, which
  keeps Chrome's ECH from HTTPS records, `v154_http3_tls`,
  `v154_windows_client_hints`, and its request templates. Its client hints
  omit `sec-ch-ua-full-version` and `sec-ch-ua-form-factors` and reduce every
  version to `.0.0.0`. Its templates drop signed exchanges from the
  navigation `Accept`, add `Sec-GPC: 1`, and leave `Accept-Language` to the
  caller, because Brave draws its `q` value per session.
- Opera 135 matches the same Chromium recipes and omits trust-anchor IDs, and
  its TCP ClientHello has no GREASE signature algorithm. `opera::` carries
  `v135_tls`, `v135_http3_tls`, `v135_windows_client_hints`, and its request
  templates, which equal the Chromium templates apart from `User-Agent`.
- `firefox_android::v156_tls` returns `firefox::v156_tls`, which the Android
  ClientHellos equal. No other Firefox for Android layer is captured,
  because no certificate override can be installed on Android.
- `opera_android::v102_*` carries only `v102_tls`, Chrome 154's ClientHello
  without trust-anchor IDs, `v102_android_client_hints()` with the captured
  `"Pixel 7"` model, and `v102_android_client_hints_for_model`. Opera for Android
  takes no switches, so only loopback captures without a certificate exist.
- `brave_android::v153_*` returns the Chromium H2, QUIC, H3, H3 request,
  and WebSocket recipes and desktop Brave's H3 TLS recipe, which the Android
  captures equal, and carries desktop Brave's TCP ClientHello without ECH from
  HTTPS records, `v153_android_client_hints`, and templates with desktop
  Brave's request-field changes and the Android `User-Agent`.
- `chrome_android::v154_*` returns the Chromium H2, QUIC, H3, H3 request,
  and WebSocket recipes, which the Android captures equal, and the Chromium
  TLS recipes with ECH from HTTPS records off. It carries
  `v154_android_client_hints()` (`?1`, `"Android"`, `"17.0.0"`, and the
  captured model `"Pixel 7"`), `v154_android_client_hints_for_model` for
  another model, and navigation and fetch templates with Chrome's reduced
  Android `User-Agent`.
- `edge_android::v153_*` carries desktop Edge's TLS recipes, which Edge 153
  and Edge 154 send alike, with ECH from HTTPS records off, returns the
  Chromium H2, QUIC, H3, and H3 request recipes, and carries
  `v153_android_client_hints()` with desktop Edge 153's brand list and the
  `"Pixel 7"` model, `v153_android_client_hints_for_model`,
  and navigation and fetch templates with Edge for Android's `User-Agent`.
  It has no WebSocket recipe.
- `firefox::v156_*` covers TLS, TCP, H2, WebSocket, cookie placement, and the
  request templates. Firefox sends no user-agent client hints, so it has no
  client-hint recipe, and no Firefox QUIC or H3 capture exists.

Request templates:

- The navigation templates match every retained page request:
  - Chrome 154 over H1 (the SSE, WebSocket, and client-hint captures), H2 (the
    WebSocket captures), and H3 (the H3 startup capture);
  - Edge 154, Brave 154, Opera 135, and Brave 153 for Android over H1, H2,
    and H3;
  - Chrome 154 and Edge 153 for Android over H1 and H2 (the WebSocket
    captures); and
  - Firefox 156 over H1 and H2.

  The fetch templates match every retained no-store report `fetch` in the
  WebSocket captures, over H1 and H2.
- Each template carries the captured H2 HEADERS priority for its request kind,
  sent on that stream only. Navigations use weight 256 exclusive (Chrome,
  Edge, Brave, Opera) and 42 (Firefox), which equal the H2 recipes' connection priority.
  Fetches use weight 220 exclusive and 22. The dependency is always stream 0,
  as in every capture. Chrome's dependency on another open stream of equal or
  higher priority is not reproduced.
- The Chrome `User-Agent` value comes from the SSE capture, which ran in
  headful launch mode. The other Chrome captures and every retained Edge,
  Brave, and Opera capture ran headless, so the Edge, Brave, and Opera
  templates leave `User-Agent` to the caller.
- The H1 template captures used plaintext loopback origins. The proxy route
  captures show what the browsers send to a named plaintext origin instead:
  no `Sec-Fetch-*` fields, no client hints, and `Accept-Encoding: gzip,
  deflate`. The templates follow them for any URL that is not
  [potentially trustworthy](glossary.md#potentially-trustworthy). No capture
  shows where a `fetch` places hints requested through `Accept-CH`, so the
  fetch templates refuse to send them. Where navigation templates place requested hints is
  captured on H1 only and inferred for H2 and H3.
- The profile's `CookiePlacement` decides where the jar's `Cookie` field goes
  in the expanded template. With the Chrome 154 and Firefox 156 presets, the
  H1 fields on each side of it agree with the `set-cookie-then-close`
  EventSource reconnect captures: last for the Chrome templates, and after
  `Referer` and before `Sec-Fetch-Dest` for the Firefox `fetch` template.
  The [cookie crumb captures](../explanation/validation.md#cookie-crumb-evidence)
  show the same neighbors on a navigation and a `fetch()` over H1, H2, and
  H3: last or before `priority` for Chrome, Edge, Brave, and Opera, which
  all use `chromium::v154_cookie_placement`, and after `Referer` for
  Firefox, before `Upgrade-Insecure-Requests` on a navigation and
  `Sec-Fetch-Dest` on a `fetch()`.
- On H2, the Chromium and Firefox recipes split the `cookie` field into one
  field per cookie and encode each crumb as the captured browser does, apart
  from Firefox's choice of name index once a crumb is in the dynamic table.
  On H3, the Chromium recipe splits it and its QPACK bytes equal Chrome's and
  Edge's ([Cookie crumbs](profiles.md#cookie-crumbs)).

Randomized fields:

- Chrome 154's trust-anchor ID order is one ascending order on every
  connection. Up to Chrome 153 the order was fixed within a browser process
  and differed between processes, a hash-iteration order rather than a
  per-connection permutation; see
  [Chrome 154 trust-anchor ID order](../explanation/validation.md#chrome-154-trust-anchor-id-order).
- The Chrome 154, Edge 154, Brave 154, Opera 135, and Chrome 154, Edge 153,
  and Brave 153 for Android recipes leave the ECH GREASE AEAD list empty and emit HKDF-SHA256 with
  AES-128-GCM on every connection, as every observed connection of those
  browsers does. Tests compare it exactly.
- Chrome 154 for Android sorts its trust-anchor IDs as desktop Chrome 154
  does, over TCP and QUIC, so `chrome_android::v154_tls` and
  `v154_http3_tls` send the Chromium order.
- Firefox 156 chooses its ECH GREASE AEAD per connection, between AES-128-GCM
  and ChaCha20-Poly1305. The recipe lists both, and the backend draws one
  uniformly for each connection. A 200-connection distribution test bounds
  the split.

The runtime uses the validated settings it receives. It does not branch on the
host OS or the client-family name. OS-specific code exists only for real
differences in sockets, trust stores, native builds, or profiling.

Carrying one version per browser retires evidence along with the recipes it
described. [Recorded coverage losses](../explanation/validation.md#recorded-coverage-losses)
lists the checks Phantom no longer runs.

## Claim boundary

Local raw captures and packet and frame differentials are the only evidence
behind the current recipes. Independent observers such as Pingly, Peet, and
Prism can reveal missing signals that a local capture and a local comparator
would both miss, and none of them alone would decide pass or fail; no
observation from one is retained today, so nothing here rests on that second
opinion. Phantom reports the concrete fields and behaviors a test covers. It
does not label a whole profile "verified".

## Next

- [Validation](../explanation/validation.md): the evidence behind each
  "Captured" cell above.
- [Route matrix](route-matrix.md): every scheme, protocol, and route
  combination.
- [Glossary](glossary.md): definitions of the terms used here.
