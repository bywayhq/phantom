# Coverage

This page is Phantom's support contract. It lists, layer by layer, what works
today and what is planned. Anything not listed as supported is unsupported.

Phantom reproduces observable HTTP-client behavior on the network. It
does not provide a DOM, JavaScript, rendering, canvas, fonts, WebRTC, or device
fingerprinting. Each protocol layer is listed separately, so a TLS match is
never presented as a complete client match.

Terms such as H1/H2/H3, exact, negotiated, route, and recipe are defined in
[Key terms](../guides/client.md#key-terms).

## What "supported" means

A feature is supported only when its whole lifecycle works: configuration,
validation, what Phantom sends, response handling, cancellation, errors,
observability, and deterministic tests. Parsing an option or completing a
connection is not enough.

## Contents

- [At a glance](#at-a-glance)
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

## At a glance

| Layer | Summary | Main gaps |
| --- | --- | --- |
| TCP | Profile `TCP_NODELAY`, keepalive, and Chromium Happy Eyeballs from browser source, on every TCP path | Firefox keepalive and address selection |
| TLS over TCP | Typed ordered ClientHellos from retained captures | More versions and platforms |
| HTTP/1.1 | Ordered streaming requests and responses, keep-alive reuse | Parallel connection policy |
| HTTP/2 | Ordered SETTINGS, fields, priority, multiplexing, extended CONNECT | HPACK representation parity for extended CONNECT |
| QUIC | BoringSSL-backed Quinn with captured transport parameters | Generic non-H3 connection API |
| HTTP/3 | Exact H3 over direct, SOCKS5, or CONNECT-UDP; opt-in Alt-Svc upgrade and racing over direct and SOCKS5 | Multiple-alternative racing, WebSocket over H3 |
| Routes | Direct, HTTP forward and CONNECT, SOCKS5, CONNECT-UDP | Other proxy authentication schemes |
| SSE and WebSocket | Feature-gated, bounded, with browser comparisons and Chrome/Firefox WebSocket recipes | H2/H3 SSE captures, proxy WebSocket captures |

The [route matrix](route-matrix.md) lists every combination of scheme,
protocol, and route.

## TCP

Supported:

- Profile TCP socket options (`ClientProfile::with_tcp`): `TCP_NODELAY`, and
  keepalive idle time and interval. Phantom applies them before connecting, on
  every TCP connection, including proxy connections and SOCKS5 UDP control
  connections. If the OS rejects an option, that connection attempt fails.
- Profile address racing (`TcpAddressRacing`): Chromium's Happy Eyeballs v2
  over the complete resolver result. At most two attempts run at once, the
  losing attempt is cancelled, and the most recent failure is returned.
- The recipes `chromium::v153_tcp` (Windows and Linux) and `firefox::v156_tcp`
  (`TCP_NODELAY` only, attempts in resolver order), both taken from browser
  source. See
  [TCP socket option evidence](../explanation/validation.md#tcp-socket-option-evidence).

Not modeled:

- Firefox's per-connection keepalive schedule and its address selection.
- Chromium's macOS idle-only keepalive as a named recipe.
- Chromium's resolver behavior before racing: its own address sorting, IPv6
  reachability probe, partial DNS results, and HTTPS records. Phantom races
  the system resolver's complete answer.
- Racing for HTTP/3. Chromium's QUIC job connects only to the first resolved
  address. Phantom's H3 connector tries the resolved addresses in order after
  a connection failure.
- An Edge TCP recipe. No public source or capture shows Edge's options.
- The TCP SYN itself (window, MSS, options, TTL). The host OS decides it.

## TLS over TCP

Supported:

- Typed, ordered profiles.
- Recipes backed by retained captures:
  - Chrome 152, Firefox 154, and Safari 18.5 from macOS captures. Chrome 152
    and Firefox 154 also match Windows captures.
  - Chrome 153, Edge 153, and Firefox 156 from Windows captures.

  See [Browser profiles](#browser-profiles).
- Certificate and hostname verification.
- ALPN (Application-Layer Protocol Negotiation) and ALPS (Application-Layer
  Protocol Settings).
- Bounded, client-owned TLS ticket caches for H1 and H2, partitioned by exact
  origin and route, with no early data.

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
- Sequential keep-alive reuse owned by the client, with bounded waiters and no
  pipelining.
- Finite opt-in HTTPS redirects.
- Opt-in typed connection-setup retries before dispatch.
- Opt-in replay of an idempotent request, once, on a fresh connection when a
  reused keep-alive connection closes before any response byte.
- Direct HTTPS and plaintext HTTP.
- Absolute-form forwarding of `http://` origins over plaintext or TLS proxies.
  This includes one replay on a fresh connection after a strict, valid Basic
  challenge.
- HTTP and HTTPS CONNECT routes, and SOCKS5 routes with local or remote DNS.
- Upgrade handoff that preserves every byte.
- At most 8 informational (1xx) responses before the final response head.

Planned:

- Parallel connection policy.
- Broader retry classes.
- Additional proxy modes.

## HTTP/2

Supported:

- Ordered SETTINGS, request and response fields, window update, pseudo-header
  order, and priority.
- Request trailers, either static or produced by a declared streaming body.
- ALPS peer settings and connection-scoped `ACCEPT_CH`.
- Flow-controlled request bodies, owned or pull-driven, and streaming
  responses.
- An early, incomplete response does not stop the request upload (RFC 9113
  §8.1). The upload continues as the caller reads the response body.
- Exact direct WebSocket extended CONNECT: an explicit order for the five
  pseudo-header fields, gating on the peer's capability, duplex DATA flow
  control, and cancellation scoped to the stream.
- Per-request HEADERS overrides. An extended CONNECT stream on a pooled
  session carries the profile's pseudo-header order and priority, while
  ordinary streams keep theirs.
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
- Per-profile HPACK representations for extended CONNECT.
- Captured extended CONNECT behavior through proxies.

## QUIC

Supported:

- A BoringSSL-backed Quinn client: handshake, packet and header protection,
  key updates, live Retry, and endpoint HMAC.
- Typed transport settings taken from captures.
- An exact, seeded transport-parameter serializer with randomized permitted
  order and GREASE (reserved values that keep peers tolerant of unknown ones).
- A reusable connection lifecycle owned by H3.
- A bounded opt-in NSS key-log queue behind the internal
  `phantom-quic-btls/keylog` feature. `phantom-http` does not expose it.
- A QUIC v1 packet analyzer that retains no payloads, and a comparator of logical
  flights that does not depend on packetization.
- Controlled decrypted Chrome and Phantom captures through the first request.

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
- RFC 9298 CONNECT-UDP proxies (see [Routes](#routes)).
- Opt-in, bounded Alt-Svc upgrade from negotiated HTTPS on a direct or SOCKS5
  route. Phantom adds a canonical `Alt-Used` field with an explicit port and
  keeps the origin authority, SNI, and authentication identity. The
  alternative is dialed over the route that learned it.

Supported wire behavior:

- Exact `h3` ALPN and the Chrome H3 ALPS offer.
- Authenticated peer application SETTINGS, and strict decoding and handoff of
  connection-scoped `ACCEPT_CH`.
- Typed, ordered SETTINGS and request and response fields.
- Chrome's nonzero inbound QPACK (the HTTP/3 field compression), randomized
  GREASE, H3 DATAGRAM, and deferred decoder-stream policy.
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
- Bounded qlog for a single connection behind the internal `phantom-net/qlog`
  feature. `phantom-http` does not expose it.
- Opt-in Alt-Svc racing (`AltSvcPolicy::race`):
  - QUIC setup to the alternative starts first. H1/H2 setup to the origin
    starts after a delay the caller sets, or at once if the alternative fails
    or a reusable pooled H2 connection exists.
  - The request is dispatched once, on the winner.
  - Alternative setup is limited to 4 seconds.
  - A losing alternative keeps connecting in the background and is then
    pooled or marked broken.
  - Broken alternatives back off as in Chromium 153: 300 seconds, doubling,
    capped at two days.

  See [Racing](../guides/http3.md#racing).

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
- Alt-Svc racing across multiple alternatives, a racing delay derived from
  RTT, and DNS HTTPS-record (`dns_alpn_h3`) jobs.
- WebSocket over H3.
- Multiplexing several CONNECT-UDP tunnels on one outer connection.
- MASQUE recipes captured from browsers.

## Public client

Supported:

- A pooled facade for exact H1, H2, and H3 that is cheap to clone.
- Pooled H1/H2 selection over a direct or SOCKS5 route, with optional later H3
  selection through Alt-Svc on the same route. H3 is tried sequentially by
  default, or raced against the origin under an opt-in policy.
- Owned request builders with explicit methods.
- Ordered trailers, either static or produced by a declared streaming body, on
  exact H1/H2/H3 and negotiated requests.
- Streaming bodies, owned-byte or pull-driven.
- Default and per-request connection retry policies for exact H1/H2/H3 setup
  and for TCP setup of negotiated requests before ALPN.
- Opt-in status retry for idempotent requests on 408, 425, 429, and 5xx
  statuses that the caller lists, with an optional capped `Retry-After` and a
  budget for the whole request.
- Opt-in per-request browser field templates. A template holds:
  - the captured field order and values for each protocol;
  - slots for caller fields and client hints;
  - the captured H2 HEADERS priority for its request kind; and
  - a check before any I/O that rejects a caller `User-Agent` or brand-list
    client hint naming another browser family or major version.

  Recipes cover address-bar navigations and same-origin no-store `fetch`
  GETs. See [Request templates](../guides/profiles.md#request-templates).
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
- Bounded retention of H1/H2 TLS tickets.
- Alt-Svc broken state per origin, route, and alternative, with capped
  doubling backoff. A successful connection to the alternative or
  `clear_alt_svc` clears it.
- An optional bounded cookie jar that the caller activates explicitly:
  - deterministic path and creation order;
  - Public Suffix List checks (including private and unlisted suffixes),
    prefix checks, and expiry;
  - Chromium-style least-recently-used eviction;
  - stores `SameSite` and `Partitioned` cookies and sends them as for a
    user-initiated top-level navigation;
  - rejects insecure `SameSite=None`, insecure `Partitioned`, and `Secure`
    cookies set over `http://`; and
  - places the `Cookie` field where the profile's `CookiePlacement` puts it,
    with Chrome 153 and Firefox 156 recipes.

  See [Cookies](../guides/connections-and-state.md#cookies).
- Client-hint fields defined by the profile, with bounded `Accept-CH` state
  per exact origin from responses, connection-scoped H2/H3 ALPS `ACCEPT_CH`,
  and one bounded `Critical-CH` retry for safe methods. A request template
  places the hints at its captured slots. Without one, they precede the
  caller's fields. See [Client hints](../guides/profiles.md#client-hints).
- Opt-in finite redirects for `https://` requests: WHATWG URL resolution,
  `https://` targets only, browser method and body transitions, and removal of
  credentials and client hints on cross-origin hops. A client with a redirect
  policy rejects `http://` requests before any I/O.

Planned:

- Cookie contexts the caller selects (cross-site and embedded requests, and
  cross-site CHIPS partitions).
- Permissions and delegation context.
- QUIC tickets and DNS state.
- Persistence of Alt-Svc brokenness, reset on network change, and proxy-route
  snapshots.
- Broader policy and retry classes.

## Server-sent events and WebSocket

Supported server-sent events (SSE, `sse` feature):

- A bounded decoder over the ordinary streaming response body.
- Finite reconnects owned by the client, with:
  - a `Last-Event-ID` placeholder the caller can position;
  - the server's retry delay, with an optional minimum;
  - an optional idle timeout on DATA activity that is safe to cancel;
  - cookies; and
  - termination on a 204 response.
- Differential tests that replay retained Chrome 153 and Firefox 156 Windows
  HTTP/1.1 captures.

Supported WebSocket (`websocket` feature):

- WebSocket over H1 on its direct and proxy routes.
- Exact WebSocket over H2 extended CONNECT, for profiles that define an
  extended CONNECT pseudo-header order. Routes: direct, HTTP CONNECT
  (plaintext or TLS proxy, HTTP/1.1 or HTTP/2 proxy transport, one Basic
  replay on a fresh proxy connection), and SOCKS5 with local or remote DNS.
  The peer capability gate applies, with no route or H1 fallback.
- Ordered, customizable handshakes, and Basic authentication to a forward
  proxy when it sends a challenge.
- Typed opt-in `permessage-deflate` (`websocket-deflate` feature).
- Client cookies, bounded messages, `Stream`/`Sink`, and strict response
  validation for each protocol.
- A profile WebSocket connection policy with Chrome 153/Edge 153 and Firefox
  156 recipes. Depending on the recipe, it reuses a capable H2 session or
  opens either an `http/1.1`-only Upgrade connection or a new H2 connection.
  It uses the captured CONNECT pseudo-header order, priority, field templates,
  and deflate offers. See
  [Profile connection policy](../guides/websocket.md#profile-connection-policy).

Planned or not captured:

- Firefox-style transaction restarts on fresh connections. Chrome's single
  resend, after a reused H1 connection closes before a response, is already
  available as opt-in reused-connection replay.
- SSE behavior over H2 and H3, on macOS, and in Safari is not yet captured.
- Other WebSocket extensions, named compression and send policies, and
  automatic reconnect.
- Remaining gaps in the WebSocket recipes: HPACK representation parity,
  Firefox's stream `WINDOW_UPDATE` and empty-message RSV1, Chrome's
  `REFUSED_STREAM` retry, and proxy captures. Retained Chrome 153, Edge 153,
  and Firefox 156 Windows captures show that Chromium uses H2 WebSockets only
  on an existing session that advertises the setting, while Firefox also
  opens fresh H2 connections. Pseudo-header order, priority, deflate offer,
  and send policy differ by family.
- WebSocket over H3, added only from evidence.

## Routes

Supported direct paths:

- Direct HTTPS over H1 or H2, plaintext HTTP over H1, exact direct H2
  WebSocket extended CONNECT, and H3 over QUIC.
- Direct negotiated HTTPS can upgrade through a learned Alt-Svc alternative
  without changing the direct route.

Supported HTTP proxies:

- HTTP/1.1 absolute-form forwarding for `http://` origins over plaintext or
  TLS-encrypted proxies. Basic authentication is challenge-driven: the first
  request is anonymous, and exactly one replay follows on a fresh connection
  over the same route. Forwarding never switches to CONNECT or another
  protocol.
- HTTP/1.1 CONNECT over plaintext proxies or TLS proxies verified with
  their own trust settings, including one bounded Basic retry after a challenge.
- HTTPS proxies reached over HTTP/2 when the route selects it explicitly
  (RFC 9113 §8.5 CONNECT). Each tunnel uses its own proxy connection, the
  profile's ALPN is offered unchanged, and a selection mismatch is a typed
  error with no fallback.

Supported SOCKS5:

- SOCKS5 with local or remote DNS and optional RFC 1929 credentials, for exact
  H1/H2 origin TLS, negotiated H1-or-H2 origin TLS, and H1 WS/WSS.
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

- Negotiated HTTPS, and therefore the Alt-Svc upgrade, over an HTTP proxy or a
  CONNECT-UDP proxy. A CONNECT tunnel is TCP and cannot reach an `h3`
  alternative; CONNECT-UDP carries QUIC only and offers no TLS stream for ALPN.
  Both are typed refusals before any proxy I/O, never a fallback. See
  [Routes that carry the upgrade](../guides/http3.md#routes-that-carry-the-upgrade).

Planned:

- Other proxy authentication schemes, and learned challenge state.
- A shared or multiplexed H2 proxy session.
- Plaintext forwarding over H2.
- Custom SOCKS5 resolvers.
- CONNECT-UDP proxy authentication schemes other than Basic.

## Validation

Supported:

- Local TLS, H2, and QUIC fixtures, and hostile H1/H2/H3 peers.
- Bounded qlog and key-log seams.
- Deterministic authenticated QUIC packet analysis, two fresh-profile Chrome
  H3 ClientHellos, and controlled Chrome and Phantom packet evidence.
- Fuzzing with AddressSanitizer: short runs on relevant changes, and longer
  weekly runs that grow a cached, uncommitted corpus. Targets are the
  test-kit ClientHello and H2 frame decoders, Quinn transport parameters, and
  the production HTTP CONNECT response and proxy Basic challenge parsers.
- Peet and Pingly as supplemental observers.

Planned:

- A repeated packet-shape study and a Prism comparison.
- Broader protocol fuzzing and sanitizers for native adapters.
- Long soak tests.

See [Validation](../explanation/validation.md) for how each claim is proved.

## Browser profiles

TLS, H2, and QUIC protocol settings are transport recipes. They do not select
behavior by host OS. Capture provenance stays platform-specific, because
browser builds, system integrations, launch conditions, and release channels
can change the bytes a browser sends.
[Browser profiles](../guides/profiles.md#recipe-names-and-platforms) explains
the naming rules.

Captures from more than one platform decide whether two recipes share
component data:

- [Cross-platform transport parity](../explanation/validation.md#cross-platform-transport-parity)
  records Windows 11 captures that match the Chrome 152 TLS, H2, QUIC, and H3
  recipes and the Firefox 154 TLS and H2 recipes on every compared field.
- SSE and WebSocket browser captures are from Windows 11 (10.0.26200) only.
  Phantom does not assume macOS parity for them.
- Chrome 153 (153.0.8010.48), Edge 153 (153.0.4234.48), and Firefox 156
  (156.0) recipes come from Windows 11 captures only. Their transport names
  carry no platform because they rest on the 152/154 finding that these layers
  did not depend on the platform.

How the recipes differ:

- `chromium::v153_*` differ from 152 only in the trust-anchor ID list: 28 IDs,
  in the most frequent of 35 orders seen across 60 processes.
- Edge 153 matches Chrome 153 on H2, QUIC, and H3 and omits trust-anchor IDs.
  So `edge::` carries only `v153_tls`, `v153_http3_tls`,
  `v153_windows_client_hints`, and its request templates.
- `firefox::v156_tls` drops FFDHE-2048/3072 and uses a 240-byte ECH GREASE
  payload. `v156_http2` equals `v154_http2` except for its captured extended
  CONNECT pseudo-header order and priority.

Request templates:

- The navigation templates match every retained page request:
  - Chrome 153 over H1 (the SSE, WebSocket, and client-hint captures), H2 (the
    WebSocket captures), and H3 (the H3 startup capture);
  - Edge 153 over H1, H2, and H3; and
  - Firefox 156 over H1 and H2.

  The fetch templates match every retained no-store report `fetch` in the
  WebSocket captures, over H1 and H2.
- Each template carries the captured H2 HEADERS priority for its request kind,
  sent on that stream only. Navigations use weight 256 exclusive (Chrome,
  Edge) and 42 (Firefox), which equal the H2 recipes' connection priority.
  Fetches use weight 220 exclusive and 22. The dependency is always stream 0,
  as in every capture. Chrome's dependency on another open stream of equal or
  higher priority is not reproduced.
- The Chrome `User-Agent` value comes from the SSE capture, which ran in
  headful launch mode. The other Chrome and Edge captures ran headless. Edge
  templates leave `User-Agent` to the caller.
- The H1 captures used plaintext loopback origins. No capture shows where a
  `fetch` places hints requested through `Accept-CH`, so the fetch templates
  refuse to send them. Where navigation templates place requested hints is
  captured on H1 only and inferred for H2 and H3.
- The profile's `CookiePlacement` decides where the jar's `Cookie` field goes
  in the expanded template. With the Chrome 153 and Firefox 156 presets, the
  H1 fields on each side of it agree with the `set-cookie-then-close`
  EventSource reconnect captures: last for the Chrome templates, and after
  `Referer` and before `Sec-Fetch-Dest` for the Firefox `fetch` template.
  Those captured requests are EventSource reconnects, and no H2 or H3 capture
  carries a cookie. The navigation, H2, and H3 positions come from browser
  source.

Randomized fields:

- Chrome's trust-anchor ID order is fixed within a browser process and
  differs between processes. It is a hash-iteration order, not a
  per-connection permutation. The Chrome 152 recipe keeps the most frequently
  observed order.
- Chrome's ECH GREASE uses HKDF-SHA256 with AES-128-GCM on every observed
  connection, and tests compare it exactly.
- Firefox 154 and 156 choose their ECH GREASE AEAD per connection, between
  AES-128-GCM and ChaCha20-Poly1305. Both Firefox recipes list both, the
  backend draws one uniformly for each connection, and 200-connection
  distribution tests bound the split.
- The Chrome 152, Chrome 153, and Edge 153 recipes leave the AEAD list empty
  and emit AES-128-GCM on every connection.

The runtime uses the validated settings it receives. It does not branch on the
host OS or the client-family name. OS-specific code exists only for real
differences in sockets, trust stores, native builds, or profiling.

### Chrome 152 build equivalence

The retained Chrome 152 transport evidence is from build `152.0.7977.83`.
Build `152.0.7977.64` is assumed, not verified, to be equivalent. Under the
major-version profile policy it is expected to use the same transport
fingerprint, but no `.64` capture or differential exists, and Phantom makes no
`.64` claim until one does.

The current client-hint recipe stays specific to the exact build and platform,
because its values include the full `.83` version and macOS platform fields.
Callers presenting `.64` must supply matching full-version hint values.

## Claim boundary

Local raw captures and packet and frame differentials are the primary
evidence. Pingly, Peet, and Prism are independent observers that can reveal
missing signals, but none of them alone decides pass or fail. Phantom reports
the concrete fields and behaviors a test covers. It does not label a whole
profile "verified".
