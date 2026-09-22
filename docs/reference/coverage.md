# Coverage

This page is the detailed support contract. It lists, layer by layer, what
Phantom supports today and what is planned. Anything not listed as supported
is unsupported.

Phantom reproduces observable HTTP-client behavior. It is not a browser DOM,
JavaScript, rendering, canvas, font, WebRTC, or device-fingerprint engine.
Within the HTTP stack, coverage is layered so a TLS match is never presented as
a complete client match.

## What "supported" means

"Supported" means the entire relevant lifecycle works: configuration,
validation, emission, response behavior, cancellation, errors, observability,
and deterministic tests. Merely parsing an option or connecting successfully
does not count.

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
| HTTP/3 | Exact H3 over direct, SOCKS5, or CONNECT-UDP; opt-in Alt-Svc upgrade and racing | Multiple-alternative racing, WebSocket over H3 |
| Routes | Direct, HTTP forward and CONNECT, SOCKS5, CONNECT-UDP | Other proxy authentication schemes |
| SSE and WebSocket | Feature-gated, bounded, with browser comparisons and Chrome/Firefox WebSocket recipes | H2/H3 SSE captures, proxy WebSocket captures |

The [route matrix](route-matrix.md) lists every scheme, protocol, and route
combination.

## TCP

Supported:

- Profile TCP socket options (`ClientProfile::with_tcp`): `TCP_NODELAY` and
  keepalive idle time and interval, applied before connecting on every TCP
  connection, including proxy and SOCKS5 UDP control connections. A socket
  option the OS rejects fails that connection attempt.
- Profile address racing (`TcpAddressRacing`): Chromium's Happy Eyeballs v2
  over the complete resolver result, with at most two concurrent attempts,
  cancellation of the losing attempt, and the most recent failure returned.
- `chromium::v153_tcp` (Windows and Linux) and `firefox::v156_tcp`
  (`TCP_NODELAY` only, resolver-order attempts), from browser source. See
  [TCP socket option evidence](../explanation/validation.md#tcp-socket-option-evidence).

Not modeled:

- Firefox's per-connection keepalive schedule, its address selection, and
  Chromium's macOS idle-only keepalive as a named recipe.
- Chromium's resolver behavior before racing: its own address sorting, IPv6
  reachability probe, partial DNS results, and HTTPS records. Phantom races
  the system resolver's complete answer.
- Racing for HTTP/3. Chromium's QUIC job connects only to the first resolved
  address; Phantom's H3 connector tries resolved addresses in order after a
  connection failure.
- An Edge TCP recipe; no public source or capture shows Edge's options.
- The TCP SYN itself (window, MSS, options, TTL), which the host OS decides.

## TLS over TCP

Supported:

- Typed ordered profiles.
- Fixture-backed recipes: Chrome 152, Firefox 154, and Safari 18.5 from macOS
  captures, with Chrome 152 and Firefox 154 also matched on Windows; Chrome
  153, Edge 153, and Firefox 156 from Windows captures. See
  [Browser profiles](#browser-profiles).
- Certificate and hostname verification.
- ALPN and ALPS.
- Bounded client-owned H1/H2 ticket caches with exact origin and route
  partitioning and no early data.

Planned:

- More versions and platform captures.
- A public ticket policy.
- Generic imported stacks.

## HTTP/1.1

Supported:

- Ordered request fields, and static or declared streaming-body-produced
  trailers.
- Ordinary methods with owned-byte or pull-driven streaming bodies; exact
  `Content-Length` validation.
- Response field order, duplicate interleaving, and name spelling.
- Streaming, backpressured responses.
- Client-owned sequential keep-alive reuse with bounded waiters and no
  pipelining.
- Finite opt-in HTTPS redirects.
- Opt-in typed pre-dispatch connection retries.
- Opt-in replay of idempotent requests once on a fresh connection after a
  reused keep-alive connection closes before any response byte.
- Direct HTTPS and plaintext HTTP.
- Absolute-form forwarding for `http://` origins over plaintext or TLS
  proxies, including one fresh-connection replay after a strict, valid Basic
  challenge.
- HTTP/HTTPS CONNECT and local-/remote-DNS SOCKS5 routes.
- Byte-preserving Upgrade handoff.
- At most 8 informational responses before the final head.

Planned:

- Parallel connection policy.
- Broader retry classes.
- Additional proxy modes.

## HTTP/2

Supported:

- Ordered SETTINGS, request and response fields, window update, pseudo-header
  order, and priority.
- Static or declared streaming-body-produced request trailers.
- ALPS peer settings and connection-scoped `ACCEPT_CH`.
- Flow-controlled owned or pull-driven request bodies and streaming responses.
- An incomplete early response keeps the request upload running (RFC 9113
  §8.1), and the upload progresses as the caller reads the response body.
- Exact direct WebSocket extended CONNECT with an explicit five-field pseudo
  order, peer capability gating, duplex DATA flow control, and stream-scoped
  cancellation.
- Per-request HEADERS overrides, so an extended CONNECT stream on a pooled
  session carries the profile's pseudo-header order and priority while
  ordinary streams keep theirs.
- Client-owned exact-origin and route reuse with bounded local active work and
  waiters, and peer stream-limit enforcement.
- Opt-in typed pre-dispatch connection retries.
- One replacement-connection retry for a bodyless GET rejected by
  `GOAWAY(NO_ERROR)`.
- Bounded response receive state: at most 8 informational responses before
  the final head, an unadvertised response header-list ceiling, and limits on
  empty and small unread DATA frames. The values are in
  [Defaults and limits](limits.md#protocol-state).

Planned:

- Broader retry classes.
- Per-profile HPACK representations for extended CONNECT.
- Captured extended-CONNECT behavior through proxies.

## QUIC

Supported:

- BoringSSL-backed Quinn client handshake, packet and header protection, key
  updates, live Retry, and endpoint HMAC.
- Typed captured transport settings.
- A seeded exact transport-parameter serializer with randomized permitted
  order and GREASE.
- An H3-owned reusable connection lifecycle.
- A bounded opt-in NSS key-log queue behind the internal
  `phantom-quic-btls/keylog` feature (not exposed by `phantom-http`).
- A payload-free QUIC v1 packet analyzer and a packetization-independent
  logical-flight comparator.
- Controlled Chrome/Phantom decrypted captures through the first request.

Planned:

- A generic non-H3 connection API.
- A repeated packet-shape stability study.

## HTTP/3

Supported requests and routes:

- Forced exact requests over direct QUIC.
- Local-/remote-DNS SOCKS5 using optionally authenticated RFC 1928 UDP
  ASSOCIATE, with a retained TCP control connection and route-keyed connection
  reuse. Remote-DNS DOMAIN targets need no local origin lookup and present a
  stable logical QUIC peer.
- RFC 9298 CONNECT-UDP proxies (see [Routes](#routes)).
- Opt-in bounded Alt-Svc upgrade from negotiated direct HTTPS, with automatic
  canonical explicit-port `Alt-Used`, while preserving origin authority, SNI,
  and authentication identity.

Supported wire behavior:

- Exact `h3` ALPN and the Chrome H3 ALPS offer.
- Authenticated peer application SETTINGS, plus strict connection-scoped
  `ACCEPT_CH` decoding and handoff.
- Typed ordered SETTINGS plus request and response fields.
- Chrome nonzero inbound QPACK, randomized GREASE, H3 DATAGRAM, and deferred
  decoder-stream policy.
- Bounded dynamic response decoding and connection-owned request encoding;
  live capture-matching QPACK stream and HEADERS bytes.
- A local 256 KiB decoded response field-section ceiling (lower when the
  profile advertises less) that does not alter the SETTINGS frame.

Supported lifecycle:

- Ordinary methods with flow-controlled owned or pull-driven request bodies
  and ordered static or declared streaming-body-produced trailers.
- Streaming data and trailers, and chained informational responses.
- Client-owned multiplexed reuse with bounded active work and waiters.
- Opt-in typed pre-dispatch DNS, endpoint, and QUIC setup retries, with
  loopback recovery tests for a refused direct handshake, a refused SOCKS5
  proxy connect, and a refused handshake retried through a fresh SOCKS5
  association.
- Exact hostile-peer close-code tests.
- Stream-scoped cancellation and bounded shutdown.
- Single-connection bounded qlog behind the internal `phantom-net/qlog`
  feature (not exposed by `phantom-http`).
- Opt-in Alt-Svc racing (`AltSvcPolicy::race`): alternative QUIC setup first,
  origin H1/H2 setup after a caller-set delay, or at once on alternative
  failure or with a reusable pooled H2 connection; one dispatch on the
  winner; a 4-second alternative setup limit; a losing alternative that keeps
  connecting in the background and is pooled or marked broken; and Chromium
  153 broken backoff (300 seconds, doubling, two-day cap). See
  [Racing](../guides/http3.md#racing).

Supported in `phantom-net` only (not exposed by the facade):

- RFC 9220 extended CONNECT for the WebSocket protocol, gated on peer SETTINGS
  from ALPS or the control stream with no local setting emitted, with an
  explicit five-field pseudo order from a custom profile, a bounded duplex
  DATA stream with FIN, stream-scoped `H3_REQUEST_CANCELLED` reset and
  datagram abort, and a readable rejection body.

Planned:

- A live BoringSSL-server H3 `ACCEPT_CH` request differential.
- Nonempty local H3 application settings.
- Repeated fresh-browser packet differentials.
- Extension-specific datagram APIs.
- Multiple-alternative Alt-Svc racing, an RTT-derived racing delay, and DNS
  HTTPS-record (`dns_alpn_h3`) jobs.
- WebSocket over H3.
- Multiplexed CONNECT-UDP tunnels on one outer connection.
- Browser-captured MASQUE recipes.

## Public client

Supported:

- A cheap-clone pooled exact-H1/H2/H3 facade.
- Pooled direct H1/H2 selection with optional later Alt-Svc H3 selection,
  sequential by default or raced against the origin by an opt-in policy.
- Owned request builders with explicit methods.
- Ordered static or declared streaming-body-produced trailers on exact
  H1/H2/H3 and negotiated requests.
- Owned-byte or pull-driven streaming bodies.
- Default and per-request connection retry policies for exact H1/H2/H3 setup
  and negotiated pre-ALPN TCP setup.
- Opt-in status retry for idempotent requests on caller-listed
  408/425/429/5xx statuses, with an optional capped `Retry-After` and a
  request-wide budget.
- Opt-in per-request browser field templates: captured field order and
  values per protocol, caller slots, client-hint slots, the captured H2
  HEADERS priority of the request kind, and a pre-I/O check
  that rejects a caller `User-Agent` or brand-list client hint naming another
  browser family or major version. Recipes cover address-bar navigations and
  same-origin no-store `fetch` GETs; see
  [Request templates](../guides/profiles.md#request-templates).
- One WHATWG/IDNA endpoint boundary shared by wire authority and state keys.
- Protocol-specific TCP and QUIC TLS settings.
- Additive DER trust roots.
- Default and per-request routes.
- A unified streaming response body with inclusive bounded collection.
- Opt-in streaming decoding of caller-advertised `gzip`/`x-gzip`, `deflate`,
  `br`, and `zstd`, with an inclusive decoded-byte cap, fail-closed chains, and
  wire-view response fields. See [Content decoding](../guides/content-decoding.md).
- Metadata for selected protocol, ordered fields, redirect count, and
  setup-retry count.
- Typed errors.

Deliberately excluded:

- Replay of H3 requests on streams that were already open when `GOAWAY`
  arrived, because servers disagree on the `GOAWAY` identifier boundary.

## Cross-request state

Supported:

- Bounded H1, H2, and H3 retained pools with per-origin-and-route active and
  waiting admission.
- Bounded per-origin negotiated pre-selection admission, converted to H1/H2
  admission after ALPN.
- A bounded opt-in exact-origin Alt-Svc store:
  - `Age`/`ma` handling, replacement, expiry, and `clear`;
  - setup-failure eviction and `421` eviction;
  - exact-origin H2 ALTSVC frame learning on negotiated requests;
  - per-location H3 connection slots so exact and Alt-Svc H3 do not churn;
  - request-scoped automatic `Alt-Used` limited to managed H3 attempts; and
  - caller-owned export and import of direct-route snapshots (canonical
    origin, location, whole-second expiry; revalidated and never extended).
- One request-scoped bounded pre-dispatch setup-retry budget across redirect
  and internal replacement attempts.
- A bounded graceful-H2-`GOAWAY` retry for exact and negotiated H2.
- Opt-in unprocessed-request replay (H2 `REFUSED_STREAM` or `GOAWAY` above the
  stream, H3 `H3_REQUEST_REJECTED` or `GOAWAY` before the stream opened) for
  any method with an absent or owned body, on a different connection with the
  same route and protocol.
- Bounded H1/H2 TLS ticket retention.
- Per-origin-and-alternative Alt-Svc broken state with doubling, capped
  backoff, cleared by a successful alternative connection or `clear_alt_svc`.
- An optional bounded cookie jar with deterministic path and creation order,
  PSL (including private and unlisted suffixes), prefix, and expiry checks,
  Chromium-style least-recently-used eviction, and explicit activation. It
  stores `SameSite` and `Partitioned` cookies and sends them as for a
  user-initiated top-level navigation. It rejects insecure `SameSite=None`,
  insecure `Partitioned`, and `Secure`-over-`http://` cookies. The jar's
  `Cookie` field goes where the profile's `CookiePlacement` puts it, with
  Chrome 153 and Firefox 156 recipes. See
  [Cookies](../guides/connections-and-state.md#cookies).
- Profile-defined client-hint fields with bounded exact-origin response
  `Accept-CH` state, connection-scoped H2/H3 ALPS `ACCEPT_CH`, and one bounded
  `Critical-CH` retry for safe methods. A request template places them at its
  captured slots; otherwise they precede the caller's fields. See
  [Client hints](../guides/profiles.md#client-hints).
- Opt-in finite redirects for `https://` requests with WHATWG resolution,
  `https://`-only targets, browser method and body transitions, and
  cross-origin credential and client-hint removal. A client with a redirect
  policy rejects `http://` requests before I/O.

Planned:

- Caller-selected cookie contexts (cross-site and embedded requests,
  cross-site CHIPS partitions).
- Permissions and delegation context.
- QUIC tickets and DNS state.
- Alt-Svc brokenness persistence and network-change reset, and proxy-route
  snapshots.
- Broader policy and retry classes.

## Server-sent events and WebSocket

Supported SSE (`sse` feature):

- A bounded decoder over the ordinary streaming response body.
- Finite client-owned reconnects with a caller-positionable `Last-Event-ID`
  placeholder, the server retry delay with an optional minimum, an optional
  cancellation-safe DATA-activity idle timeout, cookies, and 204 termination.
- Differential tests that replay retained Chrome 153 and Firefox 156 Windows
  HTTP/1.1 captures.

Supported WebSocket (`websocket` feature):

- WS/H1 over its direct and proxy routes.
- Exact WS/H2 extended CONNECT for profiles with an extended CONNECT
  pseudo-header order, over direct, HTTP CONNECT (plaintext or TLS proxy,
  HTTP/1.1 or HTTP/2 proxy transport, one Basic replay on a fresh proxy
  connection), and local-/remote-DNS SOCKS5 routes, with the peer capability
  gate and no route or H1 fallback.
- Ordered customizable handshakes and challenge-driven forward-proxy Basic
  authentication.
- Typed opt-in `permessage-deflate` (`websocket-deflate` feature).
- Client cookies, bounded messages, `Stream`/`Sink`, and protocol-specific
  strict response validation.
- A profile WebSocket connection policy with Chrome 153/Edge 153 and Firefox
  156 recipes: reuse of a capable H2 session, else an `http/1.1`-only Upgrade
  connection or a new H2 connection per recipe, with captured CONNECT pseudo
  order, priority, field templates, and deflate offers. See
  [Profile connection policy](../guides/websocket.md#profile-connection-policy).

Planned or not captured:

- Firefox-style transaction restarts on fresh connections. Chrome's single
  resend after a reused H1 connection closes before a response is available
  as opt-in reused-connection replay.
- H2, H3, macOS, and Safari SSE behavior is not yet captured.
- Other WebSocket extensions, named compression and send policies, and
  automatic reconnect.
- Remaining gaps in the WebSocket recipes: HPACK representation parity,
  Firefox's stream `WINDOW_UPDATE` and empty-message RSV1, Chrome's
  `REFUSED_STREAM` retry, and proxy captures. Retained Chrome 153, Edge 153,
  and Firefox 156 Windows captures show that Chromium uses H2 WebSockets only
  on an existing session that advertises the setting, while Firefox also
  opens fresh H2 connections; pseudo-order, priority, deflate offer, and send
  policy differ by family.
- WebSocket over H3, only from evidence.

## Routes

Supported direct paths:

- Direct HTTPS/H1/H2, plaintext HTTP/H1, exact direct H2 WebSocket extended
  CONNECT, and H3/QUIC.
- Direct negotiated HTTPS may upgrade through learned Alt-Svc without changing
  the direct route.

Supported HTTP proxies:

- HTTP/1.1 absolute-form forwarding for `http://` origins over plaintext or
  TLS-encrypted proxies, including challenge-driven Basic with an anonymous
  first request and exactly one replay on a fresh same-route connection.
  Forwarding never changes to CONNECT or another protocol.
- HTTP/1.1 CONNECT over plaintext or independently authenticated TLS proxies,
  including one bounded challenge-driven Basic retry.
- HTTPS proxies reached over HTTP/2 by explicit route choice (RFC 9113 §8.5
  CONNECT, one proxy connection per tunnel, profile ALPN offered unchanged, and
  a selection mismatch is a typed error with no fallback).

Supported SOCKS5:

- Credential-capable RFC 1929 local-/remote-DNS SOCKS5 for H1/H2 origin TLS
  and H1 WS/WSS.
- Exact H3 over local-DNS `socks5://` or remote-DNS `socks5h://` through
  RFC 1928 UDP ASSOCIATE, with a retained TCP control connection, a fixed IP
  or canonical domain target, route-keyed reuse, and typed terminal proxy
  failures.
- The SOCKS5 UDP adapter drops oversized or undeliverable datagrams like UDP
  and ends the association when its TCP control connection closes.

Supported CONNECT-UDP:

- Exact H3 over RFC 9298 CONNECT-UDP proxies with an `https` URI template and
  percent-encoded target, and independent proxy trust and SNI.
- On the default HTTP/3 leg: SETTINGS and QUIC DATAGRAM gating before any
  stream, Context ID 0 HTTP Datagrams with bounded per-stream queues, and a
  1252-byte outer path MTU with pre-I/O capacity checks.
- An explicitly selected HTTP/2 extended CONNECT or HTTP/1.1 Upgrade leg
  carrying DATAGRAM capsules.
- Challenge-driven Basic proxy authentication on every leg, with one replay on
  a fresh proxy connection.
- One outer connection per inner connection and outer-only resolve and connect
  retries.

Across all routes:

- No route or protocol fallback.
- Canonical Unicode proxy and origin hosts.
- HTTPS proxy and origin trust and ticket caches are isolated.

Planned:

- Other proxy authentication schemes and learned challenge state.
- A shared or multiplexed H2 proxy session.
- Plaintext forwarding over H2.
- Custom SOCKS5 resolvers.
- CONNECT-UDP proxy authentication schemes other than Basic.
- Proxy-route Alt-Svc upgrade.

## Validation

Supported:

- Local TLS, H2, and QUIC fixtures, and hostile H1/H2/H3 peers.
- Bounded qlog and key-log seams.
- Deterministic authenticated QUIC packet analysis, two fresh-profile Chrome
  H3 ClientHellos, and controlled Chrome/Phantom packet evidence.
- ASan-backed fuzzing (short runs on relevant changes, longer weekly runs
  growing a cached, uncommitted corpus) of Phantom's test-kit ClientHello and
  H2 frame decoders, Quinn transport parameters, and the production HTTP
  CONNECT response and proxy Basic challenge parsers.
- Peet and Pingly as supplemental observers.

Planned:

- A repeated packet-shape study and a Prism comparison.
- Broader protocol fuzzing and native-adapter sanitizers.
- Long soaks.

See [Validation](../explanation/validation.md) for how each claim is proved.

## Browser profiles

TLS, H2, and QUIC protocol settings are transport recipes, not host-OS
selectors. Capture provenance remains platform-specific because browser
builds, system integrations, launch conditions, and release channels can
change emitted bytes. [Browser profiles](../guides/profiles.md#recipe-names-and-platforms)
explains the naming rules.

Cross-platform capture decides whether two recipes share component data.

- [Cross-platform transport parity](../explanation/validation.md#cross-platform-transport-parity)
  records Windows 11 captures that match the Chrome 152 TLS, H2, QUIC, and H3
  recipes and the Firefox 154 TLS and H2 recipes on every compared field.
- SSE and WebSocket browser captures are Windows 11 (10.0.26200) only; macOS
  parity is not assumed for them.
- Chrome 153 (153.0.8010.48), Edge 153 (153.0.4234.48), and Firefox 156
  (156.0) recipes come from Windows 11 captures only. Their platform-free
  transport names rest on the 152/154 finding that these layers did not depend
  on the platform.

How the recipes differ:

- `chromium::v153_*` differ from 152 only in the trust-anchor ID list (28 IDs;
  the most frequent of 35 per-process orders in 60 processes).
- Edge 153 matches Chrome 153 on H2, QUIC, and H3 and omits trust-anchor IDs,
  so `edge::` carries only `v153_tls`, `v153_http3_tls`,
  `v153_windows_client_hints`, and its request templates.
- `firefox::v156_tls` drops FFDHE-2048/3072 and uses a 240-byte ECH GREASE
  payload; `v156_http2` equals `v154_http2` apart from its captured extended
  CONNECT pseudo order and priority.

Request templates:

- The navigation templates match every retained page request: Chrome 153
  over H1 (the SSE, WebSocket, and client-hint captures), H2 (the WebSocket
  captures), and H3 (the H3 startup capture); Edge 153 over H1, H2, and H3;
  Firefox 156 over H1 and H2. The fetch templates match every retained
  no-store report `fetch` of the WebSocket captures over H1 and H2.
- Each template carries its request kind's captured H2 HEADERS priority, sent
  on that stream only: navigations weight 256 exclusive (Chrome, Edge) and 42
  (Firefox), which equal the H2 recipes' connection priority, and fetches
  weight 220 exclusive and 22. The dependency is always stream 0, as in every
  capture; Chrome's dependency on another open stream of equal or higher
  priority is not reproduced.
- The Chrome `User-Agent` value comes from the headful launch-mode SSE
  capture; the other Chrome and Edge captures ran headless. Edge templates
  leave `User-Agent` to the caller.
- The H1 captures used plaintext loopback origins. Where a `fetch` places
  hints requested through `Accept-CH` is not captured, so the fetch
  templates refuse to send them. The navigation templates' placement of
  requested hints is captured on H1 only and inferred for H2 and H3.
- Not reproduced: the position of an automatic `Cookie` field.

Randomized fields:

- Chrome's trust-anchor ID order is fixed within a browser process and differs
  between processes (a hash-iteration order, not a per-connection
  permutation); the Chrome 152 recipe keeps the most frequently observed order.
- Chrome's ECH GREASE uses HKDF-SHA256 with AES-128-GCM on every observed
  connection and is compared exactly.
- Firefox 154 and 156 choose their ECH GREASE AEAD per connection between
  AES-128-GCM and ChaCha20-Poly1305. Both Firefox recipes list both, the
  backend draws one uniformly for each connection, and 200-connection
  distribution tests bound the split.
- Chrome 152, Chrome 153, and Edge 153 recipes leave the list empty and emit
  AES-128-GCM on every connection.

The runtime consumes the validated settings it receives and does not branch on
the host OS or client-family name. OS-specific code is reserved for real
socket, trust-store, native-build, or profiling differences.

### Chrome 152 build equivalence

The retained Chrome 152 transport evidence is from build `152.0.7977.83`.
Equivalence for build `152.0.7977.64` is an unverified assumption: under the
major-version profile policy it is expected to use the same transport
fingerprint, but no `.64` capture or differential exists, and Phantom makes no
`.64` claim until one does. The current client-hint recipe remains
exact-build- and platform-specific because its values literally include the
full `.83` version and macOS platform fields. Callers presenting `.64` must
supply matching full-version hint values.

## Claim boundary

Local raw captures and packet/frame differentials are the primary evidence.
Pingly, Peet, and Prism are independent observers that can reveal missing
signals, but none is a sole pass/fail oracle. Phantom reports the concrete
fields and behaviors covered by a test; it does not attach ceremonial
"verified" labels to an entire profile.
