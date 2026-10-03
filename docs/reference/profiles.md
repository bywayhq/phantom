# Profile reference

Lookup tables for profile components, built-in recipes, TCP and UDP socket
options, HTTP/1.1 connections, request templates, required caller fields, and
client hints. For how to
use them, see [Browser profiles](../guides/profiles.md).

> For builders and specialists looking up a recipe or template detail.

## Profile components

| Method | Adds |
| --- | --- |
| `ClientProfile::new(tls)` | TLS ClientHello for H1 and H2 |
| `with_tcp(settings)` | TCP socket options for every TCP connection |
| `with_udp(settings)` | UDP socket options for every UDP socket that carries QUIC ([details](#udp-socket-options)) |
| `with_http1(settings)` | How many HTTP/1.1 connections to keep per origin and route |
| `with_dns_cache(settings)` | How long the client reuses the addresses it resolves ([details](#address-cache)) |
| `with_http2(settings)` | HTTP/2 SETTINGS, window update, priority, pseudo-header order, HPACK encoder choices, stream numbering, and the stream limit assumed before the peer's SETTINGS |
| `with_http3(Http3ClientSettings)` | H3 TLS ClientHello, QUIC transport parameters, HTTP/3 settings, and request settings |
| `with_client_hints(settings)` | Ordered client-hint fields and when to send them |
| `with_websocket(settings)` | WebSocket opening templates, compression offer, and connection policy |
| `with_proxy_connect(template)` | Fields of the CONNECT request that opens an HTTP proxy tunnel ([details](#proxy-connect-fields)) |
| `with_cookie_placement(placement)` | Where the cookie jar's `Cookie` field goes; last by default ([details](../guides/cookies.md#place-the-cookie-field-where-a-browser-does)) |

A request fails before any network I/O if the profile lacks a component it
needs.

## Built-in recipes

Phantom carries one version per browser: the current stable build on the
capture host for a desktop browser, and for an Android browser the build the
Play Store served to the capture emulator, which can trail stable. Older
versions are retired, so a recipe name always points at a build that can be
recaptured and reverified.

| Browser | Module | TLS | HTTP/2 | QUIC and HTTP/3 | Client hints | WebSocket | Captured on |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Chrome 154 | `chromium::v154_*` | Yes | Yes | Yes | `v154_windows_client_hints`, `v154_macos_client_hints` | `v154_websocket` | Windows; macOS for client hints and templates |
| Edge 154 | `edge::v154_*` | Yes | Chromium | Chromium QUIC and H3; own H3 TLS | `v154_windows_client_hints`, `v154_macos_client_hints` | Chromium | Windows; macOS for client hints and templates |
| Brave 154 | `brave::v154_*` | Yes | Chromium | Chromium QUIC and H3; own H3 TLS | `v154_windows_client_hints` | Chromium | Windows |
| Opera 136 | `opera::v136_*` | Yes | Chromium | Chromium QUIC and H3; own H3 TLS | `v136_windows_client_hints`, `v136_macos_client_hints` | Chromium | Windows; macOS for client hints and templates |
| Firefox 157 | `firefox::v157_*` | Yes | Yes | Yes | No | `v157_websocket` | Windows; macOS for templates |
| Firefox 156 for Android | `firefox_android::v156_tls` | Yes | No | No | No | No | Android emulator |
| Opera 102 for Android | `opera_android::v102_*` | Yes | No | No | `v102_android_client_hints` | No | Android emulator |
| Brave 153 for Android | `brave_android::v153_*` | Brave | Chromium | Chromium QUIC and H3; Brave H3 TLS | `v153_android_client_hints` | Chromium | Android emulator |
| Chrome 154 for Android | `chrome_android::v154_*` | Chromium | Chromium | Chromium | `v154_android_client_hints` | Chromium | Android emulator |
| Edge 153 for Android | `edge_android::v153_*` | Edge | Chromium | Chromium QUIC and H3; Edge H3 TLS | `v153_android_client_hints` | No | Android emulator (arm64) |

- "Captured on" lists the platforms whose retained captures back the recipe.
  "Android emulator" is an emulator, not a phone. On the Windows capture
  host it is an Android 17 emulator that reports a Pixel 7, and for Firefox
  and some Chrome 153 and Brave layers an earlier Android 15 emulator. Edge
  for Android was captured on an arm64 Android 17 emulator on a Mac that
  reports a Pixel 7.
- The Chrome, Edge, Brave, and Opera for Android TLS recipes leave ECH from
  HTTPS records off, because no Android capture could use a DNS-over-HTTPS
  resolver. Otherwise the Chrome, Edge, and Brave ones equal the desktop
  recipe the TLS column names.
- "Chromium" means the recipe function returns the desktop Chromium recipe,
  which the browser's own captures equal on every compared field.
  [Coverage](coverage.md#browser-profiles) gives the exact builds and how the
  recipes differ.
- TCP recipes are not in the table, because socket options do not appear in
  a capture. `chromium::v154_tcp` comes from Chromium source and
  `firefox::v157_tcp` from Firefox 157 socket hook logs and source; the
  Chromium one also serves Brave ([TCP socket options](#tcp-socket-options)).
- HTTP/1.1 connection recipes are not in the table either, for the same
  reason. `chromium::v154_http1` and `firefox::v157_http1` come from browser
  source ([HTTP/1.1 connections](#http11-connections)).
- Address cache recipes are not in the table either: a cache is not visible
  on the wire, only the queries it saves. `chromium::v154_dns_cache` and
  `firefox::v157_dns_cache` come from browser source
  ([Address cache](#address-cache)).
- Proxy CONNECT recipes are not in the table: `chromium::v154_proxy_connect`
  serves Chrome, Edge, Brave, and Opera, and `firefox::v157_proxy_connect`
  serves Firefox
  ([Proxy CONNECT fields](#proxy-connect-fields)).
- H2 WebSocket needs a captured pseudo-header order for extended CONNECT.
  Only `chromium::v154_http2` and `firefox::v157_http2` carry one
  ([Profile connection policy](../guides/websocket.md#open-a-websocket-the-way-the-browser-does)).

## Recipe names and platforms

The runtime uses the validated settings it receives and never branches on
the host operating system or the browser name.

| Name form | Example | Means |
| --- | --- | --- |
| No platform | `chromium::v154_tls`, `firefox::v157_http2` | The recipe carries no platform-specific data. It does not mean more than one platform was captured. |
| `windows`, `macos`, or `android` in the name | `chromium::v154_windows_client_hints`, `chromium::v154_macos_client_hints`, `chrome_android::v154_android_client_hints` | Observed on that platform. Never "selected by `target_os`". Used for client-hint and request-template recipes, whose values carry platform data on the wire. |

Every recipe comes from captures on one platform: Windows 11 for the
`chromium`, `edge`, `brave`, `opera`, and `firefox` recipes without `macos`
in the name, macOS 15.5 on Apple silicon for those with it, and Android
emulators for `chrome_android`, `edge_android`, `brave_android`,
`opera_android`, and `firefox_android`. Each recipe's rustdoc names its capture build and
platform.

On macOS, Opera sends the fields of its `windows` request templates, and
Edge does too with its language list set to `en-US`. Edge otherwise takes
`Accept-Language` from the system's language list, so for another locale
override that field. Both therefore have `macos` client hints but no `macos`
templates. Their other layers are the recipes without a platform in the
name, which retained single macOS runs match
([Validation](../explanation/validation.md#macos-recipes)).

## TLS ClientHello shape

Three `TlsSettings` fields shape the ClientHello beyond its lists of
values: `extension_order`, `ech_grease_payload_length`, and
`tls12_extensions_in_tls13_client_hello`.

| Recipe | `extension_order` | `ech_grease_payload_length` | `tls12_extensions_in_tls13_client_hello` |
| --- | --- | --- | --- |
| Chromium-family `*_tls` and `*_http3_tls` | `Permuted`: every extension shuffled per connection | `BackendDefault`: 144, 176, 208, or 240 bytes, drawn per connection | `false` |
| `firefox::v157_tls` | `Fixed`: Firefox's order | `FromClientHello { maximum_name_length: 100 }` | `true`; no effect, as the recipe also offers TLS 1.2 |
| `firefox::v157_http3_tls` | `PermutedWithTail`: shuffled, then `quic_transport_parameters` and `encrypted_client_hello` | `FromClientHello { maximum_name_length: 100 }` | `true` |

- `PermutedWithTail` writes its list after the shuffled extensions; only
  `padding` and `pre_shared_key` follow it.
- `FromClientHello` sizes the GREASE payload as the NSS of Firefox 157
  does, from the ClientHello that carries it, so the length depends on the
  connection: 240 bytes on a fresh Firefox-profile ClientHello to a host
  name, more with a session ticket (368 with the capture servers' tickets),
  and padded by the address text for an IP literal
  ([Validation](../explanation/validation.md#firefox-ech-grease-payload-evidence)).
  `Exact(n)` sends `n` bytes on every connection.
- `tls12_extensions_in_tls13_client_hello` adds an empty
  `extended_master_secret` and a one-byte `renegotiation_info` to a
  ClientHello that offers only TLS 1.3, as every Firefox QUIC ClientHello
  does.

## Trust anchor ID order

`TlsSettings::requested_trust_anchor_ids` holds a `TrustAnchorIds`, which
sets the [trust anchor IDs](glossary.md#trust-anchor-ids) and when their
order is chosen. Every variant sends the same IDs; only the order changes.

| Variant | Order | Recipes |
| --- | --- | --- |
| `Fixed(ids)` | The listed order on every connection | Chrome 154 and Chrome 154 for Android, TCP and QUIC: 28 IDs in ascending byte order |
| `PerClient(orders)` | One listed order, drawn when a client is built, on every connection of that client | `opera::v136_tls`: 29 entries, one per captured process, holding 16 orders |
| `PerConnection(orders)` | One listed order, drawn for each connection | `opera::v136_http3_tls`: 20 entries, one per captured QUIC ClientHello, holding 19 orders |
| `None` (no `TrustAnchorIds`) | No extension | Edge, Brave, Firefox, and the other Android recipes |

- Each entry of a drawn variant is equally likely, so an order listed
  twice is twice as likely. The Opera recipes list each order once for
  every capture that sent it.
- `Client::build` draws each `PerClient` list, in the TLS and the HTTP/3
  TLS settings, before it builds any connector. The client's HTTP/1.1,
  HTTP/2, and WebSocket connections, its connections to an HTTPS proxy,
  and its TLS connections through a proxy tunnel all send that one order.
  A connector built from `phantom-net` without a client draws `PerClient`
  once when it is built.
- `Client::build` fails with `BuildErrorKind::InvalidProfile` when the
  orders of a `PerClient` list do not all list the same IDs, and with
  `ProtocolConfiguration` when the random number generator fails.
- The draws use BoringSSL's random number generator. Opera derives each
  order from a Chromium 152 hash-table seed; the recipes send only the
  orders the captures hold
  ([Validation](../explanation/validation.md#opera-136-trust-anchor-id-order)).

## TCP socket options

`TcpSettings` applies to every TCP socket the client opens: to origins, to
HTTP, HTTPS, and SOCKS5 proxies, and for the control connection of a SOCKS5
UDP association. It sets socket options before connecting, keepalive before
connecting or over the connection's life, and how the client tries a host's
resolved addresses.

| Recipe | `TCP_NODELAY` | `SO_SNDBUF` | Keepalive | Address order | Local port on Windows |
| --- | --- | --- | --- | --- | --- |
| None (no `with_tcp`) | OS default | OS default | OS default | One at a time, resolver order | OS default (sequential) |
| `chromium::v154_tcp` | Set (Nagle off) | OS default | 45 s idle and 45 s interval before connecting, as Chromium on Windows and Linux | Happy Eyeballs racing, 300 ms fallback delay | Random (`SO_RANDOMIZE_PORT`) from build 22621, Windows 11 22H2 |
| `firefox::v157_tcp` | Set (Nagle off) | 524,288 bytes, as Firefox on Windows | Scheduled: 10 s idle, then 600 s; off for HTTP/2 | One at a time, resolver order; the next only after a refused, unreachable, or timed-out connect | OS default (sequential) |
| Brave, Edge, Opera | `chromium::v154_tcp` | `chromium::v154_tcp` | `chromium::v154_tcp` | `chromium::v154_tcp` | `chromium::v154_tcp` |
| Android browsers | Not covered | Not covered | Not covered | Not covered | Not covered |

- Chromium racing: the first attempt prefers IPv6; a failed attempt is
  followed by one on the other family; 300 ms after the first attempt a
  second one starts, so one attempt prefers each family. `TcpAddressRacing`
  documents the full behavior.
- Chromium on macOS sets only the idle time; for that platform, set the
  interval of `TcpKeepalivePolicy::Fixed` to `None`.
- Firefox's schedule (`TcpKeepalivePolicy::Schedule`): a connection gets a
  10-second idle time and a probe interval of its setup time in whole
  seconds, at least one, once it connects and again with each HTTP/1
  request. A request still running 72 s later (with a one-second interval)
  moves the connection to 600 s; a connection idle in the pool keeps 10 s.
  HTTP/2 turns keepalive off, and an upgrade, such as WebSocket, moves to
  600 s at once. `TcpKeepaliveSchedule` documents the rule.
- `TcpAddressSelection::Backup` (`TcpBackupConnection`), which
  `firefox::v157_tcp` sets with a 250 ms delay: the first attempt tries
  every address in resolver order and moves on only after a refused,
  unreachable, or timed-out connect; after the delay, while it has not
  connected, a backup attempt tries the IPv4 addresses. The first
  connection carries the request. On the direct route of the HTTP/1.1 and
  negotiated pools the slower attempt keeps connecting, and its connection
  finishes any TLS handshake and waits idle, or goes to a request that
  claimed it, unless the first connection selected H2. Each pool remembers,
  for each origin and route, the family of its first connection, shared by
  every runtime's key; later connections try that family alone, each backup
  connect limited to `known_family_backup_timeout` (5 s for Firefox), and
  the other family once its addresses fail.
  `TcpBackupConnection` documents the full behavior.
- `TcpAddressSelection::Sequential` takes a `TcpAddressAdvance`:
  `AfterAnyFailure`, the default, moves to the next address after any
  failure, and `AfterRefusalOrTimeout`, which `firefox::v157_tcp` sets,
  only after a refused, unreachable, or timed-out connect, as Firefox does;
  any other failure, such as a reset, ends the connect.
- Firefox sets `SO_SNDBUF` on Windows only. On Linux a fixed send buffer
  turns off the kernel's send buffer autotuning, so clear
  `send_buffer_size` for a profile used off Windows.
- Not modeled for Firefox: keeping the slower connection, and remembering
  the address family, on proxy routes, WebSocket connections, exact HTTP/2
  requests, and with ECH from HTTPS records, where Phantom starts the backup
  and closes the slower attempt; skipping an address that failed before on
  the same cached DNS record; its `SO_LINGER` of `{1, 0}` (its close is
  still a FIN, as Phantom's is); and the probe
  counts of macOS and Linux.
- Brave 1.96.59 builds the Chromium tag behind `chromium::v154_tcp` and
  changes none of the values it cites, so Brave uses that recipe.
- Edge's and Opera's network source is not public. Frida hook logs of Edge
  154.0.4258.48 and Opera 136.0.6008.52 on Windows 11 show the options and
  the 300 ms fallback of `chromium::v154_tcp`, as Chrome 154's do
  ([Validation](../explanation/validation.md#socket-hook-evidence)).
- Frida hook logs of Firefox 157.0 on Windows 11 show the options and the
  keepalive changes of `firefox::v157_tcp`, and the backup connection it
  leaves out
  ([Validation](../explanation/validation.md#firefox-socket-hook-evidence)).
- `TcpPortRandomization` sets `SO_RANDOMIZE_PORT` from a minimum Windows
  build, after the other options and before a source binding binds the
  socket; Windows rejects the option on a bound socket, and a rejection
  fails the connection attempt. Chromium sets it from build 22621 and
  ignores a failure. Off Windows it changes nothing. Chrome, Edge, and Opera
  set it on every TCP socket in the Windows 11 hook logs, and Firefox 157
  does not.
- Chrome and Edge fail a refused loopback connect at once with
  `SIO_TCP_INITIAL_RTO`. No recipe sets that option; it applies only to
  loopback peers.
- The Android emulator ends the device's TCP connections and opens new ones
  from the host, so no Android browser's socket option reaches a capture.

| Rule | Value or outcome |
| --- | --- |
| Keepalive idle time and interval | Whole seconds, 1 to 32,767 |
| Schedule short-lived time | Whole seconds, 1 to 300 |
| Schedule probe count | 1 to 127 |
| Send buffer size | 1 to 2,147,483,647 bytes |
| Racing fallback delay, backup delay | Nonzero, at most 10 seconds |
| Setting the host cannot apply | `ClientBuilder::build` fails with `BuildErrorKind::InvalidProfile` |
| Windows | Sets idle and interval together, so requires an interval |
| OpenBSD, Haiku, Vita | Cannot set an idle time; some other platforms cannot set an interval |
| OS rejects an option at connect | That connection attempt fails |
| TCP SYN (window, MSS, options, TTL) | Comes from the host OS, not the profile |

Phantom applies these settings exactly or fails; it never connects with
options the profile did not ask for. Evidence:
[TCP socket option evidence](../explanation/validation.md#tcp-socket-option-evidence).

## UDP socket options

`UdpSettings` applies to every UDP socket that carries QUIC: the socket of a
direct HTTP/3 connection, of the connection to a CONNECT-UDP proxy, and of a
SOCKS5 UDP association. It sets its options before the socket binds.

| Recipe | Local port on Windows |
| --- | --- |
| None (no `with_udp`) | OS default (sequential) |
| `chromium::v154_udp` | Random (`SO_RANDOMIZE_PORT`) on every Windows |
| Brave, Edge, Opera | `chromium::v154_udp` |
| Firefox | None: Firefox 157 does not set `SO_RANDOMIZE_PORT`, so its profiles take no `with_udp` |
| Android browsers | Not covered |

- Chromium sets `SO_RANDOMIZE_PORT` on every UDP socket it connects, with
  no feature or Windows version gate, right before `connect`, and ignores a
  failure. Phantom binds its QUIC sockets instead of connecting them, sets
  the option before the bind, and fails the connection attempt if Windows
  rejects it. Off Windows the setting changes nothing.
- Chrome 154, Edge 154, and Opera 136 set the option on every UDP socket
  their network code opens in the Windows 11 hook logs; Firefox 157's
  source sets it nowhere
  ([Validation](../explanation/validation.md#udp-socket-option-evidence)).
- `UdpSettings` does not reach DNS sockets: the operating system's, which
  answer address lookups, or hickory's, which answer HTTPS record lookups
  with the `https-records` feature.

## HTTP/1.1 connections

An HTTP/1.1 connection carries one request at a time, so a browser runs
requests to one host in parallel over several connections, up to a fixed
per-host limit. `Http1Settings::max_connections_per_origin` sets that limit
for each origin and route.

| Recipe | Connections per origin and route | Source |
| --- | --- | --- |
| None (no `with_http1`) | 1; requests run one after another | Not a browser value |
| `chromium::v154_http1` | 6 | Chromium's per-group socket limit, `g_max_sockets_per_group` |
| `firefox::v157_http1` | 6 | Firefox's `network.http.max-persistent-connections-per-server` |
| Brave | 6, from `chromium::v154_http1` | Brave 1.96.59 builds the same Chromium tag and changes none of the cited values |
| Edge, Opera | 6, from `chromium::v154_http1` | Hook logs: ten concurrent requests to one origin opened six connections |
| Android browsers | Not covered | No Android source reading or capture backs a value |

- Idle connections, and connections still being established, count toward
  the limit.
- A request reuses the most recently used idle connection before it opens
  another. Once the limit is reached, it waits in arrival order, up to the
  waiter limit in [Defaults and limits](limits.md#connection-pools).
- `Http1Settings::idle_timeout` ends reuse of an idle connection.
  `chromium::v154_http1` sets `Http1IdleTimeout::CheckedOnRequest` with 300
  seconds, Chromium's used idle socket timeout: when a request reaches the
  origin and route's connections, each connection idle 300 s or more is
  closed, and the request reuses another or opens one. Nothing closes a
  connection between requests. The Chrome 154, Edge 154, and Opera 136 hook
  logs show the same replacement. `firefox::v157_http1` sets
  `Http1IdleTimeout::ClosedOnTimer` with 115 seconds, Firefox's
  `network.http.keep-alive.timeout`: a request does not reuse a connection
  idle that long, and one timer per client closes it between requests,
  within a second after the limit, as the Firefox 157 hook logs show.
- `ClientBuilder::max_concurrent_http1_requests_per_origin` replaces the
  profile's value.
- Negotiated requests, which let ALPN choose between HTTP/1.1 and HTTP/2,
  use the same limit when ALPN selects HTTP/1.1. Each connection runs its own
  TLS handshake with the same ALPN offer. When ALPN selects HTTP/2, the
  origin and route's requests share one connection.
- Until a connection to an origin and route has selected HTTP/2, concurrent
  negotiated requests start their handshakes in parallel, up to the limit,
  as Chromium and Firefox do for a server they have not yet seen speak
  HTTP/2. Requests beyond the limit wait for a handshake to finish. If
  several select HTTP/2, the first is kept and the others close.
- After one has selected HTTP/2, a request that finds a handshake to the
  same origin and route in progress waits for it instead of starting its
  own. The client remembers this for 500 origin and route pairs, beyond the
  life of their connections and pool entries, and a later HTTP/1.1
  selection does not clear it, as in both browsers. A new route to the
  origin, or a new client, starts over.
- Firefox allows 32 connections for plaintext requests forwarded through an
  HTTP proxy, and 3 more for urgent-start requests; its recipe keeps 6 for
  both. Firefox also leaves idle connections out of its count.
- Chromium's caps across groups, 256 sockets per pool and 128 per proxy
  chain, are not modeled. Neither is its cleanup of other origins: a request
  to one origin also closes the expired idle connections of every origin in
  the same proxy chain's pool, where Phantom closes only its own origin and
  route's.
- Brave keys each socket group by top-level site as well
  (`kPartitionConnectionsByNetworkIsolationKey`), so one origin embedded
  under two sites can have 6 connections for each. A Phantom client has no
  top-level site and keeps one bound per origin and route.

Each recipe's rustdoc cites the source lines. Evidence:
[HTTP/1.1 connection bound evidence](../explanation/validation.md#http11-connection-bound-evidence).

## Address cache

`DnsCacheSettings` sets how long the client reuses the addresses it resolves
for its own connections: origin hosts on a direct route, proxy hosts, and the
target of a local-DNS `socks5://` route. A target that a proxy resolves is
never resolved locally, and a name with a `ClientBuilder::resolve` override
never reaches the cache ([Resolve host names](../guides/name-resolution.md)).

| Recipe | Names kept | Answer without a record TTL kept for (`ttl`) | Answer with a record TTL kept for (`min_record_ttl`) | Failure kept for |
| --- | --- | --- | --- | --- |
| None (no `with_dns_cache`) | 0; every new connection resolves its host | Not kept | Not kept | Not kept |
| `chromium::v154_dns_cache` | 1,000 | 60 s | The TTL, at least 60 s | Not kept |
| `firefox::v157_dns_cache` | 1,600 | 60 s | The TTL | 60 s |
| Brave | 1,000, from `chromium::v154_dns_cache` | 60 s | The TTL, at least 60 s | Not kept |
| Edge, Opera | 1,000, from `chromium::v154_dns_cache` | 60 s, as hook logs show through the system resolver | The TTL, at least 60 s | Not kept |
| Android browsers | Not covered | Not covered | Not covered | Not covered |

- The operating system's resolver reports no record TTL, and neither does
  an `AddressResolver::from_fn` resolver, so by default every answer is
  kept for `ttl`: Chromium's system-resolver value and Firefox's
  `network.dnsCacheExpiration`.
- With the `https-records` feature, `AddressResolver::system_nameservers`
  sends Phantom's own A and AAAA queries, as Chromium's built-in DNS client
  does, and reports each answer's record TTL. Chromium keeps such an
  answer for its TTL, at least 60 s. No recipe turns the resolver on
  ([Resolve host names](../guides/name-resolution.md#resolve-names-with-phantoms-own-dns-queries)).
- Firefox on Windows reads the record TTL from the operating system and
  keeps the answer that long, without a lower bound. Phantom cannot read
  that TTL, so a Firefox profile keeps each answer 60 s.
- Firefox serves an expired answer for up to 600 s more while it resolves the
  name again in the background. Phantom resolves an expired name before it
  connects.
- Brave builds the Chromium tag behind `chromium::v154_dns_cache` without
  changing the cited values, but keys its cache by top-level site as well, so
  it resolves a name again under another site. A Phantom client keeps one
  cache.
- Concurrent connections to one host share one lookup, as in both browsers.
  The resolver's address order is kept, so address racing sees it
  unchanged.
- When the cache is full, an expired name is replaced first, then the one
  that would expire soonest, as in Chromium.
- `ClientBuilder::dns_cache` replaces the profile's settings and
  `ClientBuilder::no_dns_cache` turns the cache off. Browsers flush the cache
  when the network changes; Phantom does not watch the network, so call
  `Client::clear_dns_cache` after such a change.

Each recipe's rustdoc cites the source lines. Evidence:
[Address cache evidence](../explanation/validation.md#address-cache-evidence).

## Request templates

| Recipe | Request | HTTP/1.1 | HTTP/2 | HTTP/3 | `User-Agent` |
| --- | --- | --- | --- | --- | --- |
| `chromium::v154_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Captured headful Chrome 154 value |
| `chromium::v154_windows_fetch_no_store_template` | Same-origin `fetch(url, {cache: "no-store"})` GET | Yes | Yes | No | Captured headful Chrome 154 value |
| `chromium::v154_macos_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Required caller slot |
| `chromium::v154_macos_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Required caller slot |
| `edge::v154_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Required caller slot |
| `edge::v154_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Required caller slot |
| `brave::v154_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Required caller slot |
| `brave::v154_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Required caller slot |
| `opera::v136_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Required caller slot |
| `opera::v136_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Required caller slot |
| `firefox::v157_windows_navigation_template` | Address-bar navigation | Yes | Yes | No | Captured Firefox 157 value |
| `firefox::v157_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Firefox 157 value |
| `firefox::v157_macos_navigation_template` | Address-bar navigation | Yes | Yes | No | Captured Firefox 157 macOS value |
| `firefox::v157_macos_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Firefox 157 macOS value |
| `brave_android::v153_android_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Captured Brave for Android value; `Accept-Language` is a required caller slot |
| `brave_android::v153_android_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Brave for Android value; `Accept-Language` is a required caller slot |
| `chrome_android::v154_android_navigation_template` | Address-bar navigation | Yes | Yes | Chromium list | Captured Chrome 154 for Android value |
| `chrome_android::v154_android_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Chrome 154 for Android value |
| `edge_android::v153_android_navigation_template` | Address-bar navigation | Yes | Yes | Chromium list | Captured Edge 153 for Android value |
| `edge_android::v153_android_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Edge 153 for Android value |

- An address-bar navigation is an HTML document request with
  `Sec-Fetch-Site: none` and `Sec-Fetch-User: ?1`.
- "No" means no retained capture covers that protocol, so the template has
  no field list for it. "Chromium list" means the H3 list is the Chromium
  one: the Android H3 captures were opened by intent and differ from it only
  in the fields the next list names.
- A caller slot has no captured value; you supply the field. A request that
  leaves a required caller slot empty fails before any I/O.
- Every template carries the capture machine's `en-US` `Accept-Language`,
  from the Windows 11 host, the macOS host for a `macos` template, or, for
  `chrome_android` and `edge_android`, the Android emulator. Brave's
  templates leave it to you: Brave draws the `q` value of its second
  language per session. On macOS,
  Edge takes the field from the system's language list, so its templates
  match only with that list set to `en-US`; for another locale, override
  `Accept-Language`.
- The Brave templates are the Chromium templates with three changes: `Accept`
  on a navigation omits `application/signed-exchange;v=b3;q=0.7`,
  `Sec-GPC: 1` follows `Accept`, and `Accept-Language` is a
  required caller slot.
- The Chrome, Edge, and Brave for Android navigation templates model a URL
  typed into the address bar. A page that another app opens through an
  Android intent has no user activation, and Chrome then leaves out
  `Sec-Fetch-User` and sends `Sec-Fetch-Site: cross-site`; no template covers
  that case.

### Template assembly

| Aspect | Rule |
| --- | --- |
| Protocol | Each attempt uses the list for the protocol it runs on, after `Host` on HTTP/1.1 and after the pseudo-header fields on HTTP/2 and HTTP/3. A negotiated request uses the list for the protocol ALPN selects. |
| Your fields | A field whose name matches an entry takes that entry's position and name spelling, and keeps your value and sensitivity. |
| Unfilled entries | A literal entry you do not override sends its captured value. A caller slot you do not fill sends nothing. |
| Extra fields | Fields the template does not name follow its last field, in your order. They are sent, not rejected. |
| Cookies | Templates cannot contain `Cookie`. The profile's `CookiePlacement` inserts the jar's field; a `Cookie` field of your own replaces it. |
| Client hints | The profile's client hints fill the template's hint slots. |
| Forwarding | When an HTTP/1.1 proxy forwards the request in absolute form, the Chromium-family templates (Chrome, Edge, Brave, and Opera) send `Proxy-Connection: keep-alive` in the position of `Connection: keep-alive`, as those browsers do. Firefox's templates send the same fields on every route. A field of yours named `Connection` or `Proxy-Connection` keeps its value at that entry's position. |
| Proxy credentials | On a forwarded request that carries `HttpProxy::with_basic_auth` credentials, the generated `Proxy-Authorization` field takes the template's slot for the attempt. Chrome, Edge, Brave, and Opera: after `Proxy-Connection` on HTTP/1.1 and first on HTTP/2, on every attempt, except that a no-store `fetch` puts `Pragma` and `Cache-Control` before it. Firefox: with remembered credentials, before `Connection` on HTTP/1.1 and in the same place on HTTP/2 (after `referer` on a `fetch`, after `accept-encoding` on a navigation); on the replay after a `407`, last on HTTP/1.1 and before `te` on HTTP/2. Without a slot it follows every other field. On a route without configured credentials, your own `Proxy-Authorization` field on a forwarded request takes the slot for remembered credentials. |
| Origin trust | `Sec-Fetch-*` and `Accept-Encoding` depend on whether the URL is [potentially trustworthy](glossary.md#potentially-trustworthy). To such a URL a built-in template sends its captured fields; to any other `http://` URL it leaves out `Sec-Fetch-*` and sends `Accept-Encoding: gzip, deflate`. The other fields keep their order; Brave's `Sec-GPC` goes to both. |
| HTTP/2 priority | The template's HEADERS priority replaces the connection's priority for that stream only. A peer that disables RFC 7540 priorities still suppresses it. |
| Redirects | Every hop uses the same template. Origin trust is decided per hop, so a redirect to a named `http://` origin drops `Sec-Fetch-*` and the `br` and `zstd` codings. Values such as `Sec-Fetch-Site` are not adjusted. |
| `Referer` on a navigation | Navigation templates have no `Referer` slot, so an added `Referer` goes last: after `Accept-Language` on Chrome's and Edge's HTTP/1.1 list, after `priority` on their HTTP/2 and HTTP/3 lists, after `Priority` and `te` on Firefox's HTTP/1.1 and HTTP/2 lists, and after `priority` on Firefox's HTTP/3 list. A Firefox script navigation over HTTP/3 puts it after `accept-encoding`; no capture shows the other positions. |

### Cookie placement in templates

`CookiePlacement` puts the jar's `Cookie` field before the first field it
names, compared case-insensitively, or last if none is present. It matches
template and caller fields, not client hints, which are added afterward.

| Placement | Template | `Cookie` goes |
| --- | --- | --- |
| `firefox::v157_cookie_placement` | Firefox `fetch` | After `Referer`, before `Sec-Fetch-Dest` |
| `firefox::v157_cookie_placement` | Firefox navigation | Before `Upgrade-Insecure-Requests` |
| `chromium::v154_cookie_placement` | Chrome, Edge, Brave, or Opera, HTTP/1.1 | Last |
| `chromium::v154_cookie_placement` | Chrome, Edge, Brave, or Opera, HTTP/2 and HTTP/3 | Before the final `priority` |

The cookie captures of all four Chromium-family browsers show both
positions ([Cookie crumb evidence](../explanation/validation.md#cookie-crumb-evidence)).

### Cookie crumbs

On HTTP/2 and HTTP/3 a browser may split the `cookie` field into one field
per cookie, called crumbs (RFC 9113 section 8.2.3, RFC 9114 section 4.2.1).
The crumbs stay at the field's position, in the field's order. The HTTP/2
rule is `Http2HpackSettings::cookie_crumbs`; the HTTP/3 rule is
`Http3RequestSettings::cookie_crumbs`. Both default to `Whole`, one field.

| Recipe | Protocol | Split | Each crumb |
| --- | --- | --- | --- |
| `chromium::v154_http2` | HTTP/2 | At `;`, skipping one space (`IndexAll`) | Inserted into the HPACK table, then sent as an index |
| `firefox::v157_http2` | HTTP/2 | At `"; "` (`NeverIndexShort`) | Under 20 bytes: never-indexed literal; otherwise inserted, then an index |
| `chromium::v154_http3_request` | HTTP/3 | At `;`, skipping one space (`Split`) | Encoded like any other field; under the recipe's dynamic QPACK policy, inserted and then referenced |

- The rule applies to every `cookie` field on the connection: the jar's, one
  you supply, and, on HTTP/2, one in a WebSocket opening.
- While crumbs are sent, the rule chooses each crumb's representation.
  `RequestHeader::sensitive` on a `cookie` field then only hides its value
  from `Debug` output. With `Whole`, a sensitive field is a never-indexed
  literal, as the jar's field always is.
- Indexed crumbs are exposed to the HPACK and QPACK compression side
  channel; `Whole` avoids it at the cost of browser parity. See
  [Design](../explanation/design.md#cookie-crumbs-and-compression).
- On HTTP/2 each recipe applies its browser's size limit to a crumb's table
  entry (name, value, and 32 bytes). `chromium::v154_http2` inserts a crumb
  of any size, evicting older entries, and one larger than the whole table
  empties it. `firefox::v157_http2` sends a crumb larger than half the
  table, 2,048 bytes with the default 4,096, as a literal without indexing.
  Settings that keep the default `Http2IndexingLimit` stop at three
  quarters.
- HTTP/3 crumbs are not marked sensitive inside Phantom, so a crumb's
  internal `http::HeaderValue` would print in `Debug` output. The prepared
  request never leaves `phantom-net`, and Phantom logs no field values.
- The count and size limits on request fields apply to the fields as you
  supply them, before the split.
- Firefox 157 does not split `cookie` over HTTP/3, so
  `firefox::v157_http3_request` sends one joined field, a literal with a
  static name reference that is never inserted.
- Edge, Brave, and Opera use `chromium::v154_http2` and
  `chromium::v154_http3_request`, so they send crumbs as Chrome does, as
  their cookie captures show.

### Client hints in templates

A template sends only the hints the profile would send anyway: the default
hints, and hints the origin requested through `Accept-CH` or ALPS
`ACCEPT_CH`. Placement, as captured from Chromium:

| Request | Hint placement |
| --- | --- |
| No template | Automatic hints go before all of your fields |
| Navigation template | One block in profile order: after `Connection` on HTTP/1.1, first on HTTP/2 and HTTP/3. Hints requested through `Accept-CH` join that block. |
| `fetch` template | Default hints split: `sec-ch-ua-platform` before `User-Agent`; `sec-ch-ua` and `sec-ch-ua-mobile` after it |

The retained capture of requested hints on a navigation covers HTTP/1.1
only. For HTTP/2 and HTTP/3, their placement is inferred from the default
block, which every protocol's captures place the same way.

A `fetch` template (no capture shows where Chrome puts requested hints on a
`fetch`) and a Firefox template (no hint slots) do not know where requested
hints go. Phantom fails with `RequestErrorKind::RequestTemplate`:

| When | Fails |
| --- | --- |
| The template has no hint slots and the profile sends hints by default | Before any I/O |
| One of your fields carries a hint the profile sends only on request, including to an origin that gets no automatic hints | Before any I/O |
| The origin asked for such a hint through `Accept-CH`, including the retry a `Critical-CH` response asks for | Before the request is sent on the connection |

### Template limits

- Only address-bar navigations and same-origin no-store `fetch` GETs are
  captured. There are no templates for link or script navigations,
  subresources such as images, scripts, and stylesheets, `XMLHttpRequest`,
  cross-origin `fetch`, or requests with a body.
- The template captures used plaintext loopback origins, which browsers
  treat as potentially trustworthy. The fields for a named plaintext origin
  come from the proxy route captures of a page load, a default-mode
  `fetch()`, and a no-store `fetch()`.
- Firefox 157 source adds `dcb` and `dcz` to `Accept-Encoding` on a secure
  request when it holds a compression dictionary for the URL. No capture
  shows it, and the templates never send them.
- The templates always depend on stream 0, as every capture did. Chrome can
  depend on another open stream of equal or higher priority; Phantom does not
  reproduce that.
- Every retained Edge, Brave, and Opera capture ran headless, so their
  templates leave `User-Agent` to you. The Firefox value comes from headless
  captures; Firefox sent no headless marker, but no headful Firefox capture
  confirms the value.
- The Firefox HTTP/1.1, HTTP/2, and HTTP/3 lists come from Firefox 157.0
  on Windows, and the macOS templates' HTTP/1.1 and HTTP/2 fields from 157.0
  on macOS. Firefox sends `Alt-Used` after `accept-encoding` on requests to
  an origin it reached through Alt-Svc; Phantom appends the field it
  generates last.

| Browser | HTTP/2 HEADERS priority, navigation | `fetch` |
| --- | --- | --- |
| Chrome, Edge, Brave, Opera | Weight 256, exclusive | Weight 220, exclusive |
| Firefox | Weight 42, non-exclusive | Weight 22, non-exclusive |

The template's priority replaces the H2 recipe's connection priority, which
is the navigation weight.

## Proxy CONNECT fields

A `ProxyConnectTemplate` orders the fields of the CONNECT request that opens
an HTTP proxy tunnel for an HTTPS, `wss://`, or `ws://` origin, with one list
per proxy transport. It applies to a route whose CONNECT fields you did not
set with `HttpProxy::header`, `headers`, or `connect_headers`; fields you set
replace it.

| Recipe | HTTP/1.1 proxy | HTTP/2 proxy, after `:method` and `:authority` |
| --- | --- | --- |
| None (no `with_proxy_connect`) | `Host`, then `Proxy-Authorization` | `proxy-authorization` |
| `chromium::v154_proxy_connect` (Chrome 154, Edge 154, Brave 154, and Opera 136) | `Host`, `Proxy-Connection: keep-alive`, `User-Agent`, `Proxy-Authorization` | `user-agent`, `proxy-authorization` |
| `firefox::v157_proxy_connect` | `User-Agent`, `Proxy-Connection: keep-alive`, `Connection: keep-alive`, `Host`, `Proxy-Authorization` | `user-agent`, `proxy-authorization` |

- `Proxy-Authorization` is sent only with `HttpProxy::with_basic_auth`
  credentials, after a challenge or once the proxy has accepted them.
- On an HTTP/2 proxy, `Http2HpackSettings::sensitive_proxy_authorization`
  decides the field's HPACK form. `chromium::v154_http2` and
  `firefox::v157_http2` set `FieldIndexing`: a literal with incremental
  indexing on first use on a connection, then an index, as the browsers
  send it. The default, `NeverIndexed`, keeps the credential out of the
  dynamic table
  ([Design](../explanation/design.md#cookie-crumbs-and-compression)).
- `User-Agent` is a `ProxyConnectField::FromRequest` entry: the CONNECT
  copies the value of the request or WebSocket opening that opens the
  tunnel, your field or else its template's, and keeps your field's
  sensitive marking. Without one it sends none. Validation refuses a
  `FromRequest` entry for `Authorization`, `Cookie`, `Cookie2`, or
  `Proxy-Authorization`, so the origin's credentials never reach the proxy.
- A tunnel opened for one request serves later requests on the same route,
  so its CONNECT carries the first request's `User-Agent`.
- The captures cover `ws://`, `https://`, and `wss://` tunnels through both
  proxy transports, with and without a challenge; every browser sends the
  same fields for each.
- `http2_rejected` sets what an HTTP/2 CONNECT sends on a stream the proxy
  rejected, such as a challenged one, before the replay:
  `Http2RejectedConnect::EndStream` (an empty END_STREAM DATA frame) in the
  Chromium recipe and without a recipe, and `Http2RejectedConnect::LeaveOpen`
  (nothing) in the Firefox recipe. A proxy that allows one concurrent stream
  gets END_STREAM in both, and a `407` body still arriving is reset with
  `CANCEL` in both.
- `http2_connections` sets which requests share an HTTP/2 proxy connection:
  `Http2ProxyConnections::Shared` in the Chromium recipe and without a
  recipe puts forwarded `http://` requests, CONNECT tunnels, and WebSocket
  tunnels on one connection; `Http2ProxyConnections::ByPurpose` in the
  Firefox recipe gives each of the three its own connection.

Evidence: [Proxy route browser evidence](../explanation/validation.md#proxy-route-browser-evidence).

## Required caller fields

The Edge, Brave, and Opera templates mark `User-Agent` as a required caller
slot, because no headful capture of those browsers backs a literal value.
The Brave templates also mark `Accept-Language`, because Brave draws its
value per session; send one of `en-US,en;q=0.5` to `en-US,en;q=0.9` and keep
it for the session. A request with such a template and no field of that name
fails before any I/O. Phantom does not read the value you supply.

Phantom does not compare your `User-Agent` or `sec-ch-ua` with the template's
browser. Use the template, client-hint recipe, and `User-Agent` of one browser
and version together.

| Failure | Error |
| --- | --- |
| A required caller slot is empty | `RequestErrorKind::RequestTemplate` |
| Invalid template data | `InvalidRequestTemplate` from `PreparedRequestTemplate::new` |
| No HTTP/3 list on a request that may use HTTP/3 (exact H3, or negotiated with Alt-Svc enabled on a direct or SOCKS5 route) | `RequestErrorKind::RequestTemplate` |

## Client hints

`ClientHintSettings` is fixed profile data: hint names in order, values, and
whether each is sent by default or only on request. Each built-in client-hint
recipe comes from a navigation capture of its browser. Phantom never adds
Chromium client hints to a Firefox profile based on the browser name.

### Learning from `Accept-CH`

Phantom sends automatic client hints only to a
[potentially trustworthy](glossary.md#potentially-trustworthy) origin, as
Chromium does: an `https` origin, or an `http` origin on a loopback address,
`localhost`, or a `.localhost` name. For H1, H2, and H3 responses from such an
origin:

| Response `Accept-CH` | Effect on the origin's requested hints |
| --- | --- |
| Valid structured-field list | Replaces the set |
| Empty, or only unsupported names | Clears the set |
| Absent | No change |
| Malformed | Ignored |

- An origin is keyed by exact scheme, host, and effective port.
- The sets live in a bounded store that evicts the least recently used
  origin ([limits](limits.md#connection-pools)). Clones of a client share it;
  separately built clients do not. `Client::clear_client_hints` clears it.
- A configured hint field you supply keeps its position and your value.
  Automatic hints stay in profile order. A template moves both into its hint
  slots.

### Connection-level `ACCEPT_CH`

On H2 and H3, a server can send an `ACCEPT_CH` entry through ALPS during the
TLS handshake, so the first request on a connection carries the requested
hints. A request's hints are fixed when its fields are built, so the entry
never adds a field to a request about to be sent. When the entry names a
hint a navigation lacks and the origin has not requested through
`Accept-CH`, the request stops before anything of it is written and starts
again with the hint, on the same connection when it is still pooled, as
Chromium 154 restarts a navigation. Every hint the navigation lacked goes
after `Accept` and before `Sec-Fetch-Site`, where Chromium's header merge
appends it to the navigation's own fields before the network stack adds the
`Sec-Fetch-*`, `Accept-Encoding`, and `Accept-Language` fields
([evidence](../explanation/validation.md#alps-accept_ch-restart-evidence)).
The Chromium navigation templates mark that place with
`RequestField::RestartClientHints`; without a template the hints follow
every other field. Brave sets `Sec-GPC` after the browser's fields, restart
hints included, so a restarted Brave navigation sends
`accept, <hints>, sec-gpc, sec-fetch-site`
([evidence](../explanation/validation.md#alps-accept_ch-restart-evidence)).

- `RequestTemplate::restarts_for_connection_accept_ch` decides which
  requests restart. The Chromium-family navigation templates set it; the
  `fetch` and Firefox templates do not, so such a request goes out as built,
  as Chromium sends a subresource request. A request without a template
  restarts.

- The entry applies to requests whose origin matches it exactly. Default
  hints, hints learned from responses, and hints you supply all count as
  present.
- A restart builds the request's fields again, reading the cookie jar and
  learned hints again. Any method and body may restart, a streaming body
  included, because none of it was sent.
- The hints a request restarted for stay with it for the rest of its
  redirect hop, so a replacement connection whose entry names another hint
  restarts it again with both. A request restarts at most once per hint the
  profile sends on request.
- The entry is never copied into the client's store and does not clear
  learned hints when it is empty or malformed.
- If an origin appears more than once, the first valid entry wins.
  Non-canonical origins are ignored. At most 1,024 distinct origins are kept
  per connection.
- Live BoringSSL integration tests cover the restart on H2 and H3
  ([Coverage](coverage.md#http3)).
- A request sent as HTTP/3 early data goes out before the connection knows
  its entry, so neither it nor its resend after a rejection restarts.

### `Critical-CH` retry

If a `Critical-CH` response names a supported hint that was missing and the
method is safe, Phantom retries the request once.

| Case | Outcome |
| --- | --- |
| Owned body | Sent again exactly |
| Streaming body | Fails with `RequestErrorKind::RequestBody`; the original response is not returned |
| Protocol and route | Never change |
| Repeated demand | Does not loop |
| Redirect hops | Hints requested by intermediate responses are learned before the next hop. At a cross-origin boundary, configured hint fields you supplied are removed before the new origin's automatic hints are built. |

### Client-hint model limits

The model covers top-level requests from a standalone client. It does not
support:

- Permissions Policy delegation or subresource browsing contexts;
- persistence, or expiry other than explicit replacement;
- restarting a full navigation across a redirect chain already followed;
- `ACCEPT_CH` frames sent after the handshake.

Each of these needs request context or browser-engine evidence that a browser
name cannot provide. Client-hint tests send sequences of requests on one
client, so they check the step from an `Accept-CH` response to the next
request and the boundary between origins, not a single fingerprint.

There is no process-wide hint cache, and a profile never changes after it is
built.

## Next

- [Browser profiles](../guides/profiles.md): build a profile, then
  [apply a template](../guides/request-templates.md) to a request.
- [Coverage](coverage.md#browser-profiles): exact builds behind each recipe.
- [Validation](../explanation/validation.md#browser-recipes): the captures
  behind each recipe.
