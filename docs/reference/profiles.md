# Profile reference

Lookup tables for profile components, built-in recipes, TCP socket options,
HTTP/1.1 connections, request templates, required caller fields, and
client hints. For how to
use them, see [Browser profiles](../guides/profiles.md).

> For builders and specialists looking up a recipe or template detail.

## Profile components

| Method | Adds |
| --- | --- |
| `ClientProfile::new(tls)` | TLS ClientHello for H1 and H2 |
| `with_tcp(settings)` | TCP socket options for every TCP connection |
| `with_http1(settings)` | How many HTTP/1.1 connections to keep per origin and route |
| `with_dns_cache(settings)` | How long the client reuses the addresses it resolves ([details](#address-cache)) |
| `with_http2(settings)` | HTTP/2 SETTINGS, window update, priority, pseudo-header order, and HPACK encoder choices |
| `with_http3(Http3ClientSettings)` | H3 TLS ClientHello, QUIC transport parameters, HTTP/3 settings, and request settings |
| `with_client_hints(settings)` | Ordered client-hint fields and when to send them |
| `with_websocket(settings)` | WebSocket opening templates, compression offer, and connection policy |
| `with_proxy_connect(template)` | Fields of the CONNECT request that opens an HTTP proxy tunnel ([details](#proxy-connect-fields)) |
| `with_cookie_placement(placement)` | Where the cookie jar's `Cookie` field goes; last by default ([details](../guides/cookies.md#place-the-cookie-field-where-a-browser-does)) |

A request fails before any network I/O if the profile lacks a component it
needs.

## Built-in recipes

Phantom carries one version per browser: the current stable build on the
capture host. Older versions are retired, so a recipe name always points at a
build that can be recaptured and reverified.

| Browser | Module | TLS | HTTP/2 | QUIC and HTTP/3 | Client hints | WebSocket | Captured on |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Chrome 154 | `chromium::v154_*` | Yes | Yes | Yes | `v154_windows_client_hints` | `v154_websocket` | Windows |
| Edge 153 | `edge::v153_*` | Yes | Chromium | Chromium QUIC and H3; own H3 TLS | `v153_windows_client_hints` | Chromium | Windows |
| Brave 154 | `brave::v154_*` | Yes | Chromium | Chromium QUIC and H3; own H3 TLS | `v154_windows_client_hints` | Chromium | Windows |
| Opera 135 | `opera::v135_*` | Yes | Chromium | Chromium QUIC and H3; own H3 TLS | `v135_windows_client_hints` | Chromium | Windows |
| Firefox 156 | `firefox::v156_*` | Yes | Yes | No | No | `v156_websocket` | Windows |

- "Captured on" lists the platforms whose retained captures back the recipe.
  [Coverage](coverage.md#browser-profiles) gives the exact builds and how the
  recipes differ.
- TCP recipes are not in the table, because socket options do not appear in
  a capture. `chromium::v154_tcp` and `firefox::v156_tcp` come from the
  browsers' source code at the profiled release tags
  ([TCP socket options](#tcp-socket-options)).
- HTTP/1.1 connection recipes are not in the table either, for the same
  reason. `chromium::v154_http1` and `firefox::v156_http1` come from browser
  source ([HTTP/1.1 connections](#http11-connections)).
- Address cache recipes are not in the table either: a cache is not visible
  on the wire, only the queries it saves. `chromium::v154_dns_cache` and
  `firefox::v156_dns_cache` come from browser source
  ([Address cache](#address-cache)).
- Proxy CONNECT recipes are not in the table: `chromium::v154_proxy_connect`
  serves Chrome, Edge, Brave, and Opera, and `firefox::v156_proxy_connect`
  serves Firefox
  ([Proxy CONNECT fields](#proxy-connect-fields)).
- H2 WebSocket needs a captured pseudo-header order for extended CONNECT.
  Only `chromium::v154_http2` and `firefox::v156_http2` carry one
  ([Profile connection policy](../guides/websocket.md#open-a-websocket-the-way-the-browser-does)).

## Recipe names and platforms

The runtime uses the validated settings it receives and never branches on
the host operating system or the browser name.

| Name form | Example | Means |
| --- | --- | --- |
| No platform | `chromium::v154_tls`, `firefox::v156_http2` | The recipe carries no platform-specific data. It does not mean more than one platform was captured. |
| `windows` in the name | `chromium::v154_windows_client_hints` | Observed on that platform. Never "selected by `target_os`". Used for client-hint and request-template recipes, whose values carry platform data on the wire. |

Every current recipe comes from Windows captures alone. Each recipe's rustdoc
names its single capture build and platform.

## TCP socket options

`TcpSettings` applies before connect to every TCP socket the client opens: to
origins, to HTTP, HTTPS, and SOCKS5 proxies, and for the control connection
of a SOCKS5 UDP association. It also decides how the client tries a host's
resolved addresses.

| Recipe | `TCP_NODELAY` | Keepalive idle and interval | Address order |
| --- | --- | --- | --- |
| None (no `with_tcp`) | OS default | OS default | One at a time, resolver order |
| `chromium::v154_tcp` | Set (Nagle off) | 45 s and 45 s, as Chromium on Windows and Linux | Happy Eyeballs racing, 300 ms fallback delay |
| `firefox::v156_tcp` | Set (Nagle off) | Untouched | One at a time, resolver order |
| Edge, Brave, Opera | Not covered | Not covered | Not covered |

- Chromium racing: the first attempt prefers IPv6; a failed attempt is
  followed by one on the other family; 300 ms after the first attempt a
  second one starts, so one attempt prefers each family. `TcpAddressRacing`
  documents the full behavior.
- Chromium on macOS sets only the idle time; for that platform, set
  `TcpKeepalive::interval` to `None`.
- Firefox's keepalive schedule and address selection are not modeled.
- No capture shows Edge's, Brave's, or Opera's socket options, and no
  browser source has been read for them.

| Rule | Value or outcome |
| --- | --- |
| Keepalive idle time and interval | Whole seconds, 1 to 32,767 |
| Racing fallback delay | Nonzero, at most 10 seconds |
| Setting the host cannot apply | `ClientBuilder::build` fails with `BuildErrorKind::InvalidProfile` |
| Windows | Sets idle and interval together, so requires an interval |
| OpenBSD, Haiku, Vita | Cannot set an idle time; some other platforms cannot set an interval |
| OS rejects an option at connect | That connection attempt fails |
| TCP SYN (window, MSS, options, TTL) | Comes from the host OS, not the profile |

Phantom applies these settings exactly or fails; it never connects with
options the profile did not ask for. Evidence:
[TCP socket option evidence](../explanation/validation.md#tcp-socket-option-evidence).

## HTTP/1.1 connections

An HTTP/1.1 connection carries one request at a time, so a browser runs
requests to one host in parallel over several connections, up to a fixed
per-host limit. `Http1Settings::max_connections_per_origin` sets that limit
for each origin and route.

| Recipe | Connections per origin and route | Source |
| --- | --- | --- |
| None (no `with_http1`) | 1; requests run one after another | Not a browser value |
| `chromium::v154_http1` | 6 | Chromium's per-group socket limit, `g_max_sockets_per_group` |
| `firefox::v156_http1` | 6 | Firefox's `network.http.max-persistent-connections-per-server` |
| Edge, Brave, Opera | Not covered | Their values have not been read from a source or a capture |

- Idle connections, and connections still being established, count toward
  the limit.
- A request reuses the most recently used idle connection before it opens
  another. Once the limit is reached, it waits in arrival order, up to the
  waiter limit in [Defaults and limits](limits.md#connection-pools).
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
  chain, are not modeled.

Each recipe's rustdoc cites the source lines. Evidence:
[HTTP/1.1 connection bound evidence](../explanation/validation.md#http11-connection-bound-evidence).

## Address cache

`DnsCacheSettings` sets how long the client reuses the addresses it resolves
for its own connections: origin hosts on a direct route, proxy hosts, and the
target of a local-DNS `socks5://` route. A target that a proxy resolves is
never resolved locally, and a name with a `ClientBuilder::resolve` override
never reaches the cache ([Resolve host names](../guides/name-resolution.md)).

| Recipe | Names kept | Answer kept for | Failure kept for |
| --- | --- | --- | --- |
| None (no `with_dns_cache`) | 0; every new connection resolves its host | Not kept | Not kept |
| `chromium::v154_dns_cache` | 1,000 | 60 s | Not kept |
| `firefox::v156_dns_cache` | 1,600 | 60 s | 60 s |
| Edge, Brave, Opera | Not covered | Not covered | Not covered |

- Phantom resolves through the operating system, which reports no record
  TTL, or through the caller's `AddressResolver`, which returns none. Both
  recipes use the browser's value for an answer without one: Chromium's
  system-resolver path and Firefox's `network.dnsCacheExpiration`.
- Chromium's built-in DNS client keeps an answer for its record TTL, at least
  60 s, and Firefox on Windows asks the OS for the TTL. Neither is modeled.
- Firefox serves an expired answer for up to 600 s more while it resolves the
  name again in the background. Phantom resolves an expired name before it
  connects.
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
| `edge::v153_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Required caller slot |
| `edge::v153_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Required caller slot |
| `brave::v154_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Required caller slot |
| `brave::v154_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Required caller slot |
| `opera::v135_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Required caller slot |
| `opera::v135_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Required caller slot |
| `firefox::v156_windows_navigation_template` | Address-bar navigation | Yes | Yes | No | Captured Firefox 156 value |
| `firefox::v156_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Firefox 156 value |

- An address-bar navigation is an HTML document request with
  `Sec-Fetch-Site: none` and `Sec-Fetch-User: ?1`.
- "No" means no retained capture covers that protocol, so the template has
  no field list for it.
- A caller slot has no captured value; you supply the field. A request that
  leaves a required caller slot empty fails before any I/O.
- Every template was captured on Windows 11 and carries the capture machine's
  `en-US` `Accept-Language`, except Brave's, which leave it to you: Brave
  draws the `q` value of its second language per session.
- The Brave templates are the Chromium templates with three changes: `Accept`
  on a navigation omits `application/signed-exchange;v=b3;q=0.7`,
  `Sec-GPC: 1` follows `Accept`, and `Accept-Language` is a
  required caller slot.

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
| `Referer` on a navigation | Navigation templates have no `Referer` slot, so an added `Referer` goes last: after `Accept-Language` on Chrome's and Edge's HTTP/1.1 list, after `priority` on their HTTP/2 and HTTP/3 lists, and after `Priority` and `te` on Firefox's. No capture shows that position. |

### Cookie placement in templates

`CookiePlacement` puts the jar's `Cookie` field before the first field it
names, compared case-insensitively, or last if none is present. It matches
template and caller fields, not client hints, which are added afterward.

| Placement | Template | `Cookie` goes |
| --- | --- | --- |
| `firefox::v156_cookie_placement` | Firefox `fetch` | After `Referer`, before `Sec-Fetch-Dest` |
| `firefox::v156_cookie_placement` | Firefox navigation | Before `Upgrade-Insecure-Requests` |
| `chromium::v154_cookie_placement` | Chrome or Edge, HTTP/1.1 | Last |
| `chromium::v154_cookie_placement` | Chrome or Edge, HTTP/2 and HTTP/3 | Before the final `priority` |

No capture or source reading backs a cookie placement for Brave or Opera.

### Cookie crumbs

On HTTP/2 and HTTP/3 a browser may split the `cookie` field into one field
per cookie, called crumbs (RFC 9113 section 8.2.3, RFC 9114 section 4.2.1).
The crumbs stay at the field's position, in the field's order. The HTTP/2
rule is `Http2HpackSettings::cookie_crumbs`; the HTTP/3 rule is
`Http3RequestSettings::cookie_crumbs`. Both default to `Whole`, one field.

| Recipe | Protocol | Split | Each crumb |
| --- | --- | --- | --- |
| `chromium::v154_http2` | HTTP/2 | At `;`, skipping one space (`IndexAll`) | Inserted into the HPACK table, then sent as an index |
| `firefox::v156_http2` | HTTP/2 | At `"; "` (`NeverIndexShort`) | Under 20 bytes: never-indexed literal; otherwise inserted, then an index |
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
- On HTTP/2 a crumb whose table entry (name, value, and 32 bytes) exceeds
  three quarters of the table, 3,072 bytes with the default 4,096, is sent
  as a literal without indexing. Chromium inserts it anyway, evicting older
  entries or, when it exceeds the whole table, emptying it. Firefox stops
  indexing at half the table.
- HTTP/3 crumbs are not marked sensitive inside Phantom, so a crumb's
  internal `http::HeaderValue` would print in `Debug` output. The prepared
  request never leaves `phantom-net`, and Phantom logs no field values.
- The count and size limits on request fields apply to the fields as you
  supply them, before the split.
- Firefox 156 does not split `cookie` over HTTP/3; Phantom has no Firefox
  HTTP/3 recipe.
- Edge, Brave, and Opera use `chromium::v154_http2` and
  `chromium::v154_http3_request`, so they send crumbs as Chrome does. The
  Edge captures show it; no Brave or Opera capture carries a cookie.

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
| The origin asked for such a hint through `Accept-CH` or ALPS `ACCEPT_CH`, including the retry a `Critical-CH` response asks for | Before the request is sent on the connection |

### Template limits

- Only address-bar navigations and same-origin no-store `fetch` GETs are
  captured. There are no templates for link or script navigations,
  subresources such as images, scripts, and stylesheets, `XMLHttpRequest`,
  cross-origin `fetch`, or requests with a body.
- The template captures used plaintext loopback origins, which browsers
  treat as potentially trustworthy. The fields for a named plaintext origin
  come from the proxy route captures of a page load, a default-mode
  `fetch()`, and a no-store `fetch()`.
- Firefox 156 source adds `dcb` and `dcz` to `Accept-Encoding` on a secure
  request when it holds a compression dictionary for the URL. No capture
  shows it, and the templates never send them.
- The templates always depend on stream 0, as every capture did. Chrome can
  depend on another open stream of equal or higher priority; Phantom does not
  reproduce that.
- Every retained Edge, Brave, and Opera capture ran headless, so their
  templates leave `User-Agent` to you. The Firefox value comes from headless
  captures; Firefox sent no headless marker, but no headful Firefox capture
  confirms the value.
- Firefox has no HTTP/3 recipe, so its templates have no HTTP/3 list.

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
| `chromium::v154_proxy_connect` (Chrome 154, Edge 153, Brave 154, and Opera 135) | `Host`, `Proxy-Connection: keep-alive`, `User-Agent`, `Proxy-Authorization` | `user-agent`, `proxy-authorization` |
| `firefox::v156_proxy_connect` | `User-Agent`, `Proxy-Connection: keep-alive`, `Connection: keep-alive`, `Host`, `Proxy-Authorization` | `user-agent`, `proxy-authorization` |

- `Proxy-Authorization` is sent only with `HttpProxy::with_basic_auth`
  credentials, after a challenge or once the proxy has accepted them.
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
hints.

- The entry applies to requests whose origin matches it exactly, and adds to
  the hints learned from responses.
- It belongs to that connection only. It is never copied into the client's
  store, does not carry over to a replacement connection, and does not clear
  learned hints when it is empty or malformed.
- If an origin appears more than once, the first valid entry wins.
  Non-canonical origins are ignored. At most 1,024 distinct origins are kept
  per connection.
- A live BoringSSL integration test covers first-request behavior on H2. H3
  has component tests; a live H3 request test is planned
  ([Coverage](coverage.md#http3)).

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
