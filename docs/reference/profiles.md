# Browser profile reference

Lookup tables for profile components, built-in recipes, TCP socket options,
request templates, the template identity check, and client hints. For how to
use them, see [Browser profiles](../guides/profiles.md).

## Profile components

| Method | Adds |
| --- | --- |
| `ClientProfile::new(tls)` | TLS ClientHello for H1 and H2 |
| `with_tcp(settings)` | TCP socket options for every TCP connection |
| `with_http2(settings)` | HTTP/2 SETTINGS, window update, priority, and pseudo-header order |
| `with_http3(Http3ClientSettings)` | H3 TLS ClientHello, QUIC transport parameters, HTTP/3 settings, and request settings |
| `with_client_hints(settings)` | Ordered client-hint fields and when to send them |
| `with_websocket(settings)` | WebSocket opening templates, compression offer, and connection policy |
| `with_cookie_placement(placement)` | Where the cookie jar's `Cookie` field goes; last by default ([details](../guides/connections-and-state.md#place-the-cookie-field-where-a-browser-does)) |

A request fails before any network I/O if the profile lacks a component it
needs.

## Built-in recipes

Phantom carries one version per browser: the current stable build on the
capture host. Older versions are retired rather than half-maintained, so a
recipe name always points at a build that can be recaptured and reverified.

| Browser | Module | TLS | HTTP/2 | QUIC and HTTP/3 | Client hints | WebSocket | Captured on |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Chrome 154 | `chromium::v154_*` | Yes | Yes | Yes | `v154_windows_client_hints` | `v154_websocket` | Windows |
| Edge 153 | `edge::v153_*` | Yes | Chromium | Chromium QUIC and H3; own H3 TLS | `v153_windows_client_hints` | Chromium | Windows |
| Firefox 156 | `firefox::v156_*` | Yes | Yes | No | No | `v156_websocket` | Windows |

- "Captured on" lists the platforms whose retained captures back the recipe.
  [Coverage](coverage.md#browser-profiles) gives the exact builds and how the
  recipes differ.
- TCP recipes are not in the table, because socket options do not appear in
  a capture. `chromium::v154_tcp` and `firefox::v156_tcp` come from the
  browsers' source code at the profiled release tags
  ([TCP socket options](#tcp-socket-options)).
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
| Edge | No recipe | No recipe | No recipe |

- Chromium racing: the first attempt prefers IPv6; a failed attempt is
  followed by one on the other family; 300 ms after the first attempt a
  second one starts, so one attempt prefers each family. `TcpAddressRacing`
  documents the full behavior.
- Chromium on macOS sets only the idle time; for that platform, set
  `TcpKeepalive::interval` to `None`.
- Firefox's keepalive schedule and address selection are not modeled.
- No public source or capture shows Edge's socket options.

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

## Request templates

| Recipe | Request | HTTP/1.1 | HTTP/2 | HTTP/3 | `User-Agent` |
| --- | --- | --- | --- | --- | --- |
| `chromium::v154_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Captured headful Chrome 154 value |
| `chromium::v154_windows_fetch_no_store_template` | Same-origin `fetch(url, {cache: "no-store"})` GET | Yes | Yes | No | Captured headful Chrome 154 value |
| `edge::v153_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Caller slot |
| `edge::v153_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Caller slot |
| `firefox::v156_windows_navigation_template` | Address-bar navigation | Yes | Yes | No | Captured Firefox 156 value |
| `firefox::v156_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Firefox 156 value |

- An address-bar navigation is an HTML document request with
  `Sec-Fetch-Site: none` and `Sec-Fetch-User: ?1`.
- "No" means no retained capture covers that protocol, so the template has
  no field list for it.
- A caller slot has no captured value; you supply the field.
- Every template was captured on Windows 11 and carries the capture machine's
  `en-US` `Accept-Language`.

### Template assembly

| Aspect | Rule |
| --- | --- |
| Protocol | Each attempt uses the list for the protocol it runs on, after `Host` on HTTP/1.1 and after the pseudo-header fields on HTTP/2 and HTTP/3. A negotiated request uses the list for the protocol ALPN selects. |
| Your fields | A field whose name matches an entry takes that entry's position and name spelling, and keeps your value and sensitivity. |
| Unfilled entries | A literal entry you do not override sends its captured value. A caller slot you do not fill sends nothing. |
| Extra fields | Fields the template does not name follow its last field, in your order. They are sent, not rejected. |
| Cookies | Templates cannot contain `Cookie`. The profile's `CookiePlacement` inserts the jar's field; a `Cookie` field of your own replaces it. |
| Client hints | The profile's client hints fill the template's hint slots. |
| HTTP/2 priority | The template's HEADERS priority replaces the connection's priority for that stream only. A peer that disables RFC 7540 priorities still suppresses it. |
| Redirects | Every hop uses the same template. Values such as `Sec-Fetch-Site` are not adjusted. |
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
| One of your fields carries a hint the profile sends only on request, including on `http://` origins | Before any I/O |
| The origin asked for such a hint through `Accept-CH` or ALPS `ACCEPT_CH`, including the retry a `Critical-CH` response asks for | Before the request is sent on the connection |

### Template limits

- Only address-bar navigations and same-origin no-store `fetch` GETs are
  captured. There are no templates for link or script navigations,
  subresources such as images, scripts, and stylesheets, `XMLHttpRequest`,
  cross-origin `fetch`, or requests with a body.
- The HTTP/1.1 captures used plaintext loopback origins, which Chrome treats
  as secure. Fields sent to a plaintext origin that is not loopback were not
  captured.
- The templates always depend on stream 0, as every capture did. Chrome can
  depend on another open stream of equal or higher priority; Phantom does not
  reproduce that.
- Every Edge capture ran headless, so the Edge templates leave `User-Agent`
  to you. The Firefox value comes from headless captures; Firefox sent no
  headless marker, but no headful Firefox capture confirms the value.
- Firefox has no HTTP/3 recipe, so its templates have no HTTP/3 list.

| Browser | HTTP/2 HEADERS priority, navigation | `fetch` |
| --- | --- | --- |
| Chrome, Edge | Weight 256, exclusive | Weight 220, exclusive |
| Firefox | Weight 42, non-exclusive | Weight 22, non-exclusive |

The template's priority replaces the H2 recipe's connection priority, which
is the navigation weight.

## Identity check

A template claims one browser family and major version. Before any I/O,
Phantom checks a templated request against that claim.

| Template | `User-Agent` must contain | `User-Agent` must not contain | Allowed GREASE brand |
| --- | --- | --- | --- |
| Chrome 154 | `Chrome/154` (a copied `HeadlessChrome/154` does not match) | `Edg`, `Firefox` | `"Not A(Brand";v="99"` |
| Edge 153 | `Edg/153` | `HeadlessChrome`, `Firefox` | `"Not_A Brand";v="8"` |
| Firefox 156 | `Firefox/156` | `Chrome`, `HeadlessChrome`, `Edg` | None: any `sec-ch-ua` or `sec-ch-ua-full-version-list` contradicts it |

- The request must have a `User-Agent`. The Edge templates leave it to you,
  so an Edge-templated request without one fails rather than sending Edge
  brand hints with no `User-Agent`.
- A `sec-ch-ua` or `sec-ch-ua-full-version-list`, yours or the profile's, must
  list each template brand once with its major version. The only other brand
  allowed is the GREASE brand above. A list naming both `Google Chrome` and
  `Microsoft Edge` fails, and so does Chrome 153's `"Not_A Brand";v="8"` on a
  154 template.
- Requests without a template are not checked; a `ClientProfile` carries no
  browser identity to compare with.
- The check compares family and major version only. It does not compare full
  versions or platforms, or check that the TLS and HTTP/2 recipes come from
  the same browser.

| Failure | Error |
| --- | --- |
| A field contradicts the template | `RequestErrorKind::IdentityMismatch`; the field is never rewritten or dropped |
| Invalid template | `RequestErrorKind::RequestTemplate` |
| No HTTP/3 list on a request that may use HTTP/3 (exact H3, or negotiated with Alt-Svc enabled) | `RequestErrorKind::RequestTemplate` |

## Client hints

`ClientHintSettings` is fixed profile data: hint names in order, values, and
whether each is sent by default or only on request. Each built-in client-hint
recipe comes from a navigation capture of its browser. Phantom never adds
Chromium client hints to a Firefox profile based on the browser name.

### Learning from `Accept-CH`

For H1, H2, and H3 responses from an HTTPS origin:

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

- [Browser profiles](../guides/profiles.md): build a profile and apply a
  template.
- [Coverage](coverage.md#browser-profiles): exact builds behind each recipe.
- [Validation](../explanation/validation.md#browser-recipes): the captures
  behind each recipe.
