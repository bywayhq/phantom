# Browser profiles

A profile decides what a server can observe about your client at the
connection level: the TLS ClientHello, HTTP/2 SETTINGS and pseudo-header
order, QUIC transport parameters, HTTP/3 settings, TCP socket options, and
client hints. You build one from recipes. Most recipes come from browser
captures; TCP recipes come from browser source. The fields of individual
requests, such as `User-Agent`, come from
[request templates](#request-templates) instead.

A profile shapes only network behavior. Phantom is not a browser engine and
does not emulate the DOM, JavaScript, rendering, canvas, fonts, WebRTC, or
device fingerprints.

## Build a profile

`ClientProfile::new` takes the TLS settings used over TCP. Builder methods add
the other components:

| Method | Adds |
| --- | --- |
| `ClientProfile::new(tls)` | TLS ClientHello for H1 and H2 |
| `with_tcp(settings)` | TCP socket options for every TCP connection |
| `with_http2(settings)` | HTTP/2 SETTINGS, window update, priority, and pseudo-header order |
| `with_http3(Http3ClientSettings)` | H3 TLS ClientHello, QUIC transport parameters, HTTP/3 settings, and request settings |
| `with_client_hints(settings)` | Ordered client-hint fields and when to send them |
| `with_websocket(settings)` | WebSocket opening templates, compression offer, and connection policy |
| `with_cookie_placement(placement)` | Where the cookie jar's `Cookie` field goes; last by default ([details](connections-and-state.md#cookie-field-position)) |

H1, H2, and H3 mean HTTP/1.1, HTTP/2, and HTTP/3. A request fails before any
network I/O if the profile lacks a component it needs.

```rust
use phantom::profile::{chromium, edge, firefox, ClientProfile, Http3ClientSettings};

fn profiles() -> [ClientProfile; 2] {
    // Firefox 156: TLS, HTTP/2, and cookie-field recipes, plus its
    // source-derived TCP options.
    let firefox = ClientProfile::new(firefox::v156_tls())
        .with_tcp(firefox::v156_tcp())
        .with_http2(firefox::v156_http2())
        .with_cookie_placement(firefox::v156_cookie_placement());

    // Edge 153: its own TLS and client hints; H2, QUIC, and H3 match Chrome 153.
    let edge = ClientProfile::new(edge::v153_tls())
        .with_http2(chromium::v153_http2())
        .with_http3(Http3ClientSettings::new(
            edge::v153_http3_tls(),
            chromium::v153_quic(),
            chromium::v153_http3(),
            chromium::v153_http3_request(),
        ))
        .with_client_hints(edge::v153_windows_client_hints());

    [firefox, edge]
}
```

## Built-in recipes

| Browser | Module | TLS | HTTP/2 | QUIC and HTTP/3 | Client hints | WebSocket | Captured on |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Chrome 152 | `chromium::v152_*` | Yes | Yes | Yes | `v152_macos_client_hints` | No | macOS and Windows |
| Chrome 153 | `chromium::v153_*` | Yes | Yes | Yes | `v153_windows_client_hints` | `v153_websocket` | Windows |
| Edge 153 | `edge::v153_*` | Yes | Chrome 153 | Chrome 153 QUIC and H3; own H3 TLS | `v153_windows_client_hints` | Chrome 153 | Windows |
| Firefox 154 | `firefox::v154_*` | Yes | Yes | No | No | No | macOS and Windows |
| Firefox 156 | `firefox::v156_*` | Yes | Yes | No | No | `v156_websocket` | Windows |
| Safari 18.5 | `safari::v18_5_macos_tls` | Yes | No | No | No | No | macOS |

"Captured on" lists the platforms whose retained captures back the recipe.
[Coverage](../reference/coverage.md#browser-profiles) gives the exact builds
and how the recipes differ.

- TCP recipes are not in the table, because socket options do not appear in a
  capture. `chromium::v153_tcp` and `firefox::v156_tcp` come from the
  browsers' source code at the profiled release tags; see
  [TCP socket options](#tcp-socket-options).
- H2 WebSocket needs a captured pseudo-header order for extended CONNECT.
  Only `chromium::v153_http2` and `firefox::v156_http2` carry one. For the
  WebSocket recipes and their limits, see
  [Profile connection policy](websocket.md#profile-connection-policy).

## Recipe names and platforms

A recipe is a set of transport settings. It does not select behavior by host
operating system: the runtime uses the validated settings it receives and
never branches on the host OS or the browser name.

- A name without a platform, such as `chromium::v152_tls` or
  `firefox::v154_http2`, means the settings matched on more than one
  platform, or belong to a later version that relies on that finding. Each
  recipe's rustdoc names its capture builds and platforms.
- A `macos` or `windows` in a name means only "observed on that platform". It
  never means "selected by `target_os`". `safari::v18_5_macos_tls` keeps it
  because Safari was captured only on macOS. Client-hint recipes keep it
  because client hints carry platform data on the wire.
- The older `macos` names of the Chrome 152 and Firefox 154 transport recipes
  remain as hidden aliases for compatibility.

## TCP socket options

`TcpSettings` sets `TCP_NODELAY` and the keepalive idle time and interval on
each TCP socket before it connects. It also decides how the client tries a
host's resolved addresses. It applies to every TCP connection the client
opens: to origins, to HTTP, HTTPS, and SOCKS5 proxies, and for the control
connection of a SOCKS5 UDP association. Without `with_tcp`, sockets keep the
operating system's defaults and addresses are tried one at a time in resolver
order.

- `chromium::v153_tcp` disables Nagle's algorithm and sets a 45-second
  keepalive idle time and interval, as Chromium does on Windows and Linux. It
  races addresses as Chromium's Happy Eyeballs does: the first attempt prefers
  IPv6, a failed attempt is followed by one on the other family, and 300 ms
  after the first attempt a second one starts so that one attempt prefers
  each family. `TcpAddressRacing` documents the full behavior. Chromium on
  macOS sets only the idle time; for that platform, set
  `TcpKeepalive::interval` to `None`.
- `firefox::v156_tcp` disables Nagle's algorithm, leaves keepalive alone, and
  tries addresses in resolver order. Firefox's keepalive schedule and address
  selection are not modeled.
- There is no Edge recipe. No public source or capture shows Edge's socket
  options.

Keepalive times must be whole seconds from 1 to 32,767. The racing delay must
be nonzero and at most 10 seconds.

Phantom applies these settings exactly or fails; it never connects with
options the profile did not ask for.

- Settings the host cannot apply fail `ClientBuilder::build` with
  `BuildErrorKind::InvalidProfile`. Windows sets the idle time and interval
  together, so it requires an interval. OpenBSD, Haiku, and Vita cannot set an
  idle time, and some other platforms cannot set an interval.
- If the OS rejects a socket option when connecting, that connection attempt
  fails.

The TCP SYN itself (window, MSS, options, TTL) comes from the host OS. Run on
the platform the profile presents if that layer matters to you.

## Request templates

A profile shapes connections, but request fields are yours to supply. Without
help, `User-Agent`, `Accept`, `Sec-Fetch-*`, `priority`, and their order are
whatever you send. A `RequestTemplate` supplies them for one kind of browser
request. For each protocol, it lists the fields in captured order with their
captured values, plus slots marking where your own fields and the client
hints go. Apply one with `RequestBuilder::template`.

| Recipe | Request | HTTP/1.1 | HTTP/2 | HTTP/3 | `User-Agent` |
| --- | --- | --- | --- | --- | --- |
| `chromium::v153_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Captured headful Chrome 153 value |
| `chromium::v153_windows_fetch_no_store_template` | Same-origin `fetch(url, {cache: "no-store"})` GET | Yes | Yes | No | Captured headful Chrome 153 value |
| `edge::v153_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Caller slot |
| `edge::v153_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Caller slot |
| `firefox::v156_windows_navigation_template` | Address-bar navigation | Yes | Yes | No | Captured Firefox 156 value |
| `firefox::v156_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Firefox 156 value |

- An address-bar navigation is an HTML document request with
  `Sec-Fetch-Site: none` and `Sec-Fetch-User: ?1`.
- "No" means no retained capture covers that protocol, so the template has
  no field list for it.
- A caller slot has no captured value; you supply the field.
- Every template was captured on Windows 11 and carries the capture
  machine's `en-US` `Accept-Language`.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RequestHeader};

async fn navigate_then_fetch() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v153_tls())
        .with_http2(chromium::v153_http2())
        .with_client_hints(chromium::v153_windows_client_hints());
    let client = Client::builder(profile).build()?;

    let page = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .template(chromium::v153_windows_navigation_template())
        .send()
        .await?;
    page.into_body().collect_with_limit(1 << 20).await?;

    // `Referer` is a caller slot: its value is the page URL.
    let data = client
        .get(HttpProtocol::Http2, "https://example.com/data.json")?
        .template(chromium::v153_windows_fetch_no_store_template())
        .header(RequestHeader::new("referer", "https://example.com/"))
        .send()
        .await?;
    println!("{}", data.status());
    Ok(())
}
```

### How a templated request is assembled

- Protocol: Each attempt uses the template's list for the protocol it
  runs on. The list follows `Host` on HTTP/1.1 and the pseudo-header fields
  on HTTP/2 and HTTP/3. A negotiated request uses the list for the protocol
  ALPN selects.
- Your fields: A field whose name matches a template entry takes that
  entry's position and name spelling, and keeps your value and sensitivity. A
  literal entry you do not override sends its captured value. A caller slot
  you do not fill sends nothing.
- Extra fields: Fields the template does not name follow its last field,
  in your order. Phantom sends them rather than rejecting them.
- Cookies: Templates cannot contain `Cookie`. The profile's
  `CookiePlacement` inserts the cookie jar's field into the expanded list
  (see [below](#cookie-placement-in-templates)). A `Cookie` field of your own
  replaces the jar's.
- Client hints: The profile's client hints fill the template's hint slots
  (see [below](#client-hints-in-templates)).
- HTTP/2 priority: The template's HEADERS priority replaces the
  connection's priority for that request's stream only. A peer that disables
  RFC 7540 priorities still suppresses it.
- Redirects: Every redirect hop uses the same template. Phantom does not
  adjust values such as `Sec-Fetch-Site` across a redirect.

The navigation templates have no `Referer` slot, because an address-bar
navigation sends none. A `Referer` you add to one therefore goes last: after
`Accept-Language` on Chrome's and Edge's HTTP/1.1 list, after `priority` on
their HTTP/2 and HTTP/3 lists, and after `Priority` and `te` on Firefox's. No
capture shows that position. For a request that carries a `Referer`, use a
template with a `Referer` slot, such as a `fetch` template.

#### Cookie placement in templates

`CookiePlacement` puts the jar's `Cookie` field before the first field it
names, compared case-insensitively, or last if none is present
([details](connections-and-state.md#cookie-field-position)). It matches those
names against template and caller fields, not against client hints, which are
added afterward.

- With `firefox::v156_cookie_placement`, a Firefox `fetch` template sends
  `Cookie` after `Referer` and before `Sec-Fetch-Dest`. A Firefox navigation
  sends it before `Upgrade-Insecure-Requests`.
- With `chromium::v153_cookie_placement`, a Chrome or Edge template sends it
  last on HTTP/1.1 and before the final `priority` on HTTP/2 and HTTP/3.

#### Client hints in templates

A template sends only the hints the profile would send anyway: the default
hints, and hints the origin requested through `Accept-CH` or ALPS
`ACCEPT_CH`. Without a template, automatic hints go before all of your
fields. With one, where they go depends on the kind of request, as captured
from Chromium:

- On a navigation, the hints form one block in profile order: after
  `Connection` on HTTP/1.1, and first on HTTP/2 and HTTP/3. Hints requested
  through `Accept-CH` join that block. The retained capture of requested
  hints covers HTTP/1.1 only. For HTTP/2 and HTTP/3, their placement is
  inferred from the default block, which every protocol's captures place the
  same way.
- On a `fetch`, the default hints are split: `sec-ch-ua-platform` goes before
  `User-Agent`, and `sec-ch-ua` and `sec-ch-ua-mobile` go after it.

Some templates do not know where requested hints go: a `fetch` template,
because no capture shows where Chrome puts them on a `fetch`, and a Firefox
template, which has no hint slots at all. Phantom refuses to guess, and fails
with `RequestErrorKind::RequestTemplate`:

- before any I/O, when the template has no hint slots and the profile sends
  hints by default;
- before any I/O, when one of your fields carries a hint the profile sends
  only on request, including on `http://` origins;
- before the request is sent on the connection, when the origin has asked for
  such a hint through `Accept-CH` or ALPS `ACCEPT_CH`. This includes the
  retry a `Critical-CH` response asks for.

### Identity check

A template claims one browser family and major version. Before any I/O,
Phantom checks a templated request against that claim:

- A `User-Agent` you supply must contain the template's product token with
  its major version and none of its excluded tokens.
  - Chrome 153 templates require `Chrome/153` (a copied `HeadlessChrome/153`
    does not match) and reject `Edg` and `Firefox`.
  - Edge 153 templates require `Edg/153` and reject `HeadlessChrome` and
    `Firefox`.
  - Firefox 156 templates require `Firefox/156` and reject `Chrome`,
    `HeadlessChrome`, and `Edg`.
- The request must have a `User-Agent`. The Edge templates leave it to you,
  so an Edge-templated request without one fails rather than sending Edge
  brand hints with no `User-Agent`.
- A `sec-ch-ua` or `sec-ch-ua-full-version-list`, whether yours or the
  profile's, must list each of the template's brands once with its major
  version. The only other brand allowed is the GREASE brand Chromium derives
  from that major version: `"Not_A Brand";v="8"` for 153. A list naming both
  `Google Chrome` and `Microsoft Edge` fails, and so does Chrome 152's
  `"Not?A_Brand";v="24"` on a 153 template. Firefox sends neither hint, so
  either field contradicts a Firefox template.

A contradiction fails with `RequestErrorKind::IdentityMismatch`. Phantom never
rewrites or drops the field. An invalid template fails with
`RequestErrorKind::RequestTemplate`, as does a template without an HTTP/3 list
on a request that may use HTTP/3: an exact H3 request, or a negotiated request
on a client with Alt-Svc enabled.

The check rejects rather than warns, because a template is an explicit claim.
A request that contradicts it would put a mismatch between layers on the wire,
where a server can record it and it cannot be taken back. When the fields
agree, the check costs nothing.

The check has limits:

- Requests without a template are not checked. A `ClientProfile` carries no
  browser identity to compare with, and inferring one from TLS settings would
  mean branching on a browser name.
- It compares family and major version only. It does not compare full
  versions or platforms, and it does not check that the profile's TLS and
  HTTP/2 recipes come from the same browser.

### Limits of the templates

- Only address-bar navigations and same-origin no-store `fetch` GETs are
  captured. There are no templates for link or script navigations,
  subresources such as images, scripts, and stylesheets, `XMLHttpRequest`,
  cross-origin `fetch`, or requests with a body.
- The HTTP/1.1 captures used plaintext loopback origins, which Chrome treats
  as secure. Fields sent to a plaintext origin that is not loopback were not
  captured.
- On HTTP/2, the template's HEADERS priority replaces the H2 recipe's
  connection priority, which is the navigation weight. Chrome and Edge send
  weight 256 on a navigation and 220 on a `fetch`, both exclusive. Firefox
  sends 42 and 22, both non-exclusive. The templates always depend on stream
  0, as every capture did. Chrome can depend on another open stream of equal
  or higher priority; Phantom does not reproduce that.
- Every Edge capture ran headless, so the Edge templates leave `User-Agent`
  to you. The Firefox value comes from headless captures. Firefox sent no
  headless marker, but no headful Firefox capture confirms the value.
- Firefox has no HTTP/3 recipe, so its templates have no HTTP/3 list.

## Custom profiles

Built-in and custom profiles use the same types. Start from a recipe and change
its public fields, or build settings from scratch. Phantom validates settings,
and a conflict in profile policy fails before any I/O instead of being
silently ignored. A custom profile is not evidence of browser behavior; only
retained captures back a named recipe.

## Client hints

Client hints are request fields, such as `sec-ch-ua`, that describe the
browser and platform. A browser sends some by default. A server can ask for
more with the `Accept-CH` response field.

`ClientHintSettings` is fixed profile data: the hint names in order, their
values, and whether each is sent by default or only on request. The client
separately tracks which hints each origin has requested. Each built-in
client-hint recipe comes from a navigation capture of its browser. Phantom
never adds Chromium client hints to a Firefox or Safari profile based on the
browser name.

### Learning from `Accept-CH`

For H1, H2, and H3 responses from an HTTPS origin, an `Accept-CH` field
updates that origin's set of requested hints:

| Response `Accept-CH` | Effect |
| --- | --- |
| Valid structured-field list | Replaces the origin's set |
| Empty, or only unsupported names | Clears the origin's set |
| Absent | No change |
| Malformed | Ignored |

- An origin is keyed by exact scheme, host, and effective port.
- The sets live in a bounded store that evicts the least recently used
  origin. Clones of a client share it; separately built clients do not.
- `Client::clear_client_hints` clears every stored set.
- A configured hint field you supply keeps its position and your value.
  Automatic hints stay in profile order. A
  [request template](#request-templates) moves both into its hint slots.

### Connection-level `ACCEPT_CH`

On H2 and H3, a server can also send an `ACCEPT_CH` entry through ALPS, a TLS
extension that carries application settings during the handshake. This lets
the first request on a connection carry the requested hints without a
warm-up request.

- The entry applies to requests whose origin matches it exactly, and adds to
  the hints learned from responses.
- It belongs to that connection only. It is never copied into the client's
  store, does not carry over to a replacement connection, and does not clear
  learned hints when it is empty or malformed.
- If an origin appears more than once, the first valid entry wins.
  Non-canonical origins are ignored, and at most 1,024 distinct origins are
  kept per connection.

A live BoringSSL integration test covers the first-request behavior on H2. H3
has component tests; a live H3 request test against a BoringSSL server is
still planned (see [Coverage](../reference/coverage.md#http3)).

### `Critical-CH` retry

A `Critical-CH` response field names hints the server requires. If a
supported hint it names was missing and the method is safe, Phantom retries
the request once.

- An owned body is sent again exactly.
- A streaming body cannot be sent again, so the retry fails with
  `RequestErrorKind::RequestBody` and the original response is not returned.
- The retry never changes protocol or route, and a repeated demand cannot
  loop.
- Hints requested by intermediate redirect responses are learned before the
  next hop. At a cross-origin boundary, configured hint fields you supplied
  are removed before the new origin's automatic hints are built.

### Limits of the client-hint model

The model covers top-level requests from a standalone client. It does not
support:

- Permissions Policy delegation or subresource browsing contexts;
- persistence, or expiry other than explicit replacement;
- restarting a full navigation across a redirect chain already followed;
- `ACCEPT_CH` frames sent after the handshake.

Each of these needs request context or browser-engine evidence that a browser
name cannot provide. There is no process-wide hint cache, and a profile never
changes after it is built.

Tests for this feature check sequences of requests on one client, not a single
fingerprint, so the step from an `Accept-CH` response to the next request, and
the boundary between origins, are both visible.
