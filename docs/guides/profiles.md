# Browser profiles

A profile is the part of Phantom that decides what a server can observe: the
TLS ClientHello, HTTP/2 SETTINGS and pseudo-header order, QUIC transport
parameters, HTTP/3 settings, and client hints. This guide explains how to
build one from the built-in recipes, what those recipes cover, and how
[request templates](#request-templates) supply browser fields for
individual requests.

A profile only shapes network behavior. Phantom is not a browser engine and
does not emulate the DOM, JavaScript, rendering, canvas, fonts, WebRTC, or
device fingerprints.

## Build a profile

`ClientProfile::new` takes the TLS settings used over TCP. Other components
are added with builder methods:

| Method | Adds |
| --- | --- |
| `ClientProfile::new(tls)` | TLS ClientHello for H1 and H2 |
| `with_tcp(settings)` | TCP socket options for every TCP connection |
| `with_http2(settings)` | HTTP/2 SETTINGS, window update, priority, and pseudo-header order |
| `with_http3(Http3ClientSettings)` | H3 TLS ClientHello, QUIC transport parameters, HTTP/3 settings, and request settings |
| `with_client_hints(settings)` | Ordered client-hint fields and their delivery rules |
| `with_websocket(settings)` | WebSocket opening templates, compression offer, and connection policy |
| `with_cookie_placement(placement)` | Position of the cookie jar's `Cookie` field; last by default ([details](connections-and-state.md#cookie-field-position)) |

A request fails before I/O when the profile lacks a component that the request
needs.

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

"Captured on" names the platforms where retained captures back the recipe.
[Coverage](../reference/coverage.md#browser-profiles) records the exact builds
and how the recipes differ from each other.

TCP recipes are not in the table because socket options are not visible in a
capture. `chromium::v153_tcp` and `firefox::v156_tcp` come from browser source
at the profiled release tags; see
[TCP socket options](#tcp-socket-options).

Only `chromium::v153_http2` and `firefox::v156_http2` carry a captured
extended CONNECT pseudo-header order, which H2 WebSocket needs. Other HTTP/2
recipes leave it unset. The WebSocket recipes and their limits are described
in [Profile connection policy](websocket.md#profile-connection-policy).

## Recipe names and platforms

Recipes are transport settings, not host-OS selectors. The runtime consumes
the validated settings it receives and does not branch on the host OS or
client-family name.

- A name without a platform, such as `chromium::v152_tls` or
  `firefox::v154_http2`, means the settings were verified on more than one
  platform, or rest on that finding for a later version. The rustdoc of each
  recipe names its capture builds and platforms.
- A remaining `macos` or `windows` qualifier means only "observed on that
  platform", never "selected by `target_os`". `safari::v18_5_macos_tls` keeps
  it because Safari is captured only on macOS. Client-hint recipes keep it
  because client hints carry platform data on the wire.
- The former `macos` names of the Chrome 152 and Firefox 154 transport recipes
  remain as hidden compatibility aliases.

## TCP socket options

`TcpSettings` sets `TCP_NODELAY` and the keepalive idle time and interval on
every TCP socket before it connects: origin connections, HTTP, HTTPS, and
SOCKS5 proxy connections, and the TCP control connection of a SOCKS5 UDP
association. It also chooses how a host's resolved addresses are tried.
Without `with_tcp`, sockets keep their operating-system defaults and
addresses are tried one at a time in resolver order.

- `chromium::v153_tcp` disables Nagle's algorithm, sets a 45-second
  keepalive idle time and interval, as Chromium does on Windows and Linux, and
  races addresses as Chromium's Happy Eyeballs does: IPv6 first, the other
  family after a failure, and a second attempt preferring IPv4 300 ms after
  the first. `TcpAddressRacing` documents the full behavior. Chromium on macOS
  sets only the keepalive idle time; set `TcpKeepalive::interval` to `None`
  for that platform.
- `firefox::v156_tcp` disables Nagle's algorithm, leaves keepalive untouched,
  and tries addresses in resolver order, because Firefox's keepalive schedule
  and address selection are not modeled.
- There is no Edge recipe; Edge's socket options have no public source or
  capture evidence.

Keepalive times must be whole seconds from 1 to 32,767, and the racing fallback
delay must be nonzero and at most 10 seconds. Settings the host cannot apply
exactly fail `ClientBuilder::build` with `BuildErrorKind::InvalidProfile`:
Windows sets the idle time and interval together, so it needs an interval;
OpenBSD, Haiku, and Vita cannot set an idle time; and some other platforms
cannot set an interval. A socket option the OS rejects at connection time fails
that attempt rather than connecting without it. The TCP SYN itself (window, MSS,
options, TTL) comes from the host OS, which should match the platform the
profile presents.

## Request templates

A profile shapes connections, but the fields of each request are caller
data: without help, `User-Agent`, `Accept`, `Sec-Fetch-*`, `priority`, and
their order are whatever the caller sends. A `RequestTemplate` supplies them
for one kind of browser request. For each protocol it lists the fields in
captured order, with captured values, the positions of caller-supplied
fields, and the positions of client hints. `RequestBuilder::template` applies
one to a request.

| Recipe | Request | HTTP/1.1 | HTTP/2 | HTTP/3 | `User-Agent` |
| --- | --- | --- | --- | --- | --- |
| `chromium::v153_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Captured headful Chrome 153 value |
| `chromium::v153_windows_fetch_no_store_template` | Same-origin `fetch(url, {cache: "no-store"})` GET | Yes | Yes | No | Captured headful Chrome 153 value |
| `edge::v153_windows_navigation_template` | Address-bar navigation | Yes | Yes | Yes | Caller slot |
| `edge::v153_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Caller slot |
| `firefox::v156_windows_navigation_template` | Address-bar navigation | Yes | Yes | No | Captured Firefox 156 value |
| `firefox::v156_windows_fetch_no_store_template` | Same-origin no-store `fetch` GET | Yes | Yes | No | Captured Firefox 156 value |

An address-bar navigation is an HTML document request with
`Sec-Fetch-Site: none` and `Sec-Fetch-User: ?1`. "No" means no retained
capture backs that protocol, so the template has no list for it. Every
template was captured on Windows 11 and carries the capture machine's
`en-US` `Accept-Language`.

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

- Each attempt uses the template's list for the protocol it runs on, after
  `Host` on HTTP/1.1 or after the pseudo-header fields on HTTP/2 and HTTP/3.
  An ALPN-negotiated request uses the list for the protocol ALPN selects.
- A caller field whose name matches a template entry takes that entry's
  position and field-name spelling and keeps its own value and sensitivity.
  A literal entry with no caller field emits its captured value; a caller
  slot with no caller field emits nothing.
- Other caller fields follow the template in the caller's order, and the
  cookie jar's automatic `Cookie` field comes after them. The templates do
  not place `Cookie`.
- The profile's client hints fill the template's hint slots. Only hints the
  profile would send anyway are emitted: default hints, and hints the origin
  requested through `Accept-CH` or ALPS `ACCEPT_CH`.
- Every redirect hop uses the same template. Phantom does not adjust
  template values such as `Sec-Fetch-Site` across a redirect.

Where Chromium puts client hints depends on the request kind, and the
templates record it. A navigation sends them as one block in profile order
after `Connection` on HTTP/1.1 and first on HTTP/2 and HTTP/3; after
`Accept-CH`, the requested hints join that block, as the retained
client-hint capture shows. A `fetch` splits the defaults: `sec-ch-ua-platform`
precedes `User-Agent`, and `sec-ch-ua` and `sec-ch-ua-mobile` follow it. No
capture shows where Chrome puts hints requested through `Accept-CH` on a
`fetch`; the fetch templates place them after `sec-ch-ua-mobile`. Without a
template, automatic hints precede every caller field.

### Identity check

A template claims one browser family and major version. Before any I/O, a
templated request is checked against that claim:

- A caller `User-Agent` must carry the template's product tokens with its
  major version and none of its excluded tokens. The Chrome 153 templates
  require a `Chrome/153` token, which a copied `HeadlessChrome/153` is not,
  and reject `Edg` and `Firefox`; the Edge templates require `Edg/153` and
  reject `HeadlessChrome`; the Firefox templates require `Firefox/156` and
  reject `Chrome`.
- A caller `sec-ch-ua` or `sec-ch-ua-full-version-list`, and the profile's
  value of either hint, must list each of the template's brands once with
  its major version and no other brand except one GREASE brand in the shape
  Chromium generates, such as `"Not_A Brand";v="8"`. A list naming both
  `Google Chrome` and `Microsoft Edge` fails. Firefox sends neither hint, so
  any such field contradicts a Firefox template.

A contradiction fails with `RequestErrorKind::IdentityMismatch`. Phantom
never rewrites or drops the field. An invalid template, or one without an
HTTP/3 list for a request that may use HTTP/3 (an exact H3 request, or a
negotiated request on a client with Alt-Svc enabled), fails with
`RequestErrorKind::RequestTemplate`.

The check rejects instead of warning or waiting for an opt-in. A template
is an explicit claim, so a request that contradicts it is a caller error.
Sending it would put a cross-layer mismatch on the wire that a server can
record, and it cannot be recalled; failing early costs nothing when the
fields agree. Requests without a template are not checked, because a
`ClientProfile` carries no browser identity to compare with, and inferring
one from TLS settings would mean branching on a family name. The check
covers only family and major version. It does not compare full versions or
platforms, check that the profile's TLS and HTTP/2 recipes are the same
browser's, or require a `User-Agent` to be present.

### Limits of the templates

- Only address-bar navigations and same-origin no-store `fetch` GETs are
  captured. There are no templates for link or script navigations,
  subresources such as images, scripts, and stylesheets, `XMLHttpRequest`,
  cross-origin `fetch`, or requests with a body.
- The HTTP/1.1 captures used plaintext loopback origins, which Chrome treats
  as secure. Fields sent to a plaintext non-loopback origin are not
  captured.
- HTTP/2 HEADERS priority comes from the profile, not the template. Chrome
  sends weight 220 on a `fetch` and Firefox weight 22, while the recipes carry
  their navigation weights, 256 and 42.
- Every Edge capture ran headless, so the Edge templates leave `User-Agent`
  to the caller. The Firefox value comes from headless captures; Firefox
  sent no headless marker, but no headful Firefox capture confirms it.
- Firefox has no HTTP/3 recipe, so its templates have no HTTP/3 list.

## Custom profiles

Built-in and custom profiles use the same typed model. Start from a recipe and
change public fields, or build settings from scratch. Settings are validated,
and a profile-policy conflict fails before I/O rather than being accepted and
ignored. A custom profile is not evidence of browser behavior: only retained
captures back a named recipe.

## Client hints

Client hints are request fields such as `sec-ch-ua` that describe the browser
and platform. Servers can ask for more of them with the `Accept-CH` response
field.

`ClientHintSettings` is immutable profile data: it supplies ordered names,
values, and default-versus-negotiated delivery. A client owns the mutable
response `Accept-CH` selection. The Chrome 152 macOS recipe is backed by a local
navigation capture; Firefox and Safari recipes do not acquire Chromium client
hints by family-name branching.

### Learning from `Accept-CH`

For H1, H2, and H3 responses:

- a valid `Accept-CH` structured-field list replaces the exact HTTPS origin's
  selection;
- an empty or unsupported-only list clears it;
- absence leaves it unchanged; and
- malformed input is ignored.

Origin keys include the effective port. Client clones share the bounded LRU
(least recently used) store; independently built clients do not.
`Client::clear_client_hints` clears all retained selections. Caller-supplied
configured hint fields win in their existing positions, while automatic fields
retain profile order. A [request template](#request-templates) moves both
into its client-hint slots.

### Connection-level `ACCEPT_CH`

For H2 and H3, a peer can also send an `ACCEPT_CH` entry through ALPS (a TLS
extension that carries application settings during the handshake). It is
immutable metadata on that connection.

- Exact canonical origin matching augments the response-learned selection
  after connection choice, so the first request can carry requested fields
  without a warm-up request.
- Duplicate origins keep the first valid entry. Non-canonical origins are
  ignored, and retained distinct origins are capped at 1,024 per connection.
- This metadata is never copied into the client cache, does not cross a
  replacement connection, and does not clear response-learned state when its
  value is empty or malformed.

The first-request behavior has a live BoringSSL H2 integration test. H3 is
covered by the BoringSSL QUIC ALPS round trip, strict frame decoder, immutable
connection handoff, and shared request-selection tests; a live BoringSSL-server
H3 request differential remains a separate validation gate.

### `Critical-CH` retry

`Critical-CH` can cause one internal retry when a supported requested field was
missing and the HTTP method is safe.

- An owned-bytes request body is replayed exactly.
- A one-shot streaming body cannot be replayed, so the retry fails with
  `RequestErrorKind::RequestBody` and the original response is not returned.
- The retry never changes protocol or route, and a repeated demand cannot
  loop.
- Intermediate redirect responses are learned before the next hop, and
  configured caller hint fields are removed at a cross-origin boundary before
  the new origin's automatic set is built.

### Limits of the client-hint model

This is a raw-client, top-level request policy. These remain absent:

- Permissions Policy delegation and subresource browsing context;
- persistence, and expiry beyond explicit replacement;
- full-navigation restart across an already-followed redirect chain; and
- live post-handshake `ACCEPT_CH` frames.

Those require distinct public context or engine evidence; they are not inferred
from a browser name. There is no process-global hint cache and no immutable
profile mutation.

The differential for this feature is an ordered session transcript, not one
fingerprint hash. Connection observations retain TLS and H2/H3 startup state;
request observations retain ordered headers, the response stimulus, the next
request's changes, retry outcome, and connection reuse. That makes the
`Accept-CH` response-to-request transition and origin boundary visible.
