# Browser profiles

A profile is the part of Phantom that decides what a server can observe: the
TLS ClientHello, HTTP/2 SETTINGS and pseudo-header order, QUIC transport
parameters, HTTP/3 settings, and client hints. This guide explains how to
build one from the built-in recipes and what those recipes cover.

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
association. Without `with_tcp`, sockets keep their operating-system defaults.

- `chromium::v153_tcp` disables Nagle's algorithm and sets a 45-second
  keepalive idle time and interval, as Chromium does on Windows and Linux.
  Chromium on macOS sets only the idle time; set `TcpKeepalive::interval` to
  `None` for that platform.
- `firefox::v156_tcp` disables Nagle's algorithm and leaves keepalive
  untouched, because Firefox's keepalive changes over a connection's life and
  is not modeled.
- There is no Edge recipe; Edge's socket options have no public source or
  capture evidence.

Keepalive times must be whole seconds from 1 to 32,767. Windows sets the idle
time and interval together, so a keepalive without an interval fails there
with `ErrorKind::Unsupported`. A socket option the OS rejects fails that
connection attempt rather than connecting without it. The TCP SYN itself
(window, MSS, options, TTL) comes from the host OS, which should match the
platform the profile presents.

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
retain profile order.

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
