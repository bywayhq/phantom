# WebSocket

WebSocket is a two-way message protocol that starts as an HTTP request. The
optional `websocket` feature provides exact HTTP/1.1 Upgrade and
[RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html) HTTP/2 extended CONNECT
connections. `Client::websocket` remains the HTTP/1.1
shorthand; `Client::websocket_with_protocol` selects an exact protocol without
fallback. `Client::websocket_with_profile_policy` lets the profile's
[connection policy](#profile-connection-policy) choose, as a browser does,
between a pooled HTTP/2 session and a new connection. H2 accepts `wss://`
only, over direct and proxy routes, and requires an explicit five-field
extended-CONNECT pseudo-header order in the HTTP/2 profile. The Chrome 153 and
Firefox 156 HTTP/2 recipes carry their captured order; older recipes leave it
unset.

For H1, direct routes accept plaintext `ws://` or TLS-backed `wss://`;
HTTP forward proxies accept plaintext `ws://` over either plaintext or
independently authenticated proxy TLS. Local- and remote-DNS SOCKS5 routes
accept both `ws://` and `wss://`; HTTP-CONNECT routes accept `wss://`,
including through an HTTPS proxy reached over HTTP/2
(`HttpProxy::with_http2_transport`). That proxy transport cannot forward
plaintext requests, so H1 `ws://` through it fails before proxy I/O instead of
switching to CONNECT or HTTP/1.1. The
[route matrix](../reference/route-matrix.md)
summarizes every scheme, protocol, and route.
Secure connections reuse Phantom's BoringSSL TLS profile. Both transports reuse
the ordered HTTP/1 serializer, ordered response metadata, client cookies,
runtime errors, and tracing lifecycle.

## Connect over HTTP/1.1

```rust
use futures_util::{SinkExt, StreamExt};
use phantom::{Client, WebSocketMessage};

async fn example(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let socket = client
        .websocket("wss://example.com/events")?
        .connect()
        .await?;
    let (mut sender, mut receiver) = socket.split();

    sender
        .send(WebSocketMessage::Text("hello".into()))
        .await?;
    if let Some(message) = receiver.next().await {
        println!("{:?}", message?);
    }
    Ok(())
}
```

The example uses `futures-util` for `SinkExt` and `StreamExt`; add it to your
own `Cargo.toml` to call those traits.

## Connect over HTTP/2

An exact H2 connection needs an HTTP/2 profile with an extended-CONNECT
pseudo-header order. `chromium::v153_http2` and `firefox::v156_http2` carry
captured orders; the custom order below is illustrative, not a browser
capture:

```rust
use phantom::profile::{chromium, ClientProfile, Http2PseudoHeader};
use phantom::{Client, HttpProtocol};

async fn h2_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut http2 = chromium::v152_http2();
    http2.extended_connect_pseudo_header_order = Some(vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Path,
        Http2PseudoHeader::Protocol,
    ]);
    let profile = ClientProfile::new(chromium::v152_tls()).with_http2(http2);
    let client = Client::builder(profile).build()?;

    let socket = client
        .websocket_with_protocol(HttpProtocol::Http2, "wss://example.com/events")?
        .connect()
        .await?;
    assert_eq!(socket.handshake_response().version(), http::Version::HTTP_2);
    Ok(())
}
```

`handshake_response` returns an `http::Response`, so comparing its version
needs the `http` crate as a direct dependency of your crate.

This succeeds only when the HTTP/2 profile configures
`extended_connect_pseudo_header_order` and the server's initial SETTINGS enables
extended CONNECT. An absent or zero setting is a terminal typed H2 error;
Phantom does not send CONNECT HEADERS or retry as H1.

## Ordered opening fields

The default H1 opening sequence contains typed placeholders for the URI authority,
fresh random key, and client cookies. When the client profile carries
`WebSocketSettings`, its H1 and H2 templates replace these defaults for every
WebSocket builder. `WebSocketHeader::caller_field` reserves the position and
spelling of a caller-supplied field, such as `User-Agent` or `Origin`, whose
value is persona or page data; an unfilled slot emits nothing.
`WebSocketRequestBuilder::header` fills the first slot with the same
case-insensitive name, keeping the slot's spelling, and otherwise appends one
literal field. `WebSocketRequestBuilder::headers` replaces the complete
sequence with `WebSocketHeader` values, allowing callers to control placement
and field-name spelling without supplying dynamic values. The requirements
below differ for H1 and H2.
Literal Upgrade, Connection, version, subprotocol, Origin, fetch metadata, and
other fields retain their caller-provided order and casing.

Validation finishes before network I/O. The sequence must contain exactly one
authority and key placeholder, one valid Upgrade field, one Connection field
containing the Upgrade token, and version 13. Literal Host and key fields are
rejected. Literal `Proxy-Authorization` is also rejected; credentials belong to
the selected proxy route so they cannot leak to a direct origin or bypass the
bounded authentication lifecycle. Literal extension fields remain forbidden so
an offer cannot diverge from the installed codec. With `websocket-deflate`, the typed
`WebSocketHeader::permessage_deflate` placeholder emits the generated offer at
the caller-selected position and field-name spelling.

The server response must be an HTTP/1.1 `101`, contain a single matching accept
value, valid Upgrade and Connection tokens, no HTTP body framing, no unsolicited
extension, and at most one offered subprotocol. Compression responses are
strictly parsed before the frame codec is installed; duplicate, malformed,
unknown, or contradictory selections fail the handshake. An ordinary non-`101` response
is available through `WebSocketError::response` with its streaming body and
ordered fields.

The H2 opening sequence is deliberately separate. The method, authority,
scheme, path, and `:protocol = websocket` pseudo-fields come from the request
and profile; ordinary fields default to lowercase `sec-websocket-version: 13`,
the typed compression placeholder when enabled, and the client-cookie
placeholder. H2 rejects authority/key placeholders, Host, Upgrade, Connection,
`Sec-WebSocket-Key`, uppercase names, and literal extension fields before I/O.
The server accepts with a 2xx response. H2 response validation rejects H1-only
Upgrade, Connection, transfer-coding, and `Sec-WebSocket-Accept` fields while
retaining the same strict subprotocol and extension checks.

## Timeouts and retries

A WebSocket connect uses the client's profile, route, trust roots, and cookie
jar, but none of its request policy. `RequestTimeouts`, `RetryPolicy`
(connection-setup retries, status retries, and reused-connection replay),
`RedirectPolicy`, client hints, and Alt-Svc do not apply to
`WebSocketRequestBuilder::connect`, and the builder has no timeout or retry
setter. A connect therefore waits as long as the network and peer allow; wrap
the `connect` future in `tokio::time::timeout` to bound it, and dropping the
future cancels the attempt. A redirect or other non-success response is
returned through `WebSocketError::response`. The only replay is the Basic
proxy-authentication retry described below.

## Messages and ownership

`WebSocket` exposes text, binary, Ping, Pong, and Close messages. Fragmented data
frames are reassembled by the engine. Client frames are masked. Incoming Ping
and Close replies are flushed before the event is yielded. The default limits
are 16 MiB per frame and 64 MiB per reassembled message, with a bounded write
buffer. One message may contain at most 131,072 data frames by default. The
initial text or binary frame and every continuation count, including empty
fragments; interleaved control frames do not. Callers can replace all three
receive bounds through a validated `WebSocketLimits` value.

Fragment-count overflow is rejected before decompression or reassembly, returns
`WebSocketErrorKind::Capacity`, and closes the transport. This prevents a peer
from replacing a byte-size attack with unbounded work over tiny or empty
frames.

`receive` is cancellation-safe. A cancelled send has normal asynchronous-write
ambiguity and must not be retried blindly. `WebSocket` implements standard
`Stream` and `Sink`, so `StreamExt::split` supports concurrent ownership without
a Phantom background task. Dropping the connection closes the transport;
`close` sends and flushes a Close frame, after which the caller may continue
receiving until the peer replies.

WebSocket connections are exclusive and are never inserted into the client's
ordinary HTTP pool. An exact H2 WebSocket uses a dedicated connection. Under a
[profile policy](#profile-connection-policy) it may instead be one stream of
a pooled H2 session; that stream carries the profile's extended-CONNECT
pseudo-header order and priority, and the session's ordinary streams keep
their own. Before sending CONNECT, the WebSocket takes the same per-origin H2
admission an ordinary request on that pool takes: it waits while the origin
is at `max_concurrent_http2_requests_per_origin` and fails with
`WebSocketErrorKind::Capacity` when the waiting bound is also full. It holds
that slot, and a lease on the session, for its whole lifetime, like a
response body; the slot is released when the WebSocket is dropped or reaches
a terminal state such as a completed close handshake. The peer's
concurrent-stream limit still applies. DATA frames
provide simultaneous reads and writes; receive-window capacity is returned as
bytes are consumed, graceful shutdown sends END_STREAM, and premature drop
resets only the CONNECT stream. There are no implicit redirects, reconnects,
heartbeats, protocol fallbacks, or direct-route fallback after a proxy failure.
The only retry is the
configured Basic proxy-authentication replay described here. A plaintext
`ws://` request through an HTTP proxy uses an RFC 6455-compatible normalized
`http://` absolute-form target and never changes to CONNECT. With Basic
credentials configured, each logical connection starts anonymously and may
replay once, on a fresh same-route connection, only after a strict `407` Basic
challenge. No challenge state is learned. Plaintext `ws://` over SOCKS5 uses
the same origin-form Upgrade as a direct connection after the proxy tunnel is
established. `socks5://` resolves the origin locally, while `socks5h://` sends
the canonical DNS name to the proxy; configured username/password
authentication applies only to SOCKS negotiation.

### H2 through proxies

An H2 `wss://` WebSocket opens a dedicated tunnel through the selected route and
then performs exact origin TLS, the HTTP/2 preface, and extended CONNECT inside
it, exactly as on a direct route. Supported routes are HTTP CONNECT through
plaintext or TLS proxies (the proxy leg speaks HTTP/1.1 by default or RFC 9113
CONNECT with `HttpProxy::with_http2_transport`), and local- or remote-DNS
SOCKS5. Configured Basic proxy credentials follow the same bounded lifecycle as
H1: an anonymous CONNECT, then at most one replay on a fresh proxy connection
after a strict `407` Basic challenge.

The origin must still advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`; without it
the connection fails with a typed H2 error before CONNECT HEADERS are sent. A
proxy rejection, SOCKS5 failure, or proxy ALPN mismatch is a terminal proxy
error and never falls back to a direct connection or to an H1 Upgrade. `ws://`
over H2 is rejected on every route before DNS, proxy, or origin I/O.

## Profile connection policy

`WebSocketSettings` on the `ClientProfile` holds ordered H1 and H2 opening
templates, the `permessage-deflate` offer, and a `WebSocketConnectionPolicy`.
`Client::websocket_with_profile_policy` applies that policy; the explicit
`websocket` and `websocket_with_protocol` builders only use the templates.
The policy is profile data, read without regard to which client it
describes:

1. `ws://` always uses an HTTP/1.1 Upgrade.
2. For `wss://`, a pooled, reusable H2 session to the same origin and route
   whose peer enabled `SETTINGS_ENABLE_CONNECT_PROTOCOL` carries the WebSocket
   as a new extended CONNECT stream. The negotiated H1/H2 pool (direct routes
   only) is consulted before the exact H2 pool. Nothing is opened to look.
3. Otherwise `without_http2_session` or `with_incapable_http2_session`
   names the new connection: `Http1Upgrade`, a TLS connection offering
   `http1_alpn_protocols` (which must offer `http/1.1` and not `h2`), or
   `Http2ExtendedConnect`, a connection with the profile's ordinary TLS offer.
   An ALPS offer whose protocol is no longer offered is dropped from the
   Upgrade connection's ClientHello; every other TLS field is unchanged.

The choice is made once, before any WebSocket bytes are sent. A rejection,
refused stream, reset, missing peer setting, or ALPN mismatch on the chosen
connection is returned as a typed error; Phantom never retries on another
connection or protocol. Because the protocol is chosen at connect time,
`headers` (a complete replacement sequence) fails before I/O under this
builder; fill template slots with `header`. With `websocket-deflate`,
`PerMessageDeflate::from_profile` enables compression with the profile's
offer.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RequestHeader};

async fn profile_policy_example() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v153_tls())
        .with_http2(chromium::v153_http2())
        .with_websocket(chromium::v153_websocket());
    let client = Client::builder(profile).build()?;

    // Fills the recipe's caller slots at their captured positions.
    let socket = client
        .websocket_with_profile_policy("wss://example.com/events")?
        .header(RequestHeader::new("User-Agent", "ExampleAgent/1.0"))
        .header(RequestHeader::new("Origin", "https://example.com"))
        .connect()
        .await?;
    println!("{:?}", socket.handshake_response().version());
    Ok(())
}
```

| Recipe | Pooled capable H2 session | No H2 session | Session without the setting |
| --- | --- | --- | --- |
| `chromium::v153_websocket` (Chrome and Edge 153) | Extended CONNECT on it | New TLS connection offering only `http/1.1`; H1 Upgrade | Same as no session |
| `firefox::v156_websocket` | Extended CONNECT on it | New connection offering `h2,http/1.1`; extended CONNECT | New TLS connection offering only `http/1.1`; H1 Upgrade |

The paired `chromium::v153_http2` and `firefox::v156_http2` recipes carry the
captured extended-CONNECT pseudo-header order and a separate
`extended_connect_priority` (Chrome exclusive on stream 0 with weight 147
instead of 256; Firefox non-exclusive on stream 0 with weight 22 instead of
42). The recipes' H1 and H2 templates reproduce the captured field order,
spelling, and fixed values; `User-Agent`, `Origin`, `Accept-Encoding`,
`Accept-Language`, and Firefox's `Sec-Fetch-Site` and
`sec-fetch-storage-access` are caller slots. Fixture tests replay every
retained capture against the recipes, and loopback tests compare Phantom's
emitted CONNECT HEADERS and H1 openings with the captures.

These recipes do not reproduce:

- HPACK representations of `:method CONNECT` and `:protocol`: Chrome sends
  both without indexing, and Firefox names `:method` and `:path` with static
  entries 3 and 5; Phantom's encoder indexes both fields and uses entries 2
  and 4. Phantom also Huffman-codes every string, where Chrome sends shorter
  raw strings such as `CONNECT` and `13` literally, and it emits no leading
  dynamic-table size update where Firefox does.
- Firefox's stream `WINDOW_UPDATE` after CONNECT HEADERS, its CONNECT on
  stream 3 of a new connection (Phantom uses stream 1), and the second H2
  connection it opens and closes when reusing a session.
- Chrome's retry of the same fields on the next stream after
  `RST_STREAM(REFUSED_STREAM)`, and its `RST_STREAM(CANCEL)` after a
  rejection or an unoffered extension.
- Firefox's uncompressed empty message: the generic send policy sets RSV1 on
  every compressed message, as Chrome does. A per-message policy needs a
  frame-engine patch.
- Chrome's variable fragmentation of large uncompressed messages, the
  always-sent compression offer (Phantom offers only when enabled), and the
  cookie field position, which no capture shows.

## Compression

The additive `websocket-deflate` feature compiles RFC 7692 support. It does not
change the wire by itself: each connection must opt in through
`WebSocketRequestBuilder::permessage_deflate`.

`PerMessageDeflate::new()` emits
`permessage-deflate; client_max_window_bits`. The typed offer API can replace
that with any RFC-valid ordered combination, including no parameters and a
bare or valued `client_max_window_bits`. Duplicate parameters and invalid
window widths fail before I/O. Callers may also configure direction-specific
context takeover, the local encoder cap, and compression level.
`WebSocket::negotiated_permessage_deflate` returns the effective server
selection.

Compression state lives in the frame engine so RSV1, fragmented data,
interleaved control frames, context takeover, UTF-8 validation, and the
decompressed message bound share one state machine. Expansion beyond
`WebSocketLimits::max_message_size` is stopped incrementally. Codec divergence
terminates the connection instead of allowing later frames to use a mismatched
dictionary. Ping, Pong, and Close frames are never compressed. Existing
tracing records logical uncompressed byte counts and never payload contents.

## How Phantom implements WebSocket

The public client is exercised against a pinned Autobahn fuzzing server. See
[Validation](../explanation/validation.md#external-suites) for how external suites are used.

Phantom owns the opening handshake. `tokio-tungstenite` is used only after a
validated `101` as the RFC 6455 frame and message engine. Its client handshake,
TLS connectors, and public types are not exposed. The pinned engine carries a
replayable narrow patch so dependency logs never contain frames or messages and
client mask entropy failure is returned as a typed error instead of panicking.
The ordered patch series also carries the compression frame state machine;
its final default-preserving patch adds the fragment-count seam used by
Phantom. Phantom continues to own the exact opening fields and response
boundary.

## Current boundary

Chrome 153 (also used for Edge 153) and Firefox 156 WebSocket recipes cover
connection choice, extended-CONNECT pseudo-header order and priority, opening
field templates, and compression offers, from the retained Windows captures
([Validation](../explanation/validation.md#websocket-browser-evidence)). The
[profile policy](#profile-connection-policy) section lists what they do not
reproduce. Codec-output parity and browser send-selection heuristics remain
capture-driven work; the generic policy compresses every text and binary
message after negotiation. There are no browser captures of WebSockets
through a proxy, so a proxied profile-policy WebSocket follows the same rules
without captured evidence for that route. Safari and H3 WebSocket remain
uncaptured, and H3 WebSocket remains unimplemented.
