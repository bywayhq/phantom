# WebSocket

The optional `websocket` feature provides exact HTTP/1.1 Upgrade and
[RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html) HTTP/2 extended CONNECT
connections. `Client::websocket` remains the HTTP/1.1
shorthand; `Client::websocket_with_protocol` selects an exact protocol without
fallback. H2 accepts `wss://` only, over direct and proxy routes, and requires
an explicit five-field extended-CONNECT pseudo-header order in the HTTP/2
profile. Named browser profiles leave that order unset until browser captures
prove it.

For H1, direct routes accept plaintext `ws://` or TLS-backed `wss://`;
HTTP forward proxies accept plaintext `ws://` over either plaintext or
independently authenticated proxy TLS. Local- and remote-DNS SOCKS5 routes
accept both `ws://` and `wss://`; HTTP-CONNECT routes accept `wss://`,
including through an HTTPS proxy reached over HTTP/2
(`HttpProxy::with_http2_transport`). That proxy transport cannot forward
plaintext requests, so H1 `ws://` through it fails before proxy I/O instead of
switching to CONNECT or HTTP/1.1. The
[combination table](client.md#supported-scheme-protocol-and-route-combinations)
summarizes every scheme, protocol, and route.
Secure connections reuse Phantom's BoringSSL TLS profile. Both transports reuse
the ordered HTTP/1 serializer, ordered response metadata, client cookies,
runtime errors, and tracing lifecycle.

The public client is exercised against a pinned Autobahn fuzzing server. See
[Validation](validation.md#external-suites) for how external suites are used.

The additive `websocket-deflate` feature compiles RFC 7692 support. It does not
change the wire by itself: each connection must opt in through
`WebSocketRequestBuilder::permessage_deflate`.

Phantom owns the opening handshake. `tokio-tungstenite` is used only after a
validated `101` as the RFC 6455 frame and message engine. Its client handshake,
TLS connectors, and public types are not exposed. The pinned engine carries a
replayable narrow patch so dependency logs never contain frames or messages and
client mask entropy failure is returned as a typed error instead of panicking.
The ordered patch series also carries the compression frame state machine;
its final default-preserving patch adds the fragment-count seam used by
Phantom. Phantom continues to own the exact opening fields and response
boundary.

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

An H2 connection is explicit, and needs a custom HTTP/2 profile because named
recipes leave the extended-CONNECT pseudo-header order unset. The order below
is illustrative, not a browser capture:

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
fresh random key, and client cookies. `WebSocketRequestBuilder::header` appends
one literal field, and `WebSocketRequestBuilder::headers` replaces the complete
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
ordinary HTTP pool. An H2 WebSocket uses a dedicated connection so its exact
five-field pseudo-header order cannot alter ordinary H2 traffic. DATA frames
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

## Compression

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

## Current boundary

This slice does not claim a Chrome, Firefox, or Safari WebSocket header recipe.
Callers can reproduce retained ordered handshake fields and compression-offer
parameters through the public typed templates. Named compression recipes,
codec-output parity, and browser send-selection heuristics remain
capture-driven profile work; the generic policy compresses every text and
binary message after negotiation. H2 extended CONNECT is available for
explicitly configured custom profiles, over direct and proxy routes, with
deterministic standards-level fixtures. It is not yet populated in named
recipes, and there are no browser captures of H2 WebSockets through a proxy.

Retained Chrome 153, Edge 153, and Firefox 156 Windows captures
([Validation](validation.md#websocket-browser-evidence)) record extended-CONNECT
field order, HPACK representations, priority, deflate offers, per-message RSV1
and fragmentation, and reactions to `403`, refused streams, and unoffered
extensions. Chromium opens H2 WebSockets only on an existing session that
advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`; otherwise it opens a new
connection offering only `http/1.1`. Firefox also opens fresh H2 connections.
Phantom's dedicated-connection H2 WebSocket therefore does not reproduce
Chromium's connection choice. Safari and H3 WebSocket remain uncaptured, and H3
WebSocket remains unimplemented.
