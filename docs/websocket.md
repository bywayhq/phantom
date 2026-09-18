# WebSocket

The optional `websocket` feature provides WebSocket connections over an
HTTP/1.1 Upgrade. Direct routes accept plaintext `ws://` or TLS-backed `wss://`;
HTTP forward proxies accept plaintext `ws://` over either plaintext or
independently authenticated proxy TLS. Local- and remote-DNS SOCKS5 routes
accept both `ws://` and `wss://`; HTTP-CONNECT routes accept `wss://`.
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

## Ordered opening fields

The default opening sequence contains typed placeholders for the URI authority,
fresh random key, and client cookies. `WebSocketRequestBuilder::headers`
replaces the complete sequence with `WebSocketHeader` values, allowing callers
to control placement and field-name spelling without supplying dynamic values.
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
HTTP pool. There are no implicit redirects, reconnects, heartbeats, protocol
fallbacks, or direct-route fallback after a proxy failure. The only retry is the
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
binary message after negotiation. H2 extended CONNECT and H3 WebSocket require
browser captures and protocol-reaction differentials before they become
profile data.
