# WebSocket

The optional `websocket` feature provides secure WebSocket connections over an
HTTP/1.1 Upgrade. It reuses Phantom's BoringSSL TLS profile, exact direct,
HTTP-CONNECT, or local-/remote-DNS SOCKS5 route, ordered HTTP/1 serializer, ordered
response metadata, session cookies, runtime errors, and tracing lifecycle.

The public client is exercised against a pinned Autobahn fuzzing server. See
[`external-conformance.md`](external-conformance.md#autobahn-execution) for the
smoke and scheduled-suite boundaries.

The additive `websocket-deflate` feature compiles RFC 7692 support. It does not
change the wire by itself: each connection must opt in through
`WebSocketRequestBuilder::permessage_deflate`.

Phantom owns the opening handshake. `tokio-tungstenite` is used only after a
validated `101` as the RFC 6455 frame and message engine. Its client handshake,
TLS connectors, and public types are not exposed. The pinned engine carries a
replayable narrow patch so dependency logs never contain frames or messages and
client mask entropy failure is returned as a typed error instead of panicking.
The ordered patch series also carries the compression frame state machine;
Phantom continues to own the exact opening fields and response boundary.

```rust,no_run
use futures_util::{SinkExt, StreamExt};
use phantom::{Client, WebSocketMessage};

# async fn example(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
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
# Ok(())
# }
```

## Ordered opening fields

The default opening sequence contains typed placeholders for the URI authority,
fresh random key, and session cookies. `WebSocketRequestBuilder::headers`
replaces the complete sequence with `WebSocketHeader` values, allowing callers
to control placement and field-name spelling without supplying dynamic values.
Literal Upgrade, Connection, version, subprotocol, Origin, fetch metadata, and
other fields retain their caller-provided order and casing.

Validation finishes before network I/O. The sequence must contain exactly one
authority and key placeholder, one valid Upgrade field, one Connection field
containing the Upgrade token, and version 13. Literal Host and key fields are
rejected. Literal extension fields remain forbidden so an offer cannot diverge
from the installed codec. With `websocket-deflate`, the typed
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
buffer; callers can provide a validated `WebSocketLimits` value.

`receive` is cancellation-safe. A cancelled send has normal asynchronous-write
ambiguity and must not be retried blindly. `WebSocket` implements standard
`Stream` and `Sink`, so `StreamExt::split` supports concurrent ownership without
a Phantom background task. Dropping the connection closes the transport;
`close` sends and flushes a Close frame, after which the caller may continue
receiving until the peer replies.

WebSocket connections are exclusive and are never inserted into the session's
HTTP pool. There are no implicit redirects, retries, reconnects, heartbeats, or
direct-route fallback after a proxy failure.

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
