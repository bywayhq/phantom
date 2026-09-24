# WebSocket

Open a WebSocket over HTTP/1.1 (H1) or HTTP/2 (H2), shape its opening request
like a browser's, and compress messages. You need the optional `websocket`
feature; compression also needs `websocket-deflate`.

> For builders who have read [Getting started](../getting-started.md).

## Open a WebSocket over HTTP/1.1

`Client::websocket` sends an H1 Upgrade for `ws://` and `wss://` URLs:

```rust
use phantom::{Client, WebSocketMessage};

async fn echo(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let mut socket = client.websocket("wss://example.com/events")?.connect().await?;

    socket.send(WebSocketMessage::Text("hello".into())).await?;
    println!("{:?}", socket.receive().await?);
    socket.close(None).await?;
    Ok(())
}
```

- `WebSocket` also implements `Stream` and `Sink`; `StreamExt::split` from
  `futures-util` gives sender and receiver halves.
- `receive` is cancellation-safe. A cancelled `send` may have reached the
  wire, so do not retry it blindly.
- Phantom answers Ping and Close frames for you. After `close`, keep calling
  `receive` for the peer's reply.
- A redirect or other non-`101` response is returned through
  `WebSocketError::response`. Phantom never follows redirects, reconnects, or
  sends heartbeats.

## Open a WebSocket over HTTP/2

`Client::websocket_with_protocol` with `HttpProtocol::Http2` sends an RFC 8441
extended CONNECT on a new H2 connection. The client's profile needs an HTTP/2
recipe, such as `chromium::v154_http2`:

```rust
use phantom::{Client, HttpProtocol};

async fn open_h2(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let socket = client
        .websocket_with_protocol(HttpProtocol::Http2, "wss://example.com/events")?
        .connect()
        .await?;
    println!("{:?}", socket.handshake_response().version());
    Ok(())
}
```

- H2 accepts `wss://` only.
- The HTTP/2 settings must set `extended_connect_pseudo_header_order`, as
  `chromium::v154_http2` and `firefox::v156_http2` do.
- If the server does not enable `SETTINGS_ENABLE_CONNECT_PROTOCOL`, `connect`
  fails with a typed H2 error before sending CONNECT. There is no H1 retry.

## Open a WebSocket the way the browser does

With a WebSocket [recipe](../reference/glossary.md#recipe) on the profile,
`Client::websocket_with_profile_policy` sends the opening the way the captured
browser did, on a pooled H2 session or a new connection:

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RequestHeader};

async fn open_like_chrome() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_websocket(chromium::v154_websocket());
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

- `ws://` always uses an H1 Upgrade. For `wss://`, a pooled H2 session to
  the same origin and route whose peer enabled extended CONNECT carries the
  WebSocket as a new stream; otherwise the recipe picks the connection
  ([browser recipes](../reference/websocket.md#browser-recipes)).
- The choice is made once; a failure is never retried on another connection
  or protocol.
- `headers` fails under this builder. Fill the recipe's caller slots, such as
  `User-Agent` and `Origin`, with `header`.

## Order the opening request fields

`headers` replaces the opening request with your own ordered template of
literal fields and placeholders for values Phantom manages:

```rust
use phantom::{Client, RequestHeader, WebSocketHeader};

async fn open_ordered(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let field = |n: &str, v: &str| WebSocketHeader::field(RequestHeader::new(n, v));
    let socket = client
        .websocket("wss://example.com/events")?
        .headers(vec![
            WebSocketHeader::authority("Host"),
            field("Connection", "Upgrade"),
            field("Upgrade", "websocket"),
            WebSocketHeader::caller_field("User-Agent"),
            field("Sec-WebSocket-Version", "13"),
            WebSocketHeader::key("Sec-WebSocket-Key"),
            WebSocketHeader::client_cookies("Cookie"),
        ])
        .header(RequestHeader::new("User-Agent", "ExampleAgent/1.0"))
        .connect()
        .await?;
    println!("{:?}", socket.handshake_response().status());
    Ok(())
}
```

- Without `headers`, Phantom uses the profile's `WebSocketSettings`
  templates, or built-in ones.
- `header` fills the first `caller_field` slot of the same name (compared
  case-insensitively) in the slot's spelling, or appends. Unfilled slots emit
  nothing.
- A template that breaks the
  [opening template rules](../reference/websocket.md#opening-templates) fails
  before I/O. An H1 template needs the authority and key placeholders; an H2
  template rejects them.

## Bound a connect with a timeout

A WebSocket connect ignores the client's `RequestTimeouts`, so wrap it in
`tokio::time::timeout`. Dropping the future cancels the attempt:

```rust
use std::time::Duration;

use phantom::Client;

async fn open_within(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let connect = client.websocket("wss://example.com/events")?.connect();
    let socket = tokio::time::timeout(Duration::from_secs(10), connect).await??;
    println!("{:?}", socket.handshake_response().status());
    Ok(())
}
```

- A connect uses the client's profile, route, trust roots, and cookie jar,
  but not its `RetryPolicy`, `RedirectPolicy`, client hints, or Alt-Svc.
- Phantom resends an opening only after a `407` Basic proxy challenge, and,
  under a recipe with `refused_stream_retry` set to `SameSessionOnce` (as in
  `chromium::v154_websocket`), once after a `REFUSED_STREAM` reset on a pooled
  H2 session.

## Compress WebSocket messages

With the `websocket-deflate` feature, `permessage_deflate` offers RFC 7692
compression on one connection:

```rust
use phantom::{Client, PerMessageDeflate};

async fn open_compressed(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let socket = client
        .websocket("wss://example.com/events")?
        .permessage_deflate(PerMessageDeflate::new())
        .connect()
        .await?;
    println!("{:?}", socket.negotiated_permessage_deflate());
    Ok(())
}
```

- `new()` offers `permessage-deflate; client_max_window_bits`.
  `offer_parameters` sets any RFC-valid ordered offer.
- After negotiation every text and binary message is compressed; control
  frames never are.
- Empty messages are compressed with RSV1 set by default, as Chrome 154 and
  Edge 153 do. `compress_empty_messages(false)` sends them uncompressed, as
  Firefox 156 does. `PerMessageDeflate::from_profile` takes the offer and
  this rule from a recipe.

## Limits

- A message over the frame, message, or frame-count limit fails with
  `WebSocketErrorKind::Capacity`; set the limits with `WebSocketLimits`
  ([defaults](../reference/limits.md#websocket)).
- A `ws://` request through an HTTP/2 proxy transport fails, because an HTTP
  proxy forwards `ws://` and that transport cannot forward plaintext.
- Other unsupported route combinations fail before any I/O
  ([route matrix](../reference/route-matrix.md)). No failure falls back to a
  direct connection or to H1.
- A WebSocket on a pooled H2 session holds one of the origin's
  `max_concurrent_http2_requests_per_origin` slots for its life, and fails
  with `WebSocketErrorKind::Capacity` when the wait queue is full.
- A response with a wrong accept value, an unoffered extension, or an
  unoffered subprotocol fails the connect
  ([response checks](../reference/websocket.md#response-checks)).
- The recipes do not reproduce the browsers' HPACK encoding of CONNECT, some
  stream and reset behavior, or Chrome's message fragmentation
  ([differences](../reference/websocket.md#differences-from-the-captures)).
- No browser capture covers a proxied WebSocket.
- WebSocket over HTTP/3 is not implemented.

## Next

- [Browser profiles](profiles.md): add a WebSocket recipe to a profile.
- [Routes and proxies](routes-and-proxies.md): configure a proxy.
- [WebSocket browser evidence](../explanation/validation.md#websocket-browser-evidence):
  the captures behind the recipes.
