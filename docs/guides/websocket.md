# WebSocket

Open a WebSocket, send and receive messages, and open it the way Chrome or
Firefox does. Turn on the `websocket` Cargo feature first.

## Open a WebSocket over HTTP/1.1

`Client::websocket` opens a WebSocket for a `ws://` or `wss://` URL with an
HTTP/1.1 Upgrade request:

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

- `WebSocket` also implements `Stream` and `Sink`. `StreamExt::split` from
  `futures-util` gives you sender and receiver halves.
- Phantom answers Ping and Close frames for you. After `close`, keep calling
  `receive` to read the server's reply.
- A redirect, or any response other than `101`, comes back in
  `WebSocketError::response`. Phantom doesn't follow redirects or reconnect.
- `receive` is cancellation-safe. A cancelled `send` may already have
  reached the server, so don't resend it blindly.

## Open a WebSocket over HTTP/2

`Client::websocket_with_protocol` with `HttpProtocol::Http2` opens the
WebSocket as a stream on a new HTTP/2 connection. It uses extended CONNECT
(RFC 8441), a CONNECT request that names the WebSocket protocol. The
profile's HTTP/2 settings must set `extended_connect_pseudo_header_order`,
as `chromium::v154_http2` and `firefox::v157_http2` do:

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

HTTP/2 works with `wss://` URLs only. The server must enable extended
CONNECT in its HTTP/2 settings. If it doesn't, `connect` fails without
trying HTTP/1.1.

## Open a WebSocket the way the browser does

A recipe is Phantom's copy of one browser's network settings. With a
WebSocket recipe on the profile, `Client::websocket_with_profile_policy`
opens the WebSocket as that browser would. It sends the browser's headers in
the browser's order, and picks the connection the browser would use:

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RequestHeader};

async fn open_like_chrome() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_websocket(chromium::v154_websocket());
    let client = Client::builder(profile).build()?;

    // Fills the recipe's slots for these headers, in the browser's order.
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

- `ws://` always uses HTTP/1.1.
- For `wss://`, an HTTP/2 connection the client already has open to the
  server carries the WebSocket, if the server allows it. Otherwise the
  recipe picks a new connection
  ([recipes](../reference/websocket.md#browser-recipes)).
- Phantom picks the connection once and doesn't retry on another.

Set headers such as `User-Agent` and `Origin` with `header`. Calling
`headers` on this builder fails.

## Bound a connect with a timeout

Limit how long opening a WebSocket may take, from the first name lookup to
the server's reply:

```rust
use std::time::Duration;

use phantom::{Client, TimeoutPhase, WebSocketErrorKind};

async fn open_within(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let result = client
        .websocket("wss://example.com/events")?
        .handshake_timeout(Some(Duration::from_secs(10)))
        .connect()
        .await;
    match result {
        Ok(socket) => println!("{:?}", socket.handshake_response().status()),
        Err(error) if error.kind() == WebSocketErrorKind::Timeout => {
            assert_eq!(error.timeout_phase(), Some(TimeoutPhase::WebSocketHandshake));
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
```

- A WebSocket recipe sets its browser's limit: 240 seconds in
  `chromium::v154_websocket` and 20 seconds in `firefox::v157_websocket`.
- Without a recipe there is no limit. `handshake_timeout(None)` removes a
  recipe's limit.

The client's `RequestTimeouts`, `RetryPolicy`, and `RedirectPolicy` don't
apply to a WebSocket.

## Retry a connect that fails to open

Open the WebSocket again when the connection failed before anything reached
the server:

```rust
use std::{num::NonZeroUsize, time::Duration};

use phantom::{Client, WebSocketRetryPolicy};

async fn open_with_retry(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let retries = WebSocketRetryPolicy::connection_failures(
        NonZeroUsize::new(2).expect("two is nonzero"),
        Duration::from_millis(500),
    );
    let socket = client
        .websocket("wss://example.com/events")?
        .retry_policy(retries)
        .connect()
        .await?;
    println!("{:?}", socket.handshake_response().status());
    Ok(())
}
```

- Phantom retries a failed name lookup, a failed TCP connect to the server
  or proxy, and a SOCKS5 proxy that couldn't reach the server.
- Each attempt sends a new `Sec-WebSocket-Key` and gets its own timeout.
- TLS failures, proxy rejections, timeouts, and any answer from the server
  are not retried.
- Browsers don't retry an opening, so the policy is off by default and no
  recipe turns it on.

## Limits

- A message over the size limits fails. Set them with `WebSocketLimits`
  ([defaults](../reference/limits.md#websocket)).
- A WebSocket on a shared HTTP/2 connection holds one of the server's
  request slots while it's open.
- The recipes don't reproduce some of the browsers' stream and reset
  behavior, or Chrome's message fragmentation
  ([differences](../reference/websocket.md#differences-from-the-captures)).

## Next

- [WebSocket fields and compression](websocket-fields.md): order the
  opening headers yourself, use HTTP/3, and compress messages.
- [Browser profiles](profiles.md): add a WebSocket recipe to a profile.
- [WebSocket reference](../reference/websocket.md): routes, templates, and
  recipes.
