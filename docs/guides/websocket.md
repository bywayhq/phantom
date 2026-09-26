# WebSocket

Open a WebSocket over HTTP/1.1 (H1) or HTTP/2 (H2), send its opening request
the way a browser does, bound the connect with a timeout, and retry a connect
that fails to open. You need the optional `websocket` feature.

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
  `WebSocketError::response`. Phantom never follows redirects, reconnects a
  closed WebSocket, or sends heartbeats.

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
- The recipe sets `Accept-Encoding` and Firefox's `Sec-Fetch-*` by
  [origin trust](../reference/websocket.md#browser-recipes); a `header` with
  the same name replaces the value.

## Bound a connect with a timeout

Limit how long one opening may take, from the first name lookup to the
server's accepting response:

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

- A WebSocket recipe carries its browser's own timer: 240 seconds in
  `chromium::v154_websocket` and 20 seconds in `firefox::v156_websocket`
  ([evidence](../explanation/validation.md#websocket-handshake-timer-evidence)).
  It applies to every connect unless you set another value;
  `handshake_timeout(None)` removes it. Without a recipe there is no limit.
- One deadline covers name resolution, proxy setup, TLS, pooled-session
  admission, the opening request, and its response, as the browsers' timers
  do. The client's `RequestTimeouts` do not apply.
- A connect uses the client's profile, route, trust roots, and cookie jar,
  but not its `RetryPolicy`, `RedirectPolicy`, client hints, or Alt-Svc.

## Retry a connect that fails to open

Open the WebSocket again when its connection failed before anything reached
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

- Retried: a failed name lookup, a failed TCP connect to the origin or
  proxy, and a SOCKS5 proxy that could not connect or resolve. Each attempt
  sends a fresh `Sec-WebSocket-Key` on the same route and protocol and gets
  its own handshake timeout.
- Never retried: TLS failures, proxy authentication or rejection, handshake
  timeouts, and any answer from the server, a `101` or `2xx` that fails the
  handshake checks included. Browsers do not retry an opening, so the
  policy is off by default and no recipe sets it.
- Phantom also resends an opening after a `407` Basic proxy challenge, and,
  under a recipe with `refused_stream_retry` set to `SameSessionOnce` (as in
  `chromium::v154_websocket`), once after a `REFUSED_STREAM` reset on a
  pooled H2 session. Neither uses the retry policy.

## Limits

- A message over the frame, message, or frame-count limit fails with
  `WebSocketErrorKind::Capacity`; set the limits with `WebSocketLimits`
  ([defaults](../reference/limits.md#websocket)).
- Other unsupported route combinations fail before any I/O
  ([route matrix](../reference/route-matrix.md)). No failure falls back to a
  direct connection or to H1.
- A WebSocket on a pooled H2 session holds one of the origin's
  `max_concurrent_http2_requests_per_origin` slots for its life, and fails
  with `WebSocketErrorKind::Capacity` when the wait queue is full.
- The recipes do not reproduce some stream and reset behavior, or Chrome's
  message fragmentation
  ([differences](../reference/websocket.md#differences-from-the-captures)).
- No browser capture covers a `wss://` WebSocket through a proxy.
- WebSocket over HTTP/3 is not implemented.

## Next

- [WebSocket fields and compression](websocket-fields.md): order the opening
  request yourself and compress messages.
- [Browser profiles](profiles.md): add a WebSocket recipe to a profile.
- [WebSocket browser evidence](../explanation/validation.md#websocket-browser-evidence):
  the captures behind the recipes.
