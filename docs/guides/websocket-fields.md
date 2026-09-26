# WebSocket fields and compression

Write your own ordered opening request for a WebSocket, and compress its
messages with permessage-deflate. You need the optional `websocket` feature;
compression also needs `websocket-deflate`.

> For builders who have read [WebSocket](websocket.md).

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
  Edge 154 do. `compress_empty_messages(false)` sends them uncompressed, as
  Firefox 156 does. `PerMessageDeflate::from_profile` takes the offer and
  this rule from a recipe.

## Limits

- A response with a wrong accept value, an unoffered extension, or an
  unoffered subprotocol fails the connect
  ([response checks](../reference/websocket.md#response-checks)).
- Phantom offers no WebSocket extension other than permessage-deflate.

## Next

- [WebSocket reference](../reference/websocket.md): opening templates,
  response checks, and compression rules.
- [Browser profiles](profiles.md): add a WebSocket recipe to a profile.
