# WebSocket fields and compression

Write your own ordered opening request for a WebSocket, open one over
HTTP/3 to a server you run, and compress its messages with
permessage-deflate. You need the optional `websocket` feature; compression
also needs `websocket-deflate`.

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

## Open a WebSocket over HTTP/3 to your own server

`Client::websocket_with_protocol` with `HttpProtocol::Http3` sends an RFC
9220 extended CONNECT to a server you control. The profile's HTTP/3 request
settings need an extended CONNECT pseudo-header order:

```rust
use phantom::profile::{chromium, ClientProfile, Http3ClientSettings, Http3PseudoHeader};
use phantom::{Client, HttpProtocol, RequestHeader};

async fn open_h3() -> Result<(), Box<dyn std::error::Error>> {
    let mut request = chromium::v154_http3_request();
    request.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    let http3 = Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        request,
    );
    let profile = ClientProfile::new(chromium::v154_tls()).with_http3(http3);
    let client = Client::builder(profile).build()?;

    let socket = client
        .websocket_with_protocol(HttpProtocol::Http3, "wss://ws.example.com/events")?
        .header(RequestHeader::new("origin", "https://example.com"))
        .connect()
        .await?;
    println!("{:?}", socket.handshake_response().version());
    Ok(())
}
```

- No browser opens a WebSocket over HTTP/3, so no recipe sets this order or
  has HTTP/3 opening fields. The order above is a choice, not a capture.
  Without an order, `connect` fails with `ProtocolUnavailable` before I/O.
- The opening starts from the built-in H2 template, `sec-websocket-version:
  13` plus the cookie and compression placeholders. `header` appends
  lowercase fields; `headers` replaces the template under the H2 rules.
- The WebSocket is a stream on the client's pooled H3 connection to the
  origin and route, shared with exact H3 requests, and holds one of the
  origin's pool slots until it ends. It runs direct, over SOCKS5, or through
  CONNECT-UDP; `ws://` and HTTP proxies fail before I/O.
- A server that does not enable extended CONNECT fails the connect with
  `WebSocketErrorKind::Http3` before a stream is sent. Nothing falls back to
  H2 or H1.

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
  Firefox 157 does. `PerMessageDeflate::from_profile` takes the offer and
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
