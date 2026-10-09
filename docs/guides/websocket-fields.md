# WebSocket fields and compression

Write your own ordered opening request for a WebSocket, open one over
HTTP/3 to a server you run, and compress its messages. Turn on the
`websocket` Cargo feature. Compression also needs `websocket-deflate`.

## Order the opening request headers

`headers` replaces the opening request with your own list, in order. The
list mixes literal headers with placeholders for values Phantom fills in,
such as the host, the random key, and cookies:

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

- Without `headers`, Phantom uses the profile's templates, or built-in ones.
- `header` fills the first `caller_field` slot with the same name, ignoring
  case. With no matching slot, it adds the header at the end.
- A slot you don't fill sends nothing.

An HTTP/1.1 list needs the host and key placeholders, and an HTTP/2 list
must leave them out. The
[opening template rules](../reference/websocket.md#opening-templates) list
the rest.

## Open a WebSocket over HTTP/3 to your own server

`Client::websocket_with_protocol` with `HttpProtocol::Http3` opens a
WebSocket over HTTP/3. It uses extended CONNECT (RFC 9220), a CONNECT
request that names the WebSocket protocol. Browsers don't open WebSockets
this way, so no recipe sets it up. Set the pseudo-header order in the
profile's HTTP/3 request settings yourself:

```rust
use phantom::profile::{ClientProfile, Http3ClientSettings, Http3PseudoHeader, browser::chrome};
use phantom::{Client, HttpProtocol, RequestHeader};

async fn open_h3() -> Result<(), Box<dyn std::error::Error>> {
    let mut request = chrome::v154_http3_request();
    request.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    let http3 = Http3ClientSettings::new(
        chrome::v154_quic_tls(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        request,
    );
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http3(http3);
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

- The order above is an example. Use the one your server expects.
- The WebSocket is a stream on the client's HTTP/3 connection to the
  server, shared with your other HTTP/3 requests.
- It works directly, through SOCKS5, or through CONNECT-UDP, for `wss://`
  URLs.
- The server must enable extended CONNECT.

`header` adds a header at the end, and its name must be lowercase.

## Compress WebSocket messages

With the `websocket-deflate` feature, `permessage_deflate` offers
permessage-deflate compression (RFC 7692) on one connection:

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
  `offer_parameters` sets another offer.
- Once the server accepts, every text and binary message is compressed.
- Empty messages are compressed by default, as in Chrome 154 and Edge 154.
  `compress_empty_messages(false)` sends them uncompressed, as in Firefox
  157.
- `PerMessageDeflate::from_profile` copies the offer and the empty-message
  rule from a recipe.

## Limits

- A response with a wrong accept value, or with an extension or
  subprotocol you didn't offer, fails the connect
  ([response checks](../reference/websocket.md#response-checks)).
- permessage-deflate is the only extension Phantom offers.

## Next

- [WebSocket reference](../reference/websocket.md): opening templates,
  response checks, and compression rules.
- [Browser profiles](profiles.md): add a WebSocket recipe to a profile.
