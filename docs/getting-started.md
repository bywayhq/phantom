# Getting started

This guide is for Rust developers evaluating Phantom for the first time. It
covers a source build and one explicit HTTP/2 request. Broader configuration is
in [Using the client](client.md).

## Build from source

Phantom is not published to crates.io. The workspace pins its development
toolchain and declares Rust 1.85 as its minimum supported Rust version.

```console
git clone https://github.com/bywayhq/phantom.git
cd phantom
cargo build --workspace --all-features --locked
```

## Send a request

A profile describes observable wire behavior. A client owns that profile,
connection pools, and any enabled cross-request state.

```rust,no_run
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RequestHeader};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let profile = ClientProfile::new(chromium::v152_macos_tls())
    .with_http2(chromium::v152_macos_http2())
    .with_client_hints(chromium::v152_macos_client_hints());

let client = Client::builder(profile).build()?;
let response = client
    .get(HttpProtocol::Http2, "https://example.com/")?
    .header(RequestHeader::new("accept", "*/*"))
    .send()
    .await?;

println!("{}", response.status());
# Ok(())
# }
```

`get(HttpProtocol::Http2, ...)` selects exactly HTTP/2. It does not fall back.
Use `get_negotiated` for one direct TLS handshake that may select H1 or H2.
HTTP/3 requires the profile's separate H3 TLS, QUIC, HTTP/3, and request
settings.

## Optional features

| Feature | Adds |
| --- | --- |
| `cookies` | Bounded client-owned cookie storage |
| `sse` | SSE decoding and finite reconnect control |
| `websocket` | WebSocket over an ordered H1 Upgrade |
| `websocket-deflate` | Opt-in `permessage-deflate`; also enables `websocket` |
| `full` | All capabilities above |

Next, read [Using the client](client.md). Check [Coverage](coverage.md) before
depending on a protocol, route, or browser profile in production-like work.
