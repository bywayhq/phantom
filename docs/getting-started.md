# Getting started

This guide is for Rust developers evaluating Phantom for the first time. It
covers a source build and one explicit HTTP/2 request. Broader configuration is
in [Using the client](client.md).

## Distribution status

Phantom is not published to crates.io, and `phantom` has `publish = false`.
There is no supported `cargo add phantom` or downstream git-dependency path yet:
the workspace relies on root-level Cargo patches, and Cargo ignores patch tables
declared by dependencies.

The supported evaluation path is this repository checkout. Embedding Phantom in
another workspace currently means carrying its complete pinned dependency and
patch set; that interface is not stable. The repository also does not yet
declare a license, so integrators should resolve licensing with the maintainers
before redistribution.

## Prerequisites

- The pinned Rust toolchain from `rust-toolchain.toml`. The declared MSRV is
  Rust 1.85.
- Git, CMake, Clang, and a C++ toolchain for the native BoringSSL build. Windows
  also requires NASM and Visual C++ build tools.
- A Tokio 1.x runtime with network I/O and timers enabled for requests.

The platform checks in [CI](../.github/workflows/ci.yml) are the source of truth
for native build prerequisites.

## Build from source

```console
git clone https://github.com/bywayhq/phantom.git
cd phantom
cargo build -p phantom --all-features --locked
```

Build and open the API reference locally with:

```console
cargo doc -p phantom --all-features --no-deps --open
```

## Send a request

A profile describes observable wire behavior. A client owns that profile,
connection pools, and any enabled cross-request state.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RequestHeader};

async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}
```

`get(HttpProtocol::Http2, ...)` selects exactly HTTP/2. It does not fall back.
Use `get_negotiated` for one direct TLS handshake that may select H1 or H2.
HTTP/3 requires the profile's separate H3 TLS, QUIC, HTTP/3, and request
settings.

The snippet must run inside a Tokio runtime. If you construct the runtime
manually, enable both I/O and time; otherwise requests fail with
`RequestErrorKind::RuntimeUnavailable` or the runtime reports disabled timers.

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
