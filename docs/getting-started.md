# Getting started

This guide is for Rust developers evaluating Phantom for the first time. It
covers a source build and one explicit HTTP/2 request. Broader configuration is
in [Using the client](client.md).

## Distribution status

Phantom is not yet published to crates.io. Another workspace can depend on an
exact git revision or a pinned checkout with one dependency line and no
`[patch]` table; see [Downstream integration](downstream.md). The public
interface is not stable. Phantom is dual-licensed under MIT or Apache-2.0;
vendored dependencies keep their upstream licenses in `vendor/*/`.

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
cargo build -p phantom-http --all-features --locked
```

Build and open the API reference locally with:

```console
cargo doc -p phantom-http --all-features --no-deps --open
```

## Send a request

A profile describes observable wire behavior. A client owns that profile,
connection pools, and any enabled cross-request state.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RequestHeader};

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v152_tls())
        .with_http2(chromium::v152_http2())
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

HTTP/3 requires the profile's separate H3 TLS, QUIC transport, HTTP/3
connection, and request settings, grouped as `Http3ClientSettings`:

```rust
use phantom::profile::{chromium, ClientProfile, Http3ClientSettings};
use phantom::{Client, HttpProtocol};

async fn run_h3() -> Result<(), Box<dyn std::error::Error>> {
    let http3 = Http3ClientSettings::new(
        chromium::v152_http3_tls(),
        chromium::v152_quic(),
        chromium::v152_http3(),
        chromium::v152_http3_request(),
    );
    let profile = ClientProfile::new(chromium::v152_tls()).with_http3(http3);

    let client = Client::builder(profile).build()?;
    let response = client
        .get(HttpProtocol::Http3, "https://example.com/")?
        .send()
        .await?;
    println!("{}", response.status());
    Ok(())
}
```

The TCP TLS settings passed to `ClientProfile::new` stay separate from the H3
TLS settings; each protocol uses only its own.

The snippet must run inside a Tokio runtime. If you construct the runtime
manually, enable both I/O and time; otherwise requests fail with
`RequestErrorKind::RuntimeUnavailable` or the runtime reports disabled timers.

## Optional features

| Feature | Adds |
| --- | --- |
| `cookies` | Bounded client-owned cookie storage |
| `sse` | SSE decoding and finite reconnect control |
| `websocket` | WebSocket over an ordered H1 Upgrade, or H2 extended CONNECT with a custom HTTP/2 profile |
| `websocket-deflate` | Opt-in `permessage-deflate`; also enables `websocket` |
| `full` | All capabilities above |

The QUIC diagnostics features, `qlog` on `phantom-net` and `keylog` on
`phantom-quic-btls`, belong to internal crates used by capture tooling and
tests. `phantom-http` does not re-export them or any API to enable them.

Next, read [Using the client](client.md). Check [Coverage](coverage.md) before
depending on a protocol, route, or browser profile in production-like work.
