# Getting started

This tutorial takes you from a fresh checkout to one HTTP/2 request that uses a
Chrome profile. It takes about fifteen minutes, most of it the first native
build. When you finish, continue with [Using the client](guides/client.md).

## Distribution status

Phantom is pre-1.0 and not yet published to crates.io. The public interface is
not stable and may change between commits.

- Depend on it through an exact git revision or a pinned checkout, with one
  dependency line and no `[patch]` table. See
  [Adding Phantom to a project](guides/downstream.md).
- The package is named `phantom-http`; the library crate is `phantom`.
- Phantom is dual-licensed under MIT or Apache-2.0. Vendored dependencies keep
  their upstream licenses in `vendor/*/`.

## Prerequisites

- The pinned Rust toolchain from `rust-toolchain.toml`. The minimum supported
  Rust version (MSRV) is 1.88.
- Git, CMake, Clang, and a C++ toolchain for the native BoringSSL build.
  Windows also requires NASM and Visual C++ build tools; see
  [CONTRIBUTING.md](../CONTRIBUTING.md#windows) for install commands.
- A Tokio 1.x runtime with network I/O and timers enabled.

The platform checks in [CI](../.github/workflows/ci.yml) are the source of truth
for native build prerequisites.

## 1. Build from source

```console
git clone https://github.com/bywayhq/phantom.git
cd phantom
cargo build -p phantom-http --all-features --locked
```

Build and open the API reference locally with:

```console
cargo doc -p phantom-http --all-features --no-deps --open
```

## 2. Send a request

A profile describes observable wire behavior. A client owns that profile, its
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

What each step does:

1. `ClientProfile::new(chromium::v152_tls())` starts from Chrome 152's TLS
   ClientHello.
2. `with_http2` adds Chrome 152's HTTP/2 settings, and `with_client_hints`
   adds its client-hint fields.
3. `Client::builder(profile).build()` creates a client. Build it once and
   clone it; clones share pools and state.
4. `get(HttpProtocol::Http2, ...)` selects exactly HTTP/2. It does not fall
   back to another protocol.
5. `header` adds one request field. Phantom keeps fields in the order you add
   them.

## 3. Run it inside Tokio

The function must run inside a Tokio runtime. If you construct the runtime
manually, enable both I/O and time; otherwise requests fail with
`RequestErrorKind::RuntimeUnavailable` or the runtime reports disabled timers.

## Next steps

- Let the server choose the protocol: `get_negotiated` performs one direct TLS
  handshake that may select H1 or H2.
- Use HTTP/3: see [HTTP/3 and Alt-Svc](guides/http3.md).
- Pick a different browser: see [Browser profiles](guides/profiles.md).
- Configure timeouts, retries, and responses: see
  [Using the client](guides/client.md).
- Check [Coverage](reference/coverage.md) before depending on a protocol,
  route, or browser profile in production-like work.

## Optional features

No feature is enabled by default.

| Feature | Adds |
| --- | --- |
| `cookies` | Bounded client-owned cookie storage |
| `sse` | SSE decoding and finite reconnect control |
| `websocket` | WebSocket over an ordered H1 Upgrade, or H2 extended CONNECT with an HTTP/2 profile that sets its pseudo-header order |
| `websocket-deflate` | Opt-in `permessage-deflate`; also enables `websocket` |
| `full` | All capabilities above |

The QUIC diagnostics features, `qlog` on `phantom-net` and `keylog` on
`phantom-quic-btls`, belong to internal crates used by capture tooling and
tests. `phantom-http` does not re-export them or any API to enable them.
