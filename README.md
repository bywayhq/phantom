# Phantom

**A Rust HTTP client whose TLS, HTTP/2, QUIC, and HTTP/3 behavior matches
captured browsers.**

Phantom lets an application choose exactly what a server observes on the
wire. Browser behavior lives in typed, validated profiles built from real
browser captures, not in hidden transport branches. Phantom is an open-source
project maintained by [Byway](https://github.com/bywayhq).

> **Status: experimental, pre-1.0.** Phantom is not yet published to
> crates.io, and its API may change between commits. Depend on a pinned git
> revision; see [Adding Phantom to a project](docs/guides/downstream.md).
> Phantom does not claim complete browser impersonation.

## What Phantom is

A matching TLS ClientHello is only one part of a client's wire identity. HTTP
settings, header order, QUIC parameters, connection reuse, and cross-request
state are observable too. Phantom treats captured wire behavior as the
specification:

- **Profiles** control concrete TLS, HTTP/2, HTTP/3, QUIC, and client-hint
  behavior.
- **Order is preserved**: request fields, duplicates, pseudo-headers,
  trailers, and settings are sent in the order you give them.
- **No silent fallback**: a request uses the protocol and route you chose, or
  fails with a typed error.
- **Bounded state**: pools, queues, and caches are client-owned and finite.
- **Evidence-backed claims**: each compatibility claim names the captured
  layer and the test that compares it.

## What Phantom is not

- Not a browser engine. It does not emulate the DOM, JavaScript, rendering,
  canvas, fonts, WebRTC, or device fingerprints.
- Not a general-purpose client with automatic fallbacks. Redirects, retry
  policies, timeouts, cookies, and decompression are off until you enable
  them.

## Installation

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>", features = ["full"] }
```

Pin an exact commit. The native BoringSSL build needs Git, CMake, Clang, and a
C++ toolchain; see [Getting started](docs/getting-started.md#prerequisites).

## Example

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

This request uses exactly HTTP/2 with Chrome 152's TLS and HTTP/2 settings.
`get_negotiated` instead lets one TLS handshake choose HTTP/1.1 or HTTP/2.
Requests run inside a Tokio runtime with I/O and timers enabled.

## Cargo features

No feature is enabled by default.

| Feature | Adds |
| --- | --- |
| `cookies` | Bounded client-owned cookie jar |
| `sse` | Server-sent event decoding and bounded reconnects |
| `websocket` | WebSocket over HTTP/1.1 Upgrade or HTTP/2 extended CONNECT |
| `websocket-deflate` | Opt-in `permessage-deflate`; implies `websocket` |
| `full` | All of the above |

## Support at a glance

| Area | Supported today |
| --- | --- |
| Protocols | HTTP/1.1, HTTP/2, and HTTP/3, each selectable exactly; negotiated HTTP/1.1 or HTTP/2; opt-in Alt-Svc upgrade to HTTP/3 |
| Browser recipes | Chrome 152 and 153, Edge 153, Firefox 154 and 156, Safari 18.5 TLS ([details](docs/guides/profiles.md#built-in-recipes)) |
| Routes | Direct, HTTP proxy (CONNECT and forwarding), SOCKS5, and CONNECT-UDP for HTTP/3 |
| Client state | Pools, opt-in redirects, retries, cookies, client hints, Alt-Svc, and TLS sessions |
| Optional APIs | Server-sent events and WebSocket |

Not yet implemented: Alt-Svc connection racing and WebSocket over HTTP/3.
[Coverage](docs/reference/coverage.md) is the detailed support contract, and
the [route matrix](docs/reference/route-matrix.md) lists every protocol and
route combination.

## Deliberate limits

- Exact-protocol requests never downgrade, and proxy failure never falls back
  to a direct connection.
- Redirect following is HTTPS-only. A client with a redirect policy rejects
  `http://` requests before any I/O.
- Streaming request bodies are one-shot and are never replayed.
- WebSocket connects do not apply the client's timeout, retry, or redirect
  policy.

These limits make Phantom narrower than a general-purpose client but keep its
behavior explicit and testable. Each guide lists the limits of its feature.

## Documentation

- [Getting started](docs/getting-started.md): first build and request.
- [Guides](docs/README.md#guides): client, profiles, proxies, retries,
  HTTP/3, SSE, WebSocket, and more.
- [Coverage](docs/reference/coverage.md): what is supported and planned.
- [Design](docs/explanation/design.md) and
  [Validation](docs/explanation/validation.md): why Phantom works this way and
  how claims are proved.
- [Roadmap](docs/roadmap.md): current and planned work.

The [documentation index](docs/README.md) lists every page.

## Minimum supported Rust version

Phantom's MSRV is Rust 1.85. Development uses the toolchain pinned in
`rust-toolchain.toml`.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report
suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
not in a public issue.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

Vendored dependencies under [`vendor/`](vendor/) keep their upstream licenses
and license files.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Phantom by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
