# Phantom

Phantom is a Rust HTTP client that connects the way a chosen browser does.

A server can tell which program sent a request without reading its
`User-Agent`. The TLS handshake, the HTTP/2 settings, the order of header
fields, and the QUIC parameters of an HTTP/3 connection all differ between
Chrome, Firefox, curl, and a typical Rust library. Copying Chrome's headers
changes none of them. [How servers recognize a client](docs/fingerprinting.md)
explains each signal in a few minutes of reading.

Phantom reproduces those layers from recordings of real browsers, and tests
compare its output with the recordings. It never falls back to another
protocol or route. Phantom is maintained by
[Byway](https://github.com/bywayhq).

> Phantom is experimental and pre-1.0. It is not on crates.io, and its API can
> change between commits, so pin a git revision. It matches the layers listed
> below, not every way a browser can be told apart.

## What Phantom matches

| Layer | Chrome 154 | Edge 153 | Brave 154 | Opera 135 | Firefox 156 | Chrome 153 for Android |
| --- | --- | --- | --- | --- | --- | --- |
| TLS ClientHello | Yes | Yes | Yes | Yes | Yes | Yes |
| HTTP/2 SETTINGS, priority, pseudo-header order | Yes | Yes | Yes | Yes | Yes | Yes |
| QUIC and HTTP/3 | Yes | Yes | Yes | Yes | Not covered | Yes |
| Client hints | Yes | Yes | Yes | Yes | Not sent by Firefox | Yes |
| Navigation and `fetch` request templates | Yes | Yes | Yes | Yes | Yes | Yes |
| WebSocket openings | Yes | Yes | Yes | Yes | Yes | Yes |
| TCP socket options, from browser source | Yes | Not covered | Not covered | Not covered | Partial: `TCP_NODELAY` only | Not covered |

Every captured recipe comes from captures of one build per browser: Windows
11 for the desktop browsers, and an Android 15 emulator for Chrome for
Android.
[Coverage](docs/reference/coverage.md) is the full support contract, and
[Validation](docs/explanation/validation.md) lists the evidence for each row.

Beyond the browser layers, the client supports:

- HTTP/1.1, HTTP/2, and HTTP/3, each chosen exactly, or HTTP/1.1 and HTTP/2
  negotiated in one handshake, with opt-in Alt-Svc upgrade to HTTP/3;
- direct connections, HTTP proxies (CONNECT and forwarding), SOCKS5, and
  CONNECT-UDP for HTTP/3; the [route matrix](docs/reference/route-matrix.md)
  lists every combination;
- connection pools, redirects, retries, cookies, and TLS session reuse, all
  owned by one client and bounded in size;
- server-sent events and WebSocket.

Not yet available: racing more than one Alt-Svc alternative, and WebSocket
over HTTP/3.

## Quick look

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RequestHeader};

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());

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

To the server, this request has Chrome 154's TLS handshake, HTTP/2 settings,
and client hints. It always uses HTTP/2; `get_negotiated` lets the server
choose HTTP/1.1 or HTTP/2 instead. Requests run inside a Tokio runtime with
I/O and timers enabled.

## Install

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>", features = ["full"] }
```

Pin an exact commit, `be02e93` or later; earlier commits lack the Chrome 154
recipes used on this page. The documentation describes the commit it ships
with; [CHANGELOG.md](CHANGELOG.md) lists what changes between commits. The
minimum supported Rust version is 1.88; development uses the toolchain in
`rust-toolchain.toml`. Phantom
builds BoringSSL from source, so the build needs Git, CMake, Clang, and a
C++ toolchain; see [Prerequisites](docs/getting-started.md#prerequisites).

No Cargo feature is enabled by default:

| Feature | Adds |
| --- | --- |
| `cookies` | A cookie jar owned by the client, with size limits |
| `https-records` | HTTP/3 discovery from HTTPS DNS records, and, with the Chrome 154, Edge 153, and Brave 154 recipes, Encrypted Client Hello from them with a TLS handshake wait of at most 50 ms; adds the `hickory-resolver` dependency |
| `sse` | Server-sent events, with a limited number of reconnects |
| `websocket` | WebSocket over HTTP/1.1 Upgrade or HTTP/2 extended CONNECT |
| `websocket-deflate` | Opt-in `permessage-deflate` compression; turns on `websocket` |
| `serde` | Serialization of saved cookie-jar snapshots, with `cookies` |
| `full` | All of the above |
| `diagnostics` | TLS key logging and QUIC qlog files, for debugging your own connections; not part of `full` |

## What Phantom is not

Phantom shapes network traffic only and is not a browser;
[Coverage](docs/reference/coverage.md#at-a-glance) lists what it leaves out. Optional
behavior such as redirects, retries, timeouts, cookies, and decompression
stays off until you turn it on. [Why Phantom](docs/why-phantom.md#when-not-to-use-phantom)
lists the cases where another tool fits better.

## Where to go next

- Evaluate: [Why Phantom](docs/why-phantom.md) and
  [Coverage](docs/reference/coverage.md).
- Build: [Getting started](docs/getting-started.md), then the
  [documentation index](docs/README.md).
- Contribute: [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [roadmap](docs/roadmap.md).

Coding agents should read [`llms.txt`](llms.txt) first.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request. Report
a suspected vulnerability privately as described in [SECURITY.md](SECURITY.md),
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
