# Phantom

Phantom is a Rust HTTP client that connects the way a real browser does.

Servers can tell which program is talking to them without reading the
`User-Agent` header. The TLS handshake, the HTTP/2 settings, the order of
headers and the HTTP/3 parameters all differ between Chrome, Firefox, curl
and a typical Rust library, and copying Chrome's headers changes none of
them. Phantom sends all of these the way the browser you pick does.
[How servers recognize a client](docs/fingerprinting.md) explains the
signals.

> Phantom is pre-1.0 and not on crates.io yet. The API can change between
> commits, so pin a git revision.

## Browsers

Phantom includes the network settings of desktop Chrome 154, Edge 154,
Brave 154, Opera 136 and Firefox 157. Each set is called a *recipe*. A
recipe matches the browser's:

- TLS handshake;
- HTTP/2 and HTTP/3 settings;
- headers for a page load and a `fetch`, in the browser's order;
- client hints (Chromium-based browsers; Firefox sends none);
- WebSocket handshake.

There are also Android recipes for Chrome, Edge, Brave, Opera and Firefox,
which cover less. Each recipe is recorded from the real browser and tested
against that recording. [Coverage](docs/reference/coverage.md#at-a-glance)
lists what each one matches and its known gaps.

## Example

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>" }
tokio = { version = "1", features = ["full"] }
```

```rust,no_run
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;

    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .send()
        .await?;
    println!("{}", response.status());
    Ok(())
}
```

This prints `200 OK`, and the server sees Chrome 154's TLS handshake,
HTTP/2 settings and client hints. You pick the protocol for each request;
`get_negotiated` lets the server choose between HTTP/1.1 and HTTP/2.

To compare Phantom with your browser yourself, request
`https://tls.peet.ws/api/all` (a third-party service) from both and diff the
results.

## What else it does

- HTTP/1.1, HTTP/2 and HTTP/3.
- Proxies: HTTP, SOCKS5, and CONNECT-UDP for HTTP/3.
- Connection pooling and TLS session reuse.
- Redirects, retries, timeouts, cookies and decompression, each off until
  you turn it on.
- Server-sent events and WebSocket.

## Install

Use commit `be02e93` or later, and Rust 1.88 or newer. Phantom builds
BoringSSL from source, so you also need Git, CMake, Clang and a C++
compiler ([Prerequisites](docs/getting-started.md#prerequisites)).

No feature is on by default:

| Feature | Adds |
| --- | --- |
| `cookies` | A cookie jar |
| `https-records` | Finding HTTP/3 servers and ECH keys through DNS |
| `sse` | Server-sent events |
| `websocket` | WebSocket |
| `websocket-deflate` | WebSocket compression |
| `serde` | Saving and loading cookie jars |
| `full` | All of the above |
| `diagnostics` | TLS key logs and QUIC qlog files for debugging; not in `full` |
| `danger-disable-verification` | Turning off certificate checks, for testing only; not in `full` |

## What Phantom is not

Phantom only shapes network traffic. It does not run JavaScript or render
pages. [Why Phantom](docs/why-phantom.md#when-not-to-use-phantom) lists the
cases where another tool fits better.

## Where to go next

- Learn more: [Why Phantom](docs/why-phantom.md) and
  [Coverage](docs/reference/coverage.md).
- Start building: [Getting started](docs/getting-started.md), then the
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
