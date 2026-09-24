# Phantom

Phantom is a Rust HTTP client that connects the way a chosen browser does.

A server can identify a client without trusting its `User-Agent`. The TLS
handshake, the HTTP/2 settings, the order of header fields, and the QUIC
parameters of an HTTP/3 connection all differ between Chrome, Firefox, curl,
and a typical Rust library. A client that copies Chrome's headers but none of
these details is still easy to tell apart from Chrome.

Phantom reproduces these layers for each browser recipe it ships. The
browser behavior comes from recordings of real browsers, and tests compare
Phantom's output with those recordings. [Coverage](docs/reference/coverage.md)
lists which layers each recipe covers.

Phantom is an open-source project maintained by
[Byway](https://github.com/bywayhq).

> Phantom is experimental and pre-1.0. It is not on crates.io yet, and its API
> can change between commits, so pin a git revision; see
> [Adding Phantom to a project](docs/guides/downstream.md). Phantom matches
> the layers listed on this page. It does not claim to be indistinguishable
> from a browser in every respect.

## Why Phantom

Phantom matches more than the TLS handshake. Tools that match only the TLS
ClientHello can still be identified by a server that also checks HTTP/2
SETTINGS, header order, or HTTP/3. Phantom's recipes cover TCP socket
options, TLS, HTTP/1.1, HTTP/2, QUIC, HTTP/3, client hints, request fields,
and WebSocket openings.

Each built-in recipe has evidence behind it. TLS, HTTP/2, QUIC, HTTP/3,
client-hint, request-field, and WebSocket recipes come from recorded browser
traffic, and tests compare Phantom's bytes with those recordings. Where a
recording cannot show a detail, such as TCP socket options, the recipe comes
from browser source code, and the documentation says so.
[Validation](docs/explanation/validation.md) lists the evidence for each
feature.

Phantom never falls back silently. Many clients retry a failed HTTP/3
connection over HTTP/2, or a failed proxy with a direct connection. Each of
those fallbacks changes the fingerprint without telling you. Phantom uses the
protocol and route you asked for, or it returns a typed error.

Phantom keeps order. Header order is part of a fingerprint, so Phantom sends
fields, duplicates, and trailers in the order you add them, and HTTP/2
settings and pseudo-headers in the order the profile lists them. No layer
sorts, hashes, or regroups them.

State stays bounded and owned by the client. Connection pools, queues,
cookies, and caches belong to one client, and each has a size limit. Nothing
is global to the process, so a long-running service does not slowly fill
memory. Phantom's own code is safe Rust, except for one private, documented
module that calls BoringSSL's QUIC API.

## What you get

| Area | Available today |
| --- | --- |
| Protocols | HTTP/1.1, HTTP/2, and HTTP/3. Choose one exactly, let the server pick between HTTP/1.1 and HTTP/2, or opt in to Alt-Svc upgrade to HTTP/3 |
| Browsers | Chrome 154, Edge 153, Firefox 156: one version per browser, the current stable build on the capture host. [What each recipe covers](docs/guides/profiles.md#built-in-recipes) |
| Request templates | Captured navigation and `fetch` request fields for Chrome 154, Edge 153, and Firefox 156 |
| Proxies | HTTP (CONNECT and forwarding), SOCKS5, and CONNECT-UDP for HTTP/3 |
| Client state | Connection pools, redirects, retries, cookies, client hints, Alt-Svc, and TLS session reuse, each opt-in where it changes behavior |
| Streaming | Server-sent events and WebSocket |

Not yet available: racing more than one Alt-Svc alternative, and WebSocket
over HTTP/3. [Coverage](docs/reference/coverage.md) is the full list, and the
[route matrix](docs/reference/route-matrix.md) shows every protocol and proxy
combination.

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
and client hints. It always uses HTTP/2. Use `get_negotiated` instead to let
the server choose HTTP/1.1 or HTTP/2 in one handshake. Requests run inside a
Tokio runtime with I/O and timers enabled.

## Install

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>", features = ["full"] }
```

Pin an exact commit, `a84e73c` or later. Phantom builds BoringSSL from
source, so the build needs Git, CMake, Clang, and a C++ toolchain; see
[Prerequisites](docs/getting-started.md#prerequisites).

### Cargo features

No feature is enabled by default.

| Feature | Adds |
| --- | --- |
| `cookies` | A cookie jar owned by the client, with size limits |
| `sse` | Server-sent events, with a limited number of reconnects |
| `websocket` | WebSocket over HTTP/1.1 Upgrade or HTTP/2 extended CONNECT |
| `websocket-deflate` | Opt-in `permessage-deflate` compression; turns on `websocket` |
| `serde` | Serialization of saved cookie-jar snapshots, with `cookies` |
| `full` | All of the above |

## What Phantom is not

Phantom shapes network traffic only. It is not a browser: it does not run
JavaScript or emulate the DOM, rendering, canvas, fonts, WebRTC, or device
fingerprints.

Optional behavior is off by default. Redirects, retries, timeouts, cookies,
and decompression stay off until you turn them on.

Some limits are deliberate, because each keeps behavior explicit:

- A request for one protocol never downgrades to another.
- A failed proxy never falls back to a direct connection.
- Redirects are followed over HTTPS only. A client with a redirect policy
  rejects `http://` requests before it connects.
- A streaming request body is sent once and never replayed.
- WebSocket connects do not use the client's timeout, retry, or redirect
  policy.

Each guide lists the limits of its feature.

## Documentation

- [Getting started](docs/getting-started.md): build Phantom and send your
  first request.
- [Guides](docs/README.md#guides): profiles, proxies, retries, HTTP/3,
  server-sent events, WebSocket, and more.
- [Coverage](docs/reference/coverage.md): what works today and what is
  planned, layer by layer.
- [Design](docs/explanation/design.md) and
  [Validation](docs/explanation/validation.md): why Phantom works this way,
  and the evidence behind each claim.
- [Roadmap](docs/roadmap.md): what comes next.

The [documentation index](docs/README.md) lists every page.

## Minimum supported Rust version

Rust 1.88. Development uses the toolchain pinned in `rust-toolchain.toml`.

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
