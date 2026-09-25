# Getting started

In this tutorial you create a Rust project, send one HTTP/2 request with
Chrome 154's TLS handshake, HTTP/2 settings, and client hints, and then extend
it to read the body and send Chrome's own request fields.

> For builders new to Phantom. [How servers recognize a client](fingerprinting.md)
> explains what the profile below imitates.

Plan on about fifteen minutes. Most of that is the first build of BoringSSL.

## Distribution status

Phantom is pre-1.0 and not on crates.io, and its API can change between
commits. You depend on it through an exact git revision, with one dependency
line and no `[patch]` table; [Adding Phantom to a project](guides/downstream.md)
explains why. The package is named `phantom-http` and the library crate is
`phantom`.

## Prerequisites

- Rust 1.88 or newer. The repository pins its development toolchain in
  `rust-toolchain.toml`.
- Git, CMake, Clang, and a C++ toolchain for the BoringSSL build. Windows also
  needs NASM and the Visual C++ build tools; see
  [CONTRIBUTING.md](../CONTRIBUTING.md#windows). The platform jobs in
  [CI](../.github/workflows/ci.yml) are the source of truth.
- Tokio 1.x.

## 1. Create a project

```console
cargo new phantom-hello
cd phantom-hello
```

Add Phantom and Tokio to `Cargo.toml`. Replace `<commit>` with a commit hash
from the repository, `be02e93` or later; earlier commits lack the Chrome 154
recipes this tutorial uses:

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>" }
tokio = { version = "1", features = ["macros", "rt"] }
```

Run `cargo build` once now. The first build compiles BoringSSL and takes a
few minutes; later builds reuse it.

## 2. Send a request

Replace `src/main.rs` with this program:

```rust,no_run
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RequestHeader};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

Run it with `cargo run`. It prints the status line, such as `200 OK`.

What each part does:

1. A [profile](reference/glossary.md#profile) describes everything a server
   can observe about how the client connects. `ClientProfile::new` starts
   from Chrome 154's TLS ClientHello; `with_http2` and `with_client_hints`
   add Chrome 154's HTTP/2 settings and client-hint fields.
2. `Client::builder(profile).build()` creates a client. The client owns its
   connections and any state kept between requests. Build it once and clone
   it; clones share pools and state.
3. `get(HttpProtocol::Http2, ...)` asks for exactly HTTP/2. If the server
   cannot speak HTTP/2, the request fails; it never falls back to another
   protocol, because that would change the fingerprint.
4. `header` adds one request field. Fields go out in the order you add them.

`#[tokio::main]` builds a runtime with I/O and timers enabled. If you build a
runtime yourself, enable both, or requests fail with
`RequestErrorKind::RuntimeUnavailable`.

## 3. Read the body and check the protocol

A response body is a stream. `collect_with_limit` reads it into memory and
fails if it is longer than the limit you give. Each response also carries a
`ResponseInfo` with the protocol that produced it:

```rust
use phantom::{Client, HttpProtocol, ResponseInfo};

async fn fetch(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .send()
        .await?;

    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("{:?} from {}", info.protocol(), info.effective_uri());
    }

    let body = response.into_body().collect_with_limit(1 << 20).await?;
    println!("{} bytes", body.len());
    Ok(())
}
```

This prints `Http2 from https://example.com/` and the body length. Pass the
`client` from step 2 to `fetch`.

## 4. Send Chrome's request fields

The request in step 2 has Chrome's handshake but only the one field you
added. A browser navigation sends about a dozen fields in a fixed order. A
request template supplies them, as recorded from Chrome 154:

```rust
use phantom::profile::chromium;
use phantom::{Client, HttpProtocol, PreparedRequestTemplate};

async fn navigate(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    // Validate the template once and reuse it for every navigation.
    let navigation = PreparedRequestTemplate::new(chromium::v154_windows_navigation_template())?;
    let page = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .template(&navigation)
        .send()
        .await?;

    println!("{}", page.status());
    Ok(())
}
```

The template fills in `user-agent`, `accept`, the `sec-fetch-*` fields, and
the rest in Chrome's order, and places the profile's client hints in their
slots. Use a template, client hints, and `User-Agent` of one browser and
version: Phantom does not compare them.
[Request templates and client hints](guides/request-templates.md) covers
every template.

## Optional features

No feature is enabled by default. Add them to the `phantom` line in
`Cargo.toml`, for example `features = ["cookies"]`.

| Feature | Adds |
| --- | --- |
| `cookies` | A cookie jar owned by the client, with size limits |
| `https-records` | HTTP/3 discovery from HTTPS DNS records, and the `phantom::dns` lookup types |
| `sse` | Server-sent events, with a limited number of reconnects |
| `websocket` | WebSocket over HTTP/1.1 Upgrade, or HTTP/2 extended CONNECT with an HTTP/2 profile that sets its pseudo-header order |
| `websocket-deflate` | Opt-in `permessage-deflate`; turns on `websocket` |
| `serde` | `Serialize` and `Deserialize` for cookie-jar snapshots, with `cookies` |
| `full` | All of the above |
| `diagnostics` | `ClientBuilder::key_log` and `ClientBuilder::qlog_dir`; not part of `full` |

`diagnostics` writes a TLS key log, so you can decrypt a capture of your own
connections in Wireshark, and a qlog file for each QUIC connection. A key log
holds secrets that decrypt the client's traffic, so `full` leaves the feature
out.

To read the API reference offline, run
`cargo doc -p phantom-http --all-features --no-deps --open` in a checkout of
the repository.

## Next

- [Using the client](guides/client.md): timeouts, bodies, and
  `get_negotiated`, which lets the server choose HTTP/1.1 or HTTP/2.
- [HTTP/3 and Alt-Svc](guides/http3.md): send the same request over QUIC.
- [Browser profiles](guides/profiles.md): Edge, Brave, Opera, and Firefox,
  and custom profiles.
