# Getting started

In this tutorial you create a Rust project and send a request that looks like
it came from Chrome 154. Then you read the response body and send the headers
Chrome sends when it loads a page.

> If fingerprinting is new to you,
> [How servers recognize a client](fingerprinting.md) explains what Phantom
> copies from the browser.

Plan on about fifteen minutes. Most of that is the first build.

## Distribution status

Phantom is pre-1.0 and not on crates.io, so you depend on an exact git
revision. The package is named `phantom-http` and the library crate is
`phantom`. [Adding Phantom to a project](guides/downstream.md) explains why
one dependency line is enough.

## Prerequisites

- Rust 1.88 or newer.
- Git, CMake, Clang, and a C++ compiler. Phantom builds BoringSSL, Google's
  TLS library, from source. On Windows you also need NASM and the Visual C++
  build tools ([CONTRIBUTING.md](../CONTRIBUTING.md#windows) has the steps).
- Tokio 1.x.

## 1. Create a project

```console
cargo new phantom-hello
cd phantom-hello
```

Add Phantom and Tokio to `Cargo.toml`. Replace `<commit>` with a commit hash
from the repository, `be02e93` or later. Earlier commits don't have the
Chrome 154 recipes this tutorial uses.

```toml
[dependencies]
phantom = { package = "phantom-http", git = "https://github.com/bywayhq/phantom", rev = "<commit>" }
tokio = { version = "1", features = ["macros", "rt"] }
```

Run `cargo build` once now. The first build compiles BoringSSL and takes a
few minutes. Later builds reuse it.

## 2. Send a request

Replace `src/main.rs` with this program:

```rust,no_run
use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{Client, HttpProtocol, RequestHeader};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_client_hints(chrome::v154_windows_client_hints());

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

Run it:

```console
$ cargo run
200 OK
```

How it works:

1. You built a [profile](reference/glossary.md#profile): the description of
   how a client connects. `ClientProfile::new` starts from Chrome 154's TLS
   handshake. `with_http2` and `with_client_hints` add Chrome 154's HTTP/2
   settings and client hints. Each of these pieces is called a *recipe*.
2. `Client::builder(profile).build()` created a client. The client holds the
   connections and anything it remembers between requests. Build it once and
   clone it. Clones share the same connections.
3. `get(HttpProtocol::Http2, ...)` asked for HTTP/2. If the server can't
   speak HTTP/2, the request fails instead of switching to another protocol.
4. `header` added one request header. Headers go out in the order you add
   them.

If you build a Tokio runtime yourself, turn on I/O and timers.
`#[tokio::main]` does this for you.

## 3. Read the body and check the protocol

Next, read the response body and see which protocol answered. Add this
function to your program and call it from `main` with the client from step 2:

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

It prints `Http2 from https://example.com/`, then the body length.

The body arrives as a stream. `collect_with_limit` reads it into memory and
returns an error if it's longer than the limit, here 1 MiB. `ResponseInfo`
tells you which protocol and URL produced the response.

## 4. Send Chrome's request headers

The request in step 2 has Chrome's handshake but only the one header you
added. When Chrome loads a page, it sends about a dozen headers in a fixed
order. A request template adds them for you:

```rust
use phantom::profile::browser::chrome;
use phantom::{Client, HttpProtocol, PreparedRequestTemplate};

async fn navigate(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    // Validate the template once and reuse it for every navigation.
    let navigation = PreparedRequestTemplate::new(chrome::v154_windows_navigation_template())?;
    let page = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .template(&navigation)
        .send()
        .await?;

    println!("{}", page.status());
    Ok(())
}
```

The template sends `user-agent`, `accept`, the `sec-fetch-*` headers and the
rest in Chrome's order, with the profile's client hints in their places. Keep
the template, client hints, and `User-Agent` from the same browser and
version. Phantom doesn't check that they match.
[Request templates and client hints](guides/request-templates.md) lists every
template.

## Optional features

No feature is on by default. Add the ones you need to the `phantom` line in
`Cargo.toml`, for example `features = ["cookies"]`.

| Feature | Adds |
| --- | --- |
| `cookies` | A cookie jar |
| `https-records` | Finding HTTP/3 servers through DNS, and `phantom::dns` |
| `sse` | Server-sent events |
| `websocket` | WebSocket |
| `websocket-deflate` | WebSocket compression |
| `serde` | Saving and loading cookie jars |
| `full` | All of the above |
| `diagnostics` | `ClientBuilder::key_log` and `ClientBuilder::qlog_dir` |
| `danger-disable-verification` | `ServerAuthentication::DangerDisabled` |

`full` leaves out the last two. `diagnostics` writes TLS keys that decrypt
your traffic, and `danger-disable-verification` accepts any server
certificate. Use them for debugging and testing only.

To read the API reference offline, run
`cargo doc -p phantom-http --all-features --no-deps --open` in a checkout of
the repository.

## Next

- [Using the client](guides/client.md): timeouts, bodies, and letting the
  server pick the protocol.
- [HTTP/3 and Alt-Svc](guides/http3.md): send the same request over HTTP/3.
- [Browser profiles](guides/profiles.md): Edge, Brave, Opera, Firefox, and
  custom profiles.
