# Phantom

A Rust HTTP client with browser connection settings and ordered request headers.

Choose a Chrome, Firefox, Edge, Brave, or Opera profile, then send requests over
HTTP/1.1, HTTP/2, or HTTP/3. Phantom gives you control over the TLS handshake,
protocol settings, and header order without running a browser. It does not
execute JavaScript or render pages.

## Try it

Use Rust 1.88 or newer. The native TLS build needs Git, CMake, Clang, and a C++
toolchain. Windows also needs NASM and the Visual C++ build tools. See
[Getting started](https://docs.rs/phantom-http/latest/phantom/guide/getting_started/index.html)
for setup details.

```toml
[dependencies]
phantom = { package = "phantom-http", version = "0.3" }
tokio = { version = "1", features = ["macros", "rt", "net", "time"] }
```

```rust,no_run
use phantom::{profile::browser::chrome, Client, HttpProtocol};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder(chrome::v154_windows()).build()?;
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .send()
        .await?;

    println!("{}", response.status());
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    println!("{} bytes", body.len());
    Ok(())
}
```

This request selects HTTP/2 explicitly. The profile configures the connection;
[request templates](https://docs.rs/phantom-http/latest/phantom/guide/browser_profiles/index.html)
add headers for a navigation or fetch request. Reuse the client across requests
so it can reuse connections and session state.

## Learn more

- [Getting started](https://docs.rs/phantom-http/latest/phantom/guide/getting_started/index.html)
- [Browser profiles and request templates](https://docs.rs/phantom-http/latest/phantom/guide/browser_profiles/index.html)
- [Requests and responses](https://docs.rs/phantom-http/latest/phantom/guide/requests_and_responses/index.html)
- [Proxies](https://docs.rs/phantom-http/latest/phantom/guide/proxies/index.html)
- [Command-line requests and profile tools](crates/phantom-cli/README.md)
- [API reference](https://docs.rs/phantom-http/latest/phantom/) and
  [runnable examples](crates/phantom/examples/README.md)
- Bindings: [Go](bindings/go/README.md),
  [Node.js and TypeScript](bindings/node/README.md),
  [Python](bindings/python/README.md)

Phantom is pre-1.0. Commit your lockfile and read the [changelog](CHANGELOG.md)
when upgrading. For a Git or path dependency, build the docs from that checkout:
`cargo doc -p phantom-http --features full --no-deps --open`.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) to work on Phantom, or
[llms.txt](llms.txt) to use it from a coding agent. Report suspected
vulnerabilities through [SECURITY.md](SECURITY.md).

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
