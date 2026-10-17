# Examples

Each program here performs one task and prints what the server returned.
Run them from a checkout of the repository.

Run an example with `cargo run -p phantom-http --example <name>`, followed by
`--features <feature>` when the table names one and by `--` and the
example's arguments. The first build compiles BoringSSL and takes a few
minutes.

| Example | Task | Run | Feature |
| --- | --- | --- | --- |
| [`first-request`](first_request.rs) | Send an HTTP/2 GET with Chrome 154's profile; print the status and body length | `cargo run -p phantom-http --example first-request -- [url]` | None |
| [`json`](json.rs) | Read a bounded JSON array from an endpoint | `cargo run -p phantom-http --example json --features json -- <url>` | `json` |
| [`request-template`](request_template.rs) | Send a navigation, then a `fetch`, with Chrome 154's request templates | `cargo run -p phantom-http --example request-template -- [url] [fetch-path]` | None |
| [`proxy`](proxy.rs) | Send a request through an HTTP or SOCKS5 proxy | `cargo run -p phantom-http --example proxy -- <proxy-uri> [url]` | None |
| [`http3`](http3.rs) | Send an exact HTTP/3 GET with the Chrome 154 H3 recipes | `cargo run -p phantom-http --example http3 -- [url]` | None |
| [`cookies`](cookies.rs) | Send two requests that share a cookie jar | `cargo run -p phantom-http --example cookies --features cookies -- [url]` | `cookies` |
| [`sse`](sse.rs) | Read a server-sent event stream with browser-style reconnects | `cargo run -p phantom-http --example sse --features sse -- <url> [h1\|h2]` | `sse` |
| [`websocket`](websocket.rs) | Open a WebSocket, send one message, and print the reply | `cargo run -p phantom-http --example websocket --features websocket -- <url> [text]` | `websocket` |

- `[url]` defaults to `https://example.com/`. `sse` and `websocket` need a
  server that speaks the protocol, so they require a URL and print their
  usage without one.
- `proxy` reads the proxy URI from `PHANTOM_EXAMPLE_PROXY` when no argument
  is given. `socks5://` and `socks5h://` URIs select SOCKS5; any other URI
  selects an HTTP proxy. Phantom never reads the system proxy settings.
- Most examples choose an exact protocol: if the server cannot speak it, the
  example fails. `proxy` lets TLS negotiate HTTP/1.1 or HTTP/2.

Read the [guides](https://docs.rs/phantom-http/latest/phantom/guide/index.html)
for setup and how these tasks fit together.

The other programs in this directory, `autobahn-client`,
`wpt-eventsource-client`, and `quic-interop-client`, are test adapters for
conformance suites, not examples of application code.
