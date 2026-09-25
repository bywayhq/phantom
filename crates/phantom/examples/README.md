# Examples

Each program here performs one task from the guides and prints what the
server returned. Run them from a checkout of the repository.

> For builders who have read [Getting started](../../../docs/getting-started.md).

Run an example with `cargo run -p phantom-http --example <name>`, followed by
`--features <feature>` when the table names one and by `--` and the
example's arguments. The first build compiles BoringSSL and takes a few
minutes.

| Example | Task | Run | Feature | Guide |
| --- | --- | --- | --- | --- |
| [`first-request`](first_request.rs) | Send an HTTP/2 GET with Chrome 154's profile; print the status, `ResponseInfo`, and body length | `cargo run -p phantom-http --example first-request -- [url]` | None | [Getting started](../../../docs/getting-started.md) |
| [`request-template`](request_template.rs) | Send a navigation, then a `fetch`, with Chrome 154's request templates | `cargo run -p phantom-http --example request-template -- [url] [fetch-path]` | None | [Request templates and client hints](../../../docs/guides/request-templates.md#apply-a-captured-request-template) |
| [`proxy`](proxy.rs) | Send a request through an HTTP or SOCKS5 proxy | `cargo run -p phantom-http --example proxy -- <proxy-uri> [url]` | None | [Routes and proxies](../../../docs/guides/routes-and-proxies.md) |
| [`http3`](http3.rs) | Send an exact HTTP/3 GET with the Chrome 154 H3 recipes | `cargo run -p phantom-http --example http3 -- [url]` | None | [HTTP/3 and Alt-Svc](../../../docs/guides/http3.md#send-a-request-over-http3) |
| [`cookies`](cookies.rs) | Send two requests that share a cookie jar | `cargo run -p phantom-http --example cookies --features cookies -- [url]` | `cookies` | [Cookies](../../../docs/guides/cookies.md#keep-cookies-between-requests) |
| [`sse`](sse.rs) | Read a server-sent event stream with browser-style reconnects | `cargo run -p phantom-http --example sse --features sse -- <url> [h1\|h2]` | `sse` | [Server-sent events](../../../docs/guides/sse.md#reconnect-with-last-event-id) |
| [`websocket`](websocket.rs) | Open a WebSocket, send one message, and print the reply | `cargo run -p phantom-http --example websocket --features websocket -- <url> [text]` | `websocket` | [WebSocket](../../../docs/guides/websocket.md#open-a-websocket-over-http11) |

- `[url]` defaults to `https://example.com/`. `sse` and `websocket` need a
  server that speaks the protocol, so they require a URL and print their
  usage without one.
- `proxy` reads the proxy URI from `PHANTOM_EXAMPLE_PROXY` when no argument
  is given. `socks5://` and `socks5h://` URIs select SOCKS5; any other URI
  selects an HTTP proxy. Phantom never reads the system proxy settings.
- Every request uses an [exact protocol](../../../docs/reference/glossary.md#exact-protocol):
  if the server cannot speak it, the example fails instead of falling back.

The other programs in this directory, `autobahn-client`,
`wpt-eventsource-client`, and `quic-interop-client`, are test adapters for
conformance suites, not examples of application code.

## Next

- [Using the client](../../../docs/guides/client.md): timeouts, bodies, and
  negotiated requests.
- [Browser profiles](../../../docs/guides/profiles.md): Edge and Firefox
  recipes and custom profiles.
- [Routes and proxies](../../../docs/guides/routes-and-proxies.md):
  proxy authentication and trust roots.
