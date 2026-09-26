# Routes and proxies

Choose a route for a client or one request, send requests through an HTTP
proxy, and control which certificates each connection trusts. SOCKS5 and
CONNECT-UDP proxies have their own guide,
[SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md).

> For builders who have read [Using the client](client.md).

A [route](../reference/glossary.md#route) is how the client reaches a server.
The route you set is the route Phantom uses: if the proxy fails, the request
fails with a typed error and never connects directly instead
([Design](../explanation/design.md#principles)). Each pooled connection
belongs to one route, so a request through one proxy never reuses a
connection opened through another.

## Set a route for a client or a request

Set a default route on the builder, and override it for one request.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, Route, Socks5Proxy};

async fn routes() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2());
    let proxy = Socks5Proxy::new("socks5h://127.0.0.1:1080")?;
    let client = Client::builder(profile).route(Route::socks5(proxy)).build()?;

    // This request skips the proxy.
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .route(Route::direct())
        .send()
        .await?;
    drop(response);
    Ok(())
}
```

| Route | Constructor | Carries |
| --- | --- | --- |
| Direct | `Route::direct()`, the default | Every scheme and protocol |
| HTTP proxy | `Route::http_proxy(HttpProxy)` | HTTPS and WebSocket origins through CONNECT, exact or negotiated H1/H2; `http://` origins through H1 forwarding, or H2 forwarding on an HTTP/2 proxy |
| SOCKS5 | `Route::socks5(Socks5Proxy)` | Exact and negotiated H1/H2 and plaintext H1 over a TCP tunnel; exact and Alt-Svc H3 over UDP ASSOCIATE |
| CONNECT-UDP | `Route::connect_udp(ConnectUdpProxy)` | Exact H3 only |

An unsupported combination fails before any proxy or origin I/O. The
[route matrix](../reference/route-matrix.md) lists every combination of
scheme, protocol, and route.

## Send a request through an HTTP proxy

Reach HTTPS origins through a CONNECT tunnel and `http://` origins by
forwarding, with Basic credentials sent once the proxy has asked for them.

```rust
use phantom::{HttpProxy, Route};

fn route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?
        .with_basic_auth("proxy-user", "proxy-password")?;
    let route = Route::http_proxy(proxy);
    Ok(route)
}
```

- `https://` origins (exact H1 or H2, or negotiated) and `wss://` use a
  CONNECT tunnel; the origin's TLS runs inside it. `ws://` uses the same
  tunnel and sends its Upgrade inside it without TLS, as browsers do.
- A negotiated request opens one CONNECT tunnel per connection and lets ALPN
  in the origin handshake choose H1 or H2. If that handshake fails, the
  request fails; Phantom does not retry with another ALPN offer or protocol.
  A tunnel cannot carry QUIC, so these requests never learn an Alt-Svc `h3`
  alternative.
- `http://` origins use absolute-form forwarding over HTTP/1.1.
  A negotiated `http://` request is forwarded as H1, because cleartext has no
  ALPN. Forwarding never switches to CONNECT, H2, H3, or a direct route.
  The Chrome and Edge request templates send `Proxy-Connection: keep-alive`
  on a forwarded request where a direct one has `Connection: keep-alive`.
- With an `https://` proxy, Phantom verifies the proxy's certificate under
  the proxy trust settings. Basic credentials sent to an `http://` proxy
  travel unencrypted.
- The first request to a proxy carries no credentials. A valid Basic `407`
  challenge allows exactly one replay with them over the same route. The
  replay goes on the connection that carried the `407` when the proxy keeps
  it open, as browsers do, and on a new connection when the `407` says
  `Connection: close` or `Proxy-Connection: close`, has no length, or has a
  body over 64 KiB. Once the
  proxy accepts them, later tunnels, WebSocket tunnels, and forwarded
  requests through it send `Proxy-Authorization` on the first attempt, as
  Chrome, Edge, and Firefox do. A `407` to such a request allows the same
  single replay. `ClientBuilder::preemptive_proxy_authentication(false)`
  makes every request wait for a challenge
  ([Design](../explanation/design.md#proxy-authentication)).
- To send credentials on the very first request, leave out
  `with_basic_auth` and add your own `Proxy-Authorization` field: on an
  `http://` request it goes to the forward proxy, and for an HTTPS origin you
  add it to the CONNECT request with `HttpProxy::header`. On an `http://`
  request, the field fails with `RequestErrorKind::InvalidHeader` before I/O
  on any other route, where it would reach the origin, and on a proxy with
  configured credentials.
- A profile with `with_proxy_connect(chromium::v154_proxy_connect())` or
  the Firefox recipe sends the browser's CONNECT fields.
  `HttpProxy::header`, `headers`, and `connect_headers` set your own, which
  replace the profile's ([HTTP proxy rules](../reference/route-matrix.md#http-proxy-rules)).

## Speak HTTP/2 to the proxy

Open CONNECT tunnels and forward `http://` requests over HTTP/2, for a proxy
that accepts only HTTP/2.

```rust
use phantom::{HttpProxy, Route};

fn h2_proxy_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?.with_http2_transport()?;
    Ok(Route::http_proxy(proxy))
}
```

- An `http://` proxy rejects the option with a `ProxyConfigError`, because
  Phantom does not speak h2c.
- `http://` requests go to the proxy as H2 requests with `:scheme` `http`,
  as browsers send them. Use `HttpProtocol::Http2` or `get_negotiated`; exact
  `HttpProtocol::Http1` fails before I/O.
- CONNECT tunnels to different origins are streams of one proxy connection,
  as browsers open them. A tunnel past the proxy's
  `SETTINGS_MAX_CONCURRENT_STREAMS` waits on that connection until another
  stream ends. A new connection opens only after the proxy's `GOAWAY` or
  close, unless you opt into more with
  `ClientBuilder::max_http2_proxy_connections_per_route`.
- The profile's CONNECT recipe decides what else shares that connection:
  with `chromium::v154_proxy_connect`, forwarded `http://` requests and
  WebSocket tunnels do too; with `firefox::v156_proxy_connect`, each of the
  three gets its own connection, as Firefox 156 does. A profile without a
  recipe shares one connection.
- Each [session](connections-and-state.md) opens its own proxy connections.
  Routes with other Basic credentials never share one.
- With `with_basic_auth`, a challenged request or CONNECT is replayed once
  on a new stream of the proxy connection that carried the `407`.
- A proxy that selects any ALPN protocol but `h2` fails with a typed proxy
  error. The default mode accepts `http/1.1` or no ALPN.
- A profile that does not offer `h2` or carry HTTP/2 settings fails before
  proxy I/O.
- The ClientHello to the proxy offers the profile's ALPN list unchanged.

## Trust a private root or a proxy's root

Add roots or change verification separately for origins and proxies.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::Client;

fn private_roots(
    origin_root: Vec<u8>,
    proxy_root: Vec<u8>,
) -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls());
    let client = Client::builder(profile)
        .add_root_certificate_der(origin_root)
        .add_proxy_root_certificate_der(proxy_root)
        .build()?;
    Ok(client)
}
```

- `add_root_certificate_der` and `server_authentication` apply to origins.
  `add_proxy_root_certificate_der` and `proxy_server_authentication` apply to
  HTTPS proxies, including the outer connection of a CONNECT-UDP proxy.
  Added roots join the bundled roots.
- `ServerAuthentication::Disabled` is for controlled conformance work.
- Building fails when disabled origin verification is combined with added
  origin roots or an H3 profile.
- Building fails when disabled proxy verification is combined with added
  proxy roots or a CONNECT-UDP default route. A request with a CONNECT-UDP
  route of its own fails the same way.

## Limits

- A second `407`, a malformed or unsupported challenge, or a one-shot
  streaming body fails an HTTP proxy request with a typed error; see
  [Proxy authentication](../explanation/design.md#proxy-authentication).
- Exact H3 through an HTTP proxy fails before I/O. WebSocket over H3 is not
  supported.
- Configuration errors have stable kinds (`ProxyConfigErrorKind`).
- Credentials are validated before I/O and kept out of diagnostics.
- `Route::http_connect` is an older name for `Route::http_proxy`.

## Next

- [SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md): the routes
  that carry HTTP/3.
- [Retries and replays](retries.md): what may be repeated on a route.
- [Route matrix](../reference/route-matrix.md): every supported combination.
