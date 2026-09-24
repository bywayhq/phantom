# Routes and proxies

Send requests directly or through an HTTP, SOCKS5, or CONNECT-UDP proxy, and
control which certificates each connection trusts.

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
| HTTP proxy | `Route::http_proxy(HttpProxy)` | HTTPS origins through CONNECT, exact or negotiated H1/H2; `http://` origins through HTTP/1.1 forwarding |
| SOCKS5 | `Route::socks5(Socks5Proxy)` | Exact and negotiated H1/H2 and plaintext H1 over a TCP tunnel; exact and Alt-Svc H3 over UDP ASSOCIATE |
| CONNECT-UDP | `Route::connect_udp(ConnectUdpProxy)` | Exact H3 only |

An unsupported combination fails before any proxy or origin I/O. The
[route matrix](../reference/route-matrix.md) lists every combination of
scheme, protocol, and route.

## Send a request through an HTTP proxy

Reach HTTPS origins through a CONNECT tunnel and `http://` origins by
forwarding, with Basic credentials sent only when the proxy asks.

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
  CONNECT tunnel; the origin's TLS runs inside it.
- A negotiated request opens one CONNECT tunnel per connection and lets ALPN
  in the origin handshake choose H1 or H2. If that handshake fails, the
  request fails; Phantom does not retry with another ALPN offer or protocol.
  A tunnel cannot carry QUIC, so these requests never learn an Alt-Svc `h3`
  alternative.
- `http://` and `ws://` origins use absolute-form forwarding, for exact
  HTTP/1.1 only. It never switches to CONNECT, H2, H3, negotiated requests,
  or a direct route.
- With an `https://` proxy, Phantom verifies the proxy's certificate under
  the proxy trust settings. Basic credentials sent to an `http://` proxy
  travel unencrypted.
- A valid Basic `407` challenge allows exactly one replay on a fresh
  connection over the same route. The next logical request starts without
  credentials again ([Design](../explanation/design.md#forward-proxy-authentication)).
- To send credentials on the first request instead, leave out
  `with_basic_auth` and add your own `Proxy-Authorization` field: on an
  `http://` request it goes to the forward proxy, and for an HTTPS origin you
  add it to the CONNECT request with `HttpProxy::header`. On an `http://`
  request, the field fails with `RequestErrorKind::InvalidHeader` before I/O
  on any other route, where it would reach the origin, and on a proxy with
  configured credentials.
- `HttpProxy::header`, `headers`, and `connect_headers` order the CONNECT
  request's fields ([HTTP proxy rules](../reference/route-matrix.md#http-proxy-rules)).

## Speak HTTP/2 to the proxy

Open the CONNECT tunnel over HTTP/2 for a proxy that accepts only HTTP/2.

```rust
use phantom::{HttpProxy, Route};

fn h2_proxy_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?.with_http2_transport()?;
    Ok(Route::http_proxy(proxy))
}
```

- An `http://` proxy rejects the option with a `ProxyConfigError`, because
  Phantom does not speak h2c. The route carries HTTPS origins only, and
  plaintext forwarding fails before I/O.
- A proxy that selects any ALPN protocol but `h2` fails with a typed proxy
  error. The default mode accepts `http/1.1` or no ALPN.
- A profile that does not offer `h2` or carry HTTP/2 settings fails before
  proxy I/O.
- The ClientHello to the proxy offers the profile's ALPN list unchanged.

## Send a request through a SOCKS5 proxy

Tunnel H1 and H2 over TCP, and H3 over UDP ASSOCIATE, through a SOCKS5
proxy.

```rust
use phantom::{Route, Socks5Proxy};

fn socks_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = Socks5Proxy::new("socks5h://127.0.0.1:1080")?
        .with_username_password("user", "password")?;
    Ok(Route::socks5(proxy))
}
```

- `socks5://` resolves the origin locally (`Socks5DnsMode::Local`);
  `socks5h://` resolves it at the proxy (`Socks5DnsMode::Remote`).
- Credentials use RFC 1929 username and password authentication.
  Credentials inside the proxy URI are rejected.
- Exact H1 and H2, negotiated requests, and H1 `ws://` and `wss://`
  WebSockets use an RFC 1928 CONNECT tunnel. The origin keeps its own
  certificate verification and SNI.
- An exact H1 `http://` request uses the same tunnel and stays plaintext
  inside it.
- With Alt-Svc enabled, a negotiated request can later upgrade to H3 over the
  same proxy ([HTTP/3 and Alt-Svc](http3.md#upgrade-to-http3-when-the-server-advertises-it)).
- Exact H3 uses an RFC 1928 UDP ASSOCIATE relay. Its TCP control connection
  stays open while the association lives, and the association stays in the
  route's pool for reuse.

## Send HTTP/3 through a CONNECT-UDP proxy

Relay the QUIC datagrams of an exact H3 request through an RFC 9298
CONNECT-UDP (MASQUE) proxy.

```rust
use phantom::{ConnectUdpProxy, RequestHeader, Route};

fn masque_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = ConnectUdpProxy::new(
        "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
    )?
    .header(RequestHeader::new("x-client", "phantom"))
    .with_basic_auth("proxy-user", "proxy-password")?;
    Ok(Route::connect_udp(proxy))
}
```

| Proxy leg | Select with | Requires |
| --- | --- | --- |
| HTTP/3 (default) | Default | HTTP/3 Datagrams large enough for a full 1200-byte QUIC Initial, or the request fails before I/O |
| HTTP/2 | `with_http2_transport` | An extended CONNECT pseudo-header order in the HTTP/2 profile, and a proxy that selects `h2` and enables extended CONNECT |
| HTTP/1.1 | `with_http1_transport` | An `Upgrade: connect-udp` request that receives 101 |

- A template that is not `https`, lacks `{target_host}` or `{target_port}`,
  or has user information or a fragment fails when you build the proxy.
- The connection to the proxy uses the proxy trust roots; the origin
  connection inside it uses the origin trust roots.
- Routes that differ only in leg never share connections.
- `with_basic_auth` sends credentials once, after a valid `407`, on a fresh
  proxy connection.
- [CONNECT-UDP rules](../reference/route-matrix.md#connect-udp-rules) lists
  every check and failure.

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
  [Forward-proxy authentication](../explanation/design.md#forward-proxy-authentication).
- A SOCKS5 failure never tries another address
  ([SOCKS5 rules](../reference/route-matrix.md#socks5-rules)).
- Exact H3 through an HTTP proxy fails before I/O. WebSocket over H3 is not
  supported.
- H1, H2, negotiated requests, and WebSocket fail before I/O on a
  CONNECT-UDP route, so that route never uses Alt-Svc.
- A CONNECT-UDP proxy rejection fails with `RequestErrorKind::Proxy`; only
  failures to resolve or connect to the proxy are retried.
- Configuration errors have stable kinds (`ProxyConfigErrorKind`,
  `Socks5ProxyConfigErrorKind`, `ConnectUdpProxyConfigErrorKind`).
- Credentials are validated before I/O and kept out of diagnostics.
- `Route::http_connect` is an older name for `Route::http_proxy`.

## Next

- [Retries and replays](retries.md): what may be repeated on a route.
- [HTTP/3 and Alt-Svc](http3.md): H3 over SOCKS5 and CONNECT-UDP.
- [Route matrix](../reference/route-matrix.md): every supported combination.
