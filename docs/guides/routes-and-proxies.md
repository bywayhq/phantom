# Routes and proxies

Send requests directly or through an HTTP proxy, and choose which
certificates each connection trusts. SOCKS5 and CONNECT-UDP proxies, which
can also carry HTTP/3, have their own guide:
[SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md).

A **route** is how a connection reaches the server: directly, or through a
proxy. You set a default route on the client and can override it for one
request. Phantom always uses the route you set. If the proxy fails, the
request fails instead of connecting directly. Connections are pooled per
route, so a request through one proxy never reuses a connection opened
through another.

## Set a route for a client or a request

Set a default route on the builder, and override it for one request.

```rust
use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{Client, HttpProtocol, Route, Socks5Proxy};

async fn routes() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2());
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

| Route | Constructor | Protocols |
| --- | --- | --- |
| Direct | `Route::direct()`, the default | HTTP/1.1, HTTP/2, HTTP/3 |
| HTTP proxy | `Route::http_proxy(HttpProxy)` | HTTP/1.1, HTTP/2 |
| SOCKS5 | `Route::socks5(Socks5Proxy)` | HTTP/1.1, HTTP/2, HTTP/3 |
| CONNECT-UDP | `Route::connect_udp(ConnectUdpProxy)` | HTTP/3 |

Each request names its protocol. With an exact protocol, such as
`HttpProtocol::Http2`, the request uses that protocol or fails. A negotiated
request, from `get_negotiated`, lets the server pick HTTP/1.1 or HTTP/2
during the TLS handshake. A combination that a route can't carry fails
before Phantom connects. The [route matrix](../reference/route-matrix.md)
lists every combination of URL scheme, protocol, and route.

## Send a request through an HTTP proxy

Reach HTTPS servers through a tunnel in the proxy, and `http://` servers by
having the proxy forward the request.

```rust
use phantom::{HttpProxy, Route};

fn route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?
        .with_basic_auth("proxy-user", "proxy-password")?;
    let route = Route::http_proxy(proxy);
    Ok(route)
}
```

- For `https://`, `wss://`, and `ws://` URLs, Phantom sends the proxy a
  CONNECT request to open a tunnel. It then talks to the server inside the
  tunnel, with its own TLS handshake for `https://` and `wss://`.
- For `http://` URLs, the proxy receives the full URL and forwards the
  request over HTTP/1.1.
- A tunnel can't carry HTTP/3, so requests through an HTTP proxy use
  HTTP/1.1 or HTTP/2.
- Phantom sends Basic credentials after the proxy asks for them with a
  `407` response, and replays the request once. After the proxy accepts
  them, later requests through it send them up front.
  `ClientBuilder::preemptive_proxy_authentication(false)` turns that off
  ([Proxy authentication](../explanation/design.md#proxy-authentication)).
- To authenticate the very first request, leave out `with_basic_auth` and
  send your own `Proxy-Authorization` header. Put it on the request for an
  `http://` URL, or on the CONNECT request with `HttpProxy::header`.
- A profile with `with_proxy_connect(chrome::v154_proxy_connect())`, or
  the Firefox recipe, sends the browser's CONNECT headers.
  `HttpProxy::header`, `headers`, and `connect_headers` replace them with
  your own.

Basic credentials sent to an `http://` proxy travel unencrypted.

## Speak HTTP/2 to the proxy

Open tunnels and forward `http://` requests over HTTP/2, for a proxy that
accepts only HTTP/2.

```rust
use phantom::{HttpProxy, Route};

fn h2_proxy_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?.with_http2_transport()?;
    Ok(Route::http_proxy(proxy))
}
```

- The proxy URL must be `https://`, and the profile needs HTTP/2 settings.
  Phantom doesn't speak cleartext HTTP/2 (h2c).
- Tunnels to different servers are streams on one proxy connection, as in a
  browser. `ClientBuilder::max_http2_proxy_connections_per_route` allows
  more connections.
- Forwarded `http://` requests go to the proxy as HTTP/2. Send them with
  `HttpProtocol::Http2` or `get_negotiated`.

## Trust a private root or a proxy's root

Add roots or change verification separately for servers and proxies.

```rust
use phantom::profile::{ClientProfile, browser::chrome};
use phantom::Client;

fn private_roots(
    origin_root: Vec<u8>,
    proxy_root: Vec<u8>,
) -> Result<Client, Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls());
    let client = Client::builder(profile)
        .add_root_certificate_der(origin_root)
        .add_proxy_root_certificate_der(proxy_root)
        .build()?;
    Ok(client)
}
```

- `add_root_certificate_der` and `server_authentication` apply to the
  servers you request.
- `add_proxy_root_certificate_der` and `proxy_server_authentication` apply
  to HTTPS proxies, CONNECT-UDP proxies included.
- Added roots join the bundled roots.
- `ServerAuthentication::DangerDisabled` turns verification off for test
  setups. It needs the `danger-disable-verification` feature.

Building the client fails if you disable verification and also add roots
for the same side. Disabled server verification also rules out an HTTP/3
profile, and disabled proxy verification rules out a CONNECT-UDP route.

## Limits

- A second `407` from the proxy fails the request.
- A request with a one-shot streaming body can't be replayed after a `407`,
  so it fails.

## Next

- [SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md): routes that
  carry HTTP/3.
- [Retries and replays](retries.md): what may be repeated on a route.
