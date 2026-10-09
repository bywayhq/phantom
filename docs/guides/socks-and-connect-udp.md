# SOCKS5 and CONNECT-UDP proxies

Send requests through a SOCKS5 proxy, send HTTP/3 through a CONNECT-UDP
proxy, and reach a server at another address it announced.

Both proxies are routes. A route is how a connection reaches the server:
directly, or through a proxy. You pass one to `ClientBuilder::route` or to a
single request, as [Routes and proxies](routes-and-proxies.md) shows. The
[route matrix](../reference/route-matrix.md) lists what each route carries.

## Send a request through a SOCKS5 proxy

Send HTTP/1.1, HTTP/2, and HTTP/3 requests through a SOCKS5 proxy.

```rust
use phantom::{Route, Socks5Proxy};

fn socks_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = Socks5Proxy::new("socks5h://127.0.0.1:1080")?
        .with_username_password("user", "password")?;
    Ok(Route::socks5(proxy))
}
```

- `socks5://` looks up the server's name on your machine. `socks5h://` has
  the proxy look it up.
- HTTP/1.1, HTTP/2, and WebSocket traffic goes through a TCP tunnel in the
  proxy. TLS to the server runs inside the tunnel, with the server's own
  certificate check.
- HTTP/3 goes over UDP, which the proxy relays with SOCKS5 UDP ASSOCIATE.
- If you enable Alt-Svc, a request that lets the server pick its protocol
  can later move to HTTP/3 over the same proxy
  ([HTTP/3 and Alt-Svc](http3.md#upgrade-to-http3-when-the-server-advertises-it)).

Set the login with `with_username_password`. A proxy URL with credentials
in it is rejected.

## Send HTTP/3 through a CONNECT-UDP proxy

Send HTTP/3 requests through a CONNECT-UDP proxy: an HTTPS proxy that
relays UDP (RFC 9298, part of MASQUE).

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

The proxy URL is a template. Phantom fills in `{target_host}` and
`{target_port}` with the server it wants to reach. The connection to the
proxy itself, the proxy leg, uses HTTP/3 by default:

| Proxy leg | Select with |
| --- | --- |
| HTTP/3 | Default |
| HTTP/2 | `with_http2_transport` |
| HTTP/1.1 | `with_http1_transport` |

- The HTTP/2 leg needs HTTP/2 settings that set
  `extended_connect_pseudo_header_order`, as `chrome::v154_http2` does.
- The proxy's certificate is checked against the proxy roots. The server's
  certificate is checked against the server roots.
- `with_basic_auth` sends credentials only after the proxy answers `407`.
  Every tunnel starts without them.

This route carries only HTTP/3 requests that use `HttpProtocol::Http3`.
HTTP/1.1, HTTP/2, and requests that let the server pick fail on it.

## Reach a known alternative service

Send an HTTP/3 request to an alternative service you already know. An
alternative service is another host and port that serves the same site,
which a server names in its `Alt-Svc` header. A CONNECT-UDP route can't
learn one by itself, so you name it.

```rust
use phantom::{Client, HttpProtocol};

async fn fetch(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .get(HttpProtocol::Http3, "https://example.com/")?
        .alt_svc_alternative("alt.example.net", 8443)
        .send()
        .await?;
    drop(response);
    Ok(())
}
```

- Phantom connects to the alternative over the request's route, directly or
  through a CONNECT-UDP proxy.
- The request still names the original server, and the certificate must be
  valid for that name.
- No Alt-Svc store is needed.

If the alternative fails, the request fails. Phantom doesn't fall back to
the original server.

## Limits

- A CONNECT-UDP route retries only failures to reach the proxy.
- Its target port must be between 1 and 65535.
- Each connection to a server opens its own connection to a CONNECT-UDP
  proxy.

## Next

- [HTTP/3 and Alt-Svc](http3.md): HTTP/3 over SOCKS5 and CONNECT-UDP.
- [Retries and replays](retries.md): what may be repeated on a route.
