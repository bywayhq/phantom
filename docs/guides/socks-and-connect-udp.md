# SOCKS5 and CONNECT-UDP proxies

Send requests through a SOCKS5 proxy, and relay HTTP/3 (H3) through a
CONNECT-UDP proxy.

> For builders who have read [Routes and proxies](routes-and-proxies.md).

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
- An H1 `http://` request, exact or negotiated, uses the same tunnel and
  stays plaintext inside it.
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
  proxy connection. Every CONNECT-UDP tunnel starts without credentials,
  because no captured browser authenticates one.
- [CONNECT-UDP rules](../reference/route-matrix.md#connect-udp-rules) lists
  every check and failure.

## Limits

- A SOCKS5 failure never tries another address
  ([SOCKS5 rules](../reference/route-matrix.md#socks5-rules)).
- H1, H2, negotiated requests, and WebSocket fail before I/O on a
  CONNECT-UDP route, so that route never uses Alt-Svc.
- A CONNECT-UDP proxy rejection fails with `RequestErrorKind::Proxy`; only
  failures to resolve or connect to the proxy are retried.
- Configuration errors have stable kinds (`Socks5ProxyConfigErrorKind`,
  `ConnectUdpProxyConfigErrorKind`). Credentials are validated before I/O
  and kept out of diagnostics.

## Next

- [HTTP/3 and Alt-Svc](http3.md): H3 over SOCKS5 and CONNECT-UDP.
- [Route matrix](../reference/route-matrix.md): every supported combination.
- [Retries and replays](retries.md): what may be repeated on a route.
