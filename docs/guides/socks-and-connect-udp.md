# SOCKS5 and CONNECT-UDP proxies

Send requests through a SOCKS5 proxy, relay HTTP/3 (H3) through a
CONNECT-UDP proxy, and reach an origin's known alternative service.

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
- Exact H3, an H3 WebSocket included, uses an RFC 1928 UDP ASSOCIATE relay.
  Its TCP control connection stays open while the association lives, and
  the association stays in the route's pool for reuse.

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

## Reach a known alternative service

Send an [exact H3](../reference/glossary.md#exact-protocol) request to an
[alternative service](../reference/glossary.md#alt-svc) you already know,
such as one the origin's `Alt-Svc` named earlier. A CONNECT-UDP route has no
TCP connection to learn one from.

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

- QUIC goes to the alternative over the request's route, direct or through
  a CONNECT-UDP proxy, which is asked for the alternative, not the origin.
  The request keeps the origin's authority, TLS server name, and
  certificate check. As for a learned alternative, a profile that sends
  [`Alt-Used`](../reference/glossary.md#alt-used), such as Firefox's, adds
  it after the template, caller, and cookie fields; the Chromium recipes
  send none.
- It needs no Alt-Svc store. Setup retries follow the request's
  `RetryPolicy`; a failure returns the H3 error, and nothing falls back to
  the origin, even under the HTTP/2 fallback, or is stored.
- A same-origin redirect keeps the alternative; a redirect to another
  origin goes to that origin's own location.
- The host is a lowercase name, a dotted IPv4 address, or an IPv6 address
  without brackets in its shortest form, and the port is nonzero. Another
  form, a request that is not exact H3, or a caller `Alt-Used` fails before
  any I/O.

## Limits

- A SOCKS5 failure never tries another address
  ([SOCKS5 rules](../reference/route-matrix.md#socks5-rules)).
- H1, H2, negotiated requests, and H1 or H2 WebSockets fail before I/O on a
  CONNECT-UDP route, so that route never learns Alt-Svc; name a known
  alternative instead.
- A CONNECT-UDP proxy rejection fails with `RequestErrorKind::Proxy`; only
  failures to resolve or connect to the proxy are retried.
- Configuration errors have stable kinds (`Socks5ProxyConfigErrorKind`,
  `ConnectUdpProxyConfigErrorKind`). Credentials are validated before I/O
  and kept out of diagnostics.

## Next

- [HTTP/3 and Alt-Svc](http3.md): H3 over SOCKS5 and CONNECT-UDP.
- [Route matrix](../reference/route-matrix.md): every supported combination.
- [Retries and replays](retries.md): what may be repeated on a route.
