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
| HTTP proxy | `Route::http_proxy(HttpProxy)` | HTTPS origins through CONNECT; `http://` origins through HTTP/1.1 forwarding |
| SOCKS5 | `Route::socks5(Socks5Proxy)` | Exact and negotiated H1/H2 over a TCP tunnel; exact and Alt-Svc H3 over UDP ASSOCIATE |
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

- `https://` origins (exact H1 or H2) and `wss://` use a CONNECT tunnel; the
  origin's TLS runs inside it.
- `http://` and `ws://` origins use absolute-form forwarding, for exact
  HTTP/1.1 only. It never switches to CONNECT, H2, H3, negotiated requests,
  or a direct route.
- With an `https://` proxy, Phantom verifies the proxy's certificate under
  the proxy trust settings. Basic credentials sent to an `http://` proxy
  travel unencrypted.
- A valid Basic `407` challenge allows exactly one replay on a fresh
  connection over the same route. The next logical request starts without
  credentials again ([Design](../explanation/design.md#forward-proxy-authentication)).
- To order the CONNECT request's fields, `HttpProxy::header` appends one after
  the leading `Host`, `headers` replaces those after it, and
  `connect_headers` replaces the whole sequence, with
  `HttpConnectHeader::authority` placing `Host`. A literal `Host` or framing
  field fails before proxy I/O. Forwarded requests are not affected.

## Speak HTTP/2 to the proxy

Open the CONNECT tunnel over HTTP/2 for a proxy that accepts only HTTP/2.

```rust
use phantom::{HttpProxy, Route};

fn h2_proxy_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?.with_http2_transport()?;
    Ok(Route::http_proxy(proxy))
}
```

- The route then carries HTTPS origins only. An `http://` proxy rejects the
  option with a `ProxyConfigError`, because Phantom does not speak h2c.
- The ClientHello to the proxy offers the profile's ALPN list unchanged. The
  default mode accepts `http/1.1` or no ALPN; HTTP/2 mode accepts only `h2`.
  A mismatch is a typed proxy error; Phantom never switches proxy protocols.
- HTTP/2 mode needs a profile that offers `h2` and carries HTTP/2 settings,
  or the request fails before proxy I/O.

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
  certificate verification and SNI. With Alt-Svc enabled, a negotiated request
  can later upgrade to H3 over the same proxy
  ([HTTP/3 and Alt-Svc](http3.md#upgrade-to-http3-when-the-server-advertises-it)).
- Exact H3 uses an RFC 1928 UDP ASSOCIATE relay. The TCP control connection
  stays open for as long as the association lives, and associations stay in
  the route-keyed pool for reuse.

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

- The URI template must be `https`, contain `{target_host}` and
  `{target_port}`, and have no user information or fragment.
- Each inner (origin) connection opens its own outer connection to the proxy.
  The outer connection uses the proxy trust roots; the inner one uses the
  origin trust roots.
- The leg is part of the route, so routes that differ only in leg never share
  connections. An ALPN or capability mismatch is a typed proxy error;
  Phantom never switches legs.
- `with_basic_auth` sends credentials once, after a valid `407`, on a fresh
  proxy connection. A second `407` fails.

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
  Building fails when disabled origin verification is combined with added
  origin roots or an H3 profile, and when disabled proxy verification is
  combined with added proxy roots or a CONNECT-UDP default route. Disabled
  proxy verification is not supported for any CONNECT-UDP route, including
  one set per request.

## Limits

- Basic `407` handling on HTTP proxies, including CONNECT tunnels and
  plaintext WebSocket Upgrade requests, follows
  [Forward-proxy authentication](../explanation/design.md#forward-proxy-authentication):
  one replay, a sensitive `Proxy-Authorization` after all caller fields, and
  a typed error for a one-shot streaming body, a second `407`, or a malformed
  or unsupported challenge.
- In HTTP/2 proxy mode, each tunnel opens its own proxy connection with the
  profile's HTTP/2 settings. The CONNECT request (RFC 9113 section 8.5) has
  only `:method` and `:authority`, then lowercase fields; connection-specific
  fields such as `Proxy-Connection` fail before I/O. Closing the origin
  connection resets its stream and ends its proxy connection. Plaintext
  forwarding fails before I/O in this mode.
- SOCKS5 authentication, negotiation, and rejection failures are typed, and
  no other address is tried. A failed proxy TCP connect or QUIC setup is
  retried only through a fresh association on the same route, under the
  [connection-setup retry](retries.md#retry-when-a-connection-fails-to-open)
  policy. The UDP relay address rules are in
  [HTTP/3 internals](../internals/http3.md#socks5-routes).
- Exact H3 cannot use an HTTP proxy. WebSocket over H3 extended CONNECT is
  planned, not supported.
- CONNECT-UDP rejects H1, H2, negotiated requests, and WebSocket before I/O,
  so it cannot learn or use Alt-Svc. Only failures to resolve or connect to
  the proxy are retryable, and a proxy rejection's status is in the typed
  error's source ([full contract](../internals/http3.md#connect-udp-masque)).
- Configuration errors have stable kinds (`ProxyConfigErrorKind`,
  `Socks5ProxyConfigErrorKind`, `ConnectUdpProxyConfigErrorKind`).
  Credentials are validated before I/O and kept out of diagnostics.
- `Route::http_connect` is an older name for `Route::http_proxy`.

## Next

- [Retries and replays](retries.md): what may be repeated on a route.
- [HTTP/3 and Alt-Svc](http3.md): H3 over SOCKS5 and CONNECT-UDP.
- [Route matrix](../reference/route-matrix.md): every supported combination.
